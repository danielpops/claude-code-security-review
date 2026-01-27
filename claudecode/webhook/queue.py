"""In-memory job queue for webhook processing.

Provides a thread-safe queue with:
- Configurable max size
- Worker thread pool
- Job status tracking
- Deduplication (prevents re-queueing same PR if pending/running)
"""

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from ..logger import get_logger

logger = get_logger(__name__)


class JobStatus(str, Enum):
    """Job status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class PRJob:
    """A PR security scan job.

    Attributes:
        repo: Repository full name (owner/repo).
        pr_number: Pull request number.
        commit_sha: HEAD commit SHA.
        job_id: Unique job identifier (auto-generated if not provided).
        status: Current job status.
        created_at: Job creation timestamp.
        started_at: Job start timestamp (when worker picks it up).
        completed_at: Job completion timestamp.
        result: Job result (findings, error, etc.).
        error: Error message if job failed.
    """
    repo: str
    pr_number: int
    commit_sha: str
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: JobStatus = JobStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def dedup_key(self) -> str:
        """Key for deduplication (repo + PR number)."""
        return f"{self.repo}#{self.pr_number}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'job_id': self.job_id,
            'repo': self.repo,
            'pr_number': self.pr_number,
            'commit_sha': self.commit_sha,
            'status': self.status.value,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'error': self.error,
            # Don't include full result in serialization (too large)
            'has_result': self.result is not None,
        }


class QueueFullError(Exception):
    """Raised when the queue is full."""
    pass


class JobQueue:
    """Thread-safe in-memory job queue with worker pool.

    Example:
        >>> queue = JobQueue(max_size=100, num_workers=2)
        >>> queue.start(worker_fn=my_scan_function)
        >>> job = queue.enqueue(PRJob(repo="owner/repo", pr_number=1, commit_sha="abc"))
        >>> status = queue.get_status()
        >>> queue.stop()
    """

    def __init__(self, max_size: int = 100, num_workers: int = 2):
        """Initialize the job queue.

        Args:
            max_size: Maximum number of pending jobs.
            num_workers: Number of worker threads.
        """
        self.max_size = max_size
        self.num_workers = num_workers

        # Job storage
        self._pending: List[PRJob] = []
        self._running: Dict[str, PRJob] = {}  # job_id -> job
        self._completed: Dict[str, PRJob] = {}  # job_id -> job (limited history)
        self._max_completed = 1000  # Keep last N completed jobs

        # Deduplication tracking
        self._active_keys: set = set()  # dedup_keys of pending/running jobs

        # Thread synchronization
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._shutdown = threading.Event()

        # Worker pool
        self._executor: Optional[ThreadPoolExecutor] = None
        self._worker_fn: Optional[Callable[[PRJob], Dict[str, Any]]] = None

    def start(self, worker_fn: Callable[[PRJob], Dict[str, Any]]) -> None:
        """Start the worker pool.

        Args:
            worker_fn: Function to call for each job. Should return a result dict.
                      Exceptions are caught and stored in job.error.
        """
        if self._executor is not None:
            raise RuntimeError("Queue already started")

        self._worker_fn = worker_fn
        self._shutdown.clear()
        self._executor = ThreadPoolExecutor(
            max_workers=self.num_workers,
            thread_name_prefix="webhook-worker",
        )

        # Start worker threads
        for i in range(self.num_workers):
            self._executor.submit(self._worker_loop, i)

        logger.info(f"Started job queue with {self.num_workers} workers")

    def stop(self, wait: bool = True) -> None:
        """Stop the worker pool.

        Args:
            wait: If True, wait for running jobs to complete.
        """
        if self._executor is None:
            return

        logger.info("Stopping job queue...")
        self._shutdown.set()

        # Wake up any waiting workers
        with self._not_empty:
            self._not_empty.notify_all()

        self._executor.shutdown(wait=wait)
        self._executor = None
        logger.info("Job queue stopped")

    def enqueue(self, job: PRJob) -> PRJob:
        """Add a job to the queue.

        Args:
            job: Job to enqueue.

        Returns:
            The queued job (may be existing job if deduplicated).

        Raises:
            QueueFullError: If the queue is full.
        """
        with self._lock:
            # Check for deduplication
            if job.dedup_key in self._active_keys:
                # Find existing job
                for existing in self._pending:
                    if existing.dedup_key == job.dedup_key:
                        logger.info(
                            f"Job for {job.dedup_key} already pending, skipping"
                        )
                        return existing

                for existing in self._running.values():
                    if existing.dedup_key == job.dedup_key:
                        logger.info(
                            f"Job for {job.dedup_key} already running, skipping"
                        )
                        return existing

            # Check queue size
            if len(self._pending) >= self.max_size:
                raise QueueFullError(
                    f"Queue is full ({self.max_size} pending jobs)"
                )

            # Add to queue
            self._pending.append(job)
            self._active_keys.add(job.dedup_key)

            logger.info(f"Queued job {job.job_id} for {job.repo}#{job.pr_number}")

            # Wake up a worker
            self._not_empty.notify()

            return job

    def get_job(self, job_id: str) -> Optional[PRJob]:
        """Get a job by ID.

        Args:
            job_id: Job identifier.

        Returns:
            The job if found, None otherwise.
        """
        with self._lock:
            # Check pending
            for job in self._pending:
                if job.job_id == job_id:
                    return job

            # Check running
            if job_id in self._running:
                return self._running[job_id]

            # Check completed
            return self._completed.get(job_id)

    def get_status(self) -> Dict[str, Any]:
        """Get queue status.

        Returns:
            Dictionary with queue statistics.
        """
        with self._lock:
            return {
                'pending': len(self._pending),
                'running': len(self._running),
                'completed': len(self._completed),
                'max_size': self.max_size,
                'num_workers': self.num_workers,
                'is_running': self._executor is not None,
            }

    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        limit: int = 50,
    ) -> List[PRJob]:
        """List jobs, optionally filtered by status.

        Args:
            status: Filter by status (None for all).
            limit: Maximum number of jobs to return.

        Returns:
            List of jobs.
        """
        with self._lock:
            jobs = []

            if status is None or status == JobStatus.PENDING:
                jobs.extend(self._pending)

            if status is None or status == JobStatus.RUNNING:
                jobs.extend(self._running.values())

            if status is None or status in (JobStatus.COMPLETED, JobStatus.FAILED):
                # Filter completed by status if specified
                for job in self._completed.values():
                    if status is None or job.status == status:
                        jobs.append(job)

            # Sort by created_at descending
            jobs.sort(key=lambda j: j.created_at, reverse=True)

            return jobs[:limit]

    def _worker_loop(self, worker_id: int) -> None:
        """Worker thread main loop.

        Args:
            worker_id: Worker identifier for logging.
        """
        logger.debug(f"Worker {worker_id} started")

        while not self._shutdown.is_set():
            job = self._get_next_job()

            if job is None:
                continue

            logger.info(
                f"Worker {worker_id} processing job {job.job_id} "
                f"for {job.repo}#{job.pr_number}"
            )

            try:
                result = self._worker_fn(job)
                self._complete_job(job, result=result)
            except Exception as e:
                logger.exception(f"Job {job.job_id} failed: {e}")
                self._complete_job(job, error=str(e))

        logger.debug(f"Worker {worker_id} stopped")

    def _get_next_job(self) -> Optional[PRJob]:
        """Get the next pending job.

        Blocks until a job is available or shutdown is signaled.

        Returns:
            Next job, or None if shutdown.
        """
        with self._not_empty:
            while not self._pending and not self._shutdown.is_set():
                self._not_empty.wait(timeout=1.0)

            if self._shutdown.is_set() and not self._pending:
                return None

            if not self._pending:
                return None

            job = self._pending.pop(0)
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            self._running[job.job_id] = job

            return job

    def _complete_job(
        self,
        job: PRJob,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Mark a job as completed.

        Args:
            job: The completed job.
            result: Job result (if successful).
            error: Error message (if failed).
        """
        with self._lock:
            job.completed_at = time.time()
            job.result = result
            job.error = error
            job.status = JobStatus.FAILED if error else JobStatus.COMPLETED

            # Move from running to completed
            self._running.pop(job.job_id, None)
            self._completed[job.job_id] = job

            # Remove from active keys
            self._active_keys.discard(job.dedup_key)

            # Trim completed history
            if len(self._completed) > self._max_completed:
                # Remove oldest completed jobs
                sorted_jobs = sorted(
                    self._completed.items(),
                    key=lambda x: x[1].completed_at or 0,
                )
                to_remove = len(self._completed) - self._max_completed
                for job_id, _ in sorted_jobs[:to_remove]:
                    del self._completed[job_id]

            status = "completed" if not error else "failed"
            duration = (job.completed_at - job.started_at) if job.started_at else 0
            logger.info(
                f"Job {job.job_id} {status} in {duration:.1f}s"
            )
