"""FastAPI webhook server for GitHub PR security scanning.

Endpoints:
- POST /webhook: Receive GitHub webhook events
- GET /health: Health check endpoint
- GET /status: Queue status endpoint
- GET /jobs/{job_id}: Get job details
"""

import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from ..evals.eval_engine import EvaluationEngine, EvalCase, sanitize_credentials
from ..github_client import GitHubClient, validate_repo_name, validate_pr_number
from ..logger import get_logger
from ..pr_commenter import PRCommenter
from .auth import TokenProvider
from .config import WebhookConfig
from .queue import JobQueue, PRJob, QueueFullError, JobStatus

logger = get_logger(__name__)


def create_app(config: WebhookConfig) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Webhook configuration.

    Returns:
        Configured FastAPI application.
    """
    # Initialize components
    token_provider = TokenProvider(config)
    job_queue = JobQueue(
        max_size=config.max_queue_size,
        num_workers=config.max_workers,
    )

    def process_job(job: PRJob) -> Dict[str, Any]:
        """Process a security scan job.

        Args:
            job: PR job to process.

        Returns:
            Job result dictionary.
        """
        logger.info(f"Processing {job.repo}#{job.pr_number} at {job.commit_sha[:8]}")

        # Get fresh token (may refresh if using App auth)
        token = token_provider.get_token()

        # Set up environment for the evaluation engine
        os.environ['GITHUB_TOKEN'] = token
        os.environ['ANTHROPIC_API_KEY'] = config.anthropic_api_key
        if config.github_api_url != 'https://api.github.com':
            os.environ['GITHUB_API_URL'] = config.github_api_url

        # Run evaluation
        engine = EvaluationEngine(verbose=True)
        test_case = EvalCase(
            repo_name=job.repo,
            pr_number=job.pr_number,
            description=f"Webhook scan for {job.repo}#{job.pr_number}",
        )

        result = engine.run_evaluation(test_case)

        # Post findings as PR comments
        if result.success and result.full_findings:
            try:
                owner, repo = validate_repo_name(job.repo)
                client = GitHubClient(token=token, api_url=config.github_api_url)
                commenter = PRCommenter(client=client)
                posted = commenter.post_findings(
                    owner=owner,
                    repo=repo,
                    pr_number=job.pr_number,
                    commit_sha=job.commit_sha,
                    findings=result.full_findings,
                )
                logger.info(f"Posted {posted} comments to {job.repo}#{job.pr_number}")
            except Exception as e:
                logger.error(f"Failed to post comments: {sanitize_credentials(str(e))}")

        return result.to_dict()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage application lifespan events."""
        # Startup
        job_queue.start(worker_fn=process_job)
        logger.info("Webhook server started")
        yield
        # Shutdown
        job_queue.stop(wait=True)
        logger.info("Webhook server stopped")

    app = FastAPI(
        title="ClaudeCode Security Webhook",
        description="GitHub webhook service for PR security scanning",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Store in app state
    app.state.config = config
    app.state.token_provider = token_provider
    app.state.job_queue = job_queue

    @app.get("/health")
    async def health() -> Dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy"}

    @app.get("/status")
    async def status() -> Dict[str, Any]:
        """Get queue status."""
        queue_status = job_queue.get_status()
        return {
            "status": "running" if queue_status["is_running"] else "stopped",
            "queue": queue_status,
        }

    @app.get("/jobs/{job_id}")
    async def get_job(job_id: str) -> Dict[str, Any]:
        """Get job details by ID."""
        job = job_queue.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job.to_dict()

    @app.get("/jobs")
    async def list_jobs(
        status: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List jobs with optional status filter."""
        job_status = None
        if status:
            try:
                job_status = JobStatus(status)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status: {status}. Valid values: {[s.value for s in JobStatus]}",
                )

        jobs = job_queue.list_jobs(status=job_status, limit=min(limit, 100))
        return {
            "jobs": [j.to_dict() for j in jobs],
            "count": len(jobs),
        }

    @app.post("/webhook")
    async def webhook(request: Request) -> Dict[str, Any]:
        """Handle GitHub webhook events.

        Verifies the webhook signature and processes PR events.
        """
        # Get signature header
        signature = request.headers.get("X-Hub-Signature-256")
        if not signature:
            raise HTTPException(status_code=401, detail="Missing signature")

        # Read body
        body = await request.body()

        # Verify signature
        if not verify_signature(body, signature, config.webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Get event type
        event = request.headers.get("X-GitHub-Event")
        if not event:
            raise HTTPException(status_code=400, detail="Missing event type")

        # Parse payload
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        # Handle ping event (sent when webhook is first configured)
        if event == "ping":
            return {"status": "pong", "zen": payload.get("zen", "")}

        # Handle PR events
        if event == "pull_request":
            return handle_pull_request(payload, job_queue)

        # Ignore other events
        logger.debug(f"Ignoring event type: {event}")
        return {"status": "ignored", "event": event}

    return app


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify webhook signature using HMAC-SHA256.

    Args:
        payload: Request body bytes.
        signature: X-Hub-Signature-256 header value.
        secret: Webhook secret.

    Returns:
        True if signature is valid.
    """
    if not signature.startswith("sha256="):
        return False

    expected_sig = signature[7:]  # Remove "sha256=" prefix

    # Compute HMAC-SHA256
    mac = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256,
    )
    computed_sig = mac.hexdigest()

    # Use constant-time comparison
    return hmac.compare_digest(computed_sig, expected_sig)


def handle_pull_request(payload: Dict[str, Any], queue: JobQueue) -> Dict[str, Any]:
    """Handle a pull_request webhook event.

    Args:
        payload: Webhook payload.
        queue: Job queue.

    Returns:
        Response dictionary.
    """
    action = payload.get("action")

    # Only handle relevant actions
    if action not in ("opened", "synchronize", "reopened"):
        logger.debug(f"Ignoring PR action: {action}")
        return {"status": "ignored", "action": action}

    # Extract PR details
    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {}).get("full_name")

    if not repo:
        raise HTTPException(status_code=400, detail="Missing repository info")

    pr_number = pr.get("number")
    if not pr_number:
        raise HTTPException(status_code=400, detail="Missing PR number")

    commit_sha = pr.get("head", {}).get("sha")
    if not commit_sha:
        raise HTTPException(status_code=400, detail="Missing commit SHA")

    # Validate inputs
    try:
        validate_repo_name(repo)
        validate_pr_number(pr_number)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create job
    job = PRJob(
        repo=repo,
        pr_number=pr_number,
        commit_sha=commit_sha,
    )

    # Enqueue job
    try:
        queued_job = queue.enqueue(job)
        is_new = queued_job.job_id == job.job_id

        return {
            "status": "queued" if is_new else "deduplicated",
            "job_id": queued_job.job_id,
            "repo": repo,
            "pr_number": pr_number,
        }

    except QueueFullError as e:
        logger.warning(f"Queue full, rejecting job for {repo}#{pr_number}")
        raise HTTPException(status_code=503, detail=str(e))
