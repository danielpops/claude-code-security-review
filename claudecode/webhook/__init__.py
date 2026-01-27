"""Webhook service for GitHub PR security scanning.

This package provides a standalone webhook service that:
- Listens for GitHub PR events (opened, synchronize, reopened)
- Queues security scans in an in-memory job queue
- Runs scans using the existing evaluation engine
- Posts results as PR comments using the existing PR commenter

Usage:
    python -m claudecode.webhook --port 8080 --workers 2

Environment Variables:
    ANTHROPIC_API_KEY: Required. Claude API key for security analysis.
    WEBHOOK_SECRET: Required. Secret for verifying webhook signatures.
    GITHUB_TOKEN: GitHub PAT (if not using GitHub App authentication).
    GITHUB_APP_ID: GitHub App ID (for App authentication).
    GITHUB_APP_PRIVATE_KEY: GitHub App private key PEM (for App authentication).
    GITHUB_APP_INSTALLATION_ID: GitHub App installation ID.
    GITHUB_API_URL: GitHub API URL (for Enterprise).
    WEBHOOK_PORT: Port to listen on (default: 8080).
    MAX_WORKERS: Number of worker threads (default: 2).
    MAX_QUEUE_SIZE: Maximum pending jobs (default: 100).
"""

from .config import WebhookConfig
from .auth import get_github_token, GitHubAppAuth, TokenProvider
from .queue import JobQueue, PRJob, JobStatus

__all__ = [
    'WebhookConfig',
    'get_github_token',
    'GitHubAppAuth',
    'TokenProvider',
    'JobQueue',
    'PRJob',
    'JobStatus',
]
