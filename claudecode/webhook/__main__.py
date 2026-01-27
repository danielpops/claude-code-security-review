"""CLI entry point for the webhook server.

Usage:
    python -m claudecode.webhook --port 8080 --workers 2

Environment variables:
    ANTHROPIC_API_KEY: Required. Claude API key.
    WEBHOOK_SECRET: Required. Webhook signature secret.
    GITHUB_TOKEN: GitHub PAT (if not using App auth).
    GITHUB_APP_ID: GitHub App ID.
    GITHUB_APP_PRIVATE_KEY: GitHub App private key.
    GITHUB_APP_INSTALLATION_ID: GitHub App installation ID.
    GITHUB_API_URL: GitHub API URL (for Enterprise).
"""

import argparse
import sys

import uvicorn

from .config import ConfigurationError, load_config
from .server import create_app


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="GitHub webhook server for ClaudeCode security scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
  ANTHROPIC_API_KEY           Claude API key (required)
  WEBHOOK_SECRET              Webhook signature secret (required)
  GITHUB_TOKEN                GitHub PAT (if not using App auth)
  GITHUB_APP_ID               GitHub App ID
  GITHUB_APP_PRIVATE_KEY      GitHub App private key (PEM)
  GITHUB_APP_INSTALLATION_ID  GitHub App installation ID
  GITHUB_API_URL              GitHub API URL (for Enterprise)

Examples:
  # Start with default settings
  python -m claudecode.webhook

  # Custom port and workers
  python -m claudecode.webhook --port 9000 --workers 4

  # With all options
  python -m claudecode.webhook --port 8080 --workers 2 --host 0.0.0.0
        """,
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to listen on (default: 8080, or WEBHOOK_PORT env var)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of scan workers (default: 2, or MAX_WORKERS env var)",
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=None,
        help="Maximum queue size (default: 100, or MAX_QUEUE_SIZE env var)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Logging level (default: info)",
    )

    args = parser.parse_args()

    # Build config overrides from command line
    overrides = {}
    if args.port is not None:
        overrides["port"] = args.port
    if args.workers is not None:
        overrides["max_workers"] = args.workers
    if args.queue_size is not None:
        overrides["max_queue_size"] = args.queue_size

    # Load configuration
    try:
        config = load_config(**overrides)
    except ConfigurationError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        print("\nRun with --help for usage information.", file=sys.stderr)
        sys.exit(1)

    # Create app
    app = create_app(config)

    # Print startup info
    print(f"Starting ClaudeCode webhook server")
    print(f"  Host: {args.host}")
    print(f"  Port: {config.port}")
    print(f"  Workers: {config.max_workers}")
    print(f"  Queue size: {config.max_queue_size}")
    print(f"  GitHub API: {config.github_api_url}")
    print(f"  Auth mode: {'GitHub App' if config.uses_github_app else 'PAT'}")
    print()

    # Run server
    uvicorn.run(
        app,
        host=args.host,
        port=config.port,
        log_level=args.log_level,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
