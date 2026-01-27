"""Configuration management for the webhook service.

Loads configuration from environment variables with validation and defaults.
"""

import os
from dataclasses import dataclass
from typing import Optional

from ..logger import get_logger

logger = get_logger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid or incomplete."""
    pass


@dataclass
class WebhookConfig:
    """Webhook service configuration.

    Attributes:
        anthropic_api_key: Claude API key for security analysis.
        webhook_secret: Secret for verifying webhook signatures.
        github_token: GitHub PAT (mutually exclusive with App auth).
        github_app_id: GitHub App ID.
        github_app_private_key: GitHub App private key (PEM format).
        github_app_installation_id: GitHub App installation ID.
        github_api_url: GitHub API URL (defaults to api.github.com).
        port: Port to listen on.
        max_workers: Number of worker threads.
        max_queue_size: Maximum pending jobs.
    """
    anthropic_api_key: str
    webhook_secret: str

    # GitHub authentication (either PAT or App)
    github_token: Optional[str] = None
    github_app_id: Optional[str] = None
    github_app_private_key: Optional[str] = None
    github_app_installation_id: Optional[str] = None

    # GitHub API
    github_api_url: str = "https://api.github.com"

    # Server settings
    port: int = 8080
    max_workers: int = 2
    max_queue_size: int = 100

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()

    def _validate(self):
        """Validate configuration values.

        Raises:
            ConfigurationError: If configuration is invalid.
        """
        if not self.anthropic_api_key:
            raise ConfigurationError("ANTHROPIC_API_KEY is required")

        if not self.webhook_secret:
            raise ConfigurationError("WEBHOOK_SECRET is required")

        # Check GitHub authentication
        has_pat = bool(self.github_token)
        has_app = all([
            self.github_app_id,
            self.github_app_private_key,
            self.github_app_installation_id,
        ])

        if not has_pat and not has_app:
            raise ConfigurationError(
                "GitHub authentication required: either GITHUB_TOKEN or all of "
                "GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and GITHUB_APP_INSTALLATION_ID"
            )

        if has_pat and has_app:
            logger.warning(
                "Both PAT and App authentication configured. "
                "App authentication will be preferred."
            )

        # Validate numeric settings
        if self.port < 1 or self.port > 65535:
            raise ConfigurationError(f"Invalid port number: {self.port}")

        if self.max_workers < 1:
            raise ConfigurationError(f"max_workers must be >= 1, got {self.max_workers}")

        if self.max_queue_size < 1:
            raise ConfigurationError(f"max_queue_size must be >= 1, got {self.max_queue_size}")

    @property
    def uses_github_app(self) -> bool:
        """Check if GitHub App authentication is configured."""
        return all([
            self.github_app_id,
            self.github_app_private_key,
            self.github_app_installation_id,
        ])

    @classmethod
    def from_env(cls, **overrides) -> "WebhookConfig":
        """Load configuration from environment variables.

        Args:
            **overrides: Values to override from environment.

        Returns:
            WebhookConfig instance.

        Raises:
            ConfigurationError: If required configuration is missing.
        """
        def get_int(name: str, default: int) -> int:
            value = os.environ.get(name, "")
            if not value:
                return default
            try:
                return int(value)
            except ValueError:
                raise ConfigurationError(f"Invalid integer value for {name}: {value}")

        config = {
            'anthropic_api_key': os.environ.get('ANTHROPIC_API_KEY', ''),
            'webhook_secret': os.environ.get('WEBHOOK_SECRET', ''),
            'github_token': os.environ.get('GITHUB_TOKEN'),
            'github_app_id': os.environ.get('GITHUB_APP_ID'),
            'github_app_private_key': os.environ.get('GITHUB_APP_PRIVATE_KEY'),
            'github_app_installation_id': os.environ.get('GITHUB_APP_INSTALLATION_ID'),
            'github_api_url': os.environ.get('GITHUB_API_URL', 'https://api.github.com'),
            'port': get_int('WEBHOOK_PORT', 8080),
            'max_workers': get_int('MAX_WORKERS', 2),
            'max_queue_size': get_int('MAX_QUEUE_SIZE', 100),
        }

        # Apply overrides
        config.update(overrides)

        return cls(**config)


def load_config(**overrides) -> WebhookConfig:
    """Convenience function to load configuration from environment.

    Args:
        **overrides: Values to override from environment.

    Returns:
        WebhookConfig instance.
    """
    return WebhookConfig.from_env(**overrides)
