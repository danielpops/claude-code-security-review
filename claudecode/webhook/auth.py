"""GitHub authentication for the webhook service.

Supports two authentication modes:
1. Personal Access Token (PAT): Uses GITHUB_TOKEN environment variable.
2. GitHub App: Generates installation tokens from App credentials.

GitHub App authentication is preferred when configured as it:
- Provides higher rate limits
- Can be scoped to specific repositories
- Tokens auto-expire (better security)
"""

import time
from typing import Optional

import jwt
import requests

from ..logger import get_logger
from .config import WebhookConfig

logger = get_logger(__name__)


class GitHubAuthError(Exception):
    """Raised when GitHub authentication fails."""
    pass


class GitHubAppAuth:
    """GitHub App authentication handler.

    Generates and manages installation access tokens from GitHub App credentials.
    Tokens are cached and automatically refreshed before expiry.
    """

    # Refresh tokens 5 minutes before expiry
    TOKEN_REFRESH_BUFFER_SECONDS = 300

    def __init__(
        self,
        app_id: str,
        private_key: str,
        installation_id: str,
        api_url: str = "https://api.github.com",
    ):
        """Initialize GitHub App authentication.

        Args:
            app_id: GitHub App ID.
            private_key: Private key in PEM format.
            installation_id: Installation ID for the App.
            api_url: GitHub API URL (for Enterprise).
        """
        self.app_id = app_id
        self.private_key = private_key
        self.installation_id = installation_id
        self.api_url = api_url.rstrip('/')

        # Cached token and expiry time
        self._token: Optional[str] = None
        self._token_expires_at: float = 0

    def _create_jwt(self) -> str:
        """Create a JWT for authenticating as the GitHub App.

        The JWT is signed with the App's private key and is valid for 10 minutes.

        Returns:
            Signed JWT string.

        Raises:
            GitHubAuthError: If JWT creation fails.
        """
        now = int(time.time())

        payload = {
            # Issued at time (60 seconds in the past to allow for clock drift)
            'iat': now - 60,
            # Expiration time (10 minutes maximum)
            'exp': now + 600,
            # GitHub App ID
            'iss': self.app_id,
        }

        try:
            return jwt.encode(payload, self.private_key, algorithm='RS256')
        except Exception as e:
            raise GitHubAuthError(f"Failed to create JWT: {e}") from e

    def _get_installation_token(self) -> tuple[str, float]:
        """Exchange JWT for an installation access token.

        Returns:
            Tuple of (token, expiry_timestamp).

        Raises:
            GitHubAuthError: If token exchange fails.
        """
        jwt_token = self._create_jwt()

        url = f"{self.api_url}/app/installations/{self.installation_id}/access_tokens"
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json',
        }

        try:
            response = requests.post(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            token = data['token']
            # Parse expiry time (ISO 8601 format)
            expires_at = data.get('expires_at', '')

            # Default to 1 hour if no expiry provided
            if expires_at:
                import datetime
                # Parse ISO format: 2024-01-01T12:00:00Z
                dt = datetime.datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                expiry_timestamp = dt.timestamp()
            else:
                expiry_timestamp = time.time() + 3600

            return token, expiry_timestamp

        except requests.HTTPError as e:
            status = e.response.status_code if e.response else 'unknown'
            raise GitHubAuthError(
                f"Failed to get installation token: HTTP {status}"
            ) from e
        except requests.RequestException as e:
            raise GitHubAuthError(f"Request failed: {e}") from e
        except (KeyError, ValueError) as e:
            raise GitHubAuthError(f"Invalid response from GitHub: {e}") from e

    def get_token(self) -> str:
        """Get a valid installation access token.

        Returns a cached token if still valid, otherwise fetches a new one.

        Returns:
            Installation access token.

        Raises:
            GitHubAuthError: If token retrieval fails.
        """
        now = time.time()

        # Check if cached token is still valid
        if self._token and self._token_expires_at > (now + self.TOKEN_REFRESH_BUFFER_SECONDS):
            return self._token

        # Fetch new token
        logger.info("Fetching new GitHub App installation token")
        self._token, self._token_expires_at = self._get_installation_token()

        return self._token

    @property
    def token_expires_in(self) -> float:
        """Get seconds until the current token expires.

        Returns:
            Seconds until expiry, or 0 if no token is cached.
        """
        if not self._token:
            return 0
        return max(0, self._token_expires_at - time.time())


def get_github_token(config: WebhookConfig) -> str:
    """Get a GitHub token based on configuration.

    Uses GitHub App authentication if configured, otherwise falls back to PAT.

    Args:
        config: Webhook configuration.

    Returns:
        GitHub access token.

    Raises:
        GitHubAuthError: If no valid authentication is available.
    """
    if config.uses_github_app:
        auth = GitHubAppAuth(
            app_id=config.github_app_id,
            private_key=config.github_app_private_key,
            installation_id=config.github_app_installation_id,
            api_url=config.github_api_url,
        )
        return auth.get_token()

    if config.github_token:
        return config.github_token

    raise GitHubAuthError("No GitHub authentication configured")


class TokenProvider:
    """Provides GitHub tokens with automatic refresh for App authentication.

    This class wraps the authentication logic to provide a consistent interface
    for both PAT and App authentication, with automatic token refresh for Apps.
    """

    def __init__(self, config: WebhookConfig):
        """Initialize the token provider.

        Args:
            config: Webhook configuration.
        """
        self.config = config
        self._app_auth: Optional[GitHubAppAuth] = None

        if config.uses_github_app:
            self._app_auth = GitHubAppAuth(
                app_id=config.github_app_id,
                private_key=config.github_app_private_key,
                installation_id=config.github_app_installation_id,
                api_url=config.github_api_url,
            )

    def get_token(self) -> str:
        """Get a valid GitHub token.

        Returns:
            GitHub access token.

        Raises:
            GitHubAuthError: If no valid authentication is available.
        """
        if self._app_auth:
            return self._app_auth.get_token()

        if self.config.github_token:
            return self.config.github_token

        raise GitHubAuthError("No GitHub authentication configured")

    @property
    def uses_app_auth(self) -> bool:
        """Check if using GitHub App authentication."""
        return self._app_auth is not None
