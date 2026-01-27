"""Unit tests for the webhook service."""

import hashlib
import hmac
import json
import os
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import pytest

from claudecode.webhook.config import ConfigurationError, WebhookConfig, load_config
from claudecode.webhook.auth import (
    GitHubAppAuth,
    GitHubAuthError,
    TokenProvider,
    get_github_token,
)
from claudecode.webhook.queue import (
    JobQueue,
    JobStatus,
    PRJob,
    QueueFullError,
)
from claudecode.webhook.server import create_app, verify_signature, handle_pull_request


class TestWebhookConfig(unittest.TestCase):
    """Tests for WebhookConfig."""

    def test_config_from_env(self):
        """Test loading config from environment variables."""
        env = {
            'ANTHROPIC_API_KEY': 'test-anthropic-key',
            'WEBHOOK_SECRET': 'test-secret',
            'GITHUB_TOKEN': 'test-github-token',
            'GITHUB_API_URL': 'https://github.example.com/api/v3',
            'WEBHOOK_PORT': '9000',
            'MAX_WORKERS': '4',
            'MAX_QUEUE_SIZE': '50',
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_config()

            assert config.anthropic_api_key == 'test-anthropic-key'
            assert config.webhook_secret == 'test-secret'
            assert config.github_token == 'test-github-token'
            assert config.github_api_url == 'https://github.example.com/api/v3'
            assert config.port == 9000
            assert config.max_workers == 4
            assert config.max_queue_size == 50

    def test_config_missing_anthropic_key(self):
        """Test error when ANTHROPIC_API_KEY is missing."""
        env = {
            'WEBHOOK_SECRET': 'test-secret',
            'GITHUB_TOKEN': 'test-token',
        }

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError, match="ANTHROPIC_API_KEY"):
                load_config()

    def test_config_missing_webhook_secret(self):
        """Test error when WEBHOOK_SECRET is missing."""
        env = {
            'ANTHROPIC_API_KEY': 'test-key',
            'GITHUB_TOKEN': 'test-token',
        }

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError, match="WEBHOOK_SECRET"):
                load_config()

    def test_config_missing_github_auth(self):
        """Test error when no GitHub auth is configured."""
        env = {
            'ANTHROPIC_API_KEY': 'test-key',
            'WEBHOOK_SECRET': 'test-secret',
        }

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigurationError, match="GitHub authentication"):
                load_config()

    def test_config_github_app_auth(self):
        """Test config with GitHub App authentication."""
        env = {
            'ANTHROPIC_API_KEY': 'test-key',
            'WEBHOOK_SECRET': 'test-secret',
            'GITHUB_APP_ID': '12345',
            'GITHUB_APP_PRIVATE_KEY': 'test-private-key',
            'GITHUB_APP_INSTALLATION_ID': '67890',
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_config()

            assert config.uses_github_app
            assert config.github_app_id == '12345'
            assert config.github_app_private_key == 'test-private-key'
            assert config.github_app_installation_id == '67890'

    def test_config_overrides(self):
        """Test that overrides take precedence over environment."""
        env = {
            'ANTHROPIC_API_KEY': 'env-key',
            'WEBHOOK_SECRET': 'env-secret',
            'GITHUB_TOKEN': 'env-token',
            'WEBHOOK_PORT': '8080',
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_config(port=9999, max_workers=10)

            assert config.port == 9999
            assert config.max_workers == 10

    def test_config_invalid_port(self):
        """Test error with invalid port number."""
        with pytest.raises(ConfigurationError, match="Invalid port"):
            WebhookConfig(
                anthropic_api_key='key',
                webhook_secret='secret',
                github_token='token',
                port=70000,
            )

    def test_config_invalid_workers(self):
        """Test error with invalid worker count."""
        with pytest.raises(ConfigurationError, match="max_workers"):
            WebhookConfig(
                anthropic_api_key='key',
                webhook_secret='secret',
                github_token='token',
                max_workers=0,
            )


class TestGitHubAuth(unittest.TestCase):
    """Tests for GitHub authentication."""

    def test_get_token_with_pat(self):
        """Test getting token with PAT configuration."""
        config = WebhookConfig(
            anthropic_api_key='key',
            webhook_secret='secret',
            github_token='test-pat-token',
        )

        token = get_github_token(config)
        assert token == 'test-pat-token'

    @patch('claudecode.webhook.auth.requests.post')
    @patch('claudecode.webhook.auth.jwt.encode')
    def test_get_token_with_app(self, mock_jwt_encode, mock_post):
        """Test getting token with GitHub App configuration."""
        mock_jwt_encode.return_value = 'test-jwt'
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'token': 'installation-token',
            'expires_at': '2024-12-31T23:59:59Z',
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        config = WebhookConfig(
            anthropic_api_key='key',
            webhook_secret='secret',
            github_app_id='12345',
            github_app_private_key='-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----',
            github_app_installation_id='67890',
        )

        token = get_github_token(config)
        assert token == 'installation-token'

    def test_token_provider_pat(self):
        """Test TokenProvider with PAT."""
        config = WebhookConfig(
            anthropic_api_key='key',
            webhook_secret='secret',
            github_token='test-pat',
        )

        provider = TokenProvider(config)
        assert not provider.uses_app_auth
        assert provider.get_token() == 'test-pat'

    @patch.object(GitHubAppAuth, 'get_token')
    def test_token_provider_app(self, mock_get_token):
        """Test TokenProvider with GitHub App."""
        mock_get_token.return_value = 'app-token'

        config = WebhookConfig(
            anthropic_api_key='key',
            webhook_secret='secret',
            github_app_id='12345',
            github_app_private_key='test-key',
            github_app_installation_id='67890',
        )

        provider = TokenProvider(config)
        assert provider.uses_app_auth
        assert provider.get_token() == 'app-token'


class TestJobQueue(unittest.TestCase):
    """Tests for JobQueue."""

    def test_enqueue_and_process(self):
        """Test basic job enqueue and processing."""
        queue = JobQueue(max_size=10, num_workers=1)
        processed = []

        def worker_fn(job):
            processed.append(job.job_id)
            return {'status': 'success'}

        queue.start(worker_fn)

        try:
            job = PRJob(repo='owner/repo', pr_number=1, commit_sha='abc123')
            queued = queue.enqueue(job)

            assert queued.job_id == job.job_id
            assert queued.status == JobStatus.PENDING

            # Wait for processing
            time.sleep(0.5)

            assert job.job_id in processed
            completed_job = queue.get_job(job.job_id)
            assert completed_job.status == JobStatus.COMPLETED
        finally:
            queue.stop()

    def test_deduplication(self):
        """Test that duplicate jobs are not re-queued."""
        queue = JobQueue(max_size=10, num_workers=1)
        processing = threading.Event()

        def worker_fn(job):
            processing.wait()  # Block until signaled
            return {'status': 'success'}

        queue.start(worker_fn)

        try:
            job1 = PRJob(repo='owner/repo', pr_number=1, commit_sha='abc123')
            job2 = PRJob(repo='owner/repo', pr_number=1, commit_sha='def456')  # Same PR

            queued1 = queue.enqueue(job1)
            time.sleep(0.1)  # Let job1 start running
            queued2 = queue.enqueue(job2)

            # Should return existing job, not create new one
            assert queued2.job_id == queued1.job_id

            processing.set()  # Allow processing to complete
        finally:
            queue.stop()

    def test_queue_full(self):
        """Test queue full error."""
        queue = JobQueue(max_size=2, num_workers=0)  # No workers to keep jobs pending

        # Can't start without workers, so just test the queue logic
        queue._pending.append(PRJob(repo='r1', pr_number=1, commit_sha='a'))
        queue._pending.append(PRJob(repo='r2', pr_number=2, commit_sha='b'))
        queue._active_keys.add('r1#1')
        queue._active_keys.add('r2#2')

        job3 = PRJob(repo='r3', pr_number=3, commit_sha='c')

        with pytest.raises(QueueFullError):
            queue.enqueue(job3)

    def test_job_status(self):
        """Test queue status reporting."""
        queue = JobQueue(max_size=100, num_workers=2)
        status = queue.get_status()

        assert status['pending'] == 0
        assert status['running'] == 0
        assert status['completed'] == 0
        assert status['max_size'] == 100
        assert status['num_workers'] == 2
        assert status['is_running'] is False

    def test_job_failure(self):
        """Test job failure handling."""
        queue = JobQueue(max_size=10, num_workers=1)

        def worker_fn(job):
            raise ValueError("Test error")

        queue.start(worker_fn)

        try:
            job = PRJob(repo='owner/repo', pr_number=1, commit_sha='abc123')
            queue.enqueue(job)

            # Wait for processing
            time.sleep(0.5)

            completed_job = queue.get_job(job.job_id)
            assert completed_job.status == JobStatus.FAILED
            assert completed_job.error == "Test error"
        finally:
            queue.stop()

    def test_list_jobs(self):
        """Test listing jobs with status filter."""
        queue = JobQueue(max_size=100, num_workers=1)

        def worker_fn(job):
            return {'status': 'success'}

        queue.start(worker_fn)

        try:
            job1 = PRJob(repo='owner/repo1', pr_number=1, commit_sha='abc')
            job2 = PRJob(repo='owner/repo2', pr_number=2, commit_sha='def')

            queue.enqueue(job1)
            queue.enqueue(job2)

            time.sleep(0.5)  # Wait for processing

            completed = queue.list_jobs(status=JobStatus.COMPLETED)
            assert len(completed) == 2

            pending = queue.list_jobs(status=JobStatus.PENDING)
            assert len(pending) == 0
        finally:
            queue.stop()


class TestPRJob(unittest.TestCase):
    """Tests for PRJob dataclass."""

    def test_dedup_key(self):
        """Test deduplication key generation."""
        job = PRJob(repo='owner/repo', pr_number=42, commit_sha='abc123')
        assert job.dedup_key == 'owner/repo#42'

    def test_to_dict(self):
        """Test serialization to dictionary."""
        job = PRJob(repo='owner/repo', pr_number=42, commit_sha='abc123')
        data = job.to_dict()

        assert data['repo'] == 'owner/repo'
        assert data['pr_number'] == 42
        assert data['commit_sha'] == 'abc123'
        assert data['status'] == 'pending'
        assert 'job_id' in data
        assert 'created_at' in data


class TestWebhookServer(unittest.TestCase):
    """Tests for webhook server."""

    def test_verify_signature_valid(self):
        """Test valid webhook signature verification."""
        payload = b'{"test": "data"}'
        secret = 'test-secret'

        mac = hmac.new(secret.encode(), payload, hashlib.sha256)
        signature = f"sha256={mac.hexdigest()}"

        assert verify_signature(payload, signature, secret)

    def test_verify_signature_invalid(self):
        """Test invalid webhook signature rejection."""
        payload = b'{"test": "data"}'
        secret = 'test-secret'

        # Wrong signature
        assert not verify_signature(payload, "sha256=invalid", secret)

        # Missing prefix
        assert not verify_signature(payload, "invalid", secret)

        # Wrong secret
        mac = hmac.new(b'wrong-secret', payload, hashlib.sha256)
        wrong_sig = f"sha256={mac.hexdigest()}"
        assert not verify_signature(payload, wrong_sig, secret)

    def test_handle_pull_request_opened(self):
        """Test handling PR opened event."""
        queue = MagicMock()
        # Return the same job that was passed in to simulate a new job being queued
        queue.enqueue.side_effect = lambda job: job

        payload = {
            'action': 'opened',
            'repository': {'full_name': 'owner/repo'},
            'pull_request': {
                'number': 1,
                'head': {'sha': 'abc123'},
            },
        }

        result = handle_pull_request(payload, queue)

        assert result['status'] == 'queued'
        assert 'job_id' in result
        queue.enqueue.assert_called_once()

    def test_handle_pull_request_ignored_action(self):
        """Test that non-relevant PR actions are ignored."""
        queue = MagicMock()

        payload = {
            'action': 'closed',
            'repository': {'full_name': 'owner/repo'},
            'pull_request': {
                'number': 1,
                'head': {'sha': 'abc123'},
            },
        }

        result = handle_pull_request(payload, queue)

        assert result['status'] == 'ignored'
        queue.enqueue.assert_not_called()

    def test_handle_pull_request_synchronize(self):
        """Test handling PR synchronize (push) event."""
        queue = MagicMock()
        # Return the same job that was passed in to simulate a new job being queued
        queue.enqueue.side_effect = lambda job: job

        payload = {
            'action': 'synchronize',
            'repository': {'full_name': 'owner/repo'},
            'pull_request': {
                'number': 1,
                'head': {'sha': 'new-sha'},
            },
        }

        result = handle_pull_request(payload, queue)

        assert result['status'] == 'queued'
        queue.enqueue.assert_called_once()


class TestFastAPIApp(unittest.TestCase):
    """Tests for FastAPI application."""

    @pytest.fixture(autouse=True)
    def setup_test_client(self):
        """Set up test client."""
        from fastapi.testclient import TestClient

        config = WebhookConfig(
            anthropic_api_key='test-key',
            webhook_secret='test-secret',
            github_token='test-token',
        )
        app = create_app(config)

        # Don't start the queue for testing
        app.state.job_queue._executor = None

        self.client = TestClient(app, raise_server_exceptions=False)
        self.config = config

    def test_health_endpoint(self):
        """Test health check endpoint."""
        if not hasattr(self, 'client'):
            pytest.skip("Test client not set up")

        response = self.client.get('/health')
        assert response.status_code == 200
        assert response.json()['status'] == 'healthy'

    def test_status_endpoint(self):
        """Test status endpoint."""
        if not hasattr(self, 'client'):
            pytest.skip("Test client not set up")

        response = self.client.get('/status')
        assert response.status_code == 200
        data = response.json()
        assert 'status' in data
        assert 'queue' in data

    def test_webhook_missing_signature(self):
        """Test webhook rejects missing signature."""
        if not hasattr(self, 'client'):
            pytest.skip("Test client not set up")

        response = self.client.post(
            '/webhook',
            json={'action': 'opened'},
            headers={'X-GitHub-Event': 'pull_request'},
        )
        assert response.status_code == 401

    def test_webhook_invalid_signature(self):
        """Test webhook rejects invalid signature."""
        if not hasattr(self, 'client'):
            pytest.skip("Test client not set up")

        response = self.client.post(
            '/webhook',
            json={'action': 'opened'},
            headers={
                'X-GitHub-Event': 'pull_request',
                'X-Hub-Signature-256': 'sha256=invalid',
            },
        )
        assert response.status_code == 401

    def test_webhook_ping_event(self):
        """Test webhook handles ping event."""
        if not hasattr(self, 'client'):
            pytest.skip("Test client not set up")

        payload = json.dumps({'zen': 'Test zen'}).encode()
        mac = hmac.new(self.config.webhook_secret.encode(), payload, hashlib.sha256)
        signature = f"sha256={mac.hexdigest()}"

        response = self.client.post(
            '/webhook',
            content=payload,
            headers={
                'X-GitHub-Event': 'ping',
                'X-Hub-Signature-256': signature,
                'Content-Type': 'application/json',
            },
        )
        assert response.status_code == 200
        assert response.json()['status'] == 'pong'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
