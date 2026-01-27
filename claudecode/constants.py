"""
Constants and configuration values for ClaudeCode.

This module centralizes all timeout values, API configuration, and other
constants used throughout the codebase.
"""

import os

# =============================================================================
# API Configuration
# =============================================================================
DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or 'claude-opus-4-1-20250805'
DEFAULT_TIMEOUT_SECONDS = 180  # 3 minutes for API calls
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits (seconds)

# Token Limits
PROMPT_TOKEN_LIMIT = 16384  # 16k tokens max for claude-opus-4

# =============================================================================
# Timeout Constants (in seconds)
# =============================================================================
# Short operations (version checks, quick commands)
TIMEOUT_SHORT = 10

# Git operations
TIMEOUT_GIT_OPERATION = 60      # Standard git commands
TIMEOUT_GIT_CLONE = 300         # Git clone (5 minutes)
TIMEOUT_GIT_FETCH = 600         # Git fetch (10 minutes)
TIMEOUT_GIT_WORKTREE = 300      # Git worktree operations
TIMEOUT_GIT_WORKTREE_CREATE = 1200  # Git worktree creation (20 minutes)

# Claude Code execution
SUBPROCESS_TIMEOUT = 1200       # 20 minutes for GitHub Action runner
TIMEOUT_CLAUDECODE = 1800       # 30 minutes for eval engine

# =============================================================================
# Exit Codes
# =============================================================================
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

