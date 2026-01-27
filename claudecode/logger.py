"""Logging configuration for ClaudeCode.

This module provides a unified logging interface for all ClaudeCode components.
All logs go to stderr to keep stdout clean for JSON output in the GitHub Action.

Usage:
    from claudecode.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Something happened")

Environment Variables:
    GITHUB_REPOSITORY: Repository name for log prefix (e.g., "owner/repo")
    PR_NUMBER: PR number for log prefix
    CLAUDECODE_LOG_LEVEL: Log level (DEBUG, INFO, WARNING, ERROR). Default: INFO
"""

import logging
import os
import sys
from typing import Optional


# Default log level, can be overridden by CLAUDECODE_LOG_LEVEL env var
_DEFAULT_LOG_LEVEL = logging.INFO

# Global flag to enable verbose timestamps (for eval mode)
_VERBOSE_MODE = False


def set_verbose_mode(enabled: bool = True) -> None:
    """Enable or disable verbose mode with timestamps.

    When enabled, log messages include timestamps. This is useful for
    the eval runner and other interactive tools.

    Args:
        enabled: Whether to enable verbose mode
    """
    global _VERBOSE_MODE
    _VERBOSE_MODE = enabled


def get_log_level() -> int:
    """Get the configured log level.

    Returns:
        Logging level constant (e.g., logging.INFO)
    """
    level_name = os.environ.get('CLAUDECODE_LOG_LEVEL', 'INFO').upper()
    return getattr(logging, level_name, _DEFAULT_LOG_LEVEL)


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """Get a configured logger that outputs to stderr.

    Args:
        name: The name of the logger (usually __name__)
        level: Optional log level override

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only configure if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)

        # Get repo and PR number from environment for prefix
        repo_name = os.environ.get('GITHUB_REPOSITORY', '')
        pr_number = os.environ.get('PR_NUMBER', '')

        # Build prefix
        if repo_name and pr_number:
            prefix = f"[{repo_name}#{pr_number}]"
        elif repo_name:
            prefix = f"[{repo_name}]"
        elif pr_number:
            prefix = f"[PR#{pr_number}]"
        else:
            prefix = ""

        # Build format string
        # Include timestamps in verbose mode (for eval runner, etc.)
        if _VERBOSE_MODE:
            if prefix:
                format_str = f'{prefix} [%(asctime)s] [%(name)s] %(message)s'
            else:
                format_str = '[%(asctime)s] [%(name)s] %(message)s'
        else:
            if prefix:
                format_str = f'{prefix} [%(name)s] %(message)s'
            else:
                format_str = '[%(name)s] %(message)s'

        formatter = logging.Formatter(format_str, datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Set log level
        configured_level = level if level is not None else get_log_level()
        logger.setLevel(configured_level)

    return logger


def configure_root_logger(level: Optional[int] = None) -> None:
    """Configure the root logger for the application.

    This should be called once at application startup if you want to
    configure logging for all modules at once.

    Args:
        level: Optional log level override
    """
    root_logger = logging.getLogger()

    # Clear existing handlers
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)

    # Build format string
    if _VERBOSE_MODE:
        format_str = '[%(asctime)s] [%(name)s] %(levelname)s: %(message)s'
    else:
        format_str = '[%(name)s] %(levelname)s: %(message)s'

    formatter = logging.Formatter(format_str, datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Set log level
    configured_level = level if level is not None else get_log_level()
    root_logger.setLevel(configured_level)
