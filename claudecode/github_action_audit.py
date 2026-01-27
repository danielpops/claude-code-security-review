#!/usr/bin/env python3
"""
Simplified PR Security Audit for GitHub Actions.

Runs Claude Code security audit on current working directory and outputs findings to stdout.
Uses the unified GitHubClient for all GitHub API operations.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from claudecode.constants import (
    DEFAULT_CLAUDE_MODEL,
    EXIT_CONFIGURATION_ERROR,
    EXIT_GENERAL_ERROR,
    EXIT_SUCCESS,
    SUBPROCESS_TIMEOUT,
)
from claudecode.findings_filter import FindingsFilter
from claudecode.github_client import GitHubClient, GitHubClientError
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger
from claudecode.prompts import get_security_audit_prompt

logger = get_logger(__name__)


class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass


class AuditError(ValueError):
    """Raised when security audit operations fail."""
    pass


class SimpleClaudeRunner:
    """Simplified Claude Code runner for GitHub Actions."""

    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize Claude runner.

        Args:
            timeout_minutes: Timeout for Claude execution (defaults to SUBPROCESS_TIMEOUT)
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT

    def run_security_audit(
        self,
        repo_dir: Path,
        prompt: str,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Run Claude Code security audit.

        Args:
            repo_dir: Path to repository directory
            prompt: Security audit prompt

        Returns:
            Tuple of (success, error_message, parsed_results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}

        # Check prompt size
        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            logger.warning(f"Large prompt size: {prompt_size / 1024 / 1024:.2f}MB")

        try:
            # Construct Claude Code command
            # Use stdin for prompt to avoid "argument list too long" error
            cmd = [
                'claude',
                '--output-format', 'json',
                '--model', DEFAULT_CLAUDE_MODEL,
                '--disallowed-tools', 'Bash(ps:*)',
            ]

            # Run Claude Code with retry logic
            num_retries = 3
            for attempt in range(num_retries):
                result = subprocess.run(
                    cmd,
                    input=prompt,  # Pass prompt via stdin
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )

                if result.returncode != 0:
                    if attempt == num_retries - 1:
                        error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."
                        return False, error_details, {}
                    else:
                        time.sleep(5 * attempt)
                        continue

                # Parse JSON output
                success, parsed_result = parse_json_with_fallbacks(
                    result.stdout, "Claude Code output"
                )

                if success:
                    # Check for "Prompt is too long" error
                    if (
                        isinstance(parsed_result, dict)
                        and parsed_result.get('type') == 'result'
                        and parsed_result.get('subtype') == 'success'
                        and parsed_result.get('is_error')
                        and parsed_result.get('result') == 'Prompt is too long'
                    ):
                        return False, "PROMPT_TOO_LONG", {}

                    # Check for error_during_execution that should trigger retry
                    if (
                        isinstance(parsed_result, dict)
                        and parsed_result.get('type') == 'result'
                        and parsed_result.get('subtype') == 'error_during_execution'
                        and attempt == 0
                    ):
                        continue

                    # Extract security findings
                    parsed_results = self._extract_security_findings(parsed_result)
                    return True, "", parsed_results
                else:
                    if attempt == 0:
                        continue
                    else:
                        return False, "Failed to parse Claude output", {}

            return False, "Unexpected error in retry logic", {}

        except subprocess.TimeoutExpired:
            return (
                False,
                f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes",
                {},
            )
        except Exception as e:
            return False, f"Claude Code execution error: {e}", {}

    def _extract_security_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract security findings from Claude's JSON response."""
        if isinstance(claude_output, dict):
            # Only accept Claude Code wrapper with result field
            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    success, result_json = parse_json_with_fallbacks(
                        result_text, "Claude result text"
                    )
                    if success and result_json and 'findings' in result_json:
                        return result_json

        # Return empty structure if no findings found
        return {
            'findings': [],
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            },
        }

    def validate_claude_available(self) -> Tuple[bool, str]:
        """Validate that Claude Code is available."""
        try:
            result = subprocess.run(
                ['claude', '--version'],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                api_key = os.environ.get('ANTHROPIC_API_KEY', '')
                if not api_key:
                    return False, "ANTHROPIC_API_KEY environment variable is not set"
                return True, ""
            else:
                error_msg = f"Claude Code returned exit code {result.returncode}"
                if result.stderr:
                    error_msg += f". Stderr: {result.stderr}"
                if result.stdout:
                    error_msg += f". Stdout: {result.stdout}"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Claude Code command timed out"
        except FileNotFoundError:
            return False, "Claude Code is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check Claude Code: {e}"


def get_environment_config() -> Tuple[str, int]:
    """Get and validate environment configuration.

    Returns:
        Tuple of (repo_name, pr_number)

    Raises:
        ConfigurationError: If required environment variables are missing or invalid
    """
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')

    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')

    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')

    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')

    return repo_name, pr_number


def initialize_clients() -> Tuple[GitHubClient, SimpleClaudeRunner]:
    """Initialize GitHub and Claude clients.

    Returns:
        Tuple of (github_client, claude_runner)

    Raises:
        ConfigurationError: If client initialization fails
    """
    try:
        github_client = GitHubClient()
    except GitHubClientError as e:
        raise ConfigurationError(f'Failed to initialize GitHub client: {e}')

    try:
        claude_runner = SimpleClaudeRunner()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize Claude runner: {e}')

    return github_client, claude_runner


def initialize_findings_filter(
    custom_filtering_instructions: Optional[str] = None,
) -> FindingsFilter:
    """Initialize findings filter based on environment configuration.

    Args:
        custom_filtering_instructions: Optional custom filtering instructions

    Returns:
        FindingsFilter instance

    Raises:
        ConfigurationError: If filter initialization fails
    """
    try:
        use_claude_filtering = (
            os.environ.get('ENABLE_CLAUDE_FILTERING', 'false').lower() == 'true'
        )
        api_key = os.environ.get('ANTHROPIC_API_KEY')

        if use_claude_filtering and api_key:
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions,
            )
        else:
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=False,
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {e}')


def apply_findings_filter(
    findings_filter: FindingsFilter,
    original_findings: List[Dict[str, Any]],
    pr_context: Dict[str, Any],
    github_client: GitHubClient,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives.

    Args:
        findings_filter: Filter instance
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client for exclusion logic

    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    filter_success, filter_results, _ = findings_filter.filter_findings(
        original_findings, pr_context
    )

    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}

    # Apply final directory exclusion filtering
    final_kept = []
    directory_excluded = []

    for finding in kept_findings:
        file_path = finding.get('file', '')
        if file_path and github_client._is_excluded_path(file_path):
            directory_excluded.append(finding)
        else:
            final_kept.append(finding)

    analysis_summary['directory_excluded_count'] = len(directory_excluded)

    return final_kept, excluded_findings + directory_excluded, analysis_summary


def main():
    """Main execution function for GitHub Action."""
    try:
        # Get environment configuration
        try:
            repo_name, pr_number = get_environment_config()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)

        # Load custom filtering instructions if provided
        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
                    logger.info(f"Loaded custom filtering instructions from {filtering_file}")
            except Exception as e:
                logger.warning(f"Failed to read filtering instructions file {filtering_file}: {e}")

        # Load custom security scan instructions if provided
        custom_scan_instructions = None
        scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if scan_file and Path(scan_file).exists():
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    custom_scan_instructions = f.read()
                    logger.info(f"Loaded custom security scan instructions from {scan_file}")
            except Exception as e:
                logger.warning(f"Failed to read security scan instructions file {scan_file}: {e}")

        # Initialize components
        try:
            github_client, claude_runner = initialize_clients()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)

        # Initialize findings filter
        try:
            findings_filter = initialize_findings_filter(custom_filtering_instructions)
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)

        # Validate Claude Code is available
        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            print(json.dumps({'error': f'Claude Code not available: {claude_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Get PR data
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except GitHubClientError as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {e}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Generate security audit prompt
        prompt = get_security_audit_prompt(
            pr_data, pr_diff, custom_scan_instructions=custom_scan_instructions
        )

        # Run Claude Code security audit
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)

        # If prompt is too long, retry without diff
        if not success and error_msg == "PROMPT_TOO_LONG":
            logger.info(
                f"Prompt too long, retrying without diff. "
                f"Original prompt length: {len(prompt)} characters"
            )
            prompt_without_diff = get_security_audit_prompt(
                pr_data,
                pr_diff,
                include_diff=False,
                custom_scan_instructions=custom_scan_instructions,
            )
            logger.info(f"New prompt length: {len(prompt_without_diff)} characters")
            success, error_msg, results = claude_runner.run_security_audit(
                repo_dir, prompt_without_diff
            )

        if not success:
            print(json.dumps({'error': f'Security audit failed: {error_msg}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Filter findings to reduce false positives
        original_findings = results.get('findings', [])

        pr_context = {
            'repo_name': repo_name,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', ''),
        }

        kept_findings, excluded_findings, analysis_summary = apply_findings_filter(
            findings_filter, original_findings, pr_context, github_client
        )

        # Prepare output
        output = {
            'pr_number': pr_number,
            'repo': repo_name,
            'findings': kept_findings,
            'analysis_summary': results.get('analysis_summary', {}),
            'filtering_summary': {
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
                'filter_analysis': analysis_summary,
                'excluded_findings_details': excluded_findings,
            },
        }

        # Output JSON to stdout
        print(json.dumps(output, indent=2))

        # Exit with appropriate code
        high_severity_count = len([
            f for f in kept_findings
            if f.get('severity', '').upper() == 'HIGH'
        ])
        sys.exit(EXIT_GENERAL_ERROR if high_severity_count > 0 else EXIT_SUCCESS)

    except Exception as e:
        print(json.dumps({'error': f'Unexpected error: {e}'}))
        sys.exit(EXIT_CONFIGURATION_ERROR)


if __name__ == '__main__':
    main()
