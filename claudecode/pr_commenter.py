#!/usr/bin/env python3
"""Post security findings as comments on GitHub PRs.

This module handles formatting and posting security findings as PR review comments.
It uses the unified GitHubClient for all API operations.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from claudecode.github_client import GitHubClient, GitHubClientError
from claudecode.logger import get_logger

logger = get_logger(__name__)


class PRCommenter:
    """Posts security findings as review comments on GitHub PRs.

    This class formats security findings into GitHub review comments and
    posts them to the appropriate PR. It handles:
    - Duplicate detection (skips if security comments already exist)
    - File filtering (only comments on files in the PR diff)
    - Batch review creation with fallback to individual comments
    - Voting reactions for user feedback

    Environment Variables:
        GITHUB_TOKEN: Required for authentication
        GITHUB_API_URL: Optional for GitHub Enterprise
        SILENCE_CLAUDECODE_COMMENTS: Set to 'true' to suppress all comments
    """

    # Marker used to identify security comments
    SECURITY_COMMENT_MARKER = '**Security Issue:'

    def __init__(self, client: Optional[GitHubClient] = None):
        """Initialize the PR commenter.

        Args:
            client: Optional GitHubClient instance. If None, creates one from env vars.
        """
        self.client = client or GitHubClient()

    def _format_finding_comment(self, finding: Dict[str, Any]) -> str:
        """Format a security finding as a comment body.

        Args:
            finding: Security finding dictionary

        Returns:
            Formatted markdown comment body
        """
        message = (
            finding.get('description')
            or finding.get('extra', {}).get('message')
            or 'Security vulnerability detected'
        )
        severity = finding.get('severity', 'HIGH')
        category = finding.get('category', 'security_issue')

        lines = [
            f"**Security Issue: {message}**",
            "",
            f"**Severity:** {severity}",
            f"**Category:** {category}",
            "**Tool:** ClaudeCode AI Security Analysis",
        ]

        # Add exploit scenario if available
        exploit_scenario = (
            finding.get('exploit_scenario')
            or finding.get('extra', {}).get('metadata', {}).get('exploit_scenario')
        )
        if exploit_scenario:
            lines.extend(["", f"**Exploit Scenario:** {exploit_scenario}"])

        # Add recommendation if available
        recommendation = (
            finding.get('recommendation')
            or finding.get('extra', {}).get('metadata', {}).get('recommendation')
        )
        if recommendation:
            lines.extend(["", f"**Recommendation:** {recommendation}"])

        return '\n'.join(lines)

    def _add_voting_reactions(self, owner: str, repo: str, comment_id: int) -> None:
        """Add thumbs up/down reactions to a comment for easy user voting.

        This seeds the reactions so users can vote on finding validity
        with a single click instead of opening the reaction menu.

        Args:
            owner: Repository owner
            repo: Repository name
            comment_id: ID of the comment
        """
        self.client.add_reaction(owner, repo, comment_id, '+1')
        self.client.add_reaction(owner, repo, comment_id, '-1')

    def post_findings(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        findings: List[Dict[str, Any]],
        skip_duplicates: bool = True,
    ) -> int:
        """Post security findings as PR review comments.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            commit_sha: SHA of the commit to comment on
            findings: List of security findings
            skip_duplicates: Skip posting if security comments already exist

        Returns:
            Number of comments posted
        """
        if not findings:
            logger.info("No findings to post")
            return 0

        # Check if comments should be silenced
        if os.environ.get('SILENCE_CLAUDECODE_COMMENTS', '').lower() == 'true':
            logger.info(f"ClaudeCode comments silenced - excluding {len(findings)} findings")
            return 0

        # Get files in the PR diff to filter findings
        try:
            pr_files = self.client.get_pr_files(owner, repo, pr_number)
            file_set = {f['filename'] for f in pr_files}
        except GitHubClientError as e:
            logger.error(f"Failed to get PR files: {e}")
            return 0

        # Check for existing security comments
        if skip_duplicates:
            try:
                existing = self.client.get_pr_comments(owner, repo, pr_number)
                security_comments = [
                    c for c in existing
                    if c.get('body') and self.SECURITY_COMMENT_MARKER in c.get('body', '')
                ]
                if security_comments:
                    logger.info(
                        f"Found {len(security_comments)} existing security comments, "
                        "skipping to avoid duplicates"
                    )
                    return 0
            except GitHubClientError as e:
                logger.warning(f"Failed to check existing comments: {e}")

        # Build review comments for findings in the diff
        review_comments = []
        for finding in findings:
            file_path = finding.get('file') or finding.get('path')
            if not file_path:
                continue

            # Check if file is in the PR diff
            if file_path not in file_set:
                logger.debug(f"File {file_path} not in PR diff, skipping")
                continue

            line = (
                finding.get('line')
                or (finding.get('start', {}).get('line'))
                or 1
            )

            review_comments.append({
                'path': file_path,
                'line': line,
                'side': 'RIGHT',
                'body': self._format_finding_comment(finding),
            })

        if not review_comments:
            logger.info("No findings to comment on PR diff")
            return 0

        # Try to create a review with all comments
        review = self.client.create_review(
            owner, repo, pr_number, commit_sha, review_comments
        )

        if review:
            logger.info(f"Created review with {len(review_comments)} inline comments")

            # Add voting reactions to each comment
            if review.get('id'):
                comments = self.client.get_review_comments(
                    owner, repo, pr_number, review['id']
                )
                for comment in comments:
                    if comment.get('id'):
                        self._add_voting_reactions(owner, repo, comment['id'])

            return len(review_comments)

        # Fallback: create individual comments
        logger.warning("Review creation failed, attempting individual comments...")
        posted_count = 0

        for comment in review_comments:
            response = self.client.create_comment(
                owner, repo, pr_number, commit_sha,
                comment['path'], comment['line'], comment['body']
            )
            if response:
                posted_count += 1
                if response.get('id'):
                    self._add_voting_reactions(owner, repo, response['id'])

        return posted_count


def post_findings_from_file(findings_file: str = 'findings.json') -> int:
    """Post findings from a JSON file (for use as CLI or from GitHub Action).

    Args:
        findings_file: Path to findings JSON file

    Returns:
        Number of comments posted
    """
    # Read findings file
    try:
        with open(findings_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Could not read findings file: {findings_file}")
        return 0
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in findings file: {e}")
        return 0

    # Handle both list of findings and dict with 'findings' key
    if isinstance(data, list):
        findings = data
    else:
        findings = data.get('findings', [])

    if not findings:
        logger.info("No findings in file")
        return 0

    # Get GitHub context from environment
    repo_full = os.environ.get('GITHUB_REPOSITORY', '')
    if not repo_full or '/' not in repo_full:
        logger.error("GITHUB_REPOSITORY environment variable not set or invalid")
        return 0

    owner, repo = repo_full.split('/', 1)

    # Get PR number from event file
    event_path = os.environ.get('GITHUB_EVENT_PATH', '')
    if not event_path:
        logger.error("GITHUB_EVENT_PATH environment variable not set")
        return 0

    try:
        with open(event_path, 'r') as f:
            event_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Could not read event file: {e}")
        return 0

    pr_data = event_data.get('pull_request', {})
    pr_number = pr_data.get('number')
    commit_sha = pr_data.get('head', {}).get('sha')

    if not pr_number:
        logger.error("Could not determine PR number from event file")
        return 0

    if not commit_sha:
        logger.error("Could not determine commit SHA from event file")
        return 0

    # Post findings
    commenter = PRCommenter()
    return commenter.post_findings(owner, repo, pr_number, commit_sha, findings)


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Post security findings as PR comments")
    parser.add_argument(
        '--findings-file',
        default='findings.json',
        help='Path to findings JSON file'
    )
    args = parser.parse_args()

    try:
        count = post_findings_from_file(args.findings_file)
        print(f"Posted {count} comments")
        sys.exit(0 if count >= 0 else 1)
    except GitHubClientError as e:
        logger.error(f"GitHub error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to post comments: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
