#!/usr/bin/env python3
"""CLI for running SAST evaluation on a single PR."""

import argparse
import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

# Import the minimal required functionality


@dataclass
class EvalCase:
    """Single evaluation test case."""
    repo_name: str
    pr_number: int
    description: str = ""


@dataclass
class EvalResult:
    """Result of a single evaluation."""
    repo_name: str
    pr_number: int
    description: str

    # Evaluation results
    success: bool
    runtime_seconds: float
    findings_count: int
    detected_vulnerabilities: bool

    # Optional fields
    error_message: str = ""
    findings_summary: Optional[List[Dict[str, Any]]] = None
    full_findings: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


def post_comments_to_pr(repo_name: str, pr_number: int, findings: List[Dict[str, Any]], verbose: bool = False) -> None:
    """Post findings as comments on the PR.

    Args:
        repo_name: Repository name in format "owner/repo"
        pr_number: Pull request number
        findings: List of security findings to post
        verbose: Enable verbose logging
    """
    from ..pr_commenter import PRCommenter
    from ..github_client import GitHubClient, GitHubClientError

    # Check for GITHUB_TOKEN
    if not os.environ.get('GITHUB_TOKEN'):
        print("\nError: GITHUB_TOKEN environment variable is required to post comments")
        print("Please set GITHUB_TOKEN with a PAT that has repo permissions")
        return

    if '/' not in repo_name:
        print(f"\nError: Invalid repository name format: {repo_name}")
        return

    owner, repo = repo_name.split('/', 1)

    print(f"\nPosting {len(findings)} findings as comments on PR #{pr_number}...")

    try:
        client = GitHubClient()
        commenter = PRCommenter(client=client)

        # Get the commit SHA from the PR
        pr_data = client.get_pr(owner, repo, pr_number)
        commit_sha = pr_data.get('head', {}).get('sha')
        if not commit_sha:
            print("Error: Could not determine commit SHA from PR")
            return

        count = commenter.post_findings(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            commit_sha=commit_sha,
            findings=findings,
            skip_duplicates=True
        )
        print(f"Successfully posted {count} comments to PR")
    except GitHubClientError as e:
        print(f"GitHub API error: {e}")
    except ValueError as e:
        print(f"Configuration error: {e}")
    except Exception as e:
        if verbose:
            import traceback
            traceback.print_exc()
        print(f"Error posting comments: {e}")


def main():
    """Main entry point for single PR SAST evaluation."""
    parser = argparse.ArgumentParser(
        description="Run SAST security evaluation on a single GitHub PR",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "pr",
        type=str,
        help="PR to evaluate in format 'repo_owner/repo_name#pr_number' (e.g., 'example/repo#123')"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./eval_results",
        help="Directory for evaluation results"
    )
    
    parser.add_argument(
        "--work-dir",
        type=str,
        default=None,
        help="Directory for temporary repositories (defaults to ~/code/audit)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--post-comments",
        action="store_true",
        help="Post findings as comments on the PR (requires GITHUB_TOKEN)"
    )

    args = parser.parse_args()
    
    # Set EVAL_MODE=1 automatically for evaluation runs
    os.environ['EVAL_MODE'] = '1'
    
    # Check for required environment variables
    if not os.environ.get('ANTHROPIC_API_KEY'):
        print("Error: ANTHROPIC_API_KEY environment variable is not set")
        print("Please set it before running the evaluation")
        sys.exit(1)
    
    
    # Parse the PR specification
    try:
        repo_part, pr_number = args.pr.split('#')
        pr_number = int(pr_number)
        # Validate repository format
        if '/' not in repo_part or len(repo_part.split('/')) != 2:
            raise ValueError("Repository must be in format 'owner/repo'")
        owner, repo = repo_part.split('/')
        if not owner or not repo:
            raise ValueError("Repository owner and name cannot be empty")
    except ValueError as e:
        print(f"Error: Invalid PR format '{args.pr}': {e}")
        print("Expected format: 'repo_owner/repo_name#pr_number'")
        print("Example: 'example/repo#123'")
        sys.exit(1)
    
    print(f"\nEvaluating PR: {repo_part}#{pr_number}")
    print("-" * 60)
    
    # Create test case
    test_case = EvalCase(
        repo_name=repo_part,
        pr_number=pr_number,
        description=f"Evaluation for {repo_part}#{pr_number}"
    )
    
    # Import and run the evaluation
    from .eval_engine import run_single_evaluation
    
    # Run the evaluation
    result = run_single_evaluation(test_case, verbose=args.verbose, work_dir=args.work_dir)
    
    # Display results
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS:")
    print(f"Success: {result.success}")
    print(f"Runtime: {result.runtime_seconds:.1f} seconds")
    print(f"Vulnerabilities detected: {result.detected_vulnerabilities}")
    print(f"Findings count: {result.findings_count}")
    
    if result.error_message:
        print(f"Error: {result.error_message}")
    
    if result.full_findings:
        print("\nFindings:")
        for finding in result.full_findings:
            print(f"  - [{finding.get('severity', 'UNKNOWN')}] {finding.get('file', 'unknown')}:{finding.get('line', '?')}")
            if 'category' in finding:
                print(f"    Category: {finding['category']}")
            if 'description' in finding:
                print(f"    Description: {finding['description']}")
            if 'exploit_scenario' in finding:
                print(f"    Exploit: {finding['exploit_scenario']}")
            if 'recommendation' in finding:
                print(f"    Fix: {finding['recommendation']}")
            if 'confidence' in finding:
                print(f"    Confidence: {finding['confidence']}")
            print()  # Empty line between findings
    elif result.findings_summary:
        # Fallback to summary if full findings not available
        print("\nFindings:")
        for finding in result.findings_summary:
            print(f"  - [{finding.get('severity', 'UNKNOWN')}] {finding.get('file', 'unknown')}:{finding.get('line', '?')}")
            if 'title' in finding and finding['title'] != 'Unknown':
                print(f"    {finding['title']}")
            if 'description' in finding and finding['description'] != 'Unknown':
                print(f"    {finding['description']}")
    
    # Save result to output directory
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    result_file = output_path / f"pr_{repo_part.replace('/', '_')}_{pr_number}.json"
    
    with open(result_file, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)

    print(f"\nResult saved to: {result_file}")

    # Post comments to PR if requested
    if args.post_comments and result.full_findings:
        post_comments_to_pr(repo_part, pr_number, result.full_findings, args.verbose)
    elif args.post_comments and not result.full_findings:
        print("\nNo findings to post as comments.")

    # Exit with appropriate code
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()