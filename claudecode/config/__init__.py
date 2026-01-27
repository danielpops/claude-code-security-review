"""Configuration management for ClaudeCode.

This module handles loading and formatting configuration files, including
the filtering rules used to reduce false positives.
"""

import os
from pathlib import Path
from typing import Optional

import yaml

from claudecode.logger import get_logger

logger = get_logger(__name__)


# Default paths
_CONFIG_DIR = Path(__file__).parent
_DEFAULT_FILTERING_RULES = _CONFIG_DIR / 'filtering_rules.yaml'


def load_filtering_rules(custom_file: Optional[str] = None) -> dict:
    """Load filtering rules from YAML configuration.

    Args:
        custom_file: Optional path to custom rules file.
                    If None, checks FALSE_POSITIVE_FILTERING_INSTRUCTIONS env var,
                    then falls back to default rules.

    Returns:
        Dictionary containing filtering rules
    """
    # Check for custom file
    if custom_file:
        rules_path = Path(custom_file)
    else:
        env_path = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if env_path:
            rules_path = Path(env_path)
        else:
            rules_path = _DEFAULT_FILTERING_RULES

    if not rules_path.exists():
        logger.warning(f"Filtering rules file not found: {rules_path}, using defaults")
        rules_path = _DEFAULT_FILTERING_RULES

    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)
            logger.info(f"Loaded filtering rules from {rules_path}")
            return rules or {}
    except Exception as e:
        logger.error(f"Failed to load filtering rules from {rules_path}: {e}")
        return {}


def format_filtering_instructions(rules: Optional[dict] = None) -> str:
    """Format filtering rules as natural language instructions for Claude.

    This converts the structured YAML rules into the prompt format expected
    by the Claude API client.

    Args:
        rules: Optional pre-loaded rules dict. If None, loads default rules.

    Returns:
        Formatted instructions string for Claude
    """
    if rules is None:
        rules = load_filtering_rules()

    if not rules:
        return ""

    lines = []

    # Format hard exclusions
    hard_exclusions = rules.get('hard_exclusions', [])
    if hard_exclusions:
        lines.append("HARD EXCLUSIONS - Automatically exclude findings matching these patterns:")
        for i, exclusion in enumerate(hard_exclusions, 1):
            desc = exclusion.get('description', '')
            lines.append(f"{i}. {desc}")
        lines.append("")

    # Format signal criteria
    criteria = rules.get('signal_criteria', [])
    if criteria:
        lines.append("SIGNAL QUALITY CRITERIA - For remaining findings, assess:")
        for i, criterion in enumerate(criteria, 1):
            lines.append(f"{i}. {criterion}")
        lines.append("")

    # Format precedents
    precedents = rules.get('precedents', [])
    if precedents:
        lines.append("PRECEDENTS -")
        for i, precedent in enumerate(precedents, 1):
            rule = precedent.get('rule', '')
            lines.append(f"{i}. {rule}")

    return '\n'.join(lines)


def get_default_filtering_instructions() -> str:
    """Get the default filtering instructions formatted for Claude.

    This is a convenience function that loads and formats the default rules.

    Returns:
        Formatted instructions string
    """
    return format_filtering_instructions()
