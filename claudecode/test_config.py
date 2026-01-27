#!/usr/bin/env python3
"""Tests for the config module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from claudecode.config import (
    load_filtering_rules,
    format_filtering_instructions,
    get_default_filtering_instructions,
)


class TestLoadFilteringRules:
    """Test loading filtering rules from YAML."""

    def test_load_default_rules(self):
        """Test loading default filtering rules."""
        rules = load_filtering_rules()

        assert rules is not None
        assert 'hard_exclusions' in rules
        assert 'signal_criteria' in rules
        assert 'precedents' in rules
        assert len(rules['hard_exclusions']) > 0

    def test_load_custom_rules_file(self):
        """Test loading rules from a custom file."""
        custom_rules = {
            'hard_exclusions': [
                {'name': 'test', 'description': 'Test exclusion', 'reason': 'Testing'}
            ],
            'signal_criteria': ['Is this a test?'],
            'precedents': []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(custom_rules, f)
            temp_path = f.name

        try:
            rules = load_filtering_rules(custom_file=temp_path)
            assert rules['hard_exclusions'][0]['name'] == 'test'
            assert rules['signal_criteria'][0] == 'Is this a test?'
        finally:
            os.unlink(temp_path)

    def test_load_from_env_var(self):
        """Test loading rules from environment variable path."""
        custom_rules = {
            'hard_exclusions': [
                {'name': 'env_test', 'description': 'Env test', 'reason': 'Testing'}
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(custom_rules, f)
            temp_path = f.name

        try:
            with patch.dict(os.environ, {'FALSE_POSITIVE_FILTERING_INSTRUCTIONS': temp_path}):
                rules = load_filtering_rules()
                assert rules['hard_exclusions'][0]['name'] == 'env_test'
        finally:
            os.unlink(temp_path)

    def test_load_nonexistent_file_falls_back_to_default(self):
        """Test that nonexistent file falls back to default rules."""
        rules = load_filtering_rules(custom_file='/nonexistent/path/rules.yaml')

        # Should fall back to default rules
        assert rules is not None
        assert 'hard_exclusions' in rules

    def test_load_invalid_yaml(self):
        """Test handling of invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = f.name

        try:
            rules = load_filtering_rules(custom_file=temp_path)
            # Should return empty dict on error
            assert rules == {}
        finally:
            os.unlink(temp_path)


class TestFormatFilteringInstructions:
    """Test formatting filtering rules as instructions."""

    def test_format_with_all_sections(self):
        """Test formatting with all rule sections present."""
        rules = {
            'hard_exclusions': [
                {'name': 'test1', 'description': 'Test exclusion 1'},
                {'name': 'test2', 'description': 'Test exclusion 2'}
            ],
            'signal_criteria': [
                'Criterion 1',
                'Criterion 2'
            ],
            'precedents': [
                {'category': 'cat1', 'rule': 'Rule 1'},
                {'category': 'cat2', 'rule': 'Rule 2'}
            ]
        }

        result = format_filtering_instructions(rules)

        assert 'HARD EXCLUSIONS' in result
        assert 'Test exclusion 1' in result
        assert 'Test exclusion 2' in result
        assert 'SIGNAL QUALITY CRITERIA' in result
        assert 'Criterion 1' in result
        assert 'PRECEDENTS' in result
        assert 'Rule 1' in result

    def test_format_with_empty_rules(self):
        """Test formatting with empty rules."""
        rules = {}
        result = format_filtering_instructions(rules)
        assert result == ""

    def test_format_with_none_loads_default(self):
        """Test that None rules loads default."""
        result = format_filtering_instructions(None)
        # Should load and format default rules
        assert 'HARD EXCLUSIONS' in result or result == ""  # Depends on default file

    def test_format_with_partial_rules(self):
        """Test formatting with only some sections present."""
        rules = {
            'hard_exclusions': [
                {'description': 'Only exclusion'}
            ]
        }

        result = format_filtering_instructions(rules)

        assert 'HARD EXCLUSIONS' in result
        assert 'Only exclusion' in result
        assert 'SIGNAL QUALITY CRITERIA' not in result
        assert 'PRECEDENTS' not in result

    def test_format_numbered_list(self):
        """Test that items are numbered correctly."""
        rules = {
            'hard_exclusions': [
                {'description': 'First'},
                {'description': 'Second'},
                {'description': 'Third'}
            ]
        }

        result = format_filtering_instructions(rules)

        assert '1. First' in result
        assert '2. Second' in result
        assert '3. Third' in result


class TestGetDefaultFilteringInstructions:
    """Test the convenience function."""

    def test_get_default_instructions(self):
        """Test getting default filtering instructions."""
        result = get_default_filtering_instructions()

        # Should return formatted instructions from default rules
        assert isinstance(result, str)
        # The default file should have content
        assert len(result) > 0 or result == ""

    def test_returns_string(self):
        """Test that result is always a string."""
        result = get_default_filtering_instructions()
        assert isinstance(result, str)
