"""White Box Testing: llm_config.py module unit tests."""

import pytest
from unittest.mock import patch, MagicMock
import json

# White Box - Testing internal implementation details


@pytest.mark.whitebox
@pytest.mark.unit
class TestLLMConfig:
    """Test LLM configuration module."""

    def test_ollama_base_url_configuration(self):
        """Test OLLAMA_BASE_URL is properly loaded from env."""
        from llm_config import OLLAMA_BASE_URL
        
        assert OLLAMA_BASE_URL is not None
        assert isinstance(OLLAMA_BASE_URL, str)

    def test_model_names_configured(self):
        """Test that all three model names are configured."""
        from llm_config import (
            ATTACKER_MODEL, HONEYPOT_MODEL, ANALYST_MODEL
        )
        
        assert ATTACKER_MODEL is not None
        assert HONEYPOT_MODEL is not None
        assert ANALYST_MODEL is not None

    def test_llm_instances_created(self):
        """Test that LLM instances are initialized."""
        from llm_config import attacker_llm, honeypot_llm, analyst_llm
        
        assert attacker_llm is not None
        assert honeypot_llm is not None
        assert analyst_llm is not None


@pytest.mark.whitebox
@pytest.mark.unit
class TestJSONExtraction:
    """Test JSON extraction helper functions."""

    def test_strip_markdown_fences_with_json_fence(self):
        """Test markdown fence removal with json syntax."""
        from llm_config import _strip_markdown_fences
        
        text = '```json\n{"key": "value"}\n```'
        result = _strip_markdown_fences(text)
        
        assert result == '{"key": "value"}'
        assert "```" not in result

    def test_strip_markdown_fences_with_plain_fence(self):
        """Test markdown fence removal with plain fence."""
        from llm_config import _strip_markdown_fences
        
        text = '```\n{"key": "value"}\n```'
        result = _strip_markdown_fences(text)
        
        assert result == '{"key": "value"}'

    def test_strip_markdown_fences_no_fence(self):
        """Test with text that has no fences."""
        from llm_config import _strip_markdown_fences
        
        text = '{"key": "value"}'
        result = _strip_markdown_fences(text)
        
        assert result == '{"key": "value"}'

    def test_extract_json_by_depth_valid_json(self):
        """Test JSON extraction by depth with valid JSON."""
        from llm_config import _extract_json_by_depth
        
        text = 'Some text {"key": "value"} more text'
        result = _extract_json_by_depth(text)
        
        assert result is not None
        assert "key" in result

    def test_extract_json_by_depth_nested_objects(self):
        """Test extraction with nested objects."""
        from llm_config import _extract_json_by_depth
        
        text = '{"outer": {"inner": "value"}}'
        result = _extract_json_by_depth(text)
        
        assert result is not None
        assert "outer" in result
        assert "inner" in result

    def test_extract_json_by_depth_no_json(self):
        """Test with text that has no JSON."""
        from llm_config import _extract_json_by_depth
        
        text = 'No JSON here'
        result = _extract_json_by_depth(text)
        
        assert result is None


@pytest.mark.whitebox
@pytest.mark.unit
class TestValidationFunctions:
    """Test validation helper functions."""

    def test_validate_json_format_exists(self):
        """Test that validate_json_format function exists."""
        from llm_config import validate_json_format
        
        assert callable(validate_json_format)

    def test_extract_json_exists(self):
        """Test that extract_json function exists."""
        from llm_config import extract_json
        
        assert callable(extract_json)
