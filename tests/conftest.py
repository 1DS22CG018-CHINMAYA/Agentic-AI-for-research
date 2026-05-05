"""Pytest configuration and shared fixtures for all tests."""

import os
import pytest
from unittest.mock import MagicMock, patch
from dotenv import load_dotenv

load_dotenv()


@pytest.fixture
def mock_db_engine():
    """Mock database engine for testing."""
    return MagicMock()


@pytest.fixture
def mock_ollama():
    """Mock Ollama LLM service."""
    return MagicMock()


@pytest.fixture
def sample_session_id():
    """Sample session ID for testing."""
    return "test_session_12345_abc"


@pytest.fixture
def sample_mitre_tactic():
    """Sample MITRE tactic for testing."""
    return "Initial Access"


@pytest.fixture
def sample_agent_state():
    """Sample agent state for testing."""
    return {
        "session_id": "test_session_12345",
        "turn_count": 1,
        "target_mitre_tactic": "Initial Access",
        "messages": [],
        "latest_command": "whoami",
        "agent_a_cot": '{"status": "success"}',
        "latest_terminal_output": "root",
        "agent_b_explanation": "User enumeration",
        "predicted_mitre_tactic": "Initial Access",
        "threat_level": "High",
        "is_format_valid": True,
        "first_try_format_valid": True,
        "illusion_broken": False,
        "retry_count": 0,
    }
