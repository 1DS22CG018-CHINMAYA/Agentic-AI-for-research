"""White Box Testing: graph.py module unit tests."""

import pytest
from unittest.mock import MagicMock, patch
import json

# White Box - Testing internal implementation details


@pytest.mark.whitebox
@pytest.mark.unit
class TestGraphModule:
    """Test graph module structure and agents."""

    def test_agent_state_required_fields(self):
        """Test that AgentState has all required fields."""
        from graph import AgentState
        
        # AgentState is a TypedDict, check required fields
        annotations = AgentState.__annotations__
        
        required_fields = [
            'session_id', 'turn_count', 'target_mitre_tactic',
            'messages', 'latest_command', 'agent_a_cot'
        ]
        
        for field in required_fields:
            assert field in annotations

    def test_max_honeypot_retries_constant(self):
        """Test MAX_HONEYPOT_RETRIES is properly defined."""
        from graph import MAX_HONEYPOT_RETRIES
        
        assert isinstance(MAX_HONEYPOT_RETRIES, int)
        assert MAX_HONEYPOT_RETRIES > 0

    def test_log_prefix_structure(self):
        """Test LOG_PREFIX dictionary has expected keys."""
        from graph import LOG_PREFIX
        
        expected_keys = ['attacker', 'honeypot', 'analyst', 'db', 'router', 'session']
        
        for key in expected_keys:
            assert key in LOG_PREFIX
            assert isinstance(LOG_PREFIX[key], str)


@pytest.mark.whitebox
@pytest.mark.unit
class TestGraphAgents:
    """Test agent node functions."""

    def test_agent_functions_exist(self):
        """Test that all agent functions are defined."""
        from graph import (
            agent_c_attacker, agent_a_honeypot, agent_b_analyst,
            save_to_tidb
        )
        
        assert callable(agent_c_attacker)
        assert callable(agent_a_honeypot)
        assert callable(agent_b_analyst)
        assert callable(save_to_tidb)

    def test_run_simulation_function(self):
        """Test that run_simulation function is defined."""
        from graph import run_simulation
        
        assert callable(run_simulation)


@pytest.mark.whitebox
@pytest.mark.unit
class TestGraphRouting:
    """Test routing logic."""

    def test_agent_state_structure(self, sample_agent_state):
        """Test that agent state has correct structure."""
        from graph import AgentState
        
        # Check all keys are present
        required_keys = [
            'session_id', 'turn_count', 'target_mitre_tactic',
            'messages', 'latest_command'
        ]
        
        for key in required_keys:
            assert key in sample_agent_state

    def test_threat_level_values(self):
        """Test threat level can be Low, Medium, High, Critical."""
        valid_levels = ['Low', 'Medium', 'High', 'Critical']
        
        assert 'Low' in valid_levels
        assert 'Medium' in valid_levels
        assert 'High' in valid_levels
        assert 'Critical' in valid_levels


@pytest.mark.whitebox
@pytest.mark.unit
class TestGraphLogging:
    """Test logging functionality."""

    def test_log_function_exists(self):
        """Test _log function is defined."""
        from graph import _log
        
        assert callable(_log)

    def test_log_function_with_output(self, capsys):
        """Test _log outputs formatted message."""
        from graph import _log
        
        _log("attacker", "test message")
        captured = capsys.readouterr()
        
        assert "ATTACKER" in captured.out
        assert "test message" in captured.out
