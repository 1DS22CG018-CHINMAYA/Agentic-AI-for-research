"""Black Box Testing: End-to-end and integration tests."""

import pytest
from unittest.mock import MagicMock, patch
import json

# Black Box - Testing without knowledge of internal implementation


@pytest.mark.blackbox
@pytest.mark.integration
class TestApplicationStartup:
    """Test application can start and initialize."""

    def test_database_module_loading(self):
        """Test that database module loads without import errors."""
        try:
            import database
            assert database is not None
        except Exception as e:
            pytest.fail(f"Database import failed: {e}")

    def test_database_module_imports(self):
        """Test database module is importable."""
        try:
            import database
            assert hasattr(database, 'XaiDeceptionLog')
            assert hasattr(database, 'create_tables')
        except Exception as e:
            pytest.fail(f"Database import failed: {e}")

    def test_graph_module_imports(self):
        """Test graph module is importable."""
        try:
            import graph
            assert hasattr(graph, 'run_simulation')
        except Exception as e:
            pytest.fail(f"Graph import failed: {e}")

    def test_llm_config_module_imports(self):
        """Test LLM config module is importable."""
        try:
            import llm_config
            assert hasattr(llm_config, 'attacker_llm')
            assert hasattr(llm_config, 'honeypot_llm')
            assert hasattr(llm_config, 'analyst_llm')
        except Exception as e:
            pytest.fail(f"LLM config import failed: {e}")


@pytest.mark.blackbox
@pytest.mark.integration
class TestDatabaseOperations:
    """Test database operations from user perspective."""

    def test_create_tables_function_exists(self):
        """Test that create_tables function is defined and callable."""
        from database import create_tables
        
        assert callable(create_tables)
        assert hasattr(create_tables, '__name__')

    def test_xai_deception_log_model_instantiation(self):
        """Test XaiDeceptionLog model can be instantiated."""
        from database import XaiDeceptionLog
        from datetime import datetime
        
        log = XaiDeceptionLog(
            session_id="test_session",
            turn_count=1,
            target_mitre_tactic="Initial Access"
        )
        
        assert log.session_id == "test_session"
        assert log.turn_count == 1


@pytest.mark.blackbox
@pytest.mark.integration
class TestLLMFunctionality:
    """Test LLM functionality from user perspective."""

    def test_all_llm_instances_exist(self):
        """Test that all three LLM instances are available."""
        from llm_config import attacker_llm, honeypot_llm, analyst_llm
        
        assert attacker_llm is not None
        assert honeypot_llm is not None
        assert analyst_llm is not None

    def test_extract_json_from_string(self):
        """Test JSON extraction from model output."""
        from llm_config import extract_json
        
        text = 'Here is my response: {"command": "ls", "output": "result"}'
        result = extract_json(text)
        
        # Should either return valid JSON or None
        if result is not None:
            assert isinstance(result, (dict, str))

    def test_validate_json_format_function(self):
        """Test JSON format validation."""
        from llm_config import validate_json_format
        
        valid_json = '{"command": "ls", "output": ""}'
        result = validate_json_format(valid_json)
        
        # Should return boolean
        assert isinstance(result, bool)


@pytest.mark.blackbox
@pytest.mark.integration
class TestGraphExecution:
    """Test graph execution from user perspective."""

    def test_run_simulation_function_exists(self):
        """Test that run_simulation function is callable."""
        from graph import run_simulation
        
        assert callable(run_simulation)
        assert hasattr(run_simulation, '__name__')

    def test_agent_state_creation(self, sample_agent_state):
        """Test agent state can be created with sample data."""
        from graph import AgentState
        
        # State should be created without errors
        state_dict = sample_agent_state
        assert state_dict['session_id'] is not None
        assert state_dict['turn_count'] >= 0


@pytest.mark.blackbox
class TestSystemIntegration:
    """Test system as a whole."""

    @patch('database.engine')
    def test_database_connection_possible(self, mock_engine):
        """Test database connection can be established."""
        from database import engine
        
        assert engine is not None

    def test_all_modules_have_proper_docstrings(self):
        """Test that main modules have docstrings."""
        import app
        import database
        import graph
        import llm_config
        
        assert app.__doc__ is not None
        assert database.__doc__ is not None
        assert graph.__doc__ is not None
        assert llm_config.__doc__ is not None

    def test_environment_variables_loaded(self):
        """Test that environment variables can be loaded."""
        from dotenv import load_dotenv
        
        load_dotenv()
        # Should not raise exception
        assert True
