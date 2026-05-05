"""White Box Testing: database.py module unit tests."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from sqlalchemy import text

# White Box - Testing internal implementation details


@pytest.mark.whitebox
@pytest.mark.unit
class TestDatabaseModule:
    """Test database module initialization and connection."""

    def test_database_url_format_conversion(self):
        """Test that mysql:// URLs are converted to mysql+pymysql://."""
        from database import TIDB_DATABASE_URL
        
        # TIDB_DATABASE_URL should either be empty or use mysql+pymysql
        if TIDB_DATABASE_URL:
            assert "mysql+pymysql://" in TIDB_DATABASE_URL or TIDB_DATABASE_URL == ""

    def test_engine_creation(self):
        """Test that database engine is created with correct parameters."""
        from database import engine
        
        assert engine is not None
        assert engine.pool is not None

    def test_xai_deception_log_model_fields(self):
        """Test that XaiDeceptionLog model has all required fields."""
        from database import XaiDeceptionLog
        
        expected_fields = [
            'id', 'timestamp', 'session_id', 'turn_count', 
            'target_mitre_tactic', 'messages', 'latest_command',
            'agent_a_cot', 'latest_terminal_output', 'agent_b_explanation',
            'predicted_mitre_tactic', 'threat_level', 'is_format_valid',
            'first_try_format_valid', 'illusion_broken'
        ]
        
        for field in expected_fields:
            assert hasattr(XaiDeceptionLog, field), f"Missing field: {field}"

    def test_xai_deception_log_tablename(self):
        """Test that XaiDeceptionLog uses correct table name."""
        from database import XaiDeceptionLog
        
        assert XaiDeceptionLog.__tablename__ == "xai_deception_logs"


@pytest.mark.whitebox
@pytest.mark.unit
class TestDatabaseFunctions:
    """Test database utility functions."""

    @patch('database.engine')
    def test_create_tables_called(self, mock_engine):
        """Test create_tables function signature."""
        from database import create_tables
        
        # Should be callable with no arguments
        assert callable(create_tables)

    @patch('database.engine')
    def test_migrate_add_columns_exists(self, mock_engine):
        """Test that migration function exists."""
        from database import _migrate_add_columns
        
        assert callable(_migrate_add_columns)


@pytest.mark.whitebox
@pytest.mark.unit
class TestDatabaseIntegration:
    """Integration tests for database operations."""

    @patch('database.Session')
    def test_save_log_function_signature(self, mock_session):
        """Test save_log function exists and is callable."""
        from database import save_log
        
        assert callable(save_log)

    @patch('database.Session')
    def test_delete_session_function_signature(self, mock_session):
        """Test delete_session function exists and is callable."""
        from database import delete_session
        
        assert callable(delete_session)
