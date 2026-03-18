"""
database.py — TiDB Serverless connection + ORM model for DAXD system.
"""

import os
from datetime import datetime

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text, create_engine, text
)
from sqlalchemy.orm import DeclarativeBase, Session

load_dotenv()

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
TIDB_DATABASE_URL = os.getenv("TIDB_DATABASE_URL", "")

# Ensure the PyMySQL dialect is used — fix bare mysql:// → mysql+pymysql://
if TIDB_DATABASE_URL.startswith("mysql://"):
    TIDB_DATABASE_URL = TIDB_DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)

# TiDB Serverless requires SSL; we pass connect_args to PyMySQL
engine = create_engine(
    TIDB_DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    connect_args={
        "ssl": {
            "verify_cert": False,
            "verify_identity": False,
        }
    },
)


# ---------------------------------------------------------------------------
# ORM Model
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class XaiDeceptionLog(Base):
    __tablename__ = "xai_deception_logs"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    timestamp           = Column(DateTime, default=datetime.utcnow, nullable=False)

    # --- State fields -------------------------------------------------------
    session_id          = Column(String(64),  nullable=False, index=True)
    turn_count          = Column(Integer,     nullable=False, default=0)
    target_mitre_tactic = Column(String(128), nullable=True)
    # messages stored as JSON string
    messages            = Column(Text,        nullable=True)
    latest_command      = Column(Text,        nullable=True)
    agent_a_cot         = Column(Text,        nullable=True)
    latest_terminal_output = Column(Text,     nullable=True)
    agent_b_explanation = Column(Text,        nullable=True)
    predicted_mitre_tactic = Column(String(128), nullable=True)
    threat_level        = Column(String(16),  nullable=True)   # Low/Medium/High/Critical
    is_format_valid     = Column(Boolean,     nullable=True)
    first_try_format_valid = Column(Boolean,  nullable=True)   # True only if honeypot passed on first attempt
    illusion_broken     = Column(Boolean,     nullable=True, default=False)


def create_tables() -> None:
    """Create tables if they do not yet exist, then apply any pending migrations."""
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def _migrate_add_columns() -> None:
    """
    Safely add any new columns that may be missing from an already-existing table.
    TiDB / MySQL does not support IF NOT EXISTS for ADD COLUMN in older versions,
    so we check information_schema first and only ALTER if the column is absent.
    """
    migrations = [
        # (column_name, DDL type)
        ("first_try_format_valid", "BOOLEAN"),
    ]

    with engine.connect() as conn:
        for col_name, col_type in migrations:
            # Check whether the column already exists
            result = conn.execute(
                text(
                    "SELECT COUNT(*) FROM information_schema.COLUMNS "
                    "WHERE TABLE_SCHEMA = DATABASE() "
                    "  AND TABLE_NAME   = 'xai_deception_logs' "
                    "  AND COLUMN_NAME  = :col"
                ),
                {"col": col_name},
            )
            exists = result.scalar() > 0
            if not exists:
                conn.execute(
                    text(
                        f"ALTER TABLE xai_deception_logs "
                        f"ADD COLUMN {col_name} {col_type}"
                    )
                )
                conn.commit()
                print(f"[database] Migration applied: added column '{col_name}'.")


def save_log(state: dict) -> None:
    """Insert one row from the current LangGraph state dict."""
    import json

    row = XaiDeceptionLog(
        session_id             = state.get("session_id", ""),
        turn_count             = state.get("turn_count", 0),
        target_mitre_tactic    = state.get("target_mitre_tactic"),
        messages               = json.dumps(
            [m.dict() if hasattr(m, "dict") else str(m)
             for m in state.get("messages", [])],
            default=str,
        ),
        latest_command         = state.get("latest_command"),
        agent_a_cot            = state.get("agent_a_cot"),
        latest_terminal_output = state.get("latest_terminal_output"),
        agent_b_explanation    = state.get("agent_b_explanation"),
        predicted_mitre_tactic = state.get("predicted_mitre_tactic"),
        threat_level           = state.get("threat_level"),
        is_format_valid        = state.get("is_format_valid"),
        first_try_format_valid = state.get("first_try_format_valid"),
        illusion_broken        = state.get("illusion_broken", False),
        timestamp              = datetime.utcnow(),
    )

    with Session(engine) as session:
        session.add(row)
        session.commit()


def delete_session(session_id: str) -> int:
    """
    Hard-delete all log rows for the given session_id.
    Returns the number of rows deleted.
    """
    with engine.connect() as conn:
        result = conn.execute(
            text("DELETE FROM xai_deception_logs WHERE session_id = :sid"),
            {"sid": session_id},
        )
        conn.commit()
        return result.rowcount


# Create tables on module import
create_tables()
