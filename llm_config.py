"""
llm_config.py — LLM initialisation for DAXD system.

Uses ChatOllama (langchain-ollama) to talk to a local Ollama server.
Set OLLAMA_BASE_URL in .env to point at ngrok if running remotely.
"""

import json
import os
import re

from dotenv import load_dotenv
from langchain_ollama import ChatOllama

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
ATTACKER_MODEL  = os.getenv("ATTACKER_MODEL", "llama3.1:8b")
HONEYPOT_MODEL  = os.getenv("HONEYPOT_MODEL", "qwen2.5-coder:7b")
ANALYST_MODEL   = os.getenv("ANALYST_MODEL",  "llama3.2:3b")

# ---------------------------------------------------------------------------
# LLM instances — one per agent role
# ---------------------------------------------------------------------------
attacker_llm = ChatOllama(
    model       = ATTACKER_MODEL,
    base_url    = OLLAMA_BASE_URL,
    temperature = 0.7,
)

honeypot_llm = ChatOllama(
    model       = HONEYPOT_MODEL,
    base_url    = OLLAMA_BASE_URL,
    temperature = 0.1,   # low temp for strict JSON discipline
)

analyst_llm = ChatOllama(
    model       = ANALYST_MODEL,
    base_url    = OLLAMA_BASE_URL,
    temperature = 0.1,   # analytical — want consistent JSON
)


# ---------------------------------------------------------------------------
# JSON validation helpers
# ---------------------------------------------------------------------------

def extract_json(text: str) -> dict:
    """
    Best-effort extraction of a JSON dict from *text*.
    Strips markdown fences if the LLM hallucinated them.
    Returns an empty dict on failure.
    """
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}


def validate_json_format(text: str) -> bool:
    """
    Strictly validates that the response is parseable JSON with the required keys.
    Rejects empty strings, failed parses, and missing schema keys.
    """
    if not text or not text.strip():
        return False
    parsed = extract_json(text)
    if not parsed:
        return False
    if "thought_process" not in parsed or "terminal_output" not in parsed:
        return False
    return True
