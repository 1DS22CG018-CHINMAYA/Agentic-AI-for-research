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
# JSON extraction helpers
# ---------------------------------------------------------------------------

def _strip_markdown_fences(text: str) -> str:
    """Remove ```json ... ``` or ``` ... ``` wrappers that some models emit."""
    # Remove fenced code blocks: ```json\n...\n``` or ```\n...\n```
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\n?```\s*$", "", text.strip())
    return text.strip()


def _extract_json_by_depth(text: str) -> str | None:
    """
    Scan the text character-by-character to extract the first top-level
    JSON object {…}, correctly handling nested braces and quoted strings.
    Returns the raw JSON substring, or None if not found.
    """
    depth = 0
    in_string = False
    escape_next = False
    start = None

    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:i + 1]
    return None


def extract_json(text: str) -> dict:
    """
    Best-effort extraction of a JSON dict from *text*.

    Strategy (in order):
      1. Strip markdown fences, try json.loads directly.
      2. Use brace-depth scanner to locate first {...} block, then json.loads.
      3. Fallback regex (greedy DOTALL) for simple single-level objects.

    Returns an empty dict on all failures.
    """
    if not text or not text.strip():
        return {}

    # 1. Direct parse after stripping fences
    cleaned = _strip_markdown_fences(text)
    try:
        result = json.loads(cleaned)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # 2. Brace-depth extraction
    candidate = _extract_json_by_depth(cleaned) or _extract_json_by_depth(text)
    if candidate:
        try:
            result = json.loads(candidate)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    # 3. Greedy regex fallback
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group(0))
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    return {}


def validate_json_format(text: str) -> bool:
    """
    Strictly validates that the response is parseable JSON with the required
    honeypot keys: 'thought_process' and 'terminal_output'.
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
