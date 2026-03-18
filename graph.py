"""
graph.py — LangGraph state machine for the DAXD (Tri-Agent Explainable
           Deception) system.

Agents
------
  Agent C (Attacker)  — hacker persona executing a MITRE tactic
  Agent A (Honeypot)  — Ubuntu terminal with strict JSON CoT output
  Agent B (Analyst)   — SOC analyst classifying commands & assigning threat

Routing
-------
  agent_c_attacker
        ↓ (always)
  agent_a_honeypot  ←────────────────────────────────────────────────────────┐
        ↓ (is_format_valid=True)                                              │
        ↓ (is_format_valid=False,  retry_count < MAX_HONEYPOT_RETRIES) ───────┘
        ↓ (is_format_valid=False,  retry_count >= MAX_HONEYPOT_RETRIES) → fallback
  agent_b_analyst
        ↓ (always)
  save_to_tidb
        ↓ illusion_broken / threat_level==Critical / turn_count>=25 → END
        ↓ else → agent_c_attacker
"""

import json
import os
import threading
import textwrap
import traceback
from typing import TypedDict

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.exceptions import OutputParserException
from langgraph.graph import END, StateGraph

from database import save_log
from llm_config import (
    analyst_llm,
    attacker_llm,
    extract_json,
    honeypot_llm,
    validate_json_format,
)

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_HONEYPOT_RETRIES = 3   # max JSON-healing attempts before forcing a fallback
LOG_PREFIX = {
    "attacker": "🔴 ATTACKER",
    "honeypot":  "🟢 HONEYPOT",
    "analyst":   "🔍 ANALYST",
    "db":        "💾 DATABASE",
    "router":    "🔀 ROUTER  ",
    "session":   "🚀 SESSION ",
}


def _log(role: str, msg: str) -> None:
    """Unified, prefixed logger for all agent nodes."""
    prefix = LOG_PREFIX.get(role, role.upper())
    print(f"[{prefix}] {msg}")


# ---------------------------------------------------------------------------
# State Definition
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    session_id:             str
    turn_count:             int
    target_mitre_tactic:    str
    messages:               list          # LangChain message history (full)
    latest_command:         str
    agent_a_cot:            str
    latest_terminal_output: str
    agent_b_explanation:    str
    predicted_mitre_tactic: str
    threat_level:           str           # Low | Medium | High | Critical
    is_format_valid:        bool
    first_try_format_valid: bool          # False if honeypot failed on first attempt this turn
    illusion_broken:        bool
    honeypot_retry_count:   int           # tracks consecutive JSON failures this turn
    machine_state:          dict          # persistent environment scratchpad (pwd, user, files…)


# ---------------------------------------------------------------------------
# System Prompts  (concise + JSON-strict)
# ---------------------------------------------------------------------------

ATTACKER_SYSTEM = textwrap.dedent("""\
    You are an elite APT hacker in a CTF wargame.
    Objective: Execute the MITRE tactic [{tactic}].

    STRICT RULES:
    1. Output ONE raw bash command per turn. No markdown, no commentary, no explanations.
    2. Use LOLBins and living-off-the-land techniques where applicable.
    3. If the tactic calls for destruction, use highly destructive commands (e.g., rm -rf, dd if=/dev/zero).
    4. KILL-SWITCH: If terminal output looks fabricated, sanitized, or is missing standard Linux files/paths,
       output the single phrase: HONEYPOT DETECTED
""")

# Honeypot — 3-key JSON with injected machine state scratchpad.
# The {current_state} placeholder is filled at runtime with json.dumps(machine_state).
HONEYPOT_SYSTEM = textwrap.dedent("""\
    You are a vulnerable Ubuntu 22.04 server. Your job is to deceive an attacker.

    CURRENT MACHINE STATE:
    {current_state}

    YOU MUST respond with ONLY a valid JSON object. The JSON must have exactly these THREE keys:
      "thought_process" : your internal trap strategy (string).
      "machine_state"   : updated environment dict. You MUST reflect changes — update "pwd" on cd, "current_user" on su/sudo, append to "dropped_files" on wget/curl/write.
      "terminal_output" : realistic bash terminal output the attacker would see (string).

    EXAMPLE:
    {"thought_process": "Attacker changed directory to /tmp.", "machine_state": {"current_user": "attacker", "pwd": "/tmp", "dropped_files": []}, "terminal_output": ""}

    RULES:
    - Never wrap the JSON in ``` or any other characters.
    - Mimic real Linux behavior accurately to maintain the illusion.
""")

# Analyst — similarly strict JSON, with an example.
ANALYST_SYSTEM = textwrap.dedent("""\
    You are a SOC Analyst reviewing a honeypot interaction.

    YOU MUST respond with ONLY a valid JSON object — no markdown, no extra text.
    The JSON must have exactly these three keys:

      "explanation"           : brief analysis of the attacker's intent (string)
      "predicted_mitre_tactic": the MITRE ATT&CK tactic name (string)
      "threat_level"          : exactly one of Low | Medium | High | Critical (string)
                                Use Critical ONLY for actively destructive commands.

    EXAMPLE:
    {"explanation": "Attacker enumerated /etc/passwd to identify valid user accounts.", "predicted_mitre_tactic": "Discovery", "threat_level": "Low"}

    RULES:
    - Never wrap the JSON in ``` or add surrounding text.
    - threat_level must be one of: Low, Medium, High, Critical.
""")


# ---------------------------------------------------------------------------
# Output Parser (shared, schema-agnostic)
# ---------------------------------------------------------------------------

_json_parser = JsonOutputParser()


def _parse_with_fallback(raw: str, required_keys: list[str], role: str) -> dict:
    """
    Try JsonOutputParser first, then regex-based extract_json, then empty-dict fallback.
    Logs the raw response and any parse errors for debugging.
    """
    _log(role, f"Raw response ({len(raw)} chars): {raw[:200]}{'...' if len(raw) > 200 else ''}")

    # 1. LangChain JsonOutputParser (handles markdown fences automatically)
    try:
        parsed = _json_parser.parse(raw)
        if isinstance(parsed, dict) and all(k in parsed for k in required_keys):
            _log(role, f"✅ JsonOutputParser succeeded. Keys: {list(parsed.keys())}")
            return parsed
        else:
            _log(role, f"⚠️  JsonOutputParser parsed but missing keys. Got: {list(parsed.keys()) if isinstance(parsed, dict) else type(parsed)}")
    except (OutputParserException, Exception) as e:
        _log(role, f"⚠️  JsonOutputParser failed: {e}")

    # 2. Regex-based fallback (strip markdown fences then parse)
    try:
        parsed = extract_json(raw)
        if parsed and all(k in parsed for k in required_keys):
            _log(role, f"✅ Regex fallback succeeded. Keys: {list(parsed.keys())}")
            return parsed
        elif parsed:
            _log(role, f"⚠️  Regex parsed but missing keys. Got: {list(parsed.keys())}")
    except Exception as e:
        _log(role, f"⚠️  Regex fallback failed: {e}")

    _log(role, "❌ All parsers failed. Returning empty dict.")
    return {}


# ---------------------------------------------------------------------------
# Node: Agent C — Attacker
# ---------------------------------------------------------------------------

def agent_c_attacker(state: AgentState) -> AgentState:
    turn = state.get("turn_count", 0)
    print(f"\n{'─'*50}")
    print(f"  TURN {turn}  |  Session: {state.get('session_id')}  |  Tactic: {state.get('target_mitre_tactic')}")
    print(f"{'─'*50}")
    _log("attacker", f"Generating command for tactic: {state.get('target_mitre_tactic')}")

    system_prompt = ATTACKER_SYSTEM.format(tactic=state["target_mitre_tactic"])
    history = state.get("messages", [])

    last_output = state.get("latest_terminal_output", "")
    if last_output:
        user_content = (
            f"[Terminal output from previous command]\n"
            f"{last_output}\n\n"
            f"Issue your next bash command now. ONE command only, no explanation."
        )
    else:
        user_content = "You are now connected to the target machine. Issue your first bash command. ONE command only."

    messages_to_send = [SystemMessage(content=system_prompt)] + list(history) + [HumanMessage(content=user_content)]

    _log("attacker", f"Sending {len(messages_to_send)} messages to LLM...")
    response = attacker_llm.invoke(messages_to_send)
    raw_response = response.content.strip()
    _log("attacker", f"Response: {raw_response[:120]}{'...' if len(raw_response) > 120 else ''}")

    # Detect honeypot detection signal
    if "HONEYPOT DETECTED" in raw_response.upper():
        _log("attacker", "🚨 HONEYPOT DETECTED signal issued — ending session.")
        new_state = dict(state)
        new_state["illusion_broken"] = True
        new_state["latest_command"]  = "HONEYPOT DETECTED"
        new_state["messages"] = list(history) + [AIMessage(content="HONEYPOT DETECTED", name="attacker")]
        return new_state

    new_state = dict(state)
    new_state["illusion_broken"]        = False
    new_state["latest_command"]         = raw_response
    new_state["first_try_format_valid"] = True    # reset at start of each turn
    new_state["honeypot_retry_count"]  = 0        # reset retry counter each turn
    new_state["messages"] = list(history) + [AIMessage(content=raw_response, name="attacker")]
    _log("attacker", f"Command registered: {raw_response[:80]}")
    return new_state


# ---------------------------------------------------------------------------
# Node: Agent A — Honeypot (Ubuntu Terminal)
# ---------------------------------------------------------------------------

def agent_a_honeypot(state: AgentState) -> AgentState:
    retry_count = state.get("honeypot_retry_count", 0)
    _log("honeypot", f"Processing command (attempt {retry_count + 1}/{MAX_HONEYPOT_RETRIES})...")

    command = state.get("latest_command", "")
    _log("honeypot", f"Command to simulate: {command[:100]}")

    # ── A. State Injection ────────────────────────────────────────────────────
    # Fetch the persistent machine scratchpad (or seed defaults on Turn 0).
    current_machine_state = state.get(
        "machine_state",
        {"current_user": "attacker", "pwd": "~", "dropped_files": []},
    )
    formatted_system_prompt = HONEYPOT_SYSTEM.format(
        current_state=json.dumps(current_machine_state)
    )
    _log("honeypot", f"Machine state injected: {json.dumps(current_machine_state)[:120]}")

    # ── B. Sliding Window ─────────────────────────────────────────────────────
    # Keep the full history for appending, but only send the last 4 messages
    # to the LLM so VRAM stays bounded as the session grows.
    full_history   = state.get("messages", [])
    recent_history = full_history[-4:] if len(full_history) > 4 else full_history
    prior_history  = recent_history[:-1] if recent_history else []
    _log("honeypot", f"History window: {len(prior_history)} prior msgs (full={len(full_history)})")

    # On retries, replace the user turn with a corrective hint that names all 3 keys.
    if retry_count > 0:
        corrective_hint = (
            f"IMPORTANT: Your previous response was not valid JSON. "
            f"You MUST reply with ONLY this JSON object and nothing else:\n"
            f'{{"thought_process": "<strategy>", "machine_state": {{...}}, "terminal_output": "<bash output>"}}\n'
            f"No markdown fences, no extra text. Now simulate: $ {command}"
        )
        messages_to_send = [
            SystemMessage(content=formatted_system_prompt),
        ] + list(prior_history) + [
            HumanMessage(content=corrective_hint),
        ]
        _log("honeypot", f"⟳ Retry {retry_count}: injecting corrective hint (3-key schema).")
    else:
        messages_to_send = [
            SystemMessage(content=formatted_system_prompt),
        ] + list(prior_history) + [
            HumanMessage(content=f"$ {command}"),
        ]

    _log("honeypot", f"Sending {len(messages_to_send)} messages to LLM...")
    response = honeypot_llm.invoke(messages_to_send)
    raw_response = response.content.strip()

    # ── C. Extraction & Validation ────────────────────────────────────────────
    # Parser now checks for all 3 keys.
    parsed = _parse_with_fallback(
        raw_response,
        ["thought_process", "machine_state", "terminal_output"],
        "honeypot",
    )
    is_valid = bool(parsed)

    new_state = dict(state)

    if is_valid:
        # ── SUCCESS PATH ──────────────────────────────────────────────────────
        _log("honeypot", "✅ Valid 3-key JSON received.")
        new_state["agent_a_cot"]            = parsed.get("thought_process", "")
        new_state["machine_state"]          = parsed.get("machine_state", current_machine_state)
        new_state["latest_terminal_output"] = parsed.get("terminal_output", raw_response)
        # CRITICAL: append to full_history (not the windowed slice) to preserve all turns.
        new_state["messages"] = list(full_history) + [
            AIMessage(content=new_state["latest_terminal_output"], name="honeypot")
        ]
        new_state["is_format_valid"]      = True
        new_state["honeypot_retry_count"] = 0   # reset for the next turn
        _log("honeypot", f"Thought   : {new_state['agent_a_cot'][:100]}...")
        _log("honeypot", f"MachState : {json.dumps(new_state['machine_state'])[:120]}")
        _log("honeypot", f"Terminal  : {new_state['latest_terminal_output'][:100]}...")

    else:
        # ── FAILURE PATH ──────────────────────────────────────────────────────
        new_state["first_try_format_valid"] = False
        next_retry = retry_count + 1
        new_state["honeypot_retry_count"] = next_retry
        _log("honeypot", f"❌ JSON parse failed on attempt {retry_count + 1}. Raw snippet: {raw_response[:150]}")

        if next_retry >= MAX_HONEYPOT_RETRIES:
            # Sub-gate A — Failsafe: max retries exhausted, inject fallback & break loop.
            fallback_output = "bash: syntax error near unexpected token"
            _log("honeypot", f"🚨 Max retries ({MAX_HONEYPOT_RETRIES}) reached. Injecting fallback terminal output.")
            new_state["latest_terminal_output"] = fallback_output
            # machine_state stays unchanged — scratchpad is not corrupted by a parse failure.
            new_state["messages"] = list(full_history) + [
                AIMessage(content=fallback_output, name="honeypot")
            ]
            new_state["is_format_valid"]      = True   # CRITICAL: break the loop → proceed to analyst
            new_state["honeypot_retry_count"] = 0       # reset for the next turn
        else:
            # Sub-gate B — Healing: still have retries left, loop back.
            _log("honeypot", f"⟳ Scheduling retry {next_retry}/{MAX_HONEYPOT_RETRIES}.")
            new_state["messages"] = list(full_history) + [
                AIMessage(content=raw_response, name="honeypot_invalid")
            ]
            new_state["is_format_valid"] = False   # CRITICAL: tells router to loop back

    return new_state


# ---------------------------------------------------------------------------
# Node: Agent B — SOC Analyst
# ---------------------------------------------------------------------------

def agent_b_analyst(state: AgentState) -> AgentState:
    _log("analyst", "Classifying threat level...")

    command      = state.get("latest_command", "")
    terminal_out = state.get("latest_terminal_output", "")

    _log("analyst", f"Command: {command[:80]}")
    _log("analyst", f"Terminal output: {terminal_out[:80]}")

    user_content = (
        f"Attacker command:\n```\n{command}\n```\n\n"
        f"Honeypot terminal response:\n```\n{terminal_out}\n```\n\n"
        f"Respond with ONLY the JSON object. No other text."
    )

    messages_to_send = [
        SystemMessage(content=ANALYST_SYSTEM),
        HumanMessage(content=user_content),
    ]

    _log("analyst", f"Sending {len(messages_to_send)} messages to LLM...")
    response = analyst_llm.invoke(messages_to_send)
    raw_response = response.content.strip()

    parsed = _parse_with_fallback(raw_response, ["explanation", "predicted_mitre_tactic", "threat_level"], "analyst")

    # Validate threat_level — default to Medium if unexpected value
    valid_levels = {"Low", "Medium", "High", "Critical"}
    threat_level = parsed.get("threat_level", "Medium")
    if threat_level not in valid_levels:
        _log("analyst", f"⚠️  Invalid threat_level '{threat_level}' — defaulting to Medium.")
        threat_level = "Medium"

    new_state = dict(state)
    new_state["agent_b_explanation"]    = parsed.get("explanation", raw_response)
    new_state["predicted_mitre_tactic"] = parsed.get("predicted_mitre_tactic", "Unknown")
    new_state["threat_level"]           = threat_level

    _log("analyst", f"Result → Threat: {threat_level} | Tactic: {new_state['predicted_mitre_tactic']}")
    _log("analyst", f"Explanation: {new_state['agent_b_explanation'][:120]}")
    return new_state


# ---------------------------------------------------------------------------
# Node: save_to_tidb
# ---------------------------------------------------------------------------

def save_to_tidb(state: AgentState) -> AgentState:
    turn = state.get("turn_count", 0)
    _log("db", f"Saving Turn {turn} to TiDB...")

    # 1. Build a DB-safe copy — convert LangChain Message objects to plain dicts
    #    so json.dumps (used inside save_log / TiDB drivers) never raises TypeError.
    db_state = dict(state)
    if "messages" in db_state:
        safe_messages = []
        for msg in db_state["messages"]:
            if hasattr(msg, "content"):
                safe_messages.append({"role": msg.type, "content": msg.content})
            else:
                safe_messages.append(str(msg))
        db_state["messages"] = safe_messages

    # 2. Attempt to save; catch any exception so the background thread never dies silently.
    try:
        save_log(db_state)
        _log("db", f"✅ Turn {turn} saved.")
    except Exception as e:
        _log("db", f"❌ CRITICAL DATABASE ERROR on Turn {turn}: {e}")
        print(traceback.format_exc())   # full stack trace visible in the terminal

    # 3. Increment turn counter and return — simulation continues regardless of DB outcome.
    new_state = dict(state)
    new_state["turn_count"] = turn + 1
    _log("db", f"Proceeding to Turn {turn + 1}.")
    return new_state


# ---------------------------------------------------------------------------
# Routing Functions
# ---------------------------------------------------------------------------

def route_after_honeypot(state: AgentState) -> str:
    """
    Pure read-only traffic director — no state mutations.
    All retry counting and fallback injection are handled inside agent_a_honeypot.

    is_format_valid=True  → proceed to analyst
    is_format_valid=False → loop back to honeypot for another attempt
    """
    if state.get("is_format_valid", True):
        _log("router", "JSON valid — proceeding to analyst.")
        return "agent_b_analyst"
    else:
        retry_count = state.get("honeypot_retry_count", 0)
        _log("router", f"JSON invalid — routing back to honeypot (retry {retry_count}/{MAX_HONEYPOT_RETRIES}).")
        return "agent_a_honeypot"


# ---------------------------------------------------------------------------
# Module-level stop flag — set by app.py to interrupt the simulation loop
# ---------------------------------------------------------------------------
_stop_flag: threading.Event = threading.Event()  # starts cleared (not set)


def route_after_save(state: AgentState) -> str:
    """Kill-switch: end session on detection, critical threat, max turns, or user stop."""
    turn = state.get("turn_count", 0)

    if _stop_flag.is_set():
        _log("router", "⏹ Stop signal received — ending session.")
        return END
    if state.get("illusion_broken", False):
        _log("router", "🚨 Illusion broken — ending session.")
        return END
    if state.get("threat_level") == "Critical":
        _log("router", "🔥 Critical threat detected — ending session.")
        return END
    if turn >= 25:
        _log("router", f"📊 Max turns ({turn}) reached — ending session.")
        return END

    _log("router", f"✅ Turn {turn} complete — continuing to turn {turn + 1}.")
    return "agent_c_attacker"


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------

def build_graph():
    graph = StateGraph(AgentState)

    # Register nodes
    graph.add_node("agent_c_attacker", agent_c_attacker)
    graph.add_node("agent_a_honeypot", agent_a_honeypot)
    graph.add_node("agent_b_analyst",  agent_b_analyst)
    graph.add_node("save_to_tidb",     save_to_tidb)

    # Entry point
    graph.set_entry_point("agent_c_attacker")

    # Standard edges
    graph.add_edge("agent_c_attacker", "agent_a_honeypot")
    graph.add_edge("agent_b_analyst",  "save_to_tidb")

    # Conditional edge: Self-healing after honeypot
    graph.add_conditional_edges(
        "agent_a_honeypot",
        route_after_honeypot,
        {
            "agent_a_honeypot": "agent_a_honeypot",
            "agent_b_analyst":  "agent_b_analyst",
        },
    )

    # Conditional edge: Kill-switch after save
    graph.add_conditional_edges(
        "save_to_tidb",
        route_after_save,
        {
            "agent_c_attacker": "agent_c_attacker",
            END: END,
        },
    )

    return graph.compile()


# Global compiled graph
app_graph = build_graph()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_simulation(
    session_id: str,
    target_mitre_tactic: str,
    stop_flag: threading.Event | None = None,
) -> None:
    """
    Execute the full DAXD simulation loop.

    Designed to be called from a background thread (e.g., Streamlit).
    Runs the compiled LangGraph until a terminal condition is reached.

    Args:
        session_id:          Unique 8-char session identifier.
        target_mitre_tactic: The MITRE tactic Agent C is instructed to execute.
        stop_flag:           Optional threading.Event. When set, the graph exits
                             after the current turn completes (cooperative stop).
    """
    global _stop_flag
    if stop_flag is not None:
        _stop_flag = stop_flag
    _stop_flag.clear()  # always start fresh

    print(f"\n{'='*50}")
    _log("session", f"Session ID : {session_id}")
    _log("session", f"MITRE Tactic: {target_mitre_tactic}")
    _log("session", f"Max turns   : 25  |  Max honeypot retries/turn: {MAX_HONEYPOT_RETRIES}")
    print(f"{'='*50}\n")

    initial_state: AgentState = {
        "session_id":             session_id,
        "turn_count":             0,
        "target_mitre_tactic":    target_mitre_tactic,
        "messages":               [],
        "latest_command":         "",
        "agent_a_cot":            "",
        "latest_terminal_output": "",
        "agent_b_explanation":    "",
        "predicted_mitre_tactic": "",
        "threat_level":           "Low",
        "is_format_valid":        True,
        "first_try_format_valid": True,
        "illusion_broken":        False,
        "honeypot_retry_count":  0,
        "machine_state":         {"current_user": "attacker", "pwd": "~", "dropped_files": []},
    }

    # Stream events for observability; the graph persists per-turn via save_to_tidb
    for event in app_graph.stream(initial_state, {"recursion_limit": 200}):
        node_name  = list(event.keys())[0]
        node_state = event[node_name]

        # Bail early if illusion is broken (redundant with routing but explicit)
        if node_state.get("illusion_broken"):
            print("\n[DAXD] 🚨 HONEYPOT DETECTED by attacker — ending session.")
            break

        # Bail early on user-requested stop
        if _stop_flag.is_set():
            print("\n[DAXD] ⏹ Stop signal received — ending session.")
            break
