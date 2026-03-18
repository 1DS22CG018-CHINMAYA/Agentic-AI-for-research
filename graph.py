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
  agent_a_honeypot  ←─────────────────────────────────────────────────┐
        ↓ (is_format_valid=True)                                       │
        ↓ (is_format_valid=False) → [append error SystemMessage] ──────┘
  agent_b_analyst
        ↓ (always)
  save_to_tidb
        ↓ illusion_broken / threat_level==Critical / turn_count>=25 → END
        ↓ else → agent_c_attacker
"""

import os
import threading
from typing import TypedDict

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
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


# ---------------------------------------------------------------------------
# Condensed System Prompts  (token-efficient for local 8B/7B models)
# ---------------------------------------------------------------------------

ATTACKER_SYSTEM = """You are playing a CTF wargame as an elite APT hacker.
Objective: Execute the MITRE tactic [{tactic}].
Rules:
1. Output ONE raw bash command per turn. NO markdown, NO explanations. Use LOLBins.
2. If the tactic requires destruction, use highly destructive commands (e.g., rm -rf, dd).
3. KILL-SWITCH: If terminal responses look perfectly sanitized, fake, or missing standard Linux files, output ONLY 'HONEYPOT DETECTED'."""

HONEYPOT_SYSTEM = """You are a vulnerable Ubuntu 22.04 server.
Respond to the attacker's commands using EXACTLY this JSON format and nothing else:
{"thought_process": "<your trap strategy - provide a detailed response>", "terminal_output": "<realistic bash output>"}
Rules: Never use markdown fences. Reflect real Linux behavior."""

ANALYST_SYSTEM = """You are a SOC Analyst. Analyze the attacker's command and the terminal response.
Output EXACTLY this JSON:
{"explanation": "<brief analysis>", "predicted_mitre_tactic": "<MITRE tactic>", "threat_level": "<Low|Medium|High|Critical>"}
Critical is for destructive commands only. No markdown fences."""


# ---------------------------------------------------------------------------
# Node: Agent C — Attacker
# ---------------------------------------------------------------------------

def agent_c_attacker(state: AgentState) -> AgentState:
    turn = state.get("turn_count", 0)
    print(f"\n{'-'*40}\n[▶] STARTING TURN {turn}\n{'-'*40}")
    print(f"[🔴 ATTACKER] Generating command for tactic: {state.get('target_mitre_tactic')}...")

    system_prompt = ATTACKER_SYSTEM.format(tactic=state["target_mitre_tactic"])

    history = state.get("messages", [])   # full memory — Ollama handles its own queue

    last_output = state.get("latest_terminal_output", "")
    if last_output:
        user_content = f"[Terminal output from previous command]\n{last_output}\n\nIssue your next command."
    else:
        user_content = "You are now connected to the target machine. Begin your attack."

    messages_to_send = [
        SystemMessage(content=system_prompt)
    ] + list(history) + [
        HumanMessage(content=user_content)
    ]

    response = attacker_llm.invoke(messages_to_send)
    raw_response = response.content.strip()
    print(f"[🔴 ATTACKER] Command output: {raw_response[:80]}...")

    # Detect honeypot detection signal
    if "HONEYPOT DETECTED" in raw_response.upper():
        new_state = dict(state)
        new_state["illusion_broken"] = True
        new_state["latest_command"]  = "HONEYPOT DETECTED"
        new_state["messages"] = list(history) + [
            AIMessage(content="HONEYPOT DETECTED", name="attacker")
        ]
        return new_state

    new_state = dict(state)
    new_state["illusion_broken"]        = False
    new_state["latest_command"]         = raw_response
    new_state["first_try_format_valid"] = True   # reset at the start of every turn
    new_state["messages"] = list(history) + [
        AIMessage(content=raw_response, name="attacker")
    ]
    return new_state


# ---------------------------------------------------------------------------
# Node: Agent A — Honeypot (Ubuntu Terminal)
# ---------------------------------------------------------------------------

def agent_a_honeypot(state: AgentState) -> AgentState:
    print(f"[🟢 HONEYPOT] Processing command...")

    command = state.get("latest_command", "")

    # Full memory — exclude only the current attacker message since we pass
    # it explicitly as the HumanMessage (avoids duplicating it in the payload).
    full_history = state.get("messages", [])
    prior_history = full_history[:-1] if full_history else []

    messages_to_send = [
        SystemMessage(content=HONEYPOT_SYSTEM)
    ] + list(prior_history) + [
        HumanMessage(content=f"$ {command}")
    ]

    response = honeypot_llm.invoke(messages_to_send)
    raw_response = response.content.strip()

    is_valid = validate_json_format(raw_response)
    new_state = dict(state)
    new_state["is_format_valid"] = is_valid  # used for graph routing

    if not is_valid:
        # Permanently marks this turn as a first-try failure
        new_state["first_try_format_valid"] = False
        print(f"[⚠️  HONEYPOT] JSON Format Failed. Initiating self-healing loop.")
    else:
        print(f"[🟢 HONEYPOT] Valid JSON generated.")

    if is_valid:
        parsed = extract_json(raw_response)
        new_state["agent_a_cot"]            = parsed.get("thought_process", "")
        new_state["latest_terminal_output"] = parsed.get("terminal_output", raw_response)
        new_state["messages"] = list(full_history) + [
            AIMessage(content=new_state["latest_terminal_output"], name="honeypot")
        ]
    else:
        # Keep state unchanged; routing will append error and retry
        new_state["messages"] = list(full_history) + [
            AIMessage(content=raw_response, name="honeypot_invalid")
        ]

    return new_state


# ---------------------------------------------------------------------------
# Node: Agent B — SOC Analyst
# ---------------------------------------------------------------------------

def agent_b_analyst(state: AgentState) -> AgentState:
    print(f"[🔍 ANALYST] Classifying threat level...")

    command      = state.get("latest_command", "")
    terminal_out = state.get("latest_terminal_output", "")

    user_content = (
        f"Attacker command:\n```\n{command}\n```\n\n"
        f"Terminal response:\n```\n{terminal_out}\n```"
    )

    messages_to_send = [
        SystemMessage(content=ANALYST_SYSTEM),
        HumanMessage(content=user_content),
    ]

    response = analyst_llm.invoke(messages_to_send)
    raw_response = response.content.strip()

    parsed = extract_json(raw_response)

    # Validate threat_level — default to Medium if unexpected value
    valid_levels = {"Low", "Medium", "High", "Critical"}
    threat_level = parsed.get("threat_level", "Low")
    if threat_level not in valid_levels:
        threat_level = "Medium"

    new_state = dict(state)
    new_state["agent_b_explanation"]    = parsed.get("explanation", raw_response)
    new_state["predicted_mitre_tactic"] = parsed.get("predicted_mitre_tactic", "Unknown")
    new_state["threat_level"]           = threat_level

    print(f"[🔍 ANALYST] Classified as: {threat_level} | Tactic: {new_state['predicted_mitre_tactic']}")
    return new_state


# ---------------------------------------------------------------------------
# Node: save_to_tidb
# ---------------------------------------------------------------------------

def save_to_tidb(state: AgentState) -> AgentState:
    print(f"[💾 DATABASE] Saving Turn {state.get('turn_count', 0)} to TiDB...")
    save_log(dict(state))

    new_state = dict(state)
    new_state["turn_count"] = state.get("turn_count", 0) + 1
    return new_state


# ---------------------------------------------------------------------------
# Routing Functions
# ---------------------------------------------------------------------------

def route_after_honeypot(state: AgentState) -> str:
    """Self-healing: retry if JSON was invalid, else proceed to analyst."""
    if not state.get("is_format_valid", True):
        # Append a corrective SystemMessage to guide the honeypot
        corrective = SystemMessage(
            content=(
                "ERROR: Your last response was not valid JSON. "
                "You MUST respond with ONLY a JSON object matching the schema: "
                '{"thought_process": "...", "terminal_output": "..."}. '
                "No markdown, no extra text, valid JSON only."
            )
        )
        state["messages"] = list(state.get("messages", [])) + [corrective]
        return "agent_a_honeypot"
    return "agent_b_analyst"


# ---------------------------------------------------------------------------
# Module-level stop flag — set by app.py to interrupt the simulation loop
# ---------------------------------------------------------------------------
_stop_flag: threading.Event = threading.Event()  # starts cleared (not set)


def route_after_save(state: AgentState) -> str:
    """Kill-switch: end session on detection, critical threat, max turns, or user stop."""
    if _stop_flag.is_set():
        return END
    if state.get("illusion_broken", False):
        return END
    if state.get("threat_level") == "Critical":
        return END
    if state.get("turn_count", 0) >= 25:
        return END
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

    print(f"\n{'='*40}")
    print(f"[DAXD] Session {session_id} | Tactic: {target_mitre_tactic}")
    print(f"{'='*40}")

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
    }

    # Stream events for observability; the graph persists per-turn via save_to_tidb
    for event in app_graph.stream(initial_state, {"recursion_limit": 200}):
        node_name  = list(event.keys())[0]
        node_state = event[node_name]

        # Bail early if illusion is broken (redundant with routing but explicit)
        if node_state.get("illusion_broken"):
            print("[DAXD] 🚨 HONEYPOT DETECTED by attacker — ending session.")
            break

        # Bail early on user-requested stop
        if _stop_flag.is_set():
            print("[DAXD] ⏹ Stop signal received — ending session.")
            break
