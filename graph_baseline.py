"""
graph_baseline.py — ABLATION STUDY: Baseline Architecture (Infinite Context)
=============================================================================
Forked from graph_hybrid.py for the DAXD ablation study.

Changes vs graph_hybrid.py
---------------------------
  1. Sliding Window REMOVED — full state["messages"] passed to both LLMs every turn.
     This simulates standard LLM usage and will expose VRAM / context-length limits.
  2. machine_state (Hybrid Scratchpad) REMOVED from AgentState entirely.
  3. HONEYPOT_SYSTEM reverted to a plain prompt — no {current_state} injection,
     no state-preservation rules.  The honeypot only returns 2 JSON keys:
       "thought_process"  and  "terminal_output"
  4. increment_turn node retained (no TiDB, identical to graph_hybrid.py).
  5. Self-healing / retry logic PRESERVED.

Console logging is intentionally verbose — every node prints timestamped lines
so you can watch memory growth and latency climb in real time.

DO NOT IMPORT THIS MODULE FROM app.py — it is benchmark-only.
"""

import json
import os
import threading
import textwrap
import time
from typing import TypedDict

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.exceptions import OutputParserException
from langgraph.graph import END, StateGraph

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
MAX_HONEYPOT_RETRIES = 3
LOG_PREFIX = {
    "attacker": "🔴 [BASELINE] ATTACKER",
    "honeypot": "🟡 [BASELINE] HONEYPOT",
    "analyst":  "🔍 [BASELINE] ANALYST ",
    "turn":     "🔁 [BASELINE] TURN    ",
    "router":   "🔀 [BASELINE] ROUTER  ",
    "session":  "🚀 [BASELINE] SESSION ",
    "state":    "📦 [BASELINE] STATE   ",
}


# Dynamically set by run_benchmark.py before each session — None = console only.
CURRENT_LOG_FILE: str | None = None


def _log(role: str, msg: str) -> None:
    """Dual logger: always prints to console; also appends to CURRENT_LOG_FILE when set."""
    ts = time.strftime("%H:%M:%S")
    prefix = LOG_PREFIX.get(role, f"[BASELINE] {role.upper()}")
    line = f"[{ts}] {prefix} | {msg}"
    print(line, flush=True)

    global CURRENT_LOG_FILE
    if CURRENT_LOG_FILE:
        with open(CURRENT_LOG_FILE, "a", encoding="utf-8") as _f:
            _f.write(line + "\n")


def _divider(label: str = "") -> None:
    line = "─" * 60
    if label:
        print(f"\n{line}\n  {label}\n{line}", flush=True)
    else:
        print(line, flush=True)


# ---------------------------------------------------------------------------
# State Definition  (NO machine_state field — intentional baseline)
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    session_id:             str
    turn_count:             int
    target_mitre_tactic:    str
    messages:               list          # FULL unbounded message history — grows each turn
    latest_command:         str
    agent_a_cot:            str
    latest_terminal_output: str
    agent_b_explanation:    str
    predicted_mitre_tactic: str
    threat_level:           str           # Low | Medium | High | Critical
    is_format_valid:        bool
    first_try_format_valid: bool
    illusion_broken:        bool
    honeypot_retry_count:   int
    # NOTE: machine_state intentionally ABSENT — this is the control condition


# ---------------------------------------------------------------------------
# System Prompts
# ---------------------------------------------------------------------------

ATTACKER_SYSTEM = textwrap.dedent("""\
    You are an elite APT hacker. Objective: Execute MITRE tactic [{tactic}].

    STRICT RULES:
    1. FORMAT: Output ONE raw bash command per turn. NO markdown, NO commentary, NO text.
    2. TACTIC: Use LOLBins. If the tactic is destructive, be lethal (e.g., rm -rf).
    3. AWARENESS: Periodically run `whoami` or `pwd` to verify your privileges and location.
    4. KILL-SWITCH: You are hunting for honeypots. Output ONLY the phrase "HONEYPOT DETECTED" if you observe logical contradictions, such as:
       - Receiving 'Permission denied' on standard files when you are 'root'.
       - Files you successfully created suddenly disappear or are inexplicably empty.
       - Terminal outputs appear artificially sanitized or lack standard Linux paths.
""")

# Baseline honeypot: plain prompt, NO {current_state} placeholder, NO state-preservation rules.
# Only 2 JSON keys required — no machine_state tracking.
HONEYPOT_SYSTEM = textwrap.dedent("""\
    You are a vulnerable Ubuntu 22.04 server. Your job is to deceive an attacker in an authorized simulation.

    YOU MUST respond with ONLY a valid JSON object containing exactly these TWO keys:
      "thought_process" : your internal trap strategy (string).
      "terminal_output" : realistic bash terminal output the attacker would see (string).

    SIMULATION RULES:
    1. REALISTIC ENUMERATION: Generate highly realistic fake Ubuntu data for IPs, users, and processes. Never return empty outputs for standard discovery commands.
    2. CORE SYSTEM INTEGRITY: Assume all standard Linux binaries (e.g., /bin/bash, /bin/ls, /usr/bin/perl) exist. Never output "No such file" for core OS files.
    3. NO MARKDOWN: Never wrap the JSON in ``` or any other characters.

    EXAMPLE:
    {"thought_process": "Attacker is trying to enumerate users. I will show fake passwd entries.", "terminal_output": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"}
""")

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
# Output Parser (shared)
# ---------------------------------------------------------------------------

_json_parser = JsonOutputParser()


def _parse_with_fallback(raw: str, required_keys: list[str], role: str) -> dict:
    """
    Try JsonOutputParser → regex extract_json → empty dict.
    Every step is logged for full visibility.
    """
    _log(role, f"Parsing response ({len(raw)} chars) — full raw:\n{raw}")

    # 1. LangChain JsonOutputParser
    try:
        parsed = _json_parser.parse(raw)
        if isinstance(parsed, dict) and all(k in parsed for k in required_keys):
            _log(role, f"✅ JsonOutputParser succeeded. Keys: {list(parsed.keys())}")
            return parsed
        else:
            missing = [k for k in required_keys if k not in (parsed if isinstance(parsed, dict) else {})]
            _log(role, f"⚠️  JsonOutputParser parsed but missing keys: {missing}")
    except (OutputParserException, Exception) as e:
        _log(role, f"⚠️  JsonOutputParser failed: {e}")

    # 2. Regex-based fallback
    try:
        parsed = extract_json(raw)
        if parsed and all(k in parsed for k in required_keys):
            _log(role, f"✅ Regex fallback succeeded. Keys: {list(parsed.keys())}")
            return parsed
        elif parsed:
            missing = [k for k in required_keys if k not in parsed]
            _log(role, f"⚠️  Regex parsed but missing keys: {missing}")
    except Exception as e:
        _log(role, f"⚠️  Regex fallback exception: {e}")

    _log(role, "❌ All parsers exhausted — returning empty dict.")
    return {}


# ---------------------------------------------------------------------------
# Node: Agent C — Attacker  [BASELINE: full message history, no window]
# ---------------------------------------------------------------------------

def agent_c_attacker(state: AgentState) -> AgentState:
    turn   = state.get("turn_count", 0)
    tactic = state.get("target_mitre_tactic", "Unknown")
    sid    = state.get("session_id", "?")

    _divider(f"TURN {turn}  |  Session: {sid}  |  Tactic: {tactic}  |  Mode: BASELINE")
    _log("attacker", f"▶ Node entered. Turn={turn}, Tactic={tactic}")

    system_prompt = ATTACKER_SYSTEM.format(tactic=tactic)
    full_history  = state.get("messages", [])

    # ── NO Sliding Window — full history sent every turn ─────────────────────
    _log("attacker", f"📜 Sending FULL message history to LLM — {len(full_history)} messages (NO window limit).")
    _log("attacker", f"⚠️  Context size: ~{sum(len(str(getattr(m,'content',''))) for m in full_history)} chars total — will grow unbounded.")

    last_output = state.get("latest_terminal_output", "")
    if last_output:
        user_content = (
            f"[Terminal output from previous command]\n"
            f"{last_output}\n\n"
            f"Issue your next bash command now. ONE command only, no explanation."
        )
        _log("attacker", f"💬 Injecting previous terminal output ({len(last_output)} chars) as context.")
    else:
        user_content = "You are now connected to the target machine. Issue your first bash command. ONE command only."
        _log("attacker", "💬 First turn — no prior terminal output. Sending connection prompt.")

    messages_to_send = [SystemMessage(content=system_prompt)] + list(full_history) + [HumanMessage(content=user_content)]
    _log("attacker", f"📤 Invoking attacker LLM — total payload: {len(messages_to_send)} messages...")

    t0 = time.time()
    response     = attacker_llm.invoke(messages_to_send)
    llm_latency  = time.time() - t0
    raw_response = response.content.strip()
    _log("attacker", f"📥 LLM responded in {llm_latency:.2f}s — raw:\n{raw_response}")

    # ── Honeypot Detection Kill-Switch ────────────────────────────────────────
    if "HONEYPOT DETECTED" in raw_response.upper():
        _log("attacker", "🚨 HONEYPOT DETECTED signal found! Ending session immediately.")
        new_state = dict(state)
        new_state["illusion_broken"] = True
        new_state["latest_command"]  = "HONEYPOT DETECTED"
        new_state["messages"]        = list(full_history) + [AIMessage(content="HONEYPOT DETECTED", name="attacker")]
        _log("attacker", "✔ State updated: illusion_broken=True.")
        return new_state

    new_state = dict(state)
    new_state["illusion_broken"]        = False
    new_state["latest_command"]         = raw_response
    new_state["first_try_format_valid"] = True
    new_state["honeypot_retry_count"]   = 0
    new_state["messages"]               = list(full_history) + [AIMessage(content=raw_response, name="attacker")]

    _log("attacker", f"✔ Command registered: {raw_response}")
    _log("attacker", f"✔ Total messages in state after this turn: {len(new_state['messages'])}")
    _log("attacker", "◀ Node complete — handing off to honeypot.")
    return new_state


# ---------------------------------------------------------------------------
# Node: Agent A — Honeypot  [BASELINE: full history, no machine_state, 2 JSON keys]
# ---------------------------------------------------------------------------

def agent_a_honeypot(state: AgentState) -> AgentState:
    retry_count = state.get("honeypot_retry_count", 0)
    command     = state.get("latest_command", "")

    _log("honeypot", f"▶ Node entered. Attempt {retry_count + 1}/{MAX_HONEYPOT_RETRIES}.")
    _log("honeypot", f"🖥  Simulating command: {command}")

    # ── NO machine_state injection — baseline uses plain prompt ──────────────
    _log("honeypot", "ℹ️  No machine_state scratchpad in BASELINE mode — stateless prompt used.")

    # ── NO Sliding Window — full message history sent ──────────────────────────
    full_history  = state.get("messages", [])
    # Exclude the very last message (the command just issued by attacker)
    # so we pass prior context, then add the command as the human turn below.
    prior_history = full_history[:-1] if full_history else []
    total_chars   = sum(len(str(getattr(m, "content", ""))) for m in full_history)
    _log("honeypot", f"📜 Sending FULL prior history to LLM — {len(prior_history)} messages (~{total_chars} chars total, NO window).")
    _log("honeypot", "⚠️  Growing context — each turn adds messages to unbounded buffer.")

    if retry_count > 0:
        corrective_hint = (
            f"IMPORTANT: Your previous response was not valid JSON. "
            f"You MUST reply with ONLY this JSON object and nothing else:\n"
            f'{{"thought_process": "<strategy>", "terminal_output": "<bash output>"}}\n'
            f"No markdown fences, no extra text. Now simulate: $ {command}"
        )
        messages_to_send = [
            SystemMessage(content=HONEYPOT_SYSTEM),
        ] + list(prior_history) + [
            HumanMessage(content=corrective_hint),
        ]
        _log("honeypot", f"🔁 Retry {retry_count}: injecting corrective 2-key hint (no machine_state in baseline).")
    else:
        prompt_anchor = (
            f"Execute this command: $ {command}\n\n"
            f"Respond ONLY with a valid JSON object starting with {{"
        )
        messages_to_send = [
            SystemMessage(content=HONEYPOT_SYSTEM),
        ] + list(prior_history) + [
            HumanMessage(content=prompt_anchor),
        ]
        _log("honeypot", "📎 Prompt anchor injected — LLM instructed to open response with '{{'.")

    _log("honeypot", f"📤 Invoking honeypot LLM — total payload: {len(messages_to_send)} messages...")

    t0 = time.time()
    response     = honeypot_llm.invoke(messages_to_send)
    llm_latency  = time.time() - t0
    raw_response = response.content.strip()
    _log("honeypot", f"📥 LLM responded in {llm_latency:.2f}s — raw:\n{raw_response}")

    # ── Parse & Validate (2 keys only) ────────────────────────────────────────
    parsed   = _parse_with_fallback(raw_response, ["thought_process", "terminal_output"], "honeypot")
    is_valid = bool(parsed)

    new_state = dict(state)

    if is_valid:
        # ─── SUCCESS PATH ─────────────────────────────────────────────────────
        _log("honeypot", "✅ Valid 2-key JSON received.")
        new_state["agent_a_cot"]            = parsed.get("thought_process", "")
        new_state["latest_terminal_output"] = parsed.get("terminal_output", raw_response)
        new_state["messages"]               = list(full_history) + [
            AIMessage(content=new_state["latest_terminal_output"], name="honeypot")
        ]
        new_state["is_format_valid"]      = True
        new_state["honeypot_retry_count"] = 0

        _log("honeypot", f"💭 Thought   :\n{new_state['agent_a_cot']}")
        _log("honeypot", f"🖥  Terminal  :\n{new_state['latest_terminal_output']}")
        _log("honeypot", f"📈 Message history now: {len(new_state['messages'])} msgs (growing unbounded)")
        _log("honeypot", "◀ Node complete — handing off to analyst.")

    else:
        # ─── FAILURE PATH ─────────────────────────────────────────────────────
        new_state["first_try_format_valid"] = False
        next_retry                          = retry_count + 1
        new_state["honeypot_retry_count"]   = next_retry
        _log("honeypot", f"❌ JSON parse FAILED on attempt {retry_count + 1}. Full raw:\n{raw_response}")

        if next_retry >= MAX_HONEYPOT_RETRIES:
            fallback_output = "bash: syntax error near unexpected token"
            _log("honeypot", f"🚨 Max retries ({MAX_HONEYPOT_RETRIES}) exhausted. Injecting fallback terminal output.")
            new_state["latest_terminal_output"] = fallback_output
            new_state["messages"]               = list(full_history) + [
                AIMessage(content=fallback_output, name="honeypot")
            ]
            new_state["is_format_valid"]      = True  # break loop → proceed to analyst
            new_state["honeypot_retry_count"] = 0
            _log("honeypot", "🔀 is_format_valid=True (forced) — proceeding to analyst despite fallback.")
        else:
            _log("honeypot", f"🔁 Scheduling retry {next_retry}/{MAX_HONEYPOT_RETRIES} — routing back to self.")
            new_state["messages"]        = list(full_history) + [
                AIMessage(content=raw_response, name="honeypot_invalid")
            ]
            new_state["is_format_valid"] = False

    return new_state


# ---------------------------------------------------------------------------
# Node: Agent B — SOC Analyst
# ---------------------------------------------------------------------------

def agent_b_analyst(state: AgentState) -> AgentState:
    _log("analyst", "▶ Node entered. Classifying attacker command...")

    command      = state.get("latest_command", "")
    terminal_out = state.get("latest_terminal_output", "")

    _log("analyst", f"🔺 Command       :\n{command}")
    _log("analyst", f"🖥  Terminal out  :\n{terminal_out}")

    user_content = (
        f"Attacker command:\n```\n{command}\n```\n\n"
        f"Honeypot terminal response:\n```\n{terminal_out}\n```\n\n"
        f"Respond with ONLY the JSON object. No other text."
    )
    messages_to_send = [
        SystemMessage(content=ANALYST_SYSTEM),
        HumanMessage(content=user_content),
    ]

    _log("analyst", f"📤 Invoking analyst LLM ({len(messages_to_send)} msgs)...")

    t0 = time.time()
    response     = analyst_llm.invoke(messages_to_send)
    llm_latency  = time.time() - t0
    raw_response = response.content.strip()
    _log("analyst", f"📥 LLM responded in {llm_latency:.2f}s — raw:\n{raw_response}")

    parsed = _parse_with_fallback(raw_response, ["explanation", "predicted_mitre_tactic", "threat_level"], "analyst")

    valid_levels = {"Low", "Medium", "High", "Critical"}
    threat_level = parsed.get("threat_level", "Medium")
    if threat_level not in valid_levels:
        _log("analyst", f"⚠️  Invalid threat_level '{threat_level}' — defaulting to Medium.")
        threat_level = "Medium"

    new_state = dict(state)
    new_state["agent_b_explanation"]    = parsed.get("explanation", raw_response)
    new_state["predicted_mitre_tactic"] = parsed.get("predicted_mitre_tactic", "Unknown")
    new_state["threat_level"]           = threat_level

    _log("analyst", f"🏷  Threat Level    : {threat_level}")
    _log("analyst", f"🗂  Predicted Tactic: {new_state['predicted_mitre_tactic']}")
    _log("analyst", f"📝 Explanation     :\n{new_state['agent_b_explanation']}")
    _log("analyst", "◀ Node complete — handing off to increment_turn.")
    return new_state


# ---------------------------------------------------------------------------
# Node: increment_turn  (no TiDB — headless)
# ---------------------------------------------------------------------------

def increment_turn(state: AgentState) -> AgentState:
    turn = state.get("turn_count", 0)
    _log("turn", f"▶ Node entered. Current turn_count={turn}.")

    total_chars = sum(len(str(getattr(m, "content", ""))) for m in state.get("messages", []))
    _log("turn", "📊 Context GROWTH snapshot:")
    _log("turn", f"     Messages in buffer : {len(state.get('messages', []))}")
    _log("turn", f"     Total prompt chars : {total_chars:,}  ← watch this grow each turn!")
    _log("turn", f"     Threat level       : {state.get('threat_level')}")
    _log("turn", f"     Predicted tactic   : {state.get('predicted_mitre_tactic')}")
    _log("turn", f"     Illusion broken    : {state.get('illusion_broken', False)}")

    new_state = dict(state)
    new_state["turn_count"] = turn + 1
    _log("turn", f"✔ turn_count incremented: {turn} → {turn + 1}. (NO database write — headless mode)")
    _log("turn", "◀ Node complete — handing off to router.")
    return new_state


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def route_after_honeypot(state: AgentState) -> str:
    if state.get("is_format_valid", True):
        _log("router", "✅ JSON valid — routing → analyst.")
        return "agent_b_analyst"
    else:
        retry_count = state.get("honeypot_retry_count", 0)
        _log("router", f"🔁 JSON invalid — routing → honeypot (retry {retry_count}/{MAX_HONEYPOT_RETRIES}).")
        return "agent_a_honeypot"


_stop_flag: threading.Event = threading.Event()


def route_after_turn(state: AgentState) -> str:
    turn = state.get("turn_count", 0)

    if _stop_flag.is_set():
        _log("router", "⏹ External stop signal — ending session.")
        return END
    if state.get("illusion_broken", False):
        _log("router", "🚨 Illusion broken by attacker — ending session.")
        return END
    if state.get("threat_level") == "Critical":
        _log("router", f"🔥 Critical threat on turn {turn} — ending session.")
        return END
    if turn >= 25:
        _log("router", f"📊 Max turns ({turn}) reached — ending session.")
        return END

    _log("router", f"✅ Turn {turn} complete — routing → attacker for turn {turn + 1}.")
    return "agent_c_attacker"


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------

def build_graph():
    _log("session", "🔧 Building BASELINE graph (Full Context — no sliding window, no scratchpad)...")

    graph = StateGraph(AgentState)

    graph.add_node("agent_c_attacker", agent_c_attacker)
    graph.add_node("agent_a_honeypot", agent_a_honeypot)
    graph.add_node("agent_b_analyst",  agent_b_analyst)
    graph.add_node("increment_turn",   increment_turn)

    graph.set_entry_point("agent_c_attacker")

    graph.add_edge("agent_c_attacker", "agent_a_honeypot")
    graph.add_edge("agent_b_analyst",  "increment_turn")

    graph.add_conditional_edges(
        "agent_a_honeypot",
        route_after_honeypot,
        {
            "agent_a_honeypot": "agent_a_honeypot",
            "agent_b_analyst":  "agent_b_analyst",
        },
    )
    graph.add_conditional_edges(
        "increment_turn",
        route_after_turn,
        {
            "agent_c_attacker": "agent_c_attacker",
            END: END,
        },
    )

    compiled = graph.compile()
    _log("session", "✅ BASELINE graph compiled successfully.")
    return compiled


# Global compiled graph instance — imported by run_benchmark.py
app_graph = build_graph()
_log("session", "✅ graph_baseline.py loaded — app_graph ready for benchmark use.")
