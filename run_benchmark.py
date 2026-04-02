"""
run_benchmark.py — DAXD Ablation Study: Headless Benchmark Runner
==================================================================
Usage
-----
  python run_benchmark.py --mode hybrid   [--sessions 30]
  python run_benchmark.py --mode baseline [--sessions 30]

What it does
------------
  • Loads the appropriate compiled LangGraph (hybrid or baseline).
  • Cycles through 14 MITRE tactics to generate N sessions (default 30).
  • Streams each session turn-by-turn, measuring per-turn metrics.
  • Writes one CSV row per turn in append mode — crash-safe by design.
  • Catches any exception mid-session (OOM, context overflow, API timeout)
    and records "CRASH: <ExceptionType>" before moving to the next session.

Output CSV headers
------------------
  Setup_Type, Session_ID, Tactic, Turn_Number, Turn_Latency_Sec,
  Context_Message_Count, Prompt_Char_Count, Honeypot_Retries,
  Analyst_Threat_Level, Termination_Reason

DO NOT modify app.py, graph.py, or database.py.
"""

import argparse
import csv
import itertools
import os
import sys
import time
import traceback
import uuid

# ---------------------------------------------------------------------------
# CLI Argument Parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="DAXD Ablation Study — Headless Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_benchmark.py --mode hybrid
  python run_benchmark.py --mode baseline --sessions 5
        """
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["hybrid", "baseline"],
        help="Which graph to benchmark: 'hybrid' (Sliding Window + Scratchpad) or 'baseline' (full context).",
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=30,
        help="Total number of sessions to run (default: 30, cycling through 14 MITRE tactics).",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Logger (timestamped, role-prefixed)
# ---------------------------------------------------------------------------

def _log(role: str, msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [BENCHMARK:{role.upper()}] {msg}", flush=True)


def _banner(msg: str) -> None:
    line = "═" * 65
    print(f"\n{line}\n  {msg}\n{line}", flush=True)


def _section(msg: str) -> None:
    line = "─" * 65
    print(f"\n{line}\n  {msg}\n{line}", flush=True)


# ---------------------------------------------------------------------------
# MITRE Tactics Suite (14 canonical ATT&CK tactics)
# ---------------------------------------------------------------------------

MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

CSV_HEADERS = [
    "Setup_Type",
    "Session_ID",
    "Tactic",
    "Turn_Number",
    "Turn_Latency_Sec",
    "Context_Message_Count",
    "Prompt_Char_Count",
    "Honeypot_Retries",
    "Analyst_Threat_Level",
    "Termination_Reason",
]


# ---------------------------------------------------------------------------
# Metric Extraction Helpers
# ---------------------------------------------------------------------------

def _get_context_message_count(state: dict) -> int:
    """Total number of LangChain messages currently in the state buffer."""
    return len(state.get("messages", []))


def _get_prompt_char_count(state: dict) -> int:
    """
    Proxy for token count: sum of all character lengths of message content.
    Works on both LangChain message objects (have .content) and plain dicts.
    """
    total = 0
    for m in state.get("messages", []):
        if hasattr(m, "content"):
            total += len(str(m.content))
        elif isinstance(m, dict):
            total += len(str(m.get("content", "")))
        else:
            total += len(str(m))
    return total


def _determine_termination(state: dict, turn: int, max_turns: int = 25) -> str:
    """Derive a human-readable termination reason from the final state."""
    if state.get("illusion_broken", False):
        return "Illusion Broken"
    if state.get("threat_level") == "Critical":
        return "Critical Threat"
    if turn >= max_turns:
        return "Max Turns"
    return ""   # session still ongoing (written per-turn, so this row is intermediate)


# ---------------------------------------------------------------------------
# Initial State Factory
# ---------------------------------------------------------------------------

def _make_initial_state(session_id: str, tactic: str, mode: str) -> dict:
    """Build the AgentState dict that seeds the graph for a new session."""
    base = {
        "session_id":             session_id,
        "turn_count":             0,
        "target_mitre_tactic":    tactic,
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
        "honeypot_retry_count":   0,
    }
    if mode == "hybrid":
        # Hybrid mode seeds the machine_state scratchpad
        base["machine_state"] = {
            "current_user":      "attacker",
            "pwd":               "~",
            "dropped_files":     [],
            "running_processes": [],
        }
    # Baseline mode has no machine_state key (TypedDict omits it)
    return base


# ---------------------------------------------------------------------------
# Single-Session Runner
# ---------------------------------------------------------------------------

def run_single_session(
    app_graph,
    session_id: str,
    tactic: str,
    setup_type: str,
    csv_writer,
    csv_file,
    session_num: int,
    total_sessions: int,
) -> None:
    """
    Stream one full session through the graph, writing a CSV row after every turn.
    On any exception, write a CRASH row and return gracefully.
    """
    _section(f"SESSION {session_num}/{total_sessions} | ID: {session_id} | Tactic: {tactic} | Mode: {setup_type.upper()}")

    initial_state = _make_initial_state(session_id, tactic, setup_type)
    _log("runner", f"Initial state seeded.  mode={setup_type}, tactic={tactic}, session={session_id}")

    # Per-session tracking
    honeypot_retries_this_turn = 0   # accumulated across retry loops within a turn
    last_turn_written          = -1  # detect when a NEW turn has started
    turn_start_time            = time.time()
    last_state                 = initial_state

    try:
        _log("runner", "▶ Starting app_graph.stream() ...")

        for event in app_graph.stream(initial_state, {"recursion_limit": 200}):
            node_name  = list(event.keys())[0]
            node_state = event[node_name]
            last_state = node_state

            current_turn = node_state.get("turn_count", 0)

            # ── Accumulate honeypot retries within the same turn ──────────────
            if node_name == "agent_a_honeypot":
                retry_val = node_state.get("honeypot_retry_count", 0)
                honeypot_retries_this_turn = max(honeypot_retries_this_turn, retry_val)
                _log("stream", f"  ↳ node={node_name} | turn={current_turn} | retry_count={retry_val}")
            else:
                _log("stream", f"  ↳ node={node_name} | turn={current_turn}")

            # ── Write a row when increment_turn fires (= end of a full turn) ──
            # increment_turn is the last node in each turn cycle, it bumps turn_count.
            # We write the row here so we capture the fully-assembled turn metrics.
            if node_name == "increment_turn":
                turn_latency = time.time() - turn_start_time
                ctx_count    = _get_context_message_count(node_state)
                char_count   = _get_prompt_char_count(node_state)
                threat_level = node_state.get("threat_level", "")
                # Termination_Reason is blank for non-final turns
                term_reason  = _determine_termination(node_state, current_turn)

                row = {
                    "Setup_Type":            setup_type,
                    "Session_ID":            session_id,
                    "Tactic":                tactic,
                    "Turn_Number":           current_turn,       # turn BEFORE increment
                    "Turn_Latency_Sec":      round(turn_latency, 4),
                    "Context_Message_Count": ctx_count,
                    "Prompt_Char_Count":     char_count,
                    "Honeypot_Retries":      honeypot_retries_this_turn,
                    "Analyst_Threat_Level":  threat_level,
                    "Termination_Reason":    term_reason,
                }
                csv_writer.writerow(row)
                csv_file.flush()   # ensure partial data persists even if baseline crashes

                _log("csv", (
                    f"✍ Row written → Turn={current_turn} | "
                    f"Latency={turn_latency:.2f}s | "
                    f"MsgCount={ctx_count} | "
                    f"Chars={char_count:,} | "
                    f"Retries={honeypot_retries_this_turn} | "
                    f"Threat={threat_level}"
                ))

                # Reset per-turn accumulators
                honeypot_retries_this_turn = 0
                turn_start_time            = time.time()
                last_turn_written          = current_turn

            # ── Detect early exits (illusion broken before increment_turn) ────
            if node_state.get("illusion_broken", False) and node_name != "increment_turn":
                _log("runner", "🚨 Illusion broken detected mid-stream — writing final row.")
                turn_latency = time.time() - turn_start_time
                ctx_count    = _get_context_message_count(node_state)
                char_count   = _get_prompt_char_count(node_state)

                row = {
                    "Setup_Type":            setup_type,
                    "Session_ID":            session_id,
                    "Tactic":                tactic,
                    "Turn_Number":           current_turn,
                    "Turn_Latency_Sec":      round(turn_latency, 4),
                    "Context_Message_Count": ctx_count,
                    "Prompt_Char_Count":     char_count,
                    "Honeypot_Retries":      honeypot_retries_this_turn,
                    "Analyst_Threat_Level":  node_state.get("threat_level", ""),
                    "Termination_Reason":    "Illusion Broken",
                }
                csv_writer.writerow(row)
                csv_file.flush()
                _log("csv", f"✍ Final row written (Illusion Broken) → Turn={current_turn}")

        _log("runner", f"✅ Session {session_id} complete. Last turn written: {last_turn_written}.")

    except MemoryError as e:
        _handle_crash(csv_writer, csv_file, setup_type, session_id, tactic,
                      last_state, e, "MemoryError")

    except Exception as e:
        exc_type = type(e).__name__
        _handle_crash(csv_writer, csv_file, setup_type, session_id, tactic,
                      last_state, e, exc_type)


def _handle_crash(
    csv_writer, csv_file,
    setup_type: str, session_id: str, tactic: str,
    last_state: dict, exc: Exception, exc_type: str,
) -> None:
    """Write a CRASH row to CSV and log the full traceback, then return safely."""
    _log("crash", f"💥 EXCEPTION in session {session_id}: {exc_type} — {exc}")
    _log("crash", "Full traceback:")
    traceback.print_exc()

    # Best-effort metric extraction from last known state
    try:
        ctx_count  = _get_context_message_count(last_state)
        char_count = _get_prompt_char_count(last_state)
        turn_num   = last_state.get("turn_count", -1)
        threat     = last_state.get("threat_level", "")
    except Exception:
        ctx_count  = -1
        char_count = -1
        turn_num   = -1
        threat     = ""

    row = {
        "Setup_Type":            setup_type,
        "Session_ID":            session_id,
        "Tactic":                tactic,
        "Turn_Number":           turn_num,
        "Turn_Latency_Sec":      -1,
        "Context_Message_Count": ctx_count,
        "Prompt_Char_Count":     char_count,
        "Honeypot_Retries":      -1,
        "Analyst_Threat_Level":  threat,
        "Termination_Reason":    f"CRASH: {exc_type}",
    }
    csv_writer.writerow(row)
    csv_file.flush()
    _log("crash", f"✍ CRASH row written for session {session_id}. Continuing to next session...")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    mode          = args.mode
    total_sessions = args.sessions

    # ── Mode-conditional graph import ────────────────────────────────────────
    _banner(f"DAXD Ablation Study | Mode: {mode.upper()} | Sessions: {total_sessions}")
    _log("init", f"Importing graph for mode='{mode}'...")

    if mode == "hybrid":
        _log("init", "Loading graph_hybrid.app_graph ...")
        from graph_hybrid import app_graph
        output_csv = "benchmark_hybrid.csv"
        setup_type = "hybrid"
        _log("init", "✅ graph_hybrid loaded. Output → benchmark_hybrid.csv")
    else:
        _log("init", "Loading graph_baseline.app_graph ...")
        from graph_baseline import app_graph
        output_csv = "benchmark_baseline.csv"
        setup_type = "baseline"
        _log("init", "✅ graph_baseline loaded. Output → benchmark_baseline.csv")

    # ── Session List: cycle through MITRE tactics ────────────────────────────
    tactic_cycle = itertools.cycle(MITRE_TACTICS)
    sessions = []
    for i in range(total_sessions):
        tactic     = next(tactic_cycle)
        session_id = f"{setup_type[:3].upper()}-{i+1:03d}-{uuid.uuid4().hex[:6].upper()}"
        sessions.append((session_id, tactic))

    _log("init", f"Generated {total_sessions} sessions cycling over {len(MITRE_TACTICS)} MITRE tactics.")
    _log("init", "Session plan (first 10 shown):")
    for idx, (sid, tac) in enumerate(sessions[:10]):
        _log("init", f"  [{idx+1:02d}] Session {sid} → {tac}")
    if total_sessions > 10:
        _log("init", f"  ... and {total_sessions - 10} more.")

    # ── CSV Setup (append mode — safe to resume after crash) ────────────────────
    file_exists  = os.path.isfile(output_csv)
    _log("csv", f"Opening output file: {output_csv}  (append mode={'resume' if file_exists else 'new file'})")

    with open(output_csv, mode="a", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)

        # Write headers only if creating a new file
        if not file_exists or os.path.getsize(output_csv) == 0:
            csv_writer.writeheader()
            _log("csv", f"✍ Headers written to {output_csv}")
        else:
            _log("csv", f"ℹ️  Appending to existing {output_csv} — skipping header row.")

        # ── Main Session Loop ────────────────────────────────────────────────
        benchmark_start = time.time()
        _log("runner", f"🚀 Starting benchmark — {total_sessions} sessions | mode={setup_type}")
        print("", flush=True)

        for session_num, (session_id, tactic) in enumerate(sessions, start=1):
            session_wall_start = time.time()

            run_single_session(
                app_graph      = app_graph,
                session_id     = session_id,
                tactic         = tactic,
                setup_type     = setup_type,
                csv_writer     = csv_writer,
                csv_file       = csv_file,
                session_num    = session_num,
                total_sessions = total_sessions,
            )

            elapsed_session = time.time() - session_wall_start
            elapsed_total   = time.time() - benchmark_start
            remaining       = total_sessions - session_num

            _log("progress", (
                f"✅ Session {session_num}/{total_sessions} done in {elapsed_session:.1f}s | "
                f"Elapsed total: {elapsed_total:.1f}s | "
                f"Remaining: {remaining} sessions"
            ))
            print("", flush=True)

        # ── Final Summary ────────────────────────────────────────────────────
        total_elapsed = time.time() - benchmark_start
        _banner(f"BENCHMARK COMPLETE | Mode: {setup_type.upper()}")
        _log("summary", f"Total sessions   : {total_sessions}")
        _log("summary", f"Total wall time  : {total_elapsed:.1f}s  ({total_elapsed/60:.1f} min)")
        _log("summary", f"Average per session: {total_elapsed/total_sessions:.1f}s")
        _log("summary", f"Results saved to : {os.path.abspath(output_csv)}")
        _log("summary", "📊 Open the CSV to analyse latency, context growth, and crash rates.")


if __name__ == "__main__":
    main()
