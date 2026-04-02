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
  • Uses a DETERMINISTIC tactic list (14 tactics × 3, sliced to 30) so both
    runs execute the exact same sequence — a hard requirement for a valid
    apples-to-apples ablation comparison.
  • Streams each session turn-by-turn, measuring per-turn metrics.
  • Writes one CSV row per turn in append mode — crash-safe by design.
  • Catches any exception mid-session (OOM, context overflow, API timeout)
    and records "CRASH: <ExceptionType>" before moving to the next session.

Output CSV headers (academic schema v2)
---------------------------------------
  Setup_Type, Session_ID, Tactic, Turn_Number, Turn_Latency_Sec,
  Context_Message_Count, Prompt_Char_Count, Successful_Parse_Attempt,
  Fallback_Triggered, Attacker_Caught_Honeypot, Analyst_Threat_Level,
  Termination_Reason

DO NOT modify app.py, graph.py, or database.py.
"""

import argparse
import csv
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
    parser.add_argument(
        "--start-index",
        type=int,
        default=0,
        metavar="N",
        help=(
            "0-based session index to resume from (default: 0 = start from the beginning). "
            "Example: --start-index 10 skips sessions 1-10 and resumes at session 11."
        ),
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
    "Successful_Parse_Attempt",  # honeypot_retry_count + 1  (1 = first try, 2 = had a retry …)
    "Fallback_Triggered",        # True if the failsafe forced a format recovery
    "Attacker_Caught_Honeypot",  # True if illusion_broken is True
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
    Exact token proxy: sum of all character lengths of message content.
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


def _get_successful_parse_attempt(state: dict) -> int:
    """
    Parse-attempt ordinal for the honeypot node.
    0 retries → Attempt 1 (succeeded on the first try).
    1 retry   → Attempt 2 (failsafe fired once), etc.
    """
    return state.get("honeypot_retry_count", 0) + 1


def _get_fallback_triggered(state: dict) -> bool:
    """
    True when the self-healing failsafe was actually exercised:
    the graph retried (retry_count > 0) AND ultimately produced a valid
    format (is_format_valid is True — meaning the fallback forced it through).
    """
    retried      = state.get("honeypot_retry_count", 0) > 0
    forced_valid = state.get("is_format_valid", False) is True
    return retried and forced_valid


def _get_attacker_caught_honeypot(state: dict) -> bool:
    """True when the attacker has broken the illusion (honeypot detected)."""
    return state.get("illusion_broken", False) is True


def _determine_termination(state: dict, turn: int, max_turns: int = 25,
                           ongoing: bool = False) -> str:
    """Derive a human-readable termination reason from the final state."""
    if ongoing:
        return ""   # intermediate row — session is still running
    if state.get("illusion_broken", False):
        return "Illusion Broken"
    if state.get("threat_level") == "Critical":
        return "Critical Threat"
    if turn >= max_turns:
        return "Max Turns"
    return ""   # fallback: session still ongoing


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
            "current_user":      "www-data",
            "pwd":               "/var/www/html",
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
    current_turn               = 0   # tracked outside stream so crash handler knows where it died

    try:
        _log("runner", "▶ Starting app_graph.stream() ...")

        for event in app_graph.stream(
            initial_state,
            config={"recursion_limit": 150, "timeout": 250},
        ):
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
                turn_latency      = time.time() - turn_start_time
                ctx_count         = _get_context_message_count(node_state)
                char_count        = _get_prompt_char_count(node_state)
                parse_attempt     = _get_successful_parse_attempt(node_state)
                fallback          = _get_fallback_triggered(node_state)
                caught_honeypot   = _get_attacker_caught_honeypot(node_state)
                threat_level      = node_state.get("threat_level", "Unknown")
                # Termination_Reason is blank for non-final turns (ongoing=True)
                term_reason       = _determine_termination(node_state, current_turn, ongoing=True)

                row = {
                    "Setup_Type":               setup_type,
                    "Session_ID":               session_id,
                    "Tactic":                   tactic,
                    "Turn_Number":              current_turn,       # turn BEFORE increment
                    "Turn_Latency_Sec":         round(turn_latency, 4),
                    "Context_Message_Count":    ctx_count,
                    "Prompt_Char_Count":        char_count,
                    "Successful_Parse_Attempt": parse_attempt,
                    "Fallback_Triggered":        fallback,
                    "Attacker_Caught_Honeypot": caught_honeypot,
                    "Analyst_Threat_Level":     threat_level,
                    "Termination_Reason":       term_reason,
                }
                csv_writer.writerow(row)
                csv_file.flush()   # ensure partial data persists even if baseline crashes

                _log("csv", (
                    f"✍ Row written → Turn={current_turn} | "
                    f"Latency={turn_latency:.2f}s | "
                    f"MsgCount={ctx_count} | "
                    f"Chars={char_count:,} | "
                    f"ParseAttempt={parse_attempt} | "
                    f"Fallback={fallback} | "
                    f"CaughtHP={caught_honeypot} | "
                    f"Threat={threat_level}"
                ))

                # Reset per-turn accumulators
                honeypot_retries_this_turn = 0
                turn_start_time            = time.time()
                last_turn_written          = current_turn

            # ── Detect early exits (illusion broken before increment_turn) ────
            if node_state.get("illusion_broken", False) and node_name != "increment_turn":
                _log("runner", "🚨 Illusion broken detected mid-stream — writing final row.")
                turn_latency    = time.time() - turn_start_time
                ctx_count       = _get_context_message_count(node_state)
                char_count      = _get_prompt_char_count(node_state)
                parse_attempt   = _get_successful_parse_attempt(node_state)
                fallback        = _get_fallback_triggered(node_state)

                row = {
                    "Setup_Type":               setup_type,
                    "Session_ID":               session_id,
                    "Tactic":                   tactic,
                    "Turn_Number":              current_turn,
                    "Turn_Latency_Sec":         round(turn_latency, 4),
                    "Context_Message_Count":    ctx_count,
                    "Prompt_Char_Count":        char_count,
                    "Successful_Parse_Attempt": parse_attempt,
                    "Fallback_Triggered":        fallback,
                    "Attacker_Caught_Honeypot": True,   # illusion_broken is confirmed True here
                    "Analyst_Threat_Level":     node_state.get("threat_level", "Unknown"),
                    "Termination_Reason":       "Illusion Broken",
                }
                csv_writer.writerow(row)
                csv_file.flush()
                _log("csv", f"✍ Final row written (Illusion Broken) → Turn={current_turn}")

        _log("runner", f"✅ Session {session_id} complete. Last turn written: {last_turn_written}.")

    except MemoryError as e:
        _handle_crash(csv_writer, csv_file, setup_type, session_id, tactic,
                      last_state, e, "MemoryError", current_turn)

    except Exception as e:
        exc_type = type(e).__name__
        _handle_crash(csv_writer, csv_file, setup_type, session_id, tactic,
                      last_state, e, exc_type, current_turn)


def _handle_crash(
    csv_writer, csv_file,
    setup_type: str, session_id: str, tactic: str,
    last_state: dict, exc: Exception, exc_type: str,
    crash_turn: int = -1,
) -> None:
    """Write a CRASH row to CSV and log the full traceback, then return safely."""
    _log("crash", f"💥 EXCEPTION in session {session_id} at turn {crash_turn}: {exc_type} — {exc}")
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
        "Setup_Type":               setup_type,
        "Session_ID":               session_id,
        "Tactic":                   tactic,
        "Turn_Number":              turn_num,
        "Turn_Latency_Sec":         -1,
        "Context_Message_Count":    ctx_count,
        "Prompt_Char_Count":        char_count,
        "Successful_Parse_Attempt": -1,   # unknown at crash time
        "Fallback_Triggered":        False,
        "Attacker_Caught_Honeypot": False,
        "Analyst_Threat_Level":     threat,
        "Termination_Reason":       f"CRASH@turn{crash_turn}: {exc_type}",
    }
    csv_writer.writerow(row)
    csv_file.flush()
    _log("crash", f"✍ CRASH row written for session {session_id}. Continuing to next session...")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    mode           = args.mode
    total_sessions = args.sessions
    start_idx      = args.start_index

    # ── Mode-conditional graph import ────────────────────────────────────────
    _banner(f"DAXD Ablation Study | Mode: {mode.upper()} | Sessions: {total_sessions}")
    _log("init", f"Importing graph for mode='{mode}'...")

    if mode == "hybrid":
        _log("init", "Loading graph_hybrid.app_graph ...")
        import graph_hybrid
        app_graph  = graph_hybrid.app_graph
        output_csv = "benchmark_hybrid.csv"
        setup_type = "hybrid"
        _log("init", "✅ graph_hybrid loaded. Output → benchmark_hybrid.csv")
    else:
        _log("init", "Loading graph_baseline.app_graph ...")
        import graph_baseline
        app_graph  = graph_baseline.app_graph
        output_csv = "benchmark_baseline.csv"
        setup_type = "baseline"
        _log("init", "✅ graph_baseline loaded. Output → benchmark_baseline.csv")

    # ── Session List: DETERMINISTIC tactic sequence (no randomness) ─────────
    # Mathematically repeat the 14-tactic list and slice to the exact number
    # of sessions required.  Both hybrid and baseline runs will traverse the
    # identical sequence, guaranteeing a valid apples-to-apples comparison.
    test_suite_tactics = (MITRE_TACTICS * ((total_sessions // len(MITRE_TACTICS)) + 1))[:total_sessions]

    sessions = []
    for i, tactic in enumerate(test_suite_tactics):
        session_id = f"{setup_type[:3].upper()}-{i+1:03d}-{uuid.uuid4().hex[:6].upper()}"
        sessions.append((session_id, tactic))

    _log("init", f"Generated {total_sessions} sessions using deterministic tactic slice (no randomness).")
    if start_idx > 0:
        _banner(f"RESUMING FROM SESSION {start_idx + 1}/{total_sessions} | Mode: {mode.upper()}")
        _log("init", f"⏭  Skipping sessions 1–{start_idx} (already completed). Resuming at session {start_idx + 1}.")
    _log("init", "Session plan (first 10 shown from start index):")
    for idx in range(start_idx, min(start_idx + 10, total_sessions)):
        sid, tac = sessions[idx]
        _log("init", f"  [{idx+1:02d}] Session {sid} → {tac}")
    remaining_count = total_sessions - start_idx
    if remaining_count > 10:
        _log("init", f"  ... and {remaining_count - 10} more.")

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
        _log("runner", f"🚀 Starting benchmark — mode={setup_type} | total={total_sessions} | running={total_sessions - start_idx} sessions")
        print("", flush=True)

        for i in range(start_idx, total_sessions):
            session_id, tactic = sessions[i]
            session_num        = i + 1          # 1-based, always canonical
            session_wall_start = time.time()

            # ── Per-session log file setup ────────────────────────────────────
            os.makedirs("session_logs", exist_ok=True)
            safe_tactic   = tactic.replace(" ", "_")
            log_filename  = os.path.join("session_logs", f"{mode}_{safe_tactic}_{session_id}.txt")

            # Write the session header to a fresh file
            with open(log_filename, "w", encoding="utf-8") as _lf:
                _lf.write(
                    f"=== DAXD SESSION LOG ===\n"
                    f"MODE: {mode.upper()}\n"
                    f"TACTIC: {tactic}\n"
                    f"SESSION ID: {session_id}\n"
                    f"========================\n\n"
                )

            # Point the active graph module at this session’s log file
            if mode == "hybrid":
                graph_hybrid.CURRENT_LOG_FILE = log_filename
            else:
                graph_baseline.CURRENT_LOG_FILE = log_filename

            _log("runner", f"📝 Session log file: {os.path.abspath(log_filename)}")

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
