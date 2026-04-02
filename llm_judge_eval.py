"""
DAXD — LLM-as-a-Judge Evaluation
==================================
Scores SOC Analyst explanation quality across Hybrid vs Baseline architectures.

Run from the project root (same directory as run_benchmark.py):
  python llm_judge_eval.py

First-time setup (one-off):
  pip install requests pandas scipy

Arguments (all optional — defaults match the project layout):
  --hybrid_logs   session_logs/hybrid       (dir with hybrid .txt logs)
  --baseline_logs session_logs/baseline     (dir with baseline .txt logs)
  --judge_url     https://0c50-34-158-65-34.ngrok-free.app
  --judge_model   mistral-nemo
  --sample        100                       (rows sampled per architecture)
  --seed          42
  --out_dir       judge_results             (output CSVs + log written here)
  --timeout       120                       (per-API-call timeout in seconds)
  --max_retries   2

Outputs (written to --out_dir):
  judge_run_YYYYMMDD_HHMMSS.txt   — full execution log (mirrors console)
  judge_raw_results_*.csv         — all 200 scored rows
  judge_hybrid_*.csv              — hybrid subset
  judge_baseline_*.csv            — baseline subset
  judge_statistics_*.csv          — means, SDs, T-stat, U-stat, p-values
"""

import argparse
import json
import os
import random
import re
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Dependency check (nice error before cryptic ImportError) ──────────────────
_MISSING = []
try:   import pandas as pd
except ImportError: _MISSING.append("pandas")
try:   from scipy import stats
except ImportError: _MISSING.append("scipy")
try:   import langchain_ollama
except ImportError: _MISSING.append("langchain_ollama")
try:   import langchain_core
except ImportError: _MISSING.append("langchain_core")

if _MISSING:
    print(f"[ERROR] Missing dependencies: {', '.join(_MISSING)}")
    print(f"        Run:  pip install {' '.join(_MISSING)}")
    sys.exit(1)

from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama
from llm_config import extract_json


# ── CLI ────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="DAXD LLM-as-a-Judge: score Analyst explanations via Ollama.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python llm_judge_eval.py
  python llm_judge_eval.py --sample 50 --seed 7
  python llm_judge_eval.py --judge_url https://YOUR-NGROK-URL.ngrok-free.app
""",
    )
    p.add_argument("--hybrid_logs",   default="session_logs/hybrid",
                   help="Directory containing hybrid .txt session logs")
    p.add_argument("--baseline_logs", default="session_logs/baseline",
                   help="Directory containing baseline .txt session logs")
    p.add_argument("--judge_url",
                   default="https://0c50-34-158-65-34.ngrok-free.app",
                   help="Base URL of the remote Ollama judge instance")
    p.add_argument("--judge_model",   default="mistral-nemo",
                   help="Ollama model name to use for judging (default: mistral-nemo)")
    p.add_argument("--sample",        type=int, default=100,
                   help="Rows to sample per architecture (default: 100)")
    p.add_argument("--seed",          type=int, default=42,
                   help="Random seed for reproducibility (default: 42)")
    p.add_argument("--out_dir",       default="judge_results",
                   help="Output directory for CSVs and log (default: judge_results)")
    p.add_argument("--timeout",       type=int, default=120,
                   help="Per-request timeout in seconds (default: 120)")
    p.add_argument("--max_retries",   type=int, default=2,
                   help="Max retries per failed API call (default: 2)")
    p.add_argument("--retry_delay",   type=float, default=3.0,
                   help="Seconds to wait between retries (default: 3.0)")
    return p.parse_args()


# ── Dual logger — console + .txt file ─────────────────────────────────────────
_LOG_FH = None   # global file handle, opened once in main()

def _open_log(out_dir: str) -> str:
    global _LOG_FH
    os.makedirs(out_dir, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"judge_run_{ts}.txt")
    _LOG_FH = open(path, "w", encoding="utf-8")
    return path

def log(msg: str, level: str = "INFO") -> None:
    ts   = time.strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line, flush=True)
    if _LOG_FH and not _LOG_FH.closed:
        _LOG_FH.write(line + "\n")
        _LOG_FH.flush()

def log_banner(title: str) -> None:
    bar  = "═" * 65
    text = f"\n{bar}\n  {title}\n{bar}"
    print(text, flush=True)
    if _LOG_FH and not _LOG_FH.closed:
        _LOG_FH.write(text + "\n")
        _LOG_FH.flush()

def log_section(title: str) -> None:
    bar  = "─" * 65
    text = f"\n{bar}\n  {title}\n{bar}"
    print(text, flush=True)
    if _LOG_FH and not _LOG_FH.closed:
        _LOG_FH.write(text + "\n")
        _LOG_FH.flush()


# ── Session-log parser ─────────────────────────────────────────────────────────
#
# Each .txt file produced by the benchmark has timestamped lines:
#   [HH:MM:SS] 🔴 [HYBRID] ATTACKER | ▶ Node entered. Turn=0, Tactic=...
#   [HH:MM:SS] 🔴 [HYBRID] ATTACKER | ✔ Command registered: `whoami`
#   [HH:MM:SS] 🟢 [HYBRID] HONEYPOT | 🖥  Terminal  :
#   www-data
#   [HH:MM:SS] 🔍 [HYBRID] ANALYST  | 📝 Explanation   :
#   The attacker is ...
#
# Baseline logs use 🟡 for HONEYPOT and slightly different spacing.
# The parser handles both with a single state-machine pass.

_TS_PAT  = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]")   # detects log-line starts


def _extract_body(line: str) -> str:
    """Strip the '[HH:MM:SS] emoji [MODE] ROLE | ' prefix, return body text."""
    idx = line.find(" | ")
    return line[idx + 3:].strip() if idx != -1 else line.strip()


def parse_session_log(filepath: str) -> list[dict]:
    """
    Parse one session .txt file into a list of per-turn dicts:
        { session_id, tactic, mode, turn, command, terminal, explanation }
    Only turns where all three fields are non-empty are returned.
    """
    records: list[dict] = []

    with open(filepath, encoding="utf-8", errors="replace") as fh:
        lines = [ln.rstrip("\r\n") for ln in fh]

    # ── Read file header (first 10 lines) ─────────────────────────────────
    session_id = tactic = mode = "UNKNOWN"
    for ln in lines[:10]:
        if ln.startswith("MODE:"):        mode       = ln.split(":", 1)[1].strip().lower()
        elif ln.startswith("TACTIC:"):    tactic     = ln.split(":", 1)[1].strip()
        elif ln.startswith("SESSION ID:"): session_id = ln.split(":", 1)[1].strip()

    # ── Per-turn accumulators ──────────────────────────────────────────────
    cur_turn    : int           = 0
    cur_cmd     : Optional[str] = None
    cur_term    : Optional[str] = None
    cur_expl    : Optional[str] = None
    capturing   : Optional[str] = None   # "terminal" | "explanation" | None
    cap_buf     : list[str]     = []

    def _flush():
        nonlocal capturing, cap_buf, cur_term, cur_expl
        val = "\n".join(cap_buf).strip()
        if capturing == "terminal":    cur_term = val
        elif capturing == "explanation": cur_expl = val
        capturing = None
        cap_buf   = []

    def _emit():
        if cur_cmd is not None and cur_term is not None and cur_expl is not None:
            records.append({
                "session_id":  session_id,
                "tactic":      tactic,
                "mode":        mode,
                "turn":        cur_turn,
                "command":     cur_cmd,
                "terminal":    cur_term,
                "explanation": cur_expl,
            })

    for ln in lines:
        is_log = bool(_TS_PAT.match(ln))

        # Flush any active multi-line block when a new log line starts
        if capturing and is_log:
            _flush()

        if is_log:
            body = _extract_body(ln)

            # ── New attacker turn (resets accumulators) ────────────────
            m = re.search(r"▶ Node entered\. Turn=(\d+)", body)
            if m and "ATTACKER" in ln:
                new_turn = int(m.group(1)) + 1   # log is 0-based before increment
                if new_turn != cur_turn:
                    _emit()
                    cur_turn = new_turn
                    cur_cmd = cur_term = cur_expl = None

            # ── Attacker command ───────────────────────────────────────
            if "✔ Command registered:" in body:
                val = body.split("✔ Command registered:", 1)[1].strip()
                if val:
                    cur_cmd = val

            # ── Honeypot terminal output ───────────────────────────────
            if re.search(r"🖥\s+Terminal\s*:", body) and "HONEYPOT" in ln:
                inline = re.split(r"🖥\s+Terminal\s*:", body, 1)[1].strip()
                if inline:
                    cur_term  = inline
                    capturing = None
                else:
                    capturing = "terminal"
                    cap_buf   = []

            # ── Analyst explanation ────────────────────────────────────
            if re.search(r"📝 Explanation\s*:", body) and "ANALYST" in ln:
                inline = re.split(r"📝 Explanation\s*:", body, 1)[1].strip()
                if inline:
                    cur_expl  = inline
                    capturing = None
                else:
                    capturing = "explanation"
                    cap_buf   = []

        else:
            # Continuation line of a multi-line block
            if capturing is not None:
                cap_buf.append(ln)

    # EOF — flush + emit any pending turn
    if capturing:
        _flush()
    _emit()

    return records


def load_all_logs(log_dir: str, label: str) -> list[dict]:
    """Walk log_dir (recursively), parse every .txt, return all records."""
    base  = Path(log_dir)
    files = sorted(base.rglob("*.txt"))
    log(f"  [{label}] {len(files)} log files found in {log_dir}")
    all_rec: list[dict] = []
    for fp in files:
        try:
            recs = parse_session_log(str(fp))
            all_rec.extend(recs)
            log(f"    ✔ {fp.name}: {len(recs)} turns")
        except Exception as exc:
            log(f"    ✘ {fp.name}: {exc}", "WARN")
    log(f"  [{label}] Total turns collected: {len(all_rec)}")
    return all_rec


# ── Judge prompt & API call ───────────────────────────────────────────────────
_JUDGE_PROMPT = """\
You are a strict, impartial cybersecurity evaluation expert assessing the quality \
of a SOC Analyst's written explanation.

You will receive:
  1. ATTACKER_COMMAND   — the exact command the attacker executed.
  2. TERMINAL_OUTPUT    — the exact terminal response the analyst could see.
  3. ANALYST_EXPLANATION — the analyst's written interpretation.

Score on TWO dimensions using integers 1–5.

Accuracy (1–5)
  5 = Perfectly identifies attacker intent and technique from the evidence.
  4 = Mostly correct; minor omission or imprecision.
  3 = Partially correct; some aspects misidentified.
  2 = Mostly incorrect or vague, but not entirely wrong.
  1 = Completely wrong or unrelated to the evidence.

Groundedness (1–5)
  5 = Every claim directly supported by command/terminal. No hallucination.
  4 = Mostly grounded; one minor unsupported inference.
  3 = Some unsupported claims, but not critically wrong.
  2 = Several invented or unsupported claims.
  1 = Heavily hallucinates facts absent from the evidence.

--- INPUT ---
ATTACKER_COMMAND:
{command}

TERMINAL_OUTPUT:
{terminal}

ANALYST_EXPLANATION:
{explanation}

--- OUTPUT ---
Respond with ONLY a valid JSON object on a single line. Nothing else. Example:
{{"Accuracy": 4, "Groundedness": 5}}
"""


def call_judge(
    command: str,
    terminal: str,
    explanation: str,
    judge_url: str,
    judge_model: str,
    timeout: int,
    max_retries: int,
    retry_delay: float,
) -> Optional[dict]:
    """
    Invokes the ChatOllama model using LangChain.
    Returns {"Accuracy": int, "Groundedness": int} or None on failure.
    """
    prompt   = _JUDGE_PROMPT.format(
        command     = command.strip(),
        terminal    = terminal.strip() if terminal else "(empty — no terminal output)",
        explanation = explanation.strip(),
    )
    
    # Initialize the LangChain Ollama model
    llm = ChatOllama(
        model=judge_model,
        base_url=judge_url,
        temperature=0.0,
        timeout=timeout,
    )

    for attempt in range(1, max_retries + 2):   # e.g. max_retries=2 → 3 total attempts
        try:
            # Invoke the graph/model
            response = llm.invoke([HumanMessage(content=prompt)])
            raw = response.content.strip()

            # Use the robust JSON extractor block from llm_config
            scores = extract_json(raw)
            if not scores:
                raise ValueError(f"No valid JSON found in response: {raw[:300]!r}")

            acc = int(scores.get("Accuracy",     scores.get("accuracy",     0)))
            gnd = int(scores.get("Groundedness", scores.get("groundedness", 0)))

            if not (1 <= acc <= 5 and 1 <= gnd <= 5):
                raise ValueError(f"Out-of-range scores: Accuracy={acc}, Groundedness={gnd}")

            return {"Accuracy": acc, "Groundedness": gnd}

        except Exception as exc:
            if attempt <= max_retries:
                log(f"    ⚠ Attempt {attempt}/{max_retries+1} failed — {exc}. "
                    f"Retrying in {retry_delay}s...", "WARN")
                time.sleep(retry_delay)
            else:
                log(f"    ✘ All {max_retries+1} attempts failed — {exc}", "ERROR")
                return None


# ── Statistical analysis ───────────────────────────────────────────────────────
def run_statistics(h_df: "pd.DataFrame", b_df: "pd.DataFrame") -> dict:
    """Mann-Whitney U (non-parametric) + Welch T-Test for Accuracy & Groundedness."""
    out = {}
    for metric in ["Accuracy", "Groundedness"]:
        h  = h_df[metric].dropna()
        b  = b_df[metric].dropna()
        t_stat, t_p = stats.ttest_ind(h, b, equal_var=False)
        u_stat, u_p = stats.mannwhitneyu(h, b, alternative="two-sided")
        out[metric] = {
            "hybrid_mean":   round(float(h.mean()), 4),
            "baseline_mean": round(float(b.mean()), 4),
            "hybrid_std":    round(float(h.std()),  4),
            "baseline_std":  round(float(b.std()),  4),
            "hybrid_n":      int(len(h)),
            "baseline_n":    int(len(b)),
            "delta":         round(float(h.mean() - b.mean()), 4),
            "t_stat":        round(float(t_stat), 4),
            "t_pvalue":      round(float(t_p),    6),
            "u_stat":        round(float(u_stat),  2),
            "u_pvalue":      round(float(u_p),    6),
            "significant_t": bool(t_p < 0.05),
            "significant_u": bool(u_p < 0.05),
        }
    return out


def print_stats(results: dict) -> None:
    log_section("STATISTICAL RESULTS")
    for metric, r in results.items():
        sig_t = "✅ SIGNIFICANT (p<0.05)" if r["significant_t"] else "❌ not significant"
        sig_u = "✅ SIGNIFICANT (p<0.05)" if r["significant_u"] else "❌ not significant"
        log(f"\n── {metric} {'─'*(50-len(metric))}──")
        log(f"  Hybrid   : mean={r['hybrid_mean']:.3f}  sd={r['hybrid_std']:.3f}  n={r['hybrid_n']}")
        log(f"  Baseline : mean={r['baseline_mean']:.3f}  sd={r['baseline_std']:.3f}  n={r['baseline_n']}")
        log(f"  Δ (Hybrid − Baseline) = {r['delta']:+.3f}")
        log(f"  Welch T-Test : t={r['t_stat']:.4f}, p={r['t_pvalue']:.6f}  → {sig_t}")
        log(f"  Mann-Whitney : U={r['u_stat']:.0f},  p={r['u_pvalue']:.6f}  → {sig_u}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    random.seed(args.seed)

    log_path = _open_log(args.out_dir)
    ts_tag   = datetime.now().strftime("%Y%m%d_%H%M%S")

    log_banner(f"DAXD LLM-as-a-Judge Evaluation  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Execution log  → {os.path.abspath(log_path)}")
    log(f"Hybrid logs    → {os.path.abspath(args.hybrid_logs)}")
    log(f"Baseline logs  → {os.path.abspath(args.baseline_logs)}")
    log(f"Judge endpoint → {args.judge_url}")
    log(f"Judge model    → {args.judge_model}")
    log(f"Sample / arch  → {args.sample}")
    log(f"Random seed    → {args.seed}")
    log(f"Output dir     → {os.path.abspath(args.out_dir)}")

    # ── 1. Parse all logs ──────────────────────────────────────────────────
    log_section("STEP 1 — Parsing Session Logs")
    hybrid_all   = load_all_logs(args.hybrid_logs,   "HYBRID")
    baseline_all = load_all_logs(args.baseline_logs, "BASELINE")

    # Keep only rows with a non-empty explanation
    hybrid_ok   = [r for r in hybrid_all   if r["explanation"].strip()]
    baseline_ok = [r for r in baseline_all if r["explanation"].strip()]

    log(f"\n  Eligible after filtering empty explanations:")
    log(f"  Hybrid   : {len(hybrid_ok)} / {len(hybrid_all)}")
    log(f"  Baseline : {len(baseline_ok)} / {len(baseline_all)}")

    if len(hybrid_ok) == 0 or len(baseline_ok) == 0:
        log("  ✘ No eligible rows found. Check log directory paths.", "ERROR")
        sys.exit(1)

    if len(hybrid_ok) < args.sample:
        log(f"  ⚠ Hybrid has only {len(hybrid_ok)} rows — sampling all.", "WARN")
    if len(baseline_ok) < args.sample:
        log(f"  ⚠ Baseline has only {len(baseline_ok)} rows — sampling all.", "WARN")

    # ── 2. Random sample ───────────────────────────────────────────────────
    hybrid_sample   = random.sample(hybrid_ok,   min(args.sample, len(hybrid_ok)))
    baseline_sample = random.sample(baseline_ok, min(args.sample, len(baseline_ok)))
    log(f"\n  Sampled → Hybrid: {len(hybrid_sample)}  |  Baseline: {len(baseline_sample)}")

    # ── 3. Judge scoring loop ──────────────────────────────────────────────
    log_section(f"STEP 2 — LLM Judge Scoring "
                f"({len(hybrid_sample) + len(baseline_sample)} API calls)")

    results_rows = []
    total = len(hybrid_sample) + len(baseline_sample)
    done  = 0

    for arch, sample in [("hybrid", hybrid_sample), ("baseline", baseline_sample)]:
        log(f"\n  ── {arch.upper()} ({len(sample)} rows) ──────────────────")
        for rec in sample:
            done += 1
            log(f"  [{done:03d}/{total}] {arch} | "
                f"session={rec['session_id']} | turn={rec['turn']} | tactic={rec['tactic']}")

            scores = call_judge(
                command     = rec["command"],
                terminal    = rec["terminal"],
                explanation = rec["explanation"],
                judge_url   = args.judge_url,
                judge_model = args.judge_model,
                timeout     = args.timeout,
                max_retries = args.max_retries,
                retry_delay = args.retry_delay,
            )

            if scores:
                log(f"    → Accuracy={scores['Accuracy']}  "
                    f"Groundedness={scores['Groundedness']}")
            else:
                scores = {"Accuracy": None, "Groundedness": None}
                log("    → SKIPPED (all retries exhausted)", "WARN")

            results_rows.append({
                "Architecture":        arch,
                "Session_ID":          rec["session_id"],
                "Tactic":              rec["tactic"],
                "Turn":                rec["turn"],
                "Command":             rec["command"],
                "Terminal_Output":     rec["terminal"],
                "Analyst_Explanation": rec["explanation"],
                "Accuracy":            scores["Accuracy"],
                "Groundedness":        scores["Groundedness"],
            })

    # ── 4. Save CSVs ───────────────────────────────────────────────────────
    log_section("STEP 3 — Saving Result CSVs")
    import pandas as pd   # already verified above

    df_all = pd.DataFrame(results_rows)

    raw_path = os.path.join(args.out_dir, f"judge_raw_results_{ts_tag}.csv")
    df_all.to_csv(raw_path, index=False, encoding="utf-8")
    log(f"  ✔ Raw results (all)  → {os.path.abspath(raw_path)}")

    for arch in ["hybrid", "baseline"]:
        sub      = df_all[df_all["Architecture"] == arch]
        sub_path = os.path.join(args.out_dir, f"judge_{arch}_{ts_tag}.csv")
        sub.to_csv(sub_path, index=False, encoding="utf-8")
        log(f"  ✔ {arch.capitalize()} results   → {os.path.abspath(sub_path)}")

    # ── 5. Statistics ──────────────────────────────────────────────────────
    log_section("STEP 4 — Statistical Analysis")

    scored    = df_all.dropna(subset=["Accuracy", "Groundedness"])
    h_scored  = scored[scored["Architecture"] == "hybrid"]
    b_scored  = scored[scored["Architecture"] == "baseline"]
    n_skipped = len(df_all) - len(scored)

    log(f"  Scored rows : hybrid={len(h_scored)}, baseline={len(b_scored)}")
    log(f"  Skipped     : {n_skipped} (judge call failures)")

    if len(h_scored) < 5 or len(b_scored) < 5:
        log("  ⚠ Too few scored rows for reliable statistics.", "WARN")
    else:
        stat_res  = run_statistics(h_scored, b_scored)
        print_stats(stat_res)

        stat_rows = [{"Metric": m, **v} for m, v in stat_res.items()]
        stat_path = os.path.join(args.out_dir, f"judge_statistics_{ts_tag}.csv")
        pd.DataFrame(stat_rows).to_csv(stat_path, index=False, encoding="utf-8")
        log(f"\n  ✔ Statistics table   → {os.path.abspath(stat_path)}")

    # ── Summary ────────────────────────────────────────────────────────────
    log_banner("EVALUATION COMPLETE")
    log(f"  Output directory → {os.path.abspath(args.out_dir)}")
    log(f"  Execution log    → {os.path.abspath(log_path)}")

    if _LOG_FH and not _LOG_FH.closed:
        _LOG_FH.close()


if __name__ == "__main__":
    main()
