"""
app.py — Streamlit XAI Dashboard for the DAXD Tri-Agent Deception System.
Native Streamlit-first design. Clean, readable, zero raw HTML injections.
"""

import os
import threading
import uuid
from datetime import datetime

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from streamlit_autorefresh import st_autorefresh

from graph import run_simulation
from database import delete_session

load_dotenv()

# ---------------------------------------------------------------------------
# Page config — MUST be first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="DAXD — Tri-Agent Deception Arena",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Database connection (read-only for dashboard)
# ---------------------------------------------------------------------------
TIDB_DATABASE_URL = os.getenv("TIDB_DATABASE_URL", "")


@st.cache_resource
def get_engine():
    return create_engine(
        TIDB_DATABASE_URL,
        pool_pre_ping=True,
        connect_args={"ssl": {"verify_cert": False, "verify_identity": False}},
    )


def fetch_logs() -> pd.DataFrame:
    try:
        with get_engine().connect() as conn:
            result = conn.execute(
                text("SELECT * FROM xai_deception_logs ORDER BY timestamp DESC LIMIT 500")
            )
            rows = result.fetchall()
            cols = result.keys()
        return pd.DataFrame(rows, columns=cols) if rows else pd.DataFrame()
    except Exception as e:
        st.sidebar.error(f"DB error: {e}")
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# Threat level helpers
# ---------------------------------------------------------------------------
THREAT_EMOJI = {
    "Low":      "🟢 Low",
    "Medium":   "🟡 Medium",
    "High":     "🔴 High",
    "Critical": "💀 Critical",
}


def threat_label(level: str) -> str:
    return THREAT_EMOJI.get(level, f"⚪ {level}")


# ---------------------------------------------------------------------------
# Auto-refresh (every 3 seconds)
# ---------------------------------------------------------------------------
st_autorefresh(interval=3000, key="daxd_refresh")

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
df = fetch_logs()

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("🕵️ DAXD — Tri-Agent Deception Arena")
st.caption(
    "Tri-Agent Explainable Cyber Deception System · LangGraph · TiDB · Ollama  |  "
    f"Last refresh: {datetime.now().strftime('%H:%M:%S')}"
)
st.divider()

# ---------------------------------------------------------------------------
# Launching banner — shown prominently in the main area while agents initialise
# ---------------------------------------------------------------------------
_is_launching = st.session_state.get("sim_launching", False)
_is_running   = st.session_state.get("sim_running", False)

if _is_launching:
    st.warning(
        "### ⏳ Initialising Simulation…\n\n"
        "Loading LLM models and establishing the session. "
        "The first turn will appear shortly — please wait.",
        icon="⏳",
    )
    st.toast("🚀 Agents are warming up — first turn coming soon!", icon="⏳")
elif _is_running:
    st.info("🟢 **Simulation is active.** The feed below updates automatically every 3 s.", icon="🟢")


with st.sidebar:
    st.header("⚙️ Control Panel")

    mitre_tactics = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    tactic = st.selectbox("🎯 Target MITRE Tactic", mitre_tactics)
    custom_tactic = st.text_input("Or enter custom tactic", placeholder="e.g. Spearphishing")
    target_tactic = custom_tactic.strip() if custom_tactic.strip() else tactic

    st.divider()

    # ── Session state init ───────────────────────────────────────────────────
    if "sim_running" not in st.session_state:
        st.session_state.sim_running = False
    if "sim_launching" not in st.session_state:
        st.session_state.sim_launching = False
    if "stop_flag" not in st.session_state:
        st.session_state.stop_flag = threading.Event()

    is_running  = st.session_state.sim_running
    is_launching = st.session_state.sim_launching

    # ── Status indicator ─────────────────────────────────────────────────────
    if is_launching:
        st.warning("⏳ Initialising agents…", icon="⏳")
    elif is_running:
        st.success("🟢 SIMULATION ACTIVE", icon="🟢")
    else:
        st.info("⚪ IDLE — Ready to launch", icon="ℹ️")

    # ── Launch button ────────────────────────────────────────────────────────
    launch_label = (
        "⏸ RUNNING..."      if is_running
        else "⏳ LAUNCHING..." if is_launching
        else "▶ LAUNCH SIMULATION"
    )
    launch_btn = st.button(
        launch_label,
        disabled=(is_running or is_launching),
        use_container_width=True,
        type="primary",
        key="launch_btn",
    )

    if launch_btn:
        session_id = str(uuid.uuid4())[:8]
        # Enter the "launching" state immediately so the UI updates
        st.session_state.sim_launching = True
        st.session_state.sim_running   = False
        # Create a fresh stop flag for this run
        stop_flag = threading.Event()
        st.session_state.stop_flag = stop_flag

        def _run(sid, tactic_name, flag):
            try:
                # Mark the transition: launching → running
                st.session_state.sim_launching = False
                st.session_state.sim_running   = True
                run_simulation(sid, tactic_name, stop_flag=flag)
            finally:
                st.session_state.sim_running   = False
                st.session_state.sim_launching = False

        thread = threading.Thread(
            target=_run,
            args=(session_id, target_tactic, stop_flag),
            daemon=True,
        )
        thread.start()
        st.rerun()

    # ── STOP button — only shown while running ───────────────────────────────
    if is_running:
        st.divider()
        stop_btn = st.button(
            "⏹ STOP SIMULATION",
            use_container_width=True,
            type="secondary",
            key="stop_btn",
            help="Signals the simulation to stop after the current turn completes. No data is lost.",
        )
        if stop_btn:
            st.session_state.stop_flag.set()   # cooperative signal to graph.py
            st.warning("⏳ Stop signal sent — finishing current turn…", icon="⏳")

    st.divider()
    st.subheader("📂 Recent Sessions")

    if not df.empty and "session_id" in df.columns:
        recent = (
            df.groupby("session_id")
            .agg(turns=("turn_count", "max"), tactic=("target_mitre_tactic", "first"))
            .reset_index()
            .head(8)
        )
        for _, row in recent.iterrows():
            sid = row["session_id"]
            col_label, col_del = st.columns([3, 1])
            with col_label:
                st.markdown(f"**`#{sid}`**")
                st.caption(f"{row['tactic']} · {int(row['turns'])} turns")
            with col_del:
                if st.button("🗑️", key=f"del_{sid}",
                             help=f"Delete all data for session #{sid}",
                             use_container_width=True):
                    deleted = delete_session(sid)
                    st.toast(f"🗑️ Session #{sid} deleted ({deleted} rows).", icon="✅")
                    st.rerun()
    else:
        st.caption("No sessions yet.")

    st.divider()
    st.subheader("ℹ️ About")
    st.caption(
        "DAXD uses three LLM agents in a closed loop:\n\n"
        "• **Agent C** (Attacker) — launches shell commands.\n\n"
        "• **Agent A** (Honeypot) — deceives and responds.\n\n"
        "• **Agent B** (Analyst) — classifies MITRE tactics & threat levels."
    )

# ---------------------------------------------------------------------------
# Top Metrics — with help tooltips
# ---------------------------------------------------------------------------
def _pct(numerator, denominator):
    return f"{(numerator / denominator * 100):.1f}%" if denominator else "—"


if not df.empty:
    total = len(df)

    # Calculate realistic format adherence based on first attempt (not self-healed)
    fmt_n = int(df["first_try_format_valid"].sum()) if "first_try_format_valid" in df.columns else 0
    fmt_str = _pct(fmt_n, total)

    if "illusion_broken" in df.columns and "turn_count" in df.columns:
        broken_sessions = df[df["illusion_broken"] == True]
        if not broken_sessions.empty:
            avg_life = broken_sessions.groupby("session_id")["turn_count"].max().mean()
            life_str = f"{avg_life:.1f} turns"
        else:
            life_str = "∞ (No breaks)"
    else:
        life_str = "—"

    critical_n = int((df["threat_level"] == "Critical").sum()) if "threat_level" in df.columns else 0

    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric(
            label="✅ Format Adherence (1st Try)",
            value=fmt_str,
            help=(
                "The percentage of turns where Agent A produced valid JSON "
                "on its **first attempt**, before any self-healing retry. "
                "This is the academically honest metric."
            ),
        )
    with m2:
        st.metric(
            label="⏳ Illusion Lifespan",
            value=life_str,
            help=(
                "The average number of commands the attacker issued before "
                "realizing they were inside a honeypot."
            ),
        )
    with m3:
        st.metric(
            label="🔥 Critical Threats",
            value=str(critical_n),
            help=(
                "The total number of highly destructive commands "
                "(e.g., rm -rf) detected by Agent B."
            ),
        )
else:
    st.info(
        "🔲 No simulation data yet. Launch a simulation from the sidebar to begin collecting data.",
        icon="ℹ️",
    )

st.divider()

# ---------------------------------------------------------------------------
# [FIX] Aggregate Analytics Charts — now ABOVE the turn feed
# so you don't have to scroll to the bottom to see them
# ---------------------------------------------------------------------------
if not df.empty and "threat_level" in df.columns and "predicted_mitre_tactic" in df.columns:
    st.subheader("📊 Aggregate Analytics")
    ch1, ch2 = st.columns(2, gap="medium")

    with ch1:
        st.markdown(
            "**Threat Level Distribution**",
            help="Count of turns classified at each threat level across all sessions.",
        )
        threat_counts = df["threat_level"].value_counts().reindex(
            ["Critical", "High", "Medium", "Low"], fill_value=0
        )
        st.bar_chart(threat_counts, color="#7c3aed", height=240)

    with ch2:
        st.markdown(
            "**Predicted MITRE Tactics (Top 8)**",
            help="How often Agent B predicted each MITRE ATT&CK tactic across all sessions.",
        )
        tactic_counts = df["predicted_mitre_tactic"].value_counts().head(8)
        st.bar_chart(tactic_counts, color="#22c55e", height=240)

    st.divider()

# ---------------------------------------------------------------------------
# Dashboard Legend Expander
# ---------------------------------------------------------------------------
with st.expander("📖 Dashboard Legend & Methodology", expanded=False):
    st.markdown(
        """
        ### How to Read This Dashboard

        This dashboard visualises a **closed-loop, tri-agent deception experiment** powered by
        LangGraph. Each **Turn** represents one full cycle of the agent loop.

        #### Agent Roles
        | Agent | Role | Colour Cue |
        |-------|------|------------|
        | **Agent C** | **Attacker** — generates realistic shell commands targeting the honeypot. | 🔴 Red |
        | **Agent A** | **Honeypot** — responds with convincing but fake terminal output. Must reply in strict JSON. | 🟢 Green |
        | **Agent B** | **SOC Analyst** — classifies the MITRE ATT&CK tactic and threat level each turn. | 🔵 Blue |

        #### Threat Level Definitions
        | Level | Meaning |
        |-------|---------|
        | 🟢 **Low** | Benign reconnaissance; no destructive capability. |
        | 🟡 **Medium** | Elevated risk; scanning or credential probing detected. |
        | 🔴 **High** | Active exploitation attempt; privilege escalation or lateral movement. |
        | 💀 **Critical** | Highly destructive command (e.g., `rm -rf`, ransomware payload) detected. |

        #### Column Layout (per Turn)
        - **Left** — Compact expander showing the raw attacker command + honeypot response.
        - **Centre** — Agent A's Chain of Thought (CoT) reasoning.
        - **Right** — Agent B's analyst report: MITRE tactic, threat level, and explanation.
        """
    )

st.divider()

# ---------------------------------------------------------------------------
# Session Selector
# ---------------------------------------------------------------------------
if not df.empty and "session_id" in df.columns and df["session_id"].nunique() > 1:
    sessions = df["session_id"].unique().tolist()
    chosen_session = st.selectbox(
        "🗂️ View Session",
        sessions,
        index=0,
        key="session_selector",
    )
    view_df = df[df["session_id"] == chosen_session].sort_values("turn_count")
else:
    view_df = (
        df[df["session_id"] == df["session_id"].iloc[0]].sort_values("turn_count")
        if not df.empty and "session_id" in df.columns
        else df
    )

# ---------------------------------------------------------------------------
# Turn-by-Turn Live Feed  (Row-based — no desync)
# [FIX] Chat column uses compact expanders to eliminate visual clutter
# ---------------------------------------------------------------------------
if not view_df.empty:
    total_turns = len(view_df)

    # Column headers
    header_c1, header_c2, header_c3 = st.columns(3)
    with header_c1:
        st.markdown("#### 🔴 Attack vs 🟢 Honeypot")
    with header_c2:
        st.markdown("#### 🧠 Agent A — Chain of Thought")
    with header_c3:
        st.markdown("#### 🔍 Agent B — SOC Analyst")

    st.divider()

    for loop_idx, (_, row) in enumerate(view_df.iterrows()):
        turn_num   = int(row.get("turn_count", loop_idx + 1))
        cmd        = str(row.get("latest_command", "")).strip()
        resp       = str(row.get("latest_terminal_output", "")).strip()
        cot        = str(row.get("agent_a_cot", "")).strip()
        expl       = str(row.get("agent_b_explanation", "")).strip()
        pred       = str(row.get("predicted_mitre_tactic", "—")).strip()
        threat     = str(row.get("threat_level", "Low")).strip()
        fmt_ok     = bool(row.get("is_format_valid", True))
        illusion_b = bool(row.get("illusion_broken", False))

        # Latest turn starts expanded; older turns stay collapsed to reduce clutter
        is_latest = loop_idx == total_turns - 1

        st.subheader(f"Turn {turn_num:02d}")
        c1, c2, c3 = st.columns(3)

        # ── Column 1: Chat (compact expander) ────────────────────────────────
        with c1:
            cmd_preview = (cmd[:60] + "…") if len(cmd) > 60 else cmd
            with st.expander(
                f"$ {cmd_preview or '(no command)'}",
                expanded=is_latest,
            ):
                if cmd and cmd != "nan":
                    st.markdown("**🔴 Attacker Command**")
                    st.code(f"$ {cmd}", language="bash")
                else:
                    st.caption("*(no command this turn)*")

                if resp and resp != "nan":
                    resp_display = resp[:900] + ("…" if len(resp) > 900 else "")
                    st.markdown("**🟢 Honeypot Response**")
                    st.code(resp_display, language="text")
                else:
                    st.caption("*(no response this turn)*")

        # ── Column 2: Agent A CoT ─────────────────────────────────────────────
        with c2:
            if cot and cot != "nan":
                cot_display = cot[:800] + ("…" if len(cot) > 800 else "")
                if fmt_ok:
                    st.success("✅ JSON Valid", icon="✅")
                else:
                    st.error("❌ Retry (bad format)", icon="❌")
                st.info(cot_display, icon="🧠")
            else:
                st.caption("*(no CoT data this turn)*")

        # ── Column 3: Agent B Analyst ─────────────────────────────────────────
        with c3:
            if expl and expl != "nan":
                expl_display = expl[:700] + ("…" if len(expl) > 700 else "")

                threat_display = threat_label(threat)
                if threat == "Critical":
                    st.error(f"**Threat Level:** {threat_display}", icon="💀")
                elif threat == "High":
                    st.warning(f"**Threat Level:** {threat_display}", icon="🔴")
                elif threat == "Medium":
                    st.warning(f"**Threat Level:** {threat_display}", icon="🟡")
                else:
                    st.success(f"**Threat Level:** {threat_display}", icon="🟢")

                st.markdown(f"**📌 MITRE Tactic:** `{pred}`")
                st.info(expl_display, icon="🔍")

                if illusion_b:
                    st.error(
                        "🚨 **ILLUSION BROKEN** — Attacker has detected the honeypot!",
                        icon="🚨",
                    )
            else:
                st.caption("*(no analyst data this turn)*")

        st.divider()

else:
    st.info(
        "💬 No turn data available for this session yet. "
        "Launch a simulation from the sidebar to begin.",
        icon="ℹ️",
    )

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.caption(
    f"DAXD · Tri-Agent Explainable Deception · LangGraph + TiDB + Ollama  |  "
    f"Last refresh: {datetime.now().strftime('%H:%M:%S')}"
)
