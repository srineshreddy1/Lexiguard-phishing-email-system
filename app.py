"""LexiGuard Enterprise Security Gateway — Web Dashboard (app.py).

Unified multi-tab SecOps interface integrating:
- URL Threat Decomposition & Compounding Risk Engine (Phases 1-3)
- HTML & CSS Anti-Evasion / Steganography Inspection (Phase 4.5)
- Attachment Magic-Byte Signature & Double-Extension Analysis (Phase 4.5)
- Live Gmail OAuth 2.0 Ingestion Gateway & Scan Persistence (Phase 4 & 6)
- Cloud Threat Intelligence (VirusTotal & Google Web Risk) (Phase 5)
"""

from __future__ import annotations

import base64
import html
import io
import json
import os
from pathlib import Path
import sqlite3
import sys

# Force UTF-8 on Windows stdout/stderr to prevent cp1252 charmap encoding crashes on symbols like ₹ and ⚡
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from typing import Any
import zipfile

import altair as alt
import pandas as pd

try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

# Ensure project root is in Python module search path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

# Core Static Analysis Engine
from lexiguard.core.parser import parse_url
from lexiguard.core.features import PolicyCode, extract_features
from lexiguard.core.scorer import Verdict, score_risk

# Anti-Evasion & Gateway Modules
from lexiguard.evasion.html_guard import (
    EvasionFlag,
    HtmlEvasionReport,
    extract_hrefs,
    inspect_html,
    strip_html,
)
from lexiguard.gateway.attachments import (
    AttachmentReport,
    AttachmentVerdict,
    compute_hashes,
    detect_file_signature,
    extract_attachments,
    inspect_attachment,
    remember_attachment_threat,
)

# Gateway Client & Cloud Threat Intelligence
try:
    from lexiguard.gateway.gmail_client import (
        CREDENTIALS_PATH,
        TOKEN_PATH,
        get_credentials_path,
        process_unread_inbox,
    )
except ImportError:
    from gateway.gmail_client import (  # type: ignore
        CREDENTIALS_PATH,
        TOKEN_PATH,
        get_credentials_path,
        process_unread_inbox,
    )
from lexiguard.db.database import (
    DEFAULT_DB_PATH,
    get_recent_scans,
    log_scan,
    lookup_threat,
    remember_threat,
)
from lexiguard.intel.google_webrisk import check_url_webrisk, is_webrisk_configured
from lexiguard.intel.hybrid_analysis import (
    check_hash_hybrid_analysis,
    is_hybrid_analysis_configured,
)
from lexiguard.intel.virustotal import (
    check_file_hash_virustotal,
    check_url_virustotal,
    is_virustotal_configured,
)

# Incident Response & Automated Mitigation (Phase 5.2)
from lexiguard.response.responder import (
    QUARANTINE_LABEL_NAME,
    ResponseResult,
    build_security_alert,
    orchestrate_response,
    quarantine_message,
)
from lexiguard.response.webhooks import (
    AlertSeverity,
    SecurityAlert,
    WebhookConfig,
    WebhookFormat,
    broadcast_alert,
    format_discord_payload,
    format_generic_payload,
    format_slack_payload,
    format_teams_payload,
    send_security_alert,
    send_webhook,
)

# Compliance & Reporting Exporter (Phase 5.2 Option 3)
from lexiguard.reports.exporter import (
    export_scans_to_csv,
    export_scans_to_html_report,
)

# Plain-English Threat Translation & Steganography Engine
from lexiguard.ui.translator import (
    explain_risk_score,
    get_plain_english_verdict,
    translate_report,
    translate_violation,
)
from lexiguard.intel.stego_api import inspect_stego_payload
from lexiguard.db.seed_intel import seed_threat_intel

# -----------------------------------------------------------------------------
# Streamlit Page Configuration & Enterprise Dark Cyberpunk Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="LexiGuard — Enterprise Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    /* Global Styles */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Header & Branding */
    .main-title {
        font-family: 'Segoe UI', Roboto, sans-serif;
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00E5FF 0%, #7C4DFF 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .subtitle {
        color: #94a3b8;
        font-size: 1.0rem;
        margin-bottom: 1.5rem;
    }

    /* Verdict Badges */
    .badge-safe {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.9rem;
        display: inline-block;
    }
    .badge-suspicious {
        background-color: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.9rem;
        display: inline-block;
    }
    .badge-malicious {
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.9rem;
        display: inline-block;
    }
    
    /* SecOps Metric Cards */
    .metric-card {
        background: #131d2e;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 1.1rem;
        margin-bottom: 0.8rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .metric-val {
        font-size: 1.7rem;
        font-weight: 800;
        color: #38bdf8;
    }
    .metric-lbl {
        color: #94a3b8;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Code and Preformatted Blocks */
    pre, code {
        background-color: #0f172a !important;
        border-radius: 6px;
    }
    
    /* Card Alert */
    .alert-box {
        background: rgba(239, 68, 68, 0.08);
        border-left: 4px solid #ef4444;
        padding: 0.8rem 1.2rem;
        border-radius: 4px;
        margin-bottom: 1rem;
    }
    .info-box {
        background: rgba(56, 189, 248, 0.08);
        border-left: 4px solid #38bdf8;
        padding: 0.8rem 1.2rem;
        border-radius: 4px;
        margin-bottom: 1rem;
    }

    /* Understanding UI: Status Indicators, Scannable Badges & Cards */
    .status-pill-active {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.75rem;
        letter-spacing: 0.04em;
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
    }
    .status-pill-disconnected {
        background: rgba(239, 68, 68, 0.12);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.75rem;
        letter-spacing: 0.04em;
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
    }
    .intel-status-row {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 0.65rem 0.85rem;
        margin-bottom: 0.5rem;
    }
    .hero-verdict-card {
        background: linear-gradient(135deg, #131d2e 0%, #1e293b 100%);
        border-radius: 12px;
        padding: 1.4rem;
        border: 1px solid #334155;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        margin-bottom: 1.2rem;
    }
    .hero-safe {
        border-left: 6px solid #10b981;
    }
    .hero-suspicious {
        border-left: 6px solid #f59e0b;
    }
    .hero-malicious {
        border-left: 6px solid #ef4444;
    }
    .intel-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 1.1rem 1.3rem;
        margin-bottom: 0.8rem;
    }
    .threat-card-critical {
        background: #201318;
        border: 1px solid #ef4444;
        border-left: 6px solid #ef4444;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.75rem;
    }
    .threat-card-warning {
        background: #251c14;
        border: 1px solid #f59e0b;
        border-left: 6px solid #f59e0b;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.75rem;
    }
    .threat-card-info {
        background: #101c2b;
        border: 1px solid #38bdf8;
        border-left: 6px solid #38bdf8;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.75rem;
    }
    .threat-card-title {
        color: #ffffff !important;
        font-weight: 700;
        font-size: 1.05rem;
        margin-bottom: 4px;
    }
    .threat-card-text {
        color: #e2e8f0 !important;
        font-size: 0.92rem;
        line-height: 1.5;
        margin-bottom: 4px;
    }
    .threat-card-action {
        color: #38bdf8 !important;
        font-size: 0.88rem;
        font-weight: 600;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Visual Charts & UI Helper Functions ("Understanding UI" with Plotly)
# -----------------------------------------------------------------------------
def render_risk_meter_graph(
    score: int,
    max_score: int = 10,
    title: str = "Risk Hazard Meter",
    chart_key: str | None = None,
    use_bar_meter: bool = False,
) -> None:
    """Render a clean, high-contrast Plotly gauge or visual meter showing threat severity."""
    clamped = min(max(0, score), max_score)
    if clamped <= 2:
        bar_color = "#10b981"
        status_text = "🟢 SAFE (Minimal Threat)"
    elif clamped <= 7:
        bar_color = "#f59e0b"
        status_text = "🟡 CAUTION (Suspicious Indicators)"
    else:
        bar_color = "#ef4444"
        status_text = "🔴 DANGEROUS (Active Hazard)"

    if HAS_PLOTLY and not use_bar_meter:
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=clamped,
                number={"suffix": f" / {max_score}", "font": {"size": 22, "color": bar_color, "family": "Inter, sans-serif"}},
                title={"text": f"<b>{title}</b><br><span style='font-size:0.85em;color:{bar_color}'>{status_text}</span>", "font": {"size": 14, "color": "#f8fafc"}},
                gauge={
                    "axis": {"range": [0, max_score], "tickwidth": 1, "tickcolor": "#475569", "tickfont": {"color": "#94a3b8", "size": 11}},
                    "bar": {"color": bar_color, "thickness": 0.35},
                    "bgcolor": "rgba(30, 41, 59, 0.4)",
                    "borderwidth": 1,
                    "bordercolor": "rgba(255, 255, 255, 0.1)",
                    "steps": [
                        {"range": [0, 2], "color": "rgba(16, 185, 129, 0.15)"},
                        {"range": [2, 7], "color": "rgba(245, 158, 11, 0.15)"},
                        {"range": [7, 10], "color": "rgba(239, 68, 68, 0.15)"},
                    ],
                },
            )
        )
        fig.update_layout(
            paper_bgcolor="rgba(15, 23, 42, 0.0)",
            plot_bgcolor="rgba(15, 23, 42, 0.0)",
            margin=dict(l=20, r=20, t=50, b=15),
            height=165,
            font={"family": "Inter, sans-serif"},
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, key=chart_key)
    else:
        st.markdown(
            f"""
            <div style="background: #131d2e; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 16px; margin: 8px 0 16px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-weight: 700; font-size: 0.95rem; color: #f1f5f9;">{title}</span>
                    <span style="font-weight: 800; font-size: 1.15rem; color: {bar_color};">{clamped} / {max_score} &bull; {status_text}</span>
                </div>
                <div style="background: #1e293b; border-radius: 9999px; height: 12px; width: 100%; overflow: hidden; display: flex;">
                    <div style="width: {int((clamped / max_score) * 100)}%; background: {bar_color}; transition: width 0.5s ease; border-radius: 9999px;"></div>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #64748b; margin-top: 5px;">
                    <span style="color: #10b981;">● 0-2 Safe</span>
                    <span style="color: #f59e0b;">● 3-7 Caution</span>
                    <span style="color: #ef4444;">● 8-10 Critical</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_inbox_summary_chart(reports: list[dict[str, Any]]) -> None:
    """Render clean summary metrics and interactive Plotly distribution chart for scanned inbox emails."""
    if not reports:
        return

    safe_count = sum(1 for r in reports if str(r.get("verdict", "")).upper() == "SAFE")
    susp_count = sum(1 for r in reports if str(r.get("verdict", "")).upper() == "SUSPICIOUS")
    mal_count = sum(1 for r in reports if str(r.get("verdict", "")).upper() == "MALICIOUS")
    total = len(reports)

    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    col_m1.metric("Emails Scanned", total)
    col_m2.metric("🟢 Safe Emails", safe_count)
    col_m3.metric("🟡 Caution / Suspicious", susp_count)
    col_m4.metric("🔴 Dangerous Hazards", mal_count)

    categories = ["Safe Emails", "Caution / Suspicious", "Dangerous Hazards"]
    counts = [safe_count, susp_count, mal_count]
    colors = ["#10b981", "#f59e0b", "#ef4444"]

    if HAS_PLOTLY:
        fig = go.Figure(
            data=[
                go.Bar(
                    x=categories,
                    y=counts,
                    text=counts,
                    textposition="auto",
                    textfont={"size": 14, "color": "#ffffff", "family": "Inter, sans-serif"},
                    marker_color=colors,
                    marker_line=dict(width=1, color="rgba(255, 255, 255, 0.15)"),
                    width=0.42,
                )
            ]
        )
        fig.update_layout(
            paper_bgcolor="rgba(15, 23, 42, 0.0)",
            plot_bgcolor="rgba(15, 23, 42, 0.0)",
            margin=dict(l=20, r=20, t=25, b=20),
            height=210,
            xaxis=dict(
                title=None,
                tickfont={"size": 13, "color": "#f1f5f9", "family": "Inter, sans-serif"},
                showgrid=False,
            ),
            yaxis=dict(
                title="Email Count",
                title_font={"size": 12, "color": "#94a3b8"},
                tickfont={"color": "#94a3b8"},
                showgrid=True,
                gridcolor="rgba(255, 255, 255, 0.07)",
                dtick=1 if max(counts) < 6 else None,
            ),
            font={"family": "Inter, sans-serif"},
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, key="inbox_threat_summary_chart")
    else:
        chart_data = pd.DataFrame([
            {"Category": "Safe Emails", "Count": safe_count, "Color": "#10b981"},
            {"Category": "Caution / Suspicious", "Count": susp_count, "Color": "#f59e0b"},
            {"Category": "Dangerous Hazards", "Count": mal_count, "Color": "#ef4444"},
        ])
        chart = (
            alt.Chart(chart_data)
            .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
            .encode(
                x=alt.X("Category:N", title="Verdict Classification", sort=["Safe Emails", "Caution / Suspicious", "Dangerous Hazards"]),
                y=alt.Y("Count:Q", title="Email Count", axis=alt.Axis(tickMinStep=1)),
                color=alt.Color("Color:N", scale=None, legend=None),
                tooltip=["Category", "Count"],
            )
            .properties(height=180)
        )
        st.altair_chart(chart, use_container_width=True)


# -----------------------------------------------------------------------------
# Database Metrics & Helper Functions
# -----------------------------------------------------------------------------
def get_db_stats() -> tuple[int, int]:
    """Retrieve total scan count and cached threat indicator count."""
    try:
        if not DEFAULT_DB_PATH.exists():
            return 0, 0
        conn = sqlite3.connect(str(DEFAULT_DB_PATH))
        try:
            scans_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            intel_count = conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
            return int(scans_count), int(intel_count)
        finally:
            conn.close()
    except Exception:
        return 0, 0


def render_verdict_badge(verdict_str: str) -> str:
    """Render a clean, plain-language visual status badge."""
    v = verdict_str.upper()
    if v == "MALICIOUS":
        return '<span class="badge-malicious">🔴 DANGEROUS</span>'
    elif v == "SUSPICIOUS":
        return '<span class="badge-suspicious">🟡 CAUTION</span>'
    elif v == "SAFE":
        return '<span class="badge-safe">🟢 SAFE</span>'
    return f'<span class="badge-safe">{html.escape(v)}</span>'


# -----------------------------------------------------------------------------
# Sidebar: Navigation, Operational Mode & Cloud Threat Intelligence Status
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown('<div class="main-title">🛡️ LexiGuard</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">Next-Gen Enterprise Security Gateway</div>', unsafe_allow_html=True)
    st.divider()

    st.subheader("⚙️ Operational Profile")
    op_mode = st.selectbox(
        "Operating Mode",
        [
            "Active Gateway Ingestion",
            "Forensic Deep Audit",
            "Simulation & Stress Testing",
        ],
        index=0,
        help="Select inspection depth and persistence policy.",
    )

    st.divider()
    st.subheader("🌐 Threat Intelligence Feeds")
    st.caption("Active threat cloud indicators:")

    # Status-only connection telemetry (hiding raw API secrets)
    vt_active = is_virustotal_configured()
    webrisk_active = is_webrisk_configured()
    ha_active = is_hybrid_analysis_configured()

    feed_items = [
        ("VirusTotal v3", vt_active, "Multi-engine reputation & hash lookup"),
        ("Google Web Risk", webrisk_active, "Real-time Google Safe Browsing telemetry"),
        ("Hybrid Analysis", ha_active, "CrowdStrike Falcon Sandbox logs"),
    ]

    for name, active, desc in feed_items:
        badge_html = (
            '<span class="status-pill-active">🟢 ACTIVE</span>'
            if active
            else '<span class="status-pill-disconnected">🔴 DISCONNECTED</span>'
        )
        st.markdown(
            f"""
            <div class="intel-status-row">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600; font-size: 0.92rem; color: #f1f5f9;">{name}</span>
                    {badge_html}
                </div>
                <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 3px;">{desc}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()
    st.subheader("💾 Threat Memory Status")
    total_scans, total_threats = get_db_stats()
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        st.metric("Total Scans", total_scans)
    with col_sb2:
        st.metric("Known Threats", total_threats)

    st.caption(f"Database: `{DEFAULT_DB_PATH.name}`")


# -----------------------------------------------------------------------------
# Main Application Dashboard: Multi-Tab Architecture
# -----------------------------------------------------------------------------
st.markdown('<div class="main-title">Enterprise Threat Gateway Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Real-time anti-evasion, steganography deconstruction, and deep binary payload analysis</div>', unsafe_allow_html=True)

tab_url, tab_html, tab_att, tab_gmail, tab_response, tab_compliance = st.tabs([
    "🔗 URL Threat Analyzer",
    "🕵️ HTML Evasion Inspector",
    "📎 Attachment Security",
    "📬 Live Gmail Gateway",
    "🛡️ Incident Response & Webhooks",
    "📊 Audit Logs & Compliance Export",
])


# =============================================================================
# TAB 1: URL Threat Analyzer (Phases 1-3 & Phase 5)
# =============================================================================
with tab_url:
    st.header("URL Threat Inspection & Multi-Layer Gateway")
    st.caption("RFC 3986 structural decomposition, quantitative feature scoring, and verified cloud threat intelligence.")

    # Preset Quick Vectors
    st.markdown("**Quick Preset Attack Vectors:**")
    col_pre1, col_pre2, col_pre3, col_pre4, col_pre5 = st.columns(5)
    if "target_url_input" not in st.session_state:
        st.session_state["target_url_input"] = "https://login.mail.account-verify.example.com/signin"

    if col_pre1.button("✅ Safe Research", use_container_width=True):
        st.session_state["target_url_input"] = "https://github.com/google/security-research"
    if col_pre2.button("🚨 Hex IP Evasion", use_container_width=True):
        st.session_state["target_url_input"] = "http://0x7f000001/login/verify.php"
    if col_pre3.button("🚨 DGA Phishing", use_container_width=True):
        st.session_state["target_url_input"] = "https://xzkj9812-verify-account.cc/banking/signin?token=123"
    if col_pre4.button("🚨 Backslash Spoof", use_container_width=True):
        st.session_state["target_url_input"] = "https://trusted-bank.example.com\\@malicious-harvest.org/auth"
    if col_pre5.button("⚠️ Deep Subdomain", use_container_width=True):
        st.session_state["target_url_input"] = "https://login.mail.account.update.verify.phish-domain.com/secure"

    target_url = st.text_input(
        "🔗 Target URL Inspection Candidate",
        key="target_url_input",
        placeholder="Enter URL to inspect (e.g. https://www.linkedin.com/feed or http://0x7f000001/login)",
        help="Target URL analyzed across static heuristics, structural decomposition, and active cloud intelligence feeds.",
    )

    if st.button("🚀 Run Gateway Threat Scan", type="primary", use_container_width=True):
        if not target_url.strip():
            st.warning("Please provide a valid URL string.")
        else:
            with st.spinner("Analyzing target URL through multi-layer inspection gateway..."):
                try:
                    # 1. Static Feature Extraction & Verified Threat Intel Scoring
                    parsed = parse_url(target_url.strip())
                    feature_res = extract_features(parsed)

                    # Query active cloud threat intelligence
                    vt_res = check_url_virustotal(target_url.strip()) if vt_active else {}
                    wr_res = check_url_webrisk(target_url.strip()) if webrisk_active else {}
                    vt_verd = vt_res.get("verdict")
                    wr_verd = wr_res.get("verdict")
                    cloud_clean = (vt_verd == "SAFE" or wr_verd == "SAFE")
                    cloud_mal = (vt_verd == "MALICIOUS" or wr_verd == "MALICIOUS")
                    cloud_susp = (vt_verd == "SUSPICIOUS" or wr_verd == "SUSPICIOUS")

                    host = (parsed.get("host") or "").lower()
                    is_trusted = any(host == th or host.endswith("." + th) for th in (
                        "linkedin.com", "licdn.com", "google.com", "gstatic.com", "github.com",
                        "microsoft.com", "glassdoor.com", "amazon.com", "youtube.com"
                    ))

                    score_res = score_risk(
                        feature_res,
                        intel_verdict="MALICIOUS" if cloud_mal else ("SUSPICIOUS" if cloud_susp else ("SAFE" if cloud_clean else None)),
                        threat_intel_clean=cloud_clean,
                        is_trusted_domain=is_trusted,
                    )

                    verdict: Verdict = score_res["verdict"]
                    risk_score: int = score_res["risk_score"]
                    features = feature_res["features"]
                    violations = feature_res["policy_violations"]

                    # 2. Plain-English Translation
                    trans_rep = translate_report({
                        "verdict": verdict.value,
                        "risk_score": risk_score,
                        "policy_violations": violations,
                    })

                    # Determine UI card theme based on verdict
                    hero_theme = "hero-safe" if verdict == Verdict.SAFE else ("hero-suspicious" if verdict == Verdict.SUSPICIOUS else "hero-malicious")
                    score_color = "#10b981" if risk_score < 3 else ("#f59e0b" if risk_score < 8 else "#ef4444")

                    # ---------------------------------------------------------
                    # HERO VERDICT CARD ("Understanding UI")
                    # ---------------------------------------------------------
                    st.markdown(
                        f"""
                        <div class="hero-verdict-card {hero_theme}">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                                <div>
                                    <div style="font-size: 0.78rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600;">Overall Threat Assessment</div>
                                    <div style="margin-top: 6px;">{render_verdict_badge(verdict.value)}</div>
                                </div>
                                <div style="text-align: right;">
                                    <div style="font-size: 0.78rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600;">Compounding Hazard Score</div>
                                    <div style="font-size: 1.85rem; font-weight: 800; color: {score_color};">
                                        {risk_score} <span style="font-size: 1.0rem; color: #64748b; font-weight: 500;">/ 10</span>
                                    </div>
                                </div>
                            </div>
                            <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.08); margin: 1rem 0;"/>
                            <div style="font-size: 1.05rem; font-weight: 600; color: #f8fafc; margin-bottom: 0.35rem;">
                                💡 {trans_rep['key_takeaway']}
                            </div>
                            <div style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.5;">
                                <b>What This Means:</b> {trans_rep['risk_explanation']['summary']}
                            </div>
                            <div style="margin-top: 0.65rem; font-size: 0.88rem; color: #38bdf8;">
                                <b>Recommended Action:</b> <code style="color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 3px 8px; border-radius: 4px;">{trans_rep['risk_explanation']['recommended_action']}</code>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    # Interactive Python Visual Risk Meter
                    render_risk_meter_graph(risk_score, 10, title="Visual Risk Hazard Level", chart_key="url_inspection_risk_meter")

                    # ---------------------------------------------------------
                    # LIVE VERIFIED CLOUD THREAT INTELLIGENCE
                    # ---------------------------------------------------------
                    if vt_active or webrisk_active:
                        st.subheader("🌐 Live Verified Threat Intelligence")
                        c_vt, c_wr = st.columns(2)

                        # VirusTotal v3 Query & Clean Card
                        if vt_active:
                            with c_vt:
                                vt_res = check_url_virustotal(target_url.strip())
                                vt_verdict = vt_res.get("verdict", "UNKNOWN")
                                stats = vt_res.get("stats", {})
                                mal_cnt = stats.get("malicious", 0)
                                susp_cnt = stats.get("suspicious", 0)
                                clean_cnt = stats.get("harmless", 0) + stats.get("undetected", 0)
                                total_engines = mal_cnt + susp_cnt + clean_cnt

                                st.markdown(
                                    f"""
                                    <div class="intel-card">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                            <span style="font-weight: 700; color: #f1f5f9; font-size: 0.95rem;">VirusTotal v3 Consensus</span>
                                            {render_verdict_badge(vt_verdict)}
                                        </div>
                                        <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 8px;">
                                            {vt_res.get('message', 'Multi-engine cloud consensus')}
                                        </div>
                                        <div style="font-size: 0.85rem; color: {'#ef4444' if (mal_cnt + susp_cnt) > 0 else '#10b981'}; font-weight: 600;">
                                            Security Engines: {mal_cnt} Malicious | {susp_cnt} Suspicious | {clean_cnt} Clean
                                        </div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )
                                if vt_res.get("gui_link"):
                                    st.markdown(f"[🔗 View VirusTotal Community Report]({vt_res['gui_link']})")

                        # Google Web Risk Query & Clean Card
                        if webrisk_active:
                            with c_wr:
                                wr_res = check_url_webrisk(target_url.strip())
                                wr_verdict = wr_res.get("verdict", "SAFE")
                                threat_types = wr_res.get("threat_types", [])
                                threat_label = ", ".join(threat_types) if threat_types else "Safe (No threat match)"

                                st.markdown(
                                    f"""
                                    <div class="intel-card">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                            <span style="font-weight: 700; color: #f1f5f9; font-size: 0.95rem;">Google Web Risk</span>
                                            {render_verdict_badge(wr_verdict)}
                                        </div>
                                        <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 8px;">
                                            {wr_res.get('message', 'Google Safe Browsing list telemetry')}
                                        </div>
                                        <div style="font-size: 0.85rem; color: {'#ef4444' if wr_verdict == 'MALICIOUS' else '#10b981'}; font-weight: 600;">
                                            Classification: {threat_label}
                                        </div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

                    # ---------------------------------------------------------
                    # IDENTIFIED THREAT FACTORS (PLAIN-ENGLISH TRANSLATOR)
                    # ---------------------------------------------------------
                    st.subheader(f"⚠️ Identified Threat Factors ({len(violations)})")
                    if not violations:
                        st.success("✅ Clean URL — All heuristic checks and safety boundaries passed successfully.")
                    else:
                        for tv in trans_rep.get("translated_violations", []):
                            sev = tv.get("severity", "medium").lower()
                            card_class = "threat-card-critical" if sev == "high" else ("threat-card-warning" if sev == "medium" else "threat-card-info")
                            sev_color = "#ef4444" if sev == "high" else ("#f59e0b" if sev == "medium" else "#38bdf8")
                            st.markdown(
                                f"""
                                <div class="{card_class}">
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                        <span class="threat-card-title">{tv.get('title')}</span>
                                        <span style="color: {sev_color}; font-weight: 800; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">{sev} risk</span>
                                    </div>
                                    <div class="threat-card-text">
                                        <b>What it means:</b> {tv.get('meaning')}
                                    </div>
                                    <div class="threat-card-action">
                                        <b>What you should do:</b> <i>{tv.get('action')}</i>
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                    # ---------------------------------------------------------
                    # ADVANCED TECHNICAL LOGS (EXPANDER)
                    # ---------------------------------------------------------
                    with st.expander("⚙️ Show Advanced Technical Logs (Entropy, RFC 3986 & Raw Diagnostics)", expanded=False):
                        st.markdown("**Quantitative Static Feature Extraction:**")
                        m1, m2, m3, m4, m5 = st.columns(5)
                        m1.metric("Shannon Entropy", f"{features.get('shannon_entropy', 0.0):.3f}")
                        m2.metric("Hostname Length", f"{features.get('hostname_length', 0)}")
                        m3.metric("Subdomain Count", f"{features.get('subdomain_count', 0)}")
                        m4.metric("Label Count", f"{features.get('label_count', 0)}")
                        m5.metric("% Encodings", f"{features.get('percent_encoding_count', 0)}")

                        st.markdown("**RFC 3986 Normalized URL Schema:**")
                        st.json({
                            "scheme": parsed.get("scheme"),
                            "host": parsed.get("host"),
                            "port": parsed.get("port"),
                            "path": parsed.get("path"),
                            "query": parsed.get("query"),
                            "fragment": parsed.get("fragment"),
                            "is_ip_literal": parsed.get("is_ip_literal"),
                            "canonical_ipv4": parsed.get("canonical_ipv4"),
                            "userinfo": parsed.get("userinfo"),
                        })

                        if violations:
                            st.markdown("**Raw Heuristic Violation Evidence:**")
                            st.json(violations)

                    # ---------------------------------------------------------
                    # PERSISTENCE LOGGING (Phase 6 SQLite Audit Ledger)
                    # ---------------------------------------------------------
                    scan_id = log_scan(
                        message_id=f"web_scan_{os.urandom(4).hex()}",
                        sender="dashboard_user",
                        subject="Manual URL Scan",
                        verdict=verdict.value,
                        risk_score=risk_score,
                        urls=[target_url],
                        excerpt=target_url,
                        extra={
                            "features": features,
                            "violations": violations,
                            "op_mode": op_mode,
                        },
                    )
                    st.caption(f"💾 Persisted audit record to SQLite ledger (Scan ID: `#{scan_id}`).")

                except Exception as exc:
                    st.error(f"Analysis pipeline error: {type(exc).__name__}: {exc}")


# =============================================================================
# TAB 2: HTML Evasion Inspector (Phase 4.5)
# =============================================================================
with tab_html:
    st.header("HTML Evasion & Steganography Inspector")
    st.caption("Detects visual/font steganography, microscopic text (<3px), hidden CSS styles, and deceptive hyperlinks.")

    # Preset HTML Attack Vectors
    st.markdown("**Quick Preset HTML Attack Scenarios:**")
    h_col1, h_col2, h_col3, h_col4, h_col5 = st.columns(5)
    preset_html = ""

    if h_col1.button("🚨 Microscopic Font (<3px)", use_container_width=True):
        preset_html = """<p>Dear customer, your account requires verification.</p>
<span style="font-size: 1px; color: #fff;">VIAGRA PHARMACY LOTTERY WINNER FREE ROLEX COINBASE SEED PHRASE</span>
<p>Please click below to continue.</p>"""

    if h_col2.button("🚨 Hidden CSS (display:none)", use_container_width=True):
        preset_html = """<div>Welcome to Corporate IT Support</div>
<div style="display: none;">Malicious credential harvesting lure keyword injection bypass token</div>
<p>Log in using your corporate single sign-on portal.</p>"""

    if h_col3.button("🚨 Color-Matching Stego", use_container_width=True):
        preset_html = """<div style="background-color: #ffffff;">
    <p>Normal invoice document.</p>
    <span style="color: #ffffff; background-color: #ffffff;">Secret illicit transaction tokens and hidden Bayesian spam noise</span>
</div>"""

    if h_col4.button("🚨 Deceptive Anchor Link", use_container_width=True):
        preset_html = """<p>Security Alert: Your payment failed.</p>
<a href="https://evil-phish.cc/steal_login">https://www.paypal.com/signin/verify</a>"""

    if h_col5.button("✅ Clean Newsletter HTML", use_container_width=True):
        preset_html = """<!DOCTYPE html>
<html>
<body>
    <h1>Weekly Engineering Briefing</h1>
    <p>The latest updates on LexiGuard architecture are now available.</p>
    <a href="https://example.com/newsletter">Read full release notes</a>
</body>
</html>"""

    html_input = st.text_area(
        "HTML Email Body Markup",
        value=preset_html if preset_html else """<div style="display: none">Hidden steganography token</div>
<p>Please review your statement <span style="font-size: 1px">SpamBypassTokens</span> at <a href="http://evil.com/login">https://secure.chase.com</a></p>""",
        height=180,
    )

    if st.button("🔬 Deconstruct & Inspect HTML Markup", type="primary", use_container_width=True):
        with st.spinner("Deconstructing HTML styles, DOM tree, and color contrast..."):
            report: HtmlEvasionReport = inspect_html(html_input)

            # Overview Metrics
            st.divider()
            if report["has_evasion"]:
                st.markdown(
                    f"""
                    <div class="alert-box">
                        <h4 style="margin: 0; color: #ef4444;">🚨 ADVANCED EVASION DETECTED</h4>
                        <span>Multiple steganographic or hidden formatting techniques were identified.</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div class="info-box">
                        <h4 style="margin: 0; color: #10b981;">✅ NO EVASION TECHNIQUES DETECTED</h4>
                        <span>HTML content appears clean with standard visual rendering properties.</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            hc1, hc2, hc3, hc4, hc5 = st.columns(5)
            hc1.metric("Evasion Score", report["risk_score"])
            hc2.metric("Hidden Elements", report["hidden_elements_count"])
            hc3.metric("Micro Fonts (<3px)", report["microscopic_font_count"])
            hc4.metric("Color Matches", report["color_matching_count"])
            hc5.metric("Deceptive Links", report["deceptive_link_count"])

            # Evasion Flags Triggered
            if report["evasion_flags"]:
                st.subheader("🚩 Triggered Evasion Flags")
                flag_badges = " ".join([f"`{f}`" for f in report["evasion_flags"]])
                st.markdown(flag_badges)

            # Extracted Hidden Text Snippets
            st.subheader("🕵️ Extracted Hidden Text (Steganographic Payload)")
            if report["hidden_text_snippets"]:
                st.warning("The following hidden content was concealed from recipient visual rendering:")
                for snippet in report["hidden_text_snippets"]:
                    st.code(snippet, language="text")
            else:
                st.info("No concealed text snippets detected.")

            # Deceptive Links Inspector
            if report["deceptive_links"]:
                st.subheader("🎭 Deceptive Anchor Links (Spoofed Text)")
                st.error("Links where displayed text represents a legitimate domain while destination routes elsewhere:")
                for link in report["deceptive_links"]:
                    st.markdown(
                        f"""
                        - **Displayed Anchor Domain:** `{link['displayed_domain']}` (`{link['displayed_text']}`)  
                          ↳ **Actual Target URL:** `{link['destination_url']}` (Destination: `{link['destination_domain']}`)
                        """
                    )

            # Structured Violations
            with st.expander(f"⚙️ Show Advanced Technical Logs ({len(report['violations'])} Records)", expanded=False):
                st.json(report["violations"])

            # Sanitized Human-Visible Text
            with st.expander("👁️ Human-Visible Rendered Text (via strip_html)"):
                st.write(report["visible_text"])

            # Discovered URLs
            with st.expander(f"Discovered Hyperlinks ({len(report['hrefs'])})"):
                st.write(report["hrefs"])

            # Plain-English HTML Threat Translation
            html_trans = translate_report({
                "verdict": "MALICIOUS" if report["has_evasion"] else "SAFE",
                "risk_score": 8 if report["has_evasion"] else 0,
                "violations": report["violations"],
            })
            with st.expander("🗣️ Plain-English Threat Guide (For Everyday Users)", expanded=report["has_evasion"]):
                st.markdown(f"**Key Takeaway:** {html_trans['key_takeaway']}")
                st.markdown(f"**What This Means:** {html_trans['risk_explanation']['summary']}")
                st.markdown(f"**What You Should Do:** `{html_trans['risk_explanation']['recommended_action']}`")
                if html_trans["translated_violations"]:
                    st.markdown("---")
                    for tv in html_trans["translated_violations"]:
                        st.markdown(f"- **{tv['title']}** (`{tv['code']}`): {tv['meaning']} **Advice:** *{tv['action']}*")


# =============================================================================
# TAB 3: Attachment Security (Phase 4.5 & Phase 6)
# =============================================================================
with tab_att:
    st.header("Attachment Threat & Magic-Byte File Inspection")
    st.caption("Verifies true file headers, detects disguised executables (MZ-in-PDF), double-extensions, RTLO spoofing, and embedded macros.")

    # Preset Sample File Generator
    st.markdown("**Generate Synthetic Attack Payload Samples:**")
    g_col1, g_col2, g_col3, g_col4 = st.columns(4)
    simulated_file: bytes | None = None
    simulated_name: str = ""

    if g_col1.button("🚨 Disguised MZ in .pdf", use_container_width=True):
        simulated_name = "urgent_invoice.pdf"
        simulated_file = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 128
    if g_col2.button("🚨 Double Ext (.pdf.exe)", use_container_width=True):
        simulated_name = "statement_2026.pdf.exe"
        simulated_file = b"MZ\x90\x00" + b"\x00" * 64
    if g_col3.button("🚨 RTLO Spoofed Filename", use_container_width=True):
        simulated_name = "candidate_resume\u202eexe.pdf"
        simulated_file = b"%PDF-1.7 sample"
    if g_col4.button("✅ Authentic Clean PDF", use_container_width=True):
        simulated_name = "clean_whitepaper.pdf"
        simulated_file = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"

    uploaded_file = st.file_uploader(
        "Upload Attachment Binary File",
        type=None,
        help="Upload any file type (.pdf, .exe, .zip, .docx, .png, etc.) for in-memory signature analysis.",
    )

    # Resolve target file content
    target_content: bytes | None = None
    target_name: str = ""
    target_mime: str = "application/octet-stream"

    if uploaded_file is not None:
        target_content = uploaded_file.read()
        target_name = uploaded_file.name
        target_mime = uploaded_file.type or "application/octet-stream"
    elif simulated_file is not None:
        target_content = simulated_file
        target_name = simulated_name
        target_mime = "application/pdf"
        st.info(f"Loaded synthetic test vector: `{simulated_name}` ({len(simulated_file)} bytes)")

    if target_content is not None and target_name:
        with st.spinner("Analyzing binary magic bytes, cryptographic digests, and policy rules..."):
            att_report: AttachmentReport = inspect_attachment(
                target_content,
                filename=target_name,
                claimed_mime=target_mime,
            )

            meta = att_report["metadata"]
            att_verdict: AttachmentVerdict = att_report["verdict"]

            st.divider()
            av_col1, av_col2 = st.columns([1, 3])
            with av_col1:
                st.markdown("### Attachment Verdict")
                st.markdown(render_verdict_badge(att_verdict.value), unsafe_allow_html=True)
            with av_col2:
                st.metric(
                    "Hazard Risk Score",
                    f"{att_report['risk_score']} / 10+",
                    delta=att_verdict.value,
                    delta_color="inverse" if att_verdict != AttachmentVerdict.SAFE else "normal",
                )

            # File Signature Comparison
            st.subheader("🔍 Binary File Signature (Magic Bytes)")
            sig_col1, sig_col2, sig_col3 = st.columns(3)
            sig_col1.metric("Declared Extension", meta["declared_extension"] or "None")
            sig_col2.metric("Detected Format", meta["detected_format"])
            sig_col3.metric("True MIME Type", meta["detected_mime_type"])

            # Critical Type Mismatch Banner
            if meta["is_executable"] and meta["declared_extension"] in (".pdf", ".png", ".jpg", ".docx", ".xlsx"):
                st.error(
                    f"CRITICAL DISGUISED EXECUTABLE ATTACK: Attachment claims `{meta['declared_extension']}` "
                    f"extension but binary signature is `{meta['detected_format']}` (Executable PE/MZ header)!"
                )

            # Cryptographic Fingerprints & Hashes
            st.subheader("🔐 Cryptographic Fingerprints")
            h_col1, h_col2 = st.columns([3, 1])
            with h_col1:
                st.code(
                    f"SHA-256: {meta['sha256']}\n"
                    f"MD5:     {meta['md5']}\n"
                    f"SHA-1:   {meta['sha1']}",
                    language="text",
                )
            with h_col2:
                st.markdown(f"[🔗 Search on VirusTotal]({meta['virustotal_url']})")
                st.markdown(f"[🔗 Search on Hybrid Analysis](https://www.hybrid-analysis.com/sample/{meta['sha256']})")
                if st.button("💾 Remember Threat in DB"):
                    remember_attachment_threat(att_report)
                    st.success("SHA-256 registered in Threat Intel Memory!")

            # Live Cloud Threat Intelligence Lookups
            if vt_active or ha_active:
                st.subheader("🌐 Cloud Threat Consensus")
                col_c1, col_c2 = st.columns(2)
                if vt_active:
                    with col_c1:
                        st.markdown("**VirusTotal v3 Consensus**")
                        vt_file_res = check_file_hash_virustotal(meta["sha256"])
                        st.markdown(render_verdict_badge(vt_file_res.get("verdict", "UNKNOWN")), unsafe_allow_html=True)
                        st.caption(vt_file_res.get("message", ""))
                        if vt_file_res.get("meaningful_name"):
                            st.write(f"Sample Identified: `{vt_file_res['meaningful_name']}`")
                if ha_active:
                    with col_c2:
                        st.markdown("**Hybrid Analysis (Falcon Sandbox)**")
                        ha_file_res = check_hash_hybrid_analysis(meta["sha256"])
                        st.markdown(render_verdict_badge(ha_file_res.get("verdict", "UNKNOWN")), unsafe_allow_html=True)
                        st.caption(ha_file_res.get("message", ""))
                        if ha_file_res.get("threat_score") is not None:
                            st.metric("Falcon Threat Score", f"{ha_file_res['threat_score']}/100")

            # Threat Intel Local Cache Status
            if att_report["threat_intel_match"]:
                st.warning(f"MATCHED THREAT INTEL: Hash previously indexed as `{att_report['threat_intel_match']['verdict']}`!")

            # Violations List
            st.subheader(f"⚠️ Safety Violations ({len(att_report['violations'])})")
            if not att_report["violations"]:
                st.success("No file-security policy violations detected. Header matches extension.")
            else:
                for v in att_report["violations"]:
                    sev = v.get("severity", "medium").lower()
                    color = "#ef4444" if sev == "critical" else ("#f59e0b" if sev == "high" else "#38bdf8")
                    st.markdown(
                        f"""
                        <div style="border-left: 4px solid {color}; background: #131d2e; padding: 0.8rem 1rem; border-radius: 4px; margin-bottom: 0.5rem;">
                            <b>{v.get('code')}</b> — <span style="color: {color}; font-weight: bold; text-transform: uppercase;">{sev} severity</span><br/>
                            <span>{v.get('message')}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

            # Steganography & Polyglot Hidden Payload Inspection
            stego_res = inspect_stego_payload(target_content, target_name)
            with st.expander("🖼️ Steganography & Polyglot Inspection", expanded=stego_res["has_hidden_payload"]):
                st.write(f"**Stego Verdict:** `{stego_res['verdict']}` | **Entropy:** `{stego_res['entropy']}` | **LSB Entropy:** `{stego_res['lsb_entropy']}`")
                if stego_res["anomalies"]:
                    for anom in stego_res["anomalies"]:
                        st.error(f"🚨 Steganographic Anomaly: `{anom}`")
                else:
                    st.success("Clean binary byte distribution. No hidden archive polyglots or LSB steganography detected.")

            # Plain-English Attachment Threat Guide
            att_translation = translate_report({
                "verdict": att_report["verdict"].value,
                "risk_score": att_report["risk_score"],
                "violations": att_report["violations"],
            })
            with st.expander("🗣️ Plain-English Threat Guide (For Everyday Users)", expanded=(att_report["verdict"] != AttachmentVerdict.SAFE)):
                st.markdown(f"**Key Takeaway:** {att_translation['key_takeaway']}")
                st.markdown(f"**Action Required:** `{att_translation['risk_explanation']['recommended_action']}`")
                if att_translation["translated_violations"]:
                    st.markdown("---")
                    for tv in att_translation["translated_violations"]:
                        st.markdown(f"- **{tv['title']}** (`{tv['code']}`): {tv['meaning']} **Advice:** *{tv['action']}*")

            # Metadata Table
            with st.expander("⚙️ Show Advanced Technical Logs (File Signature & Metadata)", expanded=False):
                st.json(meta)


# =============================================================================
# TAB 4: Live Gmail Gateway (Phase 4 & Phase 6)
# =============================================================================
with tab_gmail:
    st.header("Live Gmail Ingestion Gateway")
    st.caption("Secure OAuth 2.0 polling, MIME decoding, zero-width sanitization, and automated SQLite scan audit persistence.")

    # OAuth Credentials & Readiness Check
    resolved_creds_path = get_credentials_path()
    creds_exist = resolved_creds_path.exists()
    token_exist = TOKEN_PATH.exists()

    is_web_client = False
    if creds_exist:
        try:
            with open(resolved_creds_path, "r", encoding="utf-8") as f:
                c_data = json.load(f)
                if "web" in c_data and "installed" not in c_data:
                    is_web_client = True
        except Exception:
            pass

    col_gw_status1, col_gw_status2 = st.columns(2)
    with col_gw_status1:
        if creds_exist and not is_web_client:
            st.success(f"Google OAuth Client Credentials Found (`{resolved_creds_path.name}` — Desktop Type)")
        elif creds_exist and is_web_client:
            st.warning(f"OAuth Client is 'Web application' (`{resolved_creds_path.name}`). 'Desktop app' required.")
        else:
            st.warning(f"Missing Google OAuth Client File (`{resolved_creds_path}`)")
    with col_gw_status2:
        if token_exist:
            st.success("Authorized User Token Active (`token.json`)")
        else:
            st.info("No active token.json (will initiate authorization flow on first poll)")

    if is_web_client:
        st.error(
            """
            🚨 **Why you see "Access blocked: This app's request is invalid" (Error 400):**
            
            Your `credentials.json` was created with **Application type: "Web application"**. Local desktop applications (like Streamlit / Python gateways) cannot use "Web application" client IDs because Google strictly blocks loopback redirects (`localhost:<dynamic_port>`) for Web clients.
            
            **How to fix in 60 seconds:**
            1. Open [Google Cloud Console Credentials](https://console.cloud.google.com/apis/credentials) (Project: `lexiguard-gateway`).
            2. Click **+ CREATE CREDENTIALS** $\\rightarrow$ **OAuth client ID**.
            3. In the **Application type** dropdown, select **Desktop app** (NOT Web application).
            4. Name it `LexiGuard Desktop` and click **Create**.
            5. Click **Download JSON**, then drag & drop the downloaded file into the uploader below!
            
            *(Also make sure your target Gmail address is added under **OAuth consent screen $\\rightarrow$ Test users**).*
            """
        )

    with st.expander("🔑 Google OAuth Client Credentials Configuration & Uploader", expanded=(not creds_exist or is_web_client)):
        st.markdown(
            """
            LexiGuard connects to Gmail using a Google Cloud OAuth 2.0 Client ID for Desktop/Web.
            - **Target Path**: `credentials.json` (auto-detected in your project workspace).
            - **Auth Token Cache**: `token.json` (created after initial browser authorization).
            """
        )
        up_file = st.file_uploader(
            "Upload new or replacement credentials.json",
            type=["json"],
            key="oauth_client_uploader",
            help="Download this JSON from Google Cloud Console > APIs & Services > Credentials",
        )
        if up_file is not None:
            try:
                raw_bytes = up_file.read()
                parsed_json = json.loads(raw_bytes.decode("utf-8"))
                if "installed" in parsed_json or "web" in parsed_json or "client_id" in parsed_json:
                    with open(resolved_creds_path, "wb") as f:
                        f.write(raw_bytes)
                    alt_path = PROJECT_ROOT / "credentials.json"
                    if alt_path != resolved_creds_path:
                        try:
                            with open(alt_path, "wb") as f:
                                f.write(raw_bytes)
                        except Exception:
                            pass
                    st.success("✅ `credentials.json` uploaded successfully! Refreshing...")
                    st.rerun()
                else:
                    st.error("Uploaded file is not a valid Google OAuth client secrets JSON file.")
            except Exception as e:
                st.error(f"Error reading JSON file: {e}")

    st.divider()

    # Ingestion Controls
    col_poll1, col_poll2 = st.columns([1, 2])
    with col_poll1:
        poll_limit = st.slider("Max unread emails to ingest", min_value=1, max_value=20, value=5)
    with col_poll2:
        st.write("")
        st.write("")
        run_live_poll = st.button("⚡ Poll & Scan Live Unread Inbox", type="primary", use_container_width=True)

    # Synthetic Test Button (Allows testing gateway without browser OAuth popup)
    run_simulated_poll = st.button("🧪 Run Gateway Simulation (Synthetic Messages)", help="Simulates live incoming emails with embedded phishing lures and attachments.")

    def render_email_report_card(idx: int, rep: dict[str, Any]) -> None:
        """Render a clean, plain-English, high-contrast security inspection card for an email."""
        v_overall = str(rep.get("verdict", "SAFE")).upper()
        risk_score = int(rep.get("risk_score", 0))
        subject = rep.get("subject", "No Subject")
        sender = rep.get("sender", "Unknown Sender")
        urls = rep.get("urls", [])
        url_scores = rep.get("url_scores", [])
        attachments = rep.get("attachment_reports", [])
        html_report = rep.get("html_report")

        icon = "🔴" if v_overall == "MALICIOUS" else ("🟡" if v_overall == "SUSPICIOUS" else "🟢")
        is_safe = v_overall == "SAFE"

        with st.expander(f"{icon} Email #{idx+1}: {subject} — From: {sender}", expanded=(not is_safe)):
            col_hdr1, col_hdr2 = st.columns([1, 2])
            with col_hdr1:
                st.markdown(f"**Security Verdict:** {render_verdict_badge(v_overall)}", unsafe_allow_html=True)
                st.caption(f"Message ID: `{rep.get('message_id')}`")
            with col_hdr2:
                render_risk_meter_graph(
                    risk_score,
                    10,
                    title="Email Hazard Level",
                    chart_key=f"email_risk_meter_{idx}_{rep.get('message_id', idx)}",
                    use_bar_meter=True,
                )

            # Plain-English Executive Summary
            if is_safe:
                st.success("✅ **Clean & Safe:** No phishing links, hidden text, or hazardous attachments were detected in this email.")
            elif v_overall == "SUSPICIOUS":
                st.warning("⚠️ **Caution Advised:** This email contains suspicious indicators (e.g. unusual links or deceptive formatting). Verify the sender before taking any action.")
            else:
                st.error("🚨 **Security Hazard Detected:** This email has been flagged as high risk! It contains confirmed phishing links, deceptive lures, or dangerous file attachments.")

            # Breakdown Sections
            col_u, col_a = st.columns(2)
            with col_u:
                st.markdown(f"**🔗 Hyperlinks Checked ({len(urls)}):**")
                if not urls:
                    st.caption("No hyperlinks found in this email.")
                elif url_scores:
                    bad_links = [u for u in url_scores if str(u.get("verdict", "")).upper() in ("MALICIOUS", "SUSPICIOUS")]
                    ok_links = [u for u in url_scores if str(u.get("verdict", "")).upper() == "SAFE"]

                    if bad_links:
                        st.error(f"⚠️ **{len(bad_links)} Flagged Link(s) Found:**")
                        for u_item in bad_links:
                            u_url = u_item.get("url", "")
                            disp_url = u_url if len(u_url) <= 75 else f"{u_url[:72]}..."
                            u_verd = str(u_item.get("verdict", "SUSPICIOUS")).upper()
                            u_icon = "🔴" if u_verd == "MALICIOUS" else "🟡"
                            st.markdown(f"{u_icon} [{disp_url}]({u_url}) — **{u_verd}**")
                        if ok_links:
                            with st.expander(f"🟢 View {len(ok_links)} Safe Hyperlinks", expanded=False):
                                for u_item in ok_links:
                                    u_url = u_item.get("url", "")
                                    disp_url = u_url if len(u_url) <= 75 else f"{u_url[:72]}..."
                                    st.markdown(f"🟢 [{disp_url}]({u_url}) — **SAFE**")
                    else:
                        st.success(f"🟢 All **{len(urls)}** links verified safe.")
                        with st.expander(f"Inspect all {len(urls)} verified links", expanded=False):
                            for u_item in ok_links:
                                u_url = u_item.get("url", "")
                                disp_url = u_url if len(u_url) <= 75 else f"{u_url[:72]}..."
                                st.markdown(f"🟢 [{disp_url}]({u_url}) — **SAFE**")
                else:
                    st.info(f"🟢 {len(urls)} link(s) found.")
                    with st.expander("Inspect all links", expanded=False):
                        for u in urls:
                            disp_url = u if len(u) <= 75 else f"{u[:72]}..."
                            st.markdown(f"🔗 [{disp_url}]({u})")

            with col_a:
                st.markdown(f"**📎 Attachments Checked ({len(attachments)}):**")
                if not attachments:
                    st.caption("No attachments found in this email.")
                else:
                    for att in attachments:
                        fname = att.get("filename", "attachment")
                        verd = str(att.get("verdict", "SAFE")).upper()
                        att_icon = "🔴" if "MALICIOUS" in verd else ("🟡" if "SUSPICIOUS" in verd else "🟢")
                        st.markdown(f"{att_icon} `{fname}` — **{verd}**")

            # HTML Steganography & Active Evasion findings (surfaced only if email is not verified safe)
            if not is_safe and html_report and html_report.get("has_evasion"):
                has_deceptive = (
                    html_report.get("microscopic_font_count", 0) > 0
                    or html_report.get("color_matching_count", 0) > 0
                    or html_report.get("deceptive_link_count", 0) > 0
                )
                if has_deceptive:
                    st.markdown("---")
                    st.markdown("**🕵️ Concealed Content & Evasion Warnings:**")
                    if html_report.get("microscopic_font_count", 0) > 0:
                        st.warning(f"Contains {html_report['microscopic_font_count']} block(s) of microscopic text (<3px) hidden from normal view.")
                    if html_report.get("color_matching_count", 0) > 0:
                        st.warning(f"Contains {html_report['color_matching_count']} text element(s) camouflaged against the background.")
                    if html_report.get("deceptive_link_count", 0) > 0:
                        st.error("⚠️ Deceptive Link Warning: Displayed text misleads user to a different website!")

            # Optional collapsed developer data
            with st.expander("⚙️ Show Advanced Technical Logs", expanded=False):
                st.json(rep)

    if run_live_poll:
        with st.spinner(f"Connecting to Gmail API and polling unread mailbox (up to {poll_limit} emails)..."):
            try:
                reports = process_unread_inbox(max_results=poll_limit)
                if not reports:
                    st.info("No unread messages found in your mailbox. Mark an email as unread in Gmail to scan it.")
                    st.session_state["inbox_scan_reports"] = []
                else:
                    st.session_state["inbox_scan_reports"] = reports
                    st.session_state["inbox_scan_source"] = "live"
                    st.session_state["inbox_requested_limit"] = poll_limit
            except Exception as exc:
                st.error(f"Gmail Ingestion Gateway error: {type(exc).__name__}: {exc}")
                st.session_state["inbox_scan_reports"] = None

    elif run_simulated_poll:
        with st.spinner("Simulating live inbox ingestion pipeline..."):
            simulated_emails = [
                {
                    "message_id": "sim_msg_001",
                    "sender": "payroll-alert@secure-payment.cc",
                    "subject": "URGENT: Payroll Verification Failure",
                    "urls": ["http://0x7f000001/verify/account", "https://evil-phish.cc/login"],
                    "url_scores": [
                        {"url": "http://0x7f000001/verify/account", "verdict": "MALICIOUS", "score": 9},
                        {"url": "https://evil-phish.cc/login", "verdict": "MALICIOUS", "score": 10},
                    ],
                    "attachment_reports": [
                        {"filename": "direct_deposit_update.pdf.exe", "verdict": "MALICIOUS", "risk_score": 10}
                    ],
                    "verdict": "MALICIOUS",
                    "risk_score": 10,
                    "html_report": {"has_evasion": True, "microscopic_font_count": 2, "hidden_elements_count": 1},
                },
                {
                    "message_id": "sim_msg_002",
                    "sender": "support-portal@account-updates.net",
                    "subject": "Security Reminder: Review Recent Login Location",
                    "urls": ["https://xzkj9812-verify-account.cc/banking/signin"],
                    "url_scores": [
                        {"url": "https://xzkj9812-verify-account.cc/banking/signin", "verdict": "SUSPICIOUS", "score": 5}
                    ],
                    "attachment_reports": [],
                    "verdict": "SUSPICIOUS",
                    "risk_score": 5,
                    "html_report": {"has_evasion": True, "hidden_elements_count": 1},
                },
                {
                    "message_id": "sim_msg_003",
                    "sender": "newsletter@engineering-weekly.org",
                    "subject": "LexiGuard v1.0 Production Security Architecture Release",
                    "urls": ["https://github.com/google/security-research"],
                    "url_scores": [
                        {"url": "https://github.com/google/security-research", "verdict": "SAFE", "score": 0}
                    ],
                    "attachment_reports": [
                        {"filename": "release_notes_v1.0.pdf", "verdict": "SAFE", "risk_score": 0}
                    ],
                    "verdict": "SAFE",
                    "risk_score": 0,
                    "html_report": {"has_evasion": False},
                },
            ]
            for sim in simulated_emails:
                log_scan(
                    message_id=sim["message_id"],
                    sender=sim["sender"],
                    subject=sim["subject"],
                    verdict=sim["verdict"],
                    risk_score=sim["risk_score"],
                    urls=sim["urls"],
                    excerpt=f"Simulated email subject: {sim['subject']}",
                    extra={"simulated": True},
                )
            st.session_state["inbox_scan_reports"] = simulated_emails
            st.session_state["inbox_scan_source"] = "simulated"
            st.session_state["inbox_requested_limit"] = len(simulated_emails)

    # Render results cleanly outside the spinner
    active_reports = st.session_state.get("inbox_scan_reports")
    if active_reports:
        actual_count = len(active_reports)
        requested_limit = st.session_state.get("inbox_requested_limit", actual_count)
        is_live = st.session_state.get("inbox_scan_source") == "live"

        if is_live:
            if actual_count < requested_limit:
                st.info(
                    f"ℹ️ **Inbox Scan Info:** You selected **{requested_limit}** emails, but your inbox currently has **{actual_count}** unread message(s). All **{actual_count}** unread emails have been analyzed."
                )
            else:
                st.success(f"✅ Successfully processed and analyzed all **{actual_count}** unread message(s) from your live inbox!")
        else:
            st.success(f"Successfully processed {actual_count} message(s) from gateway simulation!")

        st.subheader("📊 Inbox Threat Posture & Inspection Results")
        render_inbox_summary_chart(active_reports)
        st.divider()

        # Compact Quick-Overview Table (View all emails at a glance)
        with st.expander(f"📋 Executive Summary Table ({actual_count} emails)", expanded=True):
            table_rows = []
            for i, r in enumerate(active_reports):
                v_str = str(r.get("verdict", "SAFE")).upper()
                v_icon = "🟢 SAFE" if v_str == "SAFE" else ("🟡 CAUTION" if v_str == "SUSPICIOUS" else "🔴 DANGEROUS")
                table_rows.append({
                    "#": i + 1,
                    "Verdict": v_icon,
                    "Score": f"{r.get('risk_score', 0)}/10",
                    "Sender": (r.get("sender") or "Unknown")[:35],
                    "Subject": (r.get("subject") or "No Subject")[:45],
                    "Links": len(r.get("urls", [])),
                    "Attachments": len(r.get("attachment_reports", [])),
                })
            st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

        st.subheader(f"🔍 Detailed Email Inspection Cards ({actual_count} Total)")

        if actual_count <= 10:
            st.caption(f"Showing all **{actual_count}** scanned emails.")
            for idx, rep in enumerate(active_reports):
                render_email_report_card(idx, rep)
        else:
            total_pages = (actual_count + 9) // 10
            page_options = [
                f"Page {p+1} (Emails #{p*10 + 1}–{min((p+1)*10, actual_count)})"
                for p in range(total_pages)
            ] + [f"View All ({actual_count} Emails)"]

            col_opt1, col_opt2 = st.columns([2, 1])
            with col_opt1:
                selected_option = st.selectbox(
                    "Select View Option:",
                    options=page_options,
                    index=0,
                    key="inbox_view_option_box",
                    help="Switch between pages or view all emails at once.",
                )

            if "View All" in selected_option:
                st.caption(f"Displaying all **{actual_count}** scanned emails in a single view.")
                for idx, rep in enumerate(active_reports):
                    render_email_report_card(idx, rep)
            else:
                p_idx = page_options.index(selected_option)
                start_i = p_idx * 10
                end_i = min(start_i + 10, actual_count)
                st.caption(f"Displaying **Emails #{start_i + 1} to #{end_i}** of **{actual_count}** total.")
                for idx in range(start_i, end_i):
                    render_email_report_card(idx, active_reports[idx])


# =============================================================================
# TAB 5: Incident Response & Webhooks (Phase 5.2)
# =============================================================================
with tab_response:
    st.header("Incident Response & SOAR/SIEM Orchestrator")
    st.caption("Active threat containment, automated Gmail inbox quarantine, and real-time security alerting for SOC workflows.")

    # Top Metrics / Policy Overview
    col_resp_m1, col_resp_m2, col_resp_m3 = st.columns(3)
    with col_resp_m1:
        auto_quarantine_enabled = st.toggle(
            "Auto-Quarantine Active",
            value=True,
            help="When enabled, messages scoring >= threshold or marked MALICIOUS are moved from INBOX into [LexiGuard]/Quarantine.",
        )
    with col_resp_m2:
        quarantine_threshold = st.slider(
            "Quarantine Risk Threshold",
            min_value=5,
            max_value=10,
            value=8,
            help="Compounding risk score at or above which automated quarantine triggers.",
        )
    with col_resp_m3:
        st.markdown(
            f"""
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px; text-align: center;">
                <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Quarantine Folder</div>
                <div style="font-weight: 700; color: #38bdf8; font-size: 1.05rem;">{QUARANTINE_LABEL_NAME}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # Section 1: Multi-Platform Webhook & SIEM Configuration
    st.subheader("📡 Multi-Platform Webhook Endpoints")
    st.caption("Active delivery destinations for real-time security incident alerts (SIEM, Slack, Discord, MS Teams).")

    slack_val = os.environ.get("LEXIGUARD_SLACK_WEBHOOK", "")
    teams_val = os.environ.get("LEXIGUARD_TEAMS_WEBHOOK", "")
    discord_val = os.environ.get("LEXIGUARD_DISCORD_WEBHOOK", "")
    siem_val = os.environ.get("LEXIGUARD_SIEM_WEBHOOK", "https://siem.enterprise.local/api/v1/alerts")

    # Scannable status indicators
    col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
    with col_stat1:
        st.markdown(f"**Slack:** {'<span class=\"status-pill-active\">🟢 ACTIVE</span>' if slack_val else '<span class=\"status-pill-disconnected\">⚪ UNSET</span>'}", unsafe_allow_html=True)
    with col_stat2:
        st.markdown(f"**Discord:** {'<span class=\"status-pill-active\">🟢 ACTIVE</span>' if discord_val else '<span class=\"status-pill-disconnected\">⚪ UNSET</span>'}", unsafe_allow_html=True)
    with col_stat3:
        st.markdown(f"**MS Teams:** {'<span class=\"status-pill-active\">🟢 ACTIVE</span>' if teams_val else '<span class=\"status-pill-disconnected\">⚪ UNSET</span>'}", unsafe_allow_html=True)
    with col_stat4:
        st.markdown(f"**SIEM / SOAR:** {'<span class=\"status-pill-active\">🟢 ACTIVE</span>' if siem_val else '<span class=\"status-pill-disconnected\">⚪ UNSET</span>'}", unsafe_allow_html=True)

    with st.expander("⚙️ Configure Webhook & SIEM Endpoint Secrets", expanded=False):
        st.caption("Endpoints are masked to prevent token leakage. Inputs update live dispatcher destinations.")
        col_wh1, col_wh2 = st.columns(2)
        with col_wh1:
            slack_url = st.text_input(
                "Slack Incoming Webhook URL",
                value=slack_val,
                type="password",
                placeholder="https://hooks.slack.com/services/...",
                help="Dispatches Slack Block Kit formatted alert notifications.",
            )
            teams_url = st.text_input(
                "Microsoft Teams Connector URL",
                value=teams_val,
                type="password",
                placeholder="https://outlook.office.com/webhook/...",
                help="Dispatches Microsoft Teams MessageCard alert notifications.",
            )
        with col_wh2:
            discord_url = st.text_input(
                "Discord Webhook URL",
                value=discord_val,
                type="password",
                placeholder="https://discord.com/api/webhooks/...",
                help="Dispatches Discord rich embed notifications with severity styling.",
            )
            siem_url = st.text_input(
                "Generic SIEM / SOAR Endpoint URL",
                value=siem_val,
                type="password",
                placeholder="https://siem.enterprise.local/api/v1/alerts",
                help="Dispatches RFC-compliant STIX-compatible JSON incident payloads.",
            )
        if slack_url != slack_val:
            os.environ["LEXIGUARD_SLACK_WEBHOOK"] = slack_url
        if teams_url != teams_val:
            os.environ["LEXIGUARD_TEAMS_WEBHOOK"] = teams_url
        if discord_url != discord_val:
            os.environ["LEXIGUARD_DISCORD_WEBHOOK"] = discord_url
        if siem_url != siem_val:
            os.environ["LEXIGUARD_SIEM_WEBHOOK"] = siem_url

    st.divider()

    # Section 2: Interactive Webhook Connectivity Tester
    st.subheader("🧪 Test Webhook Alert Dispatcher")
    st.caption("Broadcast a synthetic high-severity security incident alert to verify network connectivity and payload schemas.")

    col_t1, col_t2, col_t3 = st.columns([2, 1, 1])
    with col_t1:
        test_target = st.selectbox(
            "Target Webhook Destination",
            [
                "Generic SIEM / SOAR Endpoint",
                "Slack Channel",
                "Discord Alert Channel",
                "Microsoft Teams Connector",
                "Broadcast to All Active Endpoints",
            ],
            index=0,
        )
    with col_t2:
        test_severity = st.selectbox(
            "Simulated Severity Tier",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
        )
    with col_t3:
        st.write("")
        st.write("")
        trigger_test = st.button("🚀 Send Test Alert", type="primary", use_container_width=True)

    if trigger_test:
        # Build synthetic test alert
        score_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        verdict_map = {"CRITICAL": "MALICIOUS", "HIGH": "MALICIOUS", "MEDIUM": "SUSPICIOUS", "LOW": "SAFE"}
        test_score = score_map[test_severity]
        test_verdict = verdict_map[test_severity]

        synthetic_report = {
            "incident_id": f"test_inc_{os.urandom(4).hex()}",
            "message_id": f"test_msg_{os.urandom(6).hex()}",
            "sender": "simulated-adversary@evil-gateway.test",
            "subject": "CRITICAL: Security Gateway Diagnostic Alert",
            "verdict": test_verdict,
            "risk_score": test_score,
            "violations": [
                {"code": "IP_LITERAL_HOST", "severity": "high"},
                {"code": "MICROSCOPIC_FONT_EVASION", "severity": "high"},
                {"code": "DOUBLE_EXTENSION_SPOOFING", "severity": "medium"},
            ],
            "cloud_intel": {
                "virustotal": {"verdict": "MALICIOUS", "positives": 14, "total": 70},
                "webrisk": {"verdict": "MALICIOUS"},
            },
            "attachments": [{"filename": "invoice_scan.pdf.exe", "verdict": "MALICIOUS", "risk_score": 10}],
            "html_evasion": {"hidden_elements": 3, "microscopic_fonts": 2},
            "quarantine_applied": auto_quarantine_enabled if test_verdict == "MALICIOUS" else False,
            "remediation_notes": "Diagnostic broadcast test initiated from LexiGuard SecOps Dashboard.",
        }

        # Resolve destination configs
        configs_to_test: list[WebhookConfig] = []
        if test_target == "Generic SIEM / SOAR Endpoint" or test_target == "Broadcast to All Active Endpoints":
            if siem_url.strip():
                configs_to_test.append(WebhookConfig(url=siem_url.strip(), format=WebhookFormat.GENERIC, name="SIEM Listener"))
        if test_target == "Slack Channel" or test_target == "Broadcast to All Active Endpoints":
            if slack_url.strip():
                configs_to_test.append(WebhookConfig(url=slack_url.strip(), format=WebhookFormat.SLACK, name="Slack SOC"))
        if test_target == "Discord Alert Channel" or test_target == "Broadcast to All Active Endpoints":
            if discord_url.strip():
                configs_to_test.append(WebhookConfig(url=discord_url.strip(), format=WebhookFormat.DISCORD, name="Discord Alerts"))
        if test_target == "Microsoft Teams Connector" or test_target == "Broadcast to All Active Endpoints":
            if teams_url.strip():
                configs_to_test.append(WebhookConfig(url=teams_url.strip(), format=WebhookFormat.TEAMS, name="MS Teams Connector"))

        if not configs_to_test:
            st.warning("No valid webhook URL found for the selected destination. Please configure an endpoint URL above.")
        else:
            with st.spinner("Dispatching security alert payload..."):
                alert_obj = SecurityAlert.from_scan_report(synthetic_report)
                results = broadcast_alert(alert_obj, configs_to_test)

                for r in results:
                    name = r.get("webhook_name", "Webhook")
                    if r["success"]:
                        st.success(f"✅ **{name}**: Delivered successfully (HTTP {r.get('status_code', 200)})")
                    else:
                        st.error(f"❌ **{name}**: Delivery failed &bull; {r.get('error', 'Unknown Error')}")

                with st.expander("⚙️ Show Advanced Technical Logs (Dispatched SecurityAlert Payload)", expanded=False):
                    st.json(alert_obj.to_dict())

    st.divider()

    # Section 3: Manual On-Demand Quarantine Action
    st.subheader("📦 Manual Quarantine Action Tool")
    st.caption("Manually move an individual Gmail message to [LexiGuard]/Quarantine by Message ID.")

    col_q1, col_q2 = st.columns([3, 1])
    with col_q1:
        manual_msg_id = st.text_input("Target Gmail Message ID", placeholder="e.g. 18c4f3a1b2d9e0f1")
    with col_q2:
        st.write("")
        st.write("")
        run_manual_quarantine = st.button("🔒 Quarantine Message", use_container_width=True)

    if run_manual_quarantine:
        if not manual_msg_id.strip():
            st.warning("Please enter a valid Gmail Message ID.")
        else:
            try:
                # Attempt to build service from token if available
                if TOKEN_PATH.exists():
                    from google.oauth2.credentials import Credentials
                    from googleapiclient.discovery import build
                    SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
                    creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
                    svc = build("gmail", "v1", credentials=creds)
                    q_res = quarantine_message(manual_msg_id.strip(), svc)
                    if q_res["success"]:
                        st.success(f"Message `{manual_msg_id}` successfully quarantined under label `{q_res['label_name']}` (ID: {q_res['label_id']})")
                    else:
                        st.error(f"Quarantine failed: {q_res.get('error')}")
                else:
                    st.info(f"Gmail token not initialized. In production, this call invokes `quarantine_message('{manual_msg_id}', service)`.")
            except Exception as exc:
                st.error(f"Quarantine execution error: {type(exc).__name__}: {exc}")


# =============================================================================
# TAB 6: Audit Logs & Compliance Export (Phase 5.2 / Option 3)
# =============================================================================
with tab_compliance:
    st.header("Audit Logs & Compliance Reporting")
    st.caption("Immutable SQLite scan audit trail, policy filtering, and one-click compliance export (CSV / HTML / Printable PDF).")

    # Fetch all records for metrics
    all_records = get_recent_scans(limit=1000)
    total_count = len(all_records)
    malicious_count = sum(1 for r in all_records if str(r.get("verdict", "")).upper() == "MALICIOUS")
    suspicious_count = sum(1 for r in all_records if str(r.get("verdict", "")).upper() == "SUSPICIOUS")
    safe_count = sum(1 for r in all_records if str(r.get("verdict", "")).upper() == "SAFE")
    avg_score = (sum(r.get("risk_score", 0) for r in all_records) / total_count) if total_count > 0 else 0.0

    # Metric Banner
    col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
    with col_m1:
        st.metric("Total Audited Events", total_count)
    with col_m2:
        st.metric("🚨 Malicious Incidents", malicious_count)
    with col_m3:
        st.metric("⚠️ Suspicious Alerts", suspicious_count)
    with col_m4:
        st.metric("✅ Verified Safe", safe_count)
    with col_m5:
        st.metric("Average Risk Score", f"{avg_score:.1f}/10")

    st.divider()

    if total_count > 0:
        st.subheader("📈 Organization Threat Posture Overview")
        chart_df = pd.DataFrame([
            {"Verdict": "Safe", "Count": safe_count, "Color": "#10b981"},
            {"Verdict": "Suspicious", "Count": suspicious_count, "Color": "#f59e0b"},
            {"Verdict": "Malicious", "Count": malicious_count, "Color": "#ef4444"},
        ])
        posture_chart = (
            alt.Chart(chart_df)
            .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
            .encode(
                x=alt.X("Verdict:N", title="Security Verdict", sort=["Safe", "Suspicious", "Malicious"]),
                y=alt.Y("Count:Q", title="Total Audited Events", axis=alt.Axis(tickMinStep=1)),
                color=alt.Color("Color:N", scale=None, legend=None),
                tooltip=["Verdict", "Count"],
            )
            .properties(height=180)
        )
        st.altair_chart(posture_chart, use_container_width=True)
        st.divider()

    # Compliance Filtering Toolbar
    col_f1, col_f2, col_f3, col_f4 = st.columns([2, 2, 1, 1])
    with col_f1:
        verdict_filter = st.selectbox(
            "Filter by Verdict",
            ["All Verdicts", "MALICIOUS", "SUSPICIOUS", "SAFE"],
            index=0,
        )
    with col_f2:
        min_score = st.slider("Minimum Risk Score", min_value=0, max_value=10, value=0)
    with col_f3:
        fetch_limit = st.selectbox("Record Limit", [25, 50, 100, 250, 500], index=1)
    with col_f4:
        st.write("")
        st.write("")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()

    # Filtered Records
    filtered_records = []
    for r in all_records:
        v_match = (verdict_filter == "All Verdicts") or (str(r.get("verdict", "")).upper() == verdict_filter)
        s_match = int(r.get("risk_score", 0)) >= min_score
        if v_match and s_match:
            filtered_records.append(r)
        if len(filtered_records) >= fetch_limit:
            break

    # Compliance Export Toolbar
    st.subheader("📥 Export Audit & Compliance Packages")
    st.caption("Generate instant compliance deliverables formatted for security auditors, CISO briefings, and SIEM ingestion.")

    csv_data = export_scans_to_csv(DEFAULT_DB_PATH, limit=fetch_limit)
    html_data = export_scans_to_html_report(DEFAULT_DB_PATH, limit=fetch_limit)

    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        st.download_button(
            label="📊 Download Audit Ledger (CSV)",
            data=csv_data,
            file_name=f"lexiguard_audit_export_limit{fetch_limit}.csv",
            mime="text/csv",
            use_container_width=True,
            help="Raw tabular export suitable for Excel, Splunk HEC, or data analytics.",
        )
    with col_exp2:
        st.download_button(
            label="📄 Download Executive Compliance Report (HTML / PDF)",
            data=html_data,
            file_name=f"lexiguard_compliance_report_limit{fetch_limit}.html",
            mime="text/html",
            use_container_width=True,
            help="Self-contained dark-mode report with risk metrics, severity badges, and print-to-PDF layout.",
        )

    st.divider()

    # Tabular Display
    if not filtered_records:
        st.info("No audit records match the current filter criteria.")
    else:
        st.subheader(f"📋 Audit Ledger ({len(filtered_records)} Records Shown)")
        table_rows = []
        for r in filtered_records:
            table_rows.append({
                "ID": r["id"],
                "Timestamp": r["created_at"],
                "Verdict": r["verdict"],
                "Risk Score": f"{r['risk_score']}/10",
                "Sender": r["sender"] or "N/A",
                "Subject": r["subject"] or r["message_id"],
                "URLs": len(r["urls"]),
            })
        st.dataframe(table_rows, use_container_width=True)

        # Deep Record Inspection Accordion
        st.subheader("🔍 Deep Record Inspection")
        for rec in filtered_records[:15]:
            with st.expander(f"Scan #{rec['id']} — [{rec['verdict']}] {rec['subject']} ({rec['created_at']})"):
                st.markdown(
                    f"**Verdict:** {render_verdict_badge(rec['verdict'])} | **Risk Score:** `{rec['risk_score']}/10`",
                    unsafe_allow_html=True,
                )
                st.write(f"**Message ID:** `{rec['message_id']}`")
                st.write(f"**Sender:** `{rec['sender']}`")
                st.write(f"**Excerpt / Input Payload:**")
                st.code(rec["excerpt"] or "(none)", language="text")
                if rec["urls"]:
                    st.write(f"**Extracted URLs ({len(rec['urls'])}):**")
                    for u in rec["urls"]:
                        st.markdown(f"- `{u}`")
                if rec["extra"]:
                    with st.expander("⚙️ Show Advanced Technical Logs (Forensic Metadata)", expanded=False):
                        st.json(rec["extra"])

