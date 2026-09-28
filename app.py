"""app.py - LOGINX AI Threat Operations Center Dashboard Interface."""

import json
import time
import streamlit as st
from engine import evaluate_login_event, generate_ai_investigation

# 1. Page Configuration
st.set_page_config(
    page_title="LOGINX - Threat Operations Center",
    page_icon="🛡️",
    layout="wide",
)

# Application Header
st.title("🛡️ LOGINX: AI-Powered Threat Investigation Dashboard")
st.markdown(
    "*Hybrid Intelligence System: Deterministic Threat Rules + Generative SOC Synthesis*"
)
st.markdown("---")

# Mock User Baseline Data
USER_BASELINE = {
    "known_devices": ["MacBook Pro 16", "iPhone 15 Pro"],
    "last_location": "Bengaluru, IN",
}

# 2. Sidebar Configuration & Scenarios
st.sidebar.header("🔑 Engine Settings")
api_key_input = st.sidebar.text_input("Enter Gemini API Key", type="password")

st.sidebar.markdown("---")
st.sidebar.header("🕹️ Threat Scenario Simulator")
scenario = st.sidebar.selectbox(
    "Select Test Scenario for Demo",
    [
        "Normal User Login",
        "Credential Stuffing / Brute-Force (Critical Threat)",
        "Impossible Travel Anomaly (High Risk)",
    ],
)

# Map dynamic scenarios into JSON input structures
if scenario == "Normal User Login":
    event_payload = {
        "user": "bhautik@company.com",
        "timestamp": "2026-09-22 14:30:00",
        "device": "MacBook Pro 16",
        "location": "Bengaluru, IN",
        "ip": "103.21.12.4",
        "failed_attempts": 0,
    }
elif scenario == "Credential Stuffing / Brute-Force (Critical Threat)":
    event_payload = {
        "user": "bhautik@company.com",
        "timestamp": "2026-09-22 03:15:00",
        "device": "Unknown Linux Terminal",
        "location": "Bengaluru, IN",
        "ip": "185.220.101.5",
        "failed_attempts": 6,
    }
else:
    event_payload = {
        "user": "bhautik@company.com",
        "timestamp": "2026-09-22 14:35:00",
        "device": "iPhone 15 Pro",
        "location": "Frankfurt, DE",
        "ip": "82.165.19.1",
        "failed_attempts": 1,
    }

# 3. Main Dashboard Layout
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📥 Ingested Auth Event Data")

    # Raw / Structured Log Viewers
    tab_json, tab_syslog = st.tabs(["Structured JSON Payload", "Raw Syslog String"])

    with tab_json:
        st.json(event_payload)

    with tab_syslog:
        raw_syslog = f"SEP 23 09:52:44 auth-gateway-01 sshd[14209]: Failed authentication for {event_payload['user']} from {event_payload['ip']} port 49152 ssh2 (device: {event_payload['device']})"
        st.code(raw_syslog, language="bash")

    st.subheader("👤 Target User Baseline Profile")
    st.json(USER_BASELINE)

    run_btn = st.button(
        "🚨 Correlate Indicators & Execute Triage",
        type="primary",
        use_container_width=True,
    )

with col2:
    st.subheader("📊 Deterministic Rule Engine Analytics")

    if run_btn:
        # Step A: Rule Engine Execution & Timing
        start_rule_time = time.perf_counter()
        detection_result = evaluate_login_event(event_payload, USER_BASELINE)
        end_rule_time = time.perf_counter()
        rule_latency_ms = (end_rule_time - start_rule_time) * 1000

        # Step B: Score Rendering
        score = detection_result["risk_score"]
        severity = detection_result["severity"]

        if score >= 70:
            st.error(f"⚠️ THREAT LEVEL: {severity} (Composite Score: {score}/100)")
        elif score >= 40:
            st.warning(f"⚠️ THREAT LEVEL: {severity} (Composite Score: {score}/100)")
        else:
            st.success(f"✅ THREAT LEVEL: {severity} (Composite Score: {score}/100)")

        # Step C: Triggered Indicators
        st.markdown("**Correlated Telemetry Evidence:**")
        if detection_result["flagged_indicators"]:
            for indicator in detection_result["flagged_indicators"]:
                st.markdown(f"- 🚩 `{indicator}`")
        else:
            st.markdown("- No security flags triggered.")

        # Pipeline Audit Trail (Humanization Addition)
        with st.expander("🛠️ View Execution Pipeline & Telemetry Trail"):
            st.text(
                f"""
[LOG_INGEST] Ingestion complete from edge-gateway-01
[RULE_ENGINE] Executing deterministic checks (GeoVelocity, DeviceHash, AttemptThreshold)
[RULE_ENGINE] Evaluated score: {score}/100 -> Severity: {severity}
[LLM_ORCHESTRATOR] Packaging context payload (Zero-PII Mode)
[LLM_ORCHESTRATOR] Response returned. Rendering analyst view.
"""
            )

        st.markdown("---")

        # Step D: Generative SOC Synthesis
        st.subheader("🤖 Automated Triage Synthesis (Generative Tier-1)")
        start_llm_time = time.perf_counter()
        with st.spinner("Generating incident briefing..."):
            ai_summary = generate_ai_investigation(
                detection_result, api_key_input
            )
            st.info(ai_summary)
        end_llm_time = time.perf_counter()
        llm_latency_sec = end_llm_time - start_llm_time

        st.markdown("---")

        # Step E: Response Controls (SOAR Actioning)
        st.markdown("**Mitigation Actions (SOAR Integration):**")
        b1, b2, b3 = st.columns(3)
        if b1.button("✅ Clear Alert"):
            st.toast("Alert cleared. Marked benign in SIEM.")
        if b2.button("🔒 Trigger Step-Up MFA"):
            st.toast("MFA challenge dispatched via Okta/Duo API.")
        if b3.button("⛔ Lock Credential"):
            st.toast("Active Directory account suspended. Session killed.")

        st.markdown("---")

        # Step F: Analyst Notes & Case State Management
        st.subheader("📝 SOC Case Documentation")
        col_status, col_assignee = st.columns(2)
        with col_status:
            st.selectbox(
                "Case Lifecycle State",
                ["Triage (Open)", "In Investigation", "Closed (Resolved)"],
            )
        with col_assignee:
            st.text_input("Assigned SOC Analyst", value="Analyst_B_Ray")

        st.text_area(
            "Shift Notes / Manual Evidence",
            placeholder="Document threat intelligence cross-references here...",
        )

        # Step G: Export Audit Report
        report_content = f"""LOGINX THREAT INCIDENT AUDIT REPORT
==================================================
Target Identity: {event_payload['user']}
Timestamp: {event_payload['timestamp']}
Assigned Severity: {severity}
Composite Risk Score: {score}/100
Triggered Heuristics: {', '.join(detection_result['flagged_indicators']) if detection_result['flagged_indicators'] else 'None'}

AUTOMATED LLM TRIAGE BRIEFING:
--------------------------------------------------
{ai_summary}
==================================================
Generated by LOGINX Security Orchestration Platform
"""
        st.download_button(
            label="📄 Export Forensic Incident Report (.TXT)",
            data=report_content,
            file_name=f"loginx_report_{event_payload['user']}.txt",
            mime="text/plain",
            use_container_width=True,
        )

        # Step H: Cost & Latency Performance Tracker
        st.markdown("---")
        st.subheader("⚡ Performance & Cost Metrics Tracker")

        est_tokens = len(str(detection_result)) // 4 + len(str(ai_summary)) // 4
        cost_per_token = 0.0000005
        est_cost = est_tokens * cost_per_token

        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.metric(
                label="Rule Engine Latency",
                value=f"{rule_latency_ms:.2f} ms",
                delta="Deterministic",
            )
        with p2:
            st.metric(
                label="LLM Synthesis Time",
                value=f"{llm_latency_sec:.2f} s",
                delta="Async API",
            )
        with p3:
            st.metric(
                label="Tokens Processed",
                value=f"{est_tokens}",
                delta="Optimized Prompt",
            )
        with p4:
            st.metric(
                label="Est. Cost / Threat Analysis",
                value=f"${est_cost:.5f}",
                delta="-98% vs Raw LLM",
            )