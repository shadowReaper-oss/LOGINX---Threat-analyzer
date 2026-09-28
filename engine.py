"""engine.py - Core Rule Evaluation Engine and LLM Synthesis Adapter for LOGINX."""

import json
import re
from datetime import datetime
from google import genai
from google.genai import types


def evaluate_login_event(event_payload: dict, user_baseline: dict) -> dict:
    """Evaluates login authentication events using deterministic threat heuristics.

    Returns risk score, severity level, and triggered rule indicators.
    """
    risk_score = 0
    flagged_indicators = []

    # 1. Device Anomaly Check
    incoming_device = event_payload.get("device", "Unknown")
    if incoming_device not in user_baseline.get("known_devices", []):
        risk_score += 30
        flagged_indicators.append(
            f"UNRECOGNIZED_DEVICE: Auth request from unregistered endpoint ({incoming_device})"
        )

    # 2. Location & Geo-Velocity Anomaly Check
    incoming_location = event_payload.get("location", "Unknown")
    last_known_location = user_baseline.get("last_location", "")
    if incoming_location != last_known_location:
        risk_score += 35
        flagged_indicators.append(
            f"IMPOSSIBLE_TRAVEL_GEO_ANOMALY: Location mismatch ({last_known_location} -> {incoming_location})"
        )

    # 3. Failed Attempt / Brute-Force Threshold Check
    failed_attempts = event_payload.get("failed_attempts", 0)
    if failed_attempts >= 5:
        risk_score += 40
        flagged_indicators.append(
            f"BRUTE_FORCE_PATTERN: Spike in failed credentials ({failed_attempts} sequential failures)"
        )
    elif failed_attempts > 1:
        risk_score += 15
        flagged_indicators.append(
            f"ELEVATED_AUTH_FAILURES: Repeated authentication errors ({failed_attempts} attempts)"
        )

    # 4. Cap Risk Score
    risk_score = min(risk_score, 100)

    # 5. Determine Severity Mapping
    if risk_score >= 70:
        severity = "CRITICAL"
    elif risk_score >= 40:
        severity = "HIGH"
    elif risk_score >= 20:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "flagged_indicators": flagged_indicators,
        "evaluation_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "raw_payload": event_payload,
    }


def generate_ai_investigation(
    detection_result: dict, api_key: str = None
) -> str:
    """Calls Gemini API via Google GenAI SDK to produce a SOC Tier-1 Threat Synthesis."""
    if not api_key:
        return (
            "⚠️ DEMO MODE (API Key Not Provided): Deterministic rule engine flagged "
            f"{len(detection_result['flagged_indicators'])} threat indicators with Severity Level "
            f"[{detection_result['severity']}]. Please supply a Gemini API Key in the sidebar for full automated LLM analysis."
        )

    try:
        # Initialize Google GenAI SDK client
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are an expert SOC Analyst Tier-3. Synthesize the following rule engine telemetry into a formal Incident Triage Brief.

EVIDENCE DATA:
- Risk Score: {detection_result['risk_score']}/100
- Severity Level: {detection_result['severity']}
- Triggered Rule Indicators: {json.dumps(detection_result['flagged_indicators'])}
- Raw Context Log: {json.dumps(detection_result['raw_payload'])}

REQUIREMENTS:
1. Provide a 2-sentence Incident Summary explaining what happened.
2. Highlight key risk vectors (IP, Device, Geo-Velocity).
3. Recommend immediate mitigation steps for the SOC team.
Keep output technical, clear, and high-density. Do not use generic filler text.
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=300,
            ),
        )
        return response.text

    except Exception as e:
        return f"❌ Threat Synthesis Failed (API Error): {str(e)}"