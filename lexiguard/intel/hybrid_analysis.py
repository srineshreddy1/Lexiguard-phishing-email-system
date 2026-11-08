"""Hybrid Analysis (Falcon Sandbox / CrowdStrike) Cloud Intelligence integration for LexiGuard.

Provides live hash & URL threat analysis via Hybrid Analysis API v2.
"""

from __future__ import annotations

import json
import os
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


def is_hybrid_analysis_configured(api_key: str | None = None) -> bool:
    """Check if a valid Hybrid Analysis API key is present."""
    key = api_key or os.environ.get("HYBRID_ANALYSIS_API_KEY")
    return bool(key and key.strip())


def check_hash_hybrid_analysis(
    sha256: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Query Hybrid Analysis v2 API for threat analysis by SHA-256 hash.

    Args:
        sha256: SHA-256 cryptographic hash of the file.
        api_key: Optional API key override. If omitted, uses HYBRID_ANALYSIS_API_KEY env var.

    Returns:
        Structured dictionary with threat score, verdict, and web permalink.
    """
    key = api_key or os.environ.get("HYBRID_ANALYSIS_API_KEY") or ""
    key = key.strip()
    clean_hash = sha256.strip().lower()
    gui_link = f"https://www.hybrid-analysis.com/sample/{clean_hash}"

    if not key:
        return {
            "configured": False,
            "verdict": "UNCHECKED",
            "threat_score": None,
            "message": "Hybrid Analysis API key not configured (set HYBRID_ANALYSIS_API_KEY).",
            "gui_link": gui_link,
        }

    api_endpoint = f"https://www.hybrid-analysis.com/api/v2/overview/{clean_hash}"
    req = urllib.request.Request(
        api_endpoint,
        headers={
            "api-key": key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            threat_score = data.get("threat_score")
            raw_verdict = str(data.get("verdict", "")).lower()

            if raw_verdict == "malicious" or (threat_score is not None and threat_score >= 80):
                verdict = "MALICIOUS"
            elif raw_verdict == "suspicious" or (threat_score is not None and threat_score >= 50):
                verdict = "SUSPICIOUS"
            elif raw_verdict == "whitelisted" or raw_verdict == "no specific threat" or (threat_score is not None and threat_score == 0):
                verdict = "SAFE"
            else:
                verdict = "UNKNOWN"

            return {
                "configured": True,
                "verdict": verdict,
                "threat_score": threat_score,
                "threat_level": data.get("threat_level"),
                "classification_tags": data.get("classification_tags") or [],
                "vx_family": data.get("vx_family"),
                "message": f"Hybrid Analysis threat score: {threat_score}/100 (verdict: {verdict})",
                "gui_link": gui_link,
            }
    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            return {
                "configured": True,
                "verdict": "UNKNOWN",
                "threat_score": None,
                "message": "Hash not yet indexed in Hybrid Analysis database.",
                "gui_link": gui_link,
            }
        return {
            "configured": True,
            "verdict": "ERROR",
            "threat_score": None,
            "message": f"Hybrid Analysis API HTTP {http_err.code}: {http_err.reason}",
            "gui_link": gui_link,
        }
    except Exception as exc:
        return {
            "configured": True,
            "verdict": "ERROR",
            "threat_score": None,
            "message": f"Hybrid Analysis lookup error: {type(exc).__name__}",
            "gui_link": gui_link,
        }
