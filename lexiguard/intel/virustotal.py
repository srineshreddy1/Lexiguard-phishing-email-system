"""VirusTotal v3 Cloud Intelligence integration for LexiGuard.

Provides static and API-based consensus lookups for target URLs and file hashes.
Safely falls back to local web permalinks if no API key is provisioned.
"""

from __future__ import annotations

import base64
import os
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import json


def is_virustotal_configured(api_key: str | None = None) -> bool:
    """Check if a valid VirusTotal API key is present in arguments or environment."""
    key = api_key or os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    return bool(key and key.strip())


def get_vt_url_id(url: str) -> str:
    """Encode a URL into the URL identifier format required by VirusTotal v3 API."""
    return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("ascii").strip("=")


def check_url_virustotal(url: str, api_key: str | None = None) -> dict[str, Any]:
    """Query VirusTotal v3 API for URL threat reputation.

    Args:
        url: Target URL to analyze.
        api_key: Optional API key override. If omitted, uses VT_API_KEY env var.

    Returns:
        Structured dictionary with consensus verdicts, stats, and permalinks.
    """
    key = api_key or os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY") or ""
    key = key.strip()
    url_id = get_vt_url_id(url)
    gui_link = f"https://www.virustotal.com/gui/url/{url_id}"

    if not key:
        return {
            "configured": False,
            "verdict": "UNCHECKED",
            "message": "VirusTotal API key not configured (set VT_API_KEY).",
            "gui_link": gui_link,
            "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
            "positives": 0,
            "total": 0,
        }

    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    req = urllib.request.Request(
        api_endpoint,
        headers={
            "x-apikey": key,
            "User-Agent": "LexiGuard-Security-Gateway/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious >= 3:
                verdict = "MALICIOUS"
            elif malicious >= 1 or suspicious >= 2:
                verdict = "SUSPICIOUS"
            elif harmless > 0:
                verdict = "SAFE"
            else:
                verdict = "UNKNOWN"

            return {
                "configured": True,
                "verdict": verdict,
                "message": f"VT consensus: {malicious}/{total} security vendors flagged as malicious.",
                "gui_link": gui_link,
                "stats": stats,
                "positives": malicious,
                "total": total,
                "reputation": attributes.get("reputation", 0),
            }
    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            return {
                "configured": True,
                "verdict": "UNKNOWN",
                "message": "URL not yet analyzed in VirusTotal database.",
                "gui_link": gui_link,
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "positives": 0,
                "total": 0,
            }
        return {
            "configured": True,
            "verdict": "ERROR",
            "message": f"VirusTotal API HTTP {http_err.code}: {http_err.reason}",
            "gui_link": gui_link,
            "stats": {},
            "positives": 0,
            "total": 0,
        }
    except Exception as exc:
        return {
            "configured": True,
            "verdict": "ERROR",
            "message": f"VirusTotal lookup error: {type(exc).__name__}",
            "gui_link": gui_link,
            "stats": {},
            "positives": 0,
            "total": 0,
        }


def check_file_hash_virustotal(sha256: str, api_key: str | None = None) -> dict[str, Any]:
    """Query VirusTotal v3 API for file reputation by SHA-256 hash."""
    key = api_key or os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY") or ""
    key = key.strip()
    gui_link = f"https://www.virustotal.com/gui/file/{sha256}"

    if not key:
        return {
            "configured": False,
            "verdict": "UNCHECKED",
            "message": "VirusTotal API key not configured.",
            "gui_link": gui_link,
            "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
            "positives": 0,
            "total": 0,
        }

    api_endpoint = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(
        api_endpoint,
        headers={"x-apikey": key, "User-Agent": "LexiGuard-Security-Gateway/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious >= 3:
                verdict = "MALICIOUS"
            elif malicious >= 1 or suspicious >= 2:
                verdict = "SUSPICIOUS"
            elif harmless > 0:
                verdict = "SAFE"
            else:
                verdict = "UNKNOWN"

            return {
                "configured": True,
                "verdict": verdict,
                "message": f"VT consensus: {malicious}/{total} security vendors flagged as malicious.",
                "gui_link": gui_link,
                "stats": stats,
                "positives": malicious,
                "total": total,
                "meaningful_name": attributes.get("meaningful_name", ""),
            }
    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            return {
                "configured": True,
                "verdict": "UNKNOWN",
                "message": "Hash not yet indexed in VirusTotal database.",
                "gui_link": gui_link,
                "stats": {},
                "positives": 0,
                "total": 0,
            }
        return {
            "configured": True,
            "verdict": "ERROR",
            "message": f"VirusTotal API HTTP {http_err.code}: {http_err.reason}",
            "gui_link": gui_link,
            "stats": {},
            "positives": 0,
            "total": 0,
        }
    except Exception as exc:
        return {
            "configured": True,
            "verdict": "ERROR",
            "message": f"VirusTotal lookup error: {type(exc).__name__}",
            "gui_link": gui_link,
            "stats": {},
            "positives": 0,
            "total": 0,
        }
