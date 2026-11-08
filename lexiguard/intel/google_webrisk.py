"""Google Web Risk Cloud Intelligence integration for LexiGuard.

Provides live threat categorization checks against Google Safe Browsing / Web Risk
threat feeds (Malware, Social Engineering / Phishing, Unwanted Software).
"""

from __future__ import annotations

import json
import os
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


def is_webrisk_configured(api_key: str | None = None) -> bool:
    """Check if a valid Google Web Risk API key is configured."""
    key = api_key or os.environ.get("WEBRISK_API_KEY") or os.environ.get("GOOGLE_WEBRISK_API_KEY")
    return bool(key and key.strip())


def check_url_webrisk(url: str, api_key: str | None = None) -> dict[str, Any]:
    """Query Google Web Risk API for a target URI.

    Args:
        url: Target URI to query.
        api_key: Optional API key override.

    Returns:
        Structured result with threat types and categorical verdict.
    """
    key = api_key or os.environ.get("WEBRISK_API_KEY") or os.environ.get("GOOGLE_WEBRISK_API_KEY") or ""
    key = key.strip()

    if not key:
        return {
            "configured": False,
            "verdict": "UNCHECKED",
            "message": "Google Web Risk API key not configured (set WEBRISK_API_KEY).",
            "threat_types": [],
            "is_threat": False,
        }

    params = [
        ("uri", url.strip()),
        ("threatTypes", "MALWARE"),
        ("threatTypes", "SOCIAL_ENGINEERING"),
        ("threatTypes", "UNWANTED_SOFTWARE"),
        ("key", key),
    ]
    query_string = urllib.parse.urlencode(params)
    api_endpoint = f"https://webrisk.googleapis.com/v1/uris:search?{query_string}"

    req = urllib.request.Request(
        api_endpoint,
        headers={"User-Agent": "LexiGuard-Security-Gateway/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            threat = data.get("threat")
            if threat:
                threat_types = threat.get("threatTypes", [])
                expire_time = threat.get("expireTime", "")
                return {
                    "configured": True,
                    "verdict": "MALICIOUS",
                    "is_threat": True,
                    "threat_types": threat_types,
                    "expire_time": expire_time,
                    "message": f"Google Web Risk flagged threat: {', '.join(threat_types)}",
                }
            else:
                return {
                    "configured": True,
                    "verdict": "SAFE",
                    "is_threat": False,
                    "threat_types": [],
                    "message": "No threats identified in Google Web Risk database.",
                }
    except urllib.error.HTTPError as http_err:
        return {
            "configured": True,
            "verdict": "ERROR",
            "is_threat": False,
            "threat_types": [],
            "message": f"Google Web Risk API HTTP {http_err.code}: {http_err.reason}",
        }
    except Exception as exc:
        return {
            "configured": True,
            "verdict": "ERROR",
            "is_threat": False,
            "threat_types": [],
            "message": f"Google Web Risk lookup error: {type(exc).__name__}",
        }
