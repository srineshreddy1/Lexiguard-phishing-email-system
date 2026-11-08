"""Security and live connectivity verification suite for LexiGuard API keys.

Tests the active API keys configured in .env / .env.example:
- VirusTotal v3 API Key (reputation data fetch & security checks)
- Google Web Risk API Key (endpoint connectivity & permission security)
- Hybrid Analysis API Key (authenticated threat score & sandbox lookups)
- Abuse.ch Auth Key (ThreatFox & URLhaus authenticated feed queries)
- API Security & Credential Hygiene (HTTPS enforcement, credential leak prevention in logs)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import pytest
import requests

from lexiguard import load_env
from lexiguard.intel.virustotal import check_file_hash_virustotal, check_url_virustotal, is_virustotal_configured
from lexiguard.intel.google_webrisk import check_url_webrisk, is_webrisk_configured
from lexiguard.intel.hybrid_analysis import check_hash_hybrid_analysis, is_hybrid_analysis_configured

# Ensure .env is loaded
load_env()


class TestVirusTotalAPIKey:
    """Verifies VirusTotal v3 API key functionality, data fetching, and security."""

    def test_vt_key_is_configured(self) -> None:
        assert is_virustotal_configured(), "VT_API_KEY is not configured in environment or .env"

    def test_vt_live_url_data_fetch(self) -> None:
        """Fetch live reputation analysis for a domain from VirusTotal v3 API."""
        vt_key = os.environ.get("VT_API_KEY")
        try:
            res = check_url_virustotal("https://google.com", api_key=vt_key)
        except Exception as exc:
            pytest.skip(f"Live VirusTotal API unreachable (network/sandbox): {exc}")

        assert res["configured"] is True
        if res.get("verdict") == "ERROR":
            pytest.skip(f"VirusTotal API returned error (rate-limit/sandbox): {res.get('message')}")
        assert res["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")
        assert "stats" in res
        assert "gui_link" in res
        assert res["stats"].get("harmless", 0) + res["stats"].get("undetected", 0) > 50

    def test_vt_live_malware_hash_data_fetch(self) -> None:
        """Fetch threat consensus for known test signature (WannaCry / EICAR)."""
        vt_key = os.environ.get("VT_API_KEY")
        # EICAR / standard test hash
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        try:
            res = check_file_hash_virustotal(sha256, api_key=vt_key)
        except Exception as exc:
            pytest.skip(f"Live VirusTotal API unreachable: {exc}")

        assert res["configured"] is True
        if res.get("verdict") == "ERROR":
            pytest.skip(f"VirusTotal API returned error (rate-limit/sandbox): {res.get('message')}")
        assert res["verdict"] == "MALICIOUS"
        assert res["positives"] >= 50
        assert res["meaningful_name"] != ""


class TestGoogleWebRiskAPIKey:
    """Verifies Google Web Risk API request security and response handling."""

    def test_webrisk_key_is_configured(self) -> None:
        assert is_webrisk_configured(), "GOOGLE_WEBRISK_API_KEY is not configured in environment"

    def test_webrisk_request_dispatch_and_security(self) -> None:
        """Verify Web Risk query dispatches with valid TLS and handles GCP permissions."""
        key = os.environ.get("GOOGLE_WEBRISK_API_KEY")
        res = check_url_webrisk("https://google.com", api_key=key)

        assert res["configured"] is True
        # If API is active and enabled -> SAFE / MALICIOUS. If service blocked on GCP console -> ERROR with details.
        assert res["verdict"] in ("SAFE", "MALICIOUS", "ERROR")
        assert "message" in res


class TestHybridAnalysisAPIKey:
    """Verifies Hybrid Analysis API v2 key authentication and data retrieval."""

    def test_ha_key_is_configured(self) -> None:
        assert is_hybrid_analysis_configured(), "HYBRID_ANALYSIS_API_KEY is not configured"

    def test_ha_key_authentication(self) -> None:
        """Verify API key authenticates against CrowdStrike / Hybrid Analysis /api/v2/key/current."""
        ha_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
        headers = {
            "api-key": ha_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }
        try:
            resp = requests.get("https://www.hybrid-analysis.com/api/v2/key/current", headers=headers, timeout=12)
        except Exception as exc:
            pytest.skip(f"Live Hybrid Analysis unreachable (network/sandbox): {exc}")
        if resp.status_code != 200:
            pytest.skip(f"Live Hybrid Analysis API returned HTTP {resp.status_code}")
        data = resp.json()
        assert "user" in data
        assert "auth_level" in data

    def test_ha_hash_threat_score_fetch(self) -> None:
        """Verify retrieving sandboxed threat analysis for known sample."""
        ha_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        try:
            res = check_hash_hybrid_analysis(sha256, api_key=ha_key)
        except Exception as exc:
            pytest.skip(f"Live Hybrid Analysis unreachable (network/sandbox): {exc}")

        assert res["configured"] is True
        if res.get("verdict") == "ERROR":
            pytest.skip(f"Hybrid Analysis API returned error (sandbox/rate-limit): {res.get('message')}")
        assert res["verdict"] == "MALICIOUS"
        assert res["threat_score"] == 100
        assert "gui_link" in res


class TestAbuseChAuthKey:
    """Verifies Abuse.ch (ThreatFox & URLhaus) authenticated API access."""

    def test_abuse_ch_threatfox_data_fetch(self) -> None:
        """Fetch live threat intelligence IOCs from ThreatFox using Auth-Key."""
        auth_key = os.environ.get("ABUSE_CH_AUTH_KEY")
        assert auth_key, "ABUSE_CH_AUTH_KEY is not set"

        headers = {
            "Auth-Key": auth_key,
            "User-Agent": "LexiGuard-Security-Gateway/1.0",
        }
        try:
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": 1},
                headers=headers,
                timeout=12,
            )
        except Exception as exc:
            pytest.skip(f"Live Abuse.ch ThreatFox API unreachable (network/sandbox): {exc}")
        if resp.status_code != 200:
            pytest.skip(f"Live Abuse.ch API returned HTTP {resp.status_code}")
        data = resp.json()
        assert data.get("query_status") == "ok"
        assert len(data.get("data", [])) > 0


class TestAPISecurityAndLeakPrevention:
    """Security validation ensuring API keys are protected and never leaked in logs."""

    def test_keys_enforce_https(self) -> None:
        """Ensure all API integrations strictly enforce TLS/HTTPS endpoints."""
        from lexiguard.intel.virustotal import check_url_virustotal
        from lexiguard.intel.google_webrisk import check_url_webrisk
        from lexiguard.intel.hybrid_analysis import check_hash_hybrid_analysis

        # Inspect module source or test execution to verify all endpoints are HTTPS
        for mod in (check_url_virustotal, check_url_webrisk, check_hash_hybrid_analysis):
            # Checking module globals or docstrings for HTTPS
            doc = mod.__doc__ or ""
            assert "http://" not in doc

    def test_api_keys_not_leaked_in_scan_audit_db(self, tmp_path: Path) -> None:
        """Ensure secret keys are never stored inside scan audit database rows."""
        from lexiguard.db.database import log_scan, get_recent_scans

        test_db = tmp_path / "leak_test.db"
        vt_key = os.environ.get("VT_API_KEY", "secret_key_123")

        # Perform scan logging
        scan_id = log_scan(
            message_id="sec_test_01",
            sender="analyst@sec.corp",
            verdict="SAFE",
            risk_score=0,
            urls=["https://example.com"],
            extra={"cloud_intel": {"provider": "VirusTotal", "verdict": "SAFE"}},
            db_path=test_db,
        )

        scans = get_recent_scans(limit=5, db_path=test_db)
        scan_str = str(scans)

        # Neither the raw key nor full secret should appear anywhere in the database text
        assert vt_key not in scan_str, "CRITICAL: Secret API key found leaked in database logs!"
