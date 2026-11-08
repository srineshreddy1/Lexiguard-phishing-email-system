"""Unit tests for LexiGuard Plain-English Threat Translator."""

from __future__ import annotations

from lexiguard.ui.translator import (
    explain_risk_score,
    get_plain_english_verdict,
    translate_report,
    translate_violation,
)


class TestTranslateViolation:
    def test_known_violation_codes(self) -> None:
        ip_res = translate_violation("IP_LITERAL_HOST")
        assert ip_res["code"] == "IP_LITERAL_HOST"
        assert "Number Address" in ip_res["title"]
        assert "phishing" in ip_res["tactic"].lower()
        assert len(ip_res["action"]) > 10

        font_res = translate_violation("MICROSCOPIC_FONT_EVASION")
        assert font_res["severity"] == "Critical"
        assert "Micro-Font" in font_res["title"]

        file_res = translate_violation("MAGIC_BYTE_MISMATCH")
        assert file_res["severity"] == "Critical"
        assert "Disguised File" in file_res["title"]

    def test_unknown_dynamic_code_fallback(self) -> None:
        custom_res = translate_violation("CUSTOM_ZERO_DAY_PAYLOAD_DETECTED")
        assert custom_res["code"] == "CUSTOM_ZERO_DAY_PAYLOAD_DETECTED"
        assert "Custom Zero Day Payload Detected" in custom_res["title"]
        assert "Security Anomaly" in custom_res["title"]
        assert custom_res["severity"] == "Medium"


class TestExplainRiskScore:
    def test_malicious_and_high_score(self) -> None:
        info = explain_risk_score(9, "MALICIOUS")
        assert "Danger" in info["verdict_plain"]
        assert info["badge_color"] == "red"
        assert "9/10" in info["summary"]

    def test_suspicious_score(self) -> None:
        info = explain_risk_score(5, "SUSPICIOUS")
        assert "Caution" in info["verdict_plain"]
        assert info["badge_color"] == "amber"

    def test_safe_score(self) -> None:
        info = explain_risk_score(0, "SAFE")
        assert "Safe" in info["verdict_plain"]
        assert info["badge_color"] == "emerald"


class TestGetPlainEnglishVerdict:
    def test_verdict_labels(self) -> None:
        assert "Confirmed Threat" in get_plain_english_verdict("MALICIOUS")
        assert "Suspicious" in get_plain_english_verdict("SUSPICIOUS")
        assert "Verified Safe" in get_plain_english_verdict("SAFE")
        assert "Unclassified" in get_plain_english_verdict("OTHER")


class TestTranslateReport:
    def test_full_report_translation(self) -> None:
        report = {
            "verdict": "MALICIOUS",
            "risk_score": 9,
            "violations": [
                {"code": "IP_LITERAL_HOST", "severity": "high"},
                "MICROSCOPIC_FONT_EVASION",
            ],
        }
        res = translate_report(report)
        assert "Confirmed Threat" in res["verdict_plain"]
        assert res["violation_count"] == 2
        assert len(res["translated_violations"]) == 2
        assert "CRITICAL" in res["key_takeaway"]

    def test_empty_or_invalid_report(self) -> None:
        res = translate_report({})
        assert res["violation_count"] == 0
        assert "SAFE" in res["key_takeaway"]

        non_dict_res = translate_report("bad_input")  # type: ignore[arg-type]
        assert non_dict_res["plain_verdict"] == "Unknown"
