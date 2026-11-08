"""Unit tests for the LexiGuard risk scoring engine."""

from __future__ import annotations

from lexiguard.features import extract_features
from lexiguard.parser import parse_url
from lexiguard.scorer import Verdict, score_risk


def _result(*severities: str, codes: list[str] | None = None) -> dict:
    violations = []
    for index, severity in enumerate(severities):
        code = (codes[index] if codes and index < len(codes) else f"T{index}")
        violations.append(
            {
                "code": code,
                "severity": severity,
                "message": "test",
                "evidence": {},
            }
        )
    return {"features": {}, "policy_violations": violations}


def test_zero_violations_is_safe() -> None:
    scored = score_risk({"features": {}, "policy_violations": []})
    assert scored["risk_score"] == 0
    assert scored["verdict"] is Verdict.SAFE
    assert scored["summary"]["violation_count"] == 0
    assert scored["summary"]["low"] == 0
    assert scored["summary"]["medium"] == 0
    assert scored["summary"]["high"] == 0


def test_low_weight_is_one_and_not_safe() -> None:
    scored = score_risk(_result("low"))
    assert scored["risk_score"] == 1
    assert scored["verdict"] is Verdict.SUSPICIOUS
    assert scored["summary"]["low"] == 1


def test_medium_weight_is_three_suspicious() -> None:
    scored = score_risk(_result("medium"))
    assert scored["risk_score"] == 3
    assert scored["verdict"] is Verdict.SUSPICIOUS
    assert scored["summary"]["medium"] == 1


def test_single_high_is_five_suspicious() -> None:
    scored = score_risk(_result("high"))
    assert scored["risk_score"] == 5
    assert scored["verdict"] is Verdict.SUSPICIOUS
    assert scored["summary"]["high"] == 1


def test_score_seven_remains_suspicious() -> None:
    scored = score_risk(_result("high", "low", "low"))
    assert scored["risk_score"] == 7
    assert scored["verdict"] is Verdict.SUSPICIOUS


def test_score_eight_is_malicious() -> None:
    scored = score_risk(_result("high", "medium"))
    assert scored["risk_score"] == 8
    assert scored["verdict"] is Verdict.MALICIOUS


def test_two_high_violations_compound_to_malicious() -> None:
    scored = score_risk(_result("high", "high"))
    assert scored["risk_score"] == 10
    assert scored["summary"]["high"] == 2
    assert scored["verdict"] is Verdict.MALICIOUS


def test_severity_matching_is_case_insensitive() -> None:
    scored = score_risk(_result("HIGH", "Medium", "LOW"))
    assert scored["risk_score"] == 9
    assert scored["verdict"] is Verdict.MALICIOUS
    assert scored["summary"]["high"] == 1
    assert scored["summary"]["medium"] == 1
    assert scored["summary"]["low"] == 1


def test_malformed_entries_are_ignored_not_raised() -> None:
    payload = {
        "policy_violations": [
            None,
            "not-a-dict",
            {"code": "X", "message": "missing severity"},
            {"code": "Y", "severity": "critical", "message": "unknown"},
            {"code": "Z", "severity": "high", "message": "ok", "evidence": {}},
        ]
    }
    scored = score_risk(payload)
    assert scored["risk_score"] == 5
    assert scored["verdict"] is Verdict.SUSPICIOUS
    assert scored["summary"]["ignored"] == 4
    assert scored["summary"]["high"] == 1
    assert scored["summary"]["violation_count"] == 1


def test_none_and_non_dict_inputs_are_safe() -> None:
    for bad in (None, "nope", 12, ["list"]):
        scored = score_risk(bad)  # type: ignore[arg-type]
        assert scored["risk_score"] == 0
        assert scored["verdict"] is Verdict.SAFE
        assert scored["summary"]["ignored"] >= 1


def test_missing_policy_key_is_safe() -> None:
    scored = score_risk({"features": {}})
    assert scored["verdict"] is Verdict.SAFE
    assert scored["risk_score"] == 0


def test_non_list_violations_are_safe() -> None:
    scored = score_risk({"policy_violations": {"code": "X"}})
    assert scored["verdict"] is Verdict.SAFE
    assert scored["summary"]["ignored"] == 1


def test_end_to_end_obfuscated_ip_and_keyword() -> None:
    parsed = parse_url("http://0x7f000001/login")
    features = extract_features(parsed)
    scored = score_risk(features)
    # high obfuscated IP (5) + medium keyword (3) = 8 -> MALICIOUS
    assert scored["risk_score"] >= 8
    assert scored["verdict"] is Verdict.MALICIOUS
    assert "OBFUSCATED_IP" in scored["summary"]["contributing_codes"]
    assert "PHISHING_KEYWORD" in scored["summary"]["contributing_codes"]


def test_end_to_end_clean_url_is_safe() -> None:
    parsed = parse_url("https://docs.example.com/guides/intro")
    scored = score_risk(extract_features(parsed))
    assert scored["verdict"] is Verdict.SAFE
    assert scored["risk_score"] == 0


def test_score_result_shape() -> None:
    scored = score_risk(_result("medium"))
    assert set(scored) == {"risk_score", "verdict", "summary"}
    assert isinstance(scored["verdict"], Verdict)
    assert set(scored["summary"]) == {
        "low",
        "medium",
        "high",
        "ignored",
        "violation_count",
        "contributing_codes",
    }
