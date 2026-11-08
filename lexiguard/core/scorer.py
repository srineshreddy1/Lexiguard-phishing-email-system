"""Deterministic risk scoring and verdict engine for LexiGuard.

Consumes Phase 2 ``extract_features`` output. Never performs network I/O.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, TypedDict

SEVERITY_WEIGHTS: dict[str, int] = {
    "low": 1,
    "medium": 3,
    "high": 5,
}

MALICIOUS_SCORE_THRESHOLD = 8
SUSPICIOUS_SCORE_MIN = 3
SUSPICIOUS_SCORE_MAX = 7
COMPOUNDING_HIGH_VIOLATIONS = 2


class Verdict(str, Enum):
    """Categorical outcome of the compounding scoring policy."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class SeveritySummary(TypedDict):
    low: int
    medium: int
    high: int
    ignored: int
    violation_count: int
    contributing_codes: list[str]


class ScoreResult(TypedDict):
    risk_score: int
    verdict: Verdict
    summary: SeveritySummary


def _empty_summary() -> SeveritySummary:
    return {
        "low": 0,
        "medium": 0,
        "high": 0,
        "ignored": 0,
        "violation_count": 0,
        "contributing_codes": [],
    }


def _safe_result(*, ignored: int = 0) -> ScoreResult:
    summary = _empty_summary()
    summary["ignored"] = ignored
    return {
        "risk_score": 0,
        "verdict": Verdict.SAFE,
        "summary": summary,
    }


def _normalize_severity(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in SEVERITY_WEIGHTS:
        return normalized
    return None


def _iter_violations(feature_result: dict[str, Any]) -> list[Any]:
    raw = feature_result.get("policy_violations", [])
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    return None  # type: ignore[return-value]


def _decide_verdict(
    risk_score: int,
    high_count: int,
    contributing_codes: list[str] | None = None,
    *,
    intel_verdict: str | None = None,
    threat_intel_clean: bool = False,
    auth_verified: bool = False,
    is_trusted_domain: bool = False,
    has_auth_failure: bool = False,
    has_spoofing_indicators: bool = False,
) -> Verdict:
    """Evaluate final verdict according to Universal Authentication & Strict Heuristic Escalation."""
    # 1. External Threat Intelligence Override (VirusTotal, WebRisk, Abuse.ch)
    if intel_verdict:
        iv = intel_verdict.strip().upper()
        if iv == "MALICIOUS":
            return Verdict.MALICIOUS
        if iv == "SUSPICIOUS":
            return Verdict.SUSPICIOUS
        if iv in ("SAFE", "CLEAN"):
            threat_intel_clean = True

    # 2. Critical score or compounding high violations
    if risk_score >= MALICIOUS_SCORE_THRESHOLD or high_count >= COMPOUNDING_HIGH_VIOLATIONS:
        return Verdict.MALICIOUS
    if risk_score == 0:
        return Verdict.SAFE

    # 3. Domain Spoofing & Deceptive Evasion Indicators
    codes = set(contributing_codes or [])
    has_spoofing = has_spoofing_indicators or bool(codes.intersection({
        "OBFUSCATED_IP",
        "HEX_OCTAL_IP_ENCODING",
        "BACKSLASH_CONFUSION",
        "BACKSLASH_DELIMITER_CONFUSION",
        "PUNYCODE_HOMOGLYPH",
        "INVALID_PARSE_INPUT",
        "DECEPTIVE_ANCHOR_TEXT",
    }))

    # 4. Strict Heuristic Escalation for Keywords (e.g., /login, /verify, account-verify):
    # Keywords trigger SUSPICIOUS/MALICIOUS ONLY if:
    # - Threat intel explicitly flags the URL as suspicious/malicious, OR
    # - SPF/DKIM fails or domain spoofing is present, OR
    # - Deceptive evasion techniques are used.
    if codes == {"PHISHING_KEYWORD"}:
        if not has_auth_failure and not has_spoofing:
            return Verdict.SAFE

    # 5. Universal Authentication & Clean Threat Intel Override:
    # If external threat intelligence is clean and authentication is verified (or trusted),
    # never allow non-critical heuristics without spoofing to escalate to SUSPICIOUS.
    if (threat_intel_clean or auth_verified or is_trusted_domain) and not has_spoofing and high_count == 0:
        return Verdict.SAFE

    # Non-zero remainder: score 1–2 (lows only) or 3–7 / any medium|high.
    return Verdict.SUSPICIOUS


def score_risk(
    feature_result: dict[str, Any] | None,
    *,
    intel_verdict: str | None = None,
    threat_intel_clean: bool = False,
    auth_verified: bool = False,
    is_trusted_domain: bool = False,
    has_auth_failure: bool = False,
    has_spoofing_indicators: bool = False,
) -> ScoreResult:
    """Map Phase 2 policy violations to a deterministic score and verdict.

    Malformed input never raises. Missing or unusable violation lists are
    treated as zero violations (SAFE, score 0) and recorded in ``summary``.
    """
    try:
        if feature_result is None or not isinstance(feature_result, dict):
            return _safe_result(ignored=1)

        violations = _iter_violations(feature_result)
        if violations is None:
            return _safe_result(ignored=1)

        summary = _empty_summary()
        risk_score = 0
        codes: list[str] = []

        for item in violations:
            if not isinstance(item, dict):
                summary["ignored"] += 1
                continue

            severity = _normalize_severity(item.get("severity"))
            if severity is None:
                summary["ignored"] += 1
                continue

            summary[severity] += 1  # type: ignore[literal-required]
            summary["violation_count"] += 1
            risk_score += SEVERITY_WEIGHTS[severity]

            code = item.get("code")
            if isinstance(code, str) and code and code not in codes:
                codes.append(code)

        summary["contributing_codes"] = codes
        verdict = _decide_verdict(
            risk_score,
            summary["high"],
            codes,
            intel_verdict=intel_verdict,
            threat_intel_clean=threat_intel_clean,
            auth_verified=auth_verified,
            is_trusted_domain=is_trusted_domain,
            has_auth_failure=has_auth_failure,
            has_spoofing_indicators=has_spoofing_indicators,
        )

        # Normalize score if verdict was ruled SAFE via Universal Trust or lack of spoofing
        if verdict == Verdict.SAFE and risk_score > 2:
            is_clean_context = auth_verified or threat_intel_clean or is_trusted_domain or not has_spoofing_indicators
            risk_score = 0 if is_clean_context else min(risk_score, 2)

        return {
            "risk_score": risk_score,
            "verdict": verdict,
            "summary": summary,
        }
    except Exception:  # noqa: BLE001 — CLI must never crash on bad analysis input
        return _safe_result(ignored=1)
