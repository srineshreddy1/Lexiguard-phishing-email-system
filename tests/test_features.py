"""Unit tests for LexiGuard feature extraction and policy checks."""

from __future__ import annotations

from lexiguard.features import PolicyCode, extract_features
from lexiguard.parser import parse_url


def _codes(result: dict) -> list[str]:
    return [item["code"] for item in result["policy_violations"]]


def test_quantitative_features_for_ordinary_hostname() -> None:
    parsed = parse_url("https://login.mail.example.com/inbox?ref=home")
    result = extract_features(parsed)
    features = result["features"]

    assert features["hostname_length"] == len("login.mail.example.com")
    assert features["path_length"] == len("/inbox")
    assert features["query_length"] == len("ref=home")
    assert features["label_count"] == 4
    assert features["hostname_depth"] == 4
    assert features["subdomain_count"] == 2
    assert features["dot_count"] == 3
    assert features["hyphen_count"] == 0
    assert features["digit_count"] == 0
    assert features["percent_encoding_count"] == 0
    assert features["shannon_entropy"] > 0
    assert isinstance(features["shannon_entropy"], float)


def test_hyphen_digit_and_percent_encoding_counts() -> None:
    parsed = parse_url("https://a1-b2.example.com/reset%20now?q=%2Flogin")
    features = extract_features(parsed)["features"]

    assert features["hyphen_count"] == 1
    assert features["digit_count"] == 2
    assert features["percent_encoding_count"] >= 2


def test_hex_dword_obfuscated_ip_policy() -> None:
    parsed = parse_url("http://0x7f000001/hidden")
    result = extract_features(parsed)

    assert PolicyCode.OBFUSCATED_IP in _codes(result)
    warning = next(item for item in result["policy_violations"] if item["code"] == PolicyCode.OBFUSCATED_IP)
    assert warning["severity"] == "high"
    assert warning["evidence"]["canonical_ipv4"] == "127.0.0.1"
    assert warning["evidence"]["form"] == "hex_dword"


def test_decimal_dword_obfuscated_ip_policy() -> None:
    parsed = parse_url("http://2130706433/")
    result = extract_features(parsed)

    assert PolicyCode.OBFUSCATED_IP in _codes(result)
    warning = next(item for item in result["policy_violations"] if item["code"] == PolicyCode.OBFUSCATED_IP)
    assert warning["evidence"]["canonical_ipv4"] == "127.0.0.1"
    assert warning["evidence"]["form"] == "decimal_dword"


def test_dotted_octal_obfuscated_ip_policy() -> None:
    parsed = parse_url("http://0177.0.0.1/admin")
    result = extract_features(parsed)

    assert PolicyCode.OBFUSCATED_IP in _codes(result)
    warning = next(item for item in result["policy_violations"] if item["code"] == PolicyCode.OBFUSCATED_IP)
    assert warning["evidence"]["canonical_ipv4"] == "127.0.0.1"
    assert "octal" in warning["evidence"]["notations"]


def test_dotted_hex_obfuscated_ip_policy() -> None:
    parsed = parse_url("http://0x7f.0x0.0x0.0x1/")
    result = extract_features(parsed)

    assert PolicyCode.OBFUSCATED_IP in _codes(result)
    warning = next(item for item in result["policy_violations"] if item["code"] == PolicyCode.OBFUSCATED_IP)
    assert warning["evidence"]["canonical_ipv4"] == "127.0.0.1"


def test_canonical_dotted_ip_is_not_obfuscated_policy() -> None:
    parsed = parse_url("http://192.0.2.10/login")
    result = extract_features(parsed)

    assert parsed["is_ip_literal"] is True
    assert PolicyCode.OBFUSCATED_IP not in _codes(result)


def test_backslash_confusion_in_raw_url() -> None:
    parsed = parse_url(r"http://example.com\evil.example/path")
    # Parser may drop or keep the slash; policy still inspects raw.
    parsed["raw"] = r"http://example.com\evil.example/path"
    result = extract_features(parsed)

    assert PolicyCode.BACKSLASH_CONFUSION in _codes(result)
    warning = next(
        item for item in result["policy_violations"] if item["code"] == PolicyCode.BACKSLASH_CONFUSION
    )
    assert warning["severity"] == "high"
    assert "raw" in warning["evidence"]["fields"]


def test_phishing_keywords_in_path_and_query() -> None:
    parsed = parse_url("https://example.com/secure/verify-account?update=1&signin=true")
    result = extract_features(parsed)

    assert PolicyCode.PHISHING_KEYWORD in _codes(result)
    warning = next(
        item for item in result["policy_violations"] if item["code"] == PolicyCode.PHISHING_KEYWORD
    )
    assert warning["severity"] == "medium"
    matched = set(warning["evidence"]["matched_terms"])
    assert {"secure", "verify", "account", "update", "signin"} <= matched


def test_percent_encoded_keyword_is_detected_after_local_decode() -> None:
    parsed = parse_url("https://example.com/%6cogin")
    result = extract_features(parsed)

    assert PolicyCode.PHISHING_KEYWORD in _codes(result)
    warning = next(
        item for item in result["policy_violations"] if item["code"] == PolicyCode.PHISHING_KEYWORD
    )
    assert "login" in warning["evidence"]["matched_terms"]


def test_banking_keyword_logged() -> None:
    parsed = parse_url("https://example.com/online-banking")
    result = extract_features(parsed)
    warning = next(
        item for item in result["policy_violations"] if item["code"] == PolicyCode.PHISHING_KEYWORD
    )
    assert warning["evidence"]["matched_terms"] == ["banking"]


def test_ordinary_url_without_policy_hits() -> None:
    parsed = parse_url("https://docs.example.com/guides/intro")
    result = extract_features(parsed)
    assert result["policy_violations"] == []


def test_ip_literal_has_zero_subdomain_depth() -> None:
    parsed = parse_url("http://192.0.2.1/index")
    features = extract_features(parsed)["features"]
    assert features["subdomain_count"] == 0
    assert features["hostname_depth"] == 0
    assert features["label_count"] == 0


def test_invalid_input_does_not_raise() -> None:
    result = extract_features(None)  # type: ignore[arg-type]
    assert result["features"]["hostname_length"] == 0
    assert PolicyCode.INVALID_PARSE_INPUT in _codes(result)


def test_violation_shape_matches_phase1() -> None:
    parsed = parse_url("http://0x7f000001/login")
    result = extract_features(parsed)
    assert result["policy_violations"]
    for item in result["policy_violations"]:
        assert set(item) == {"code", "severity", "message", "evidence"}
        assert isinstance(item["evidence"], dict)
