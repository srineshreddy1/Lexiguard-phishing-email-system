"""Unit tests for the LexiGuard local URL parser.

These tests exercise static parsing only. They never open sockets or fetch URLs.
"""

from __future__ import annotations

import pytest

from lexiguard.parser import MAX_URL_LENGTH, WarningCode, parse_url


def _codes(result: dict) -> list[str]:
    return [item["code"] for item in result["warnings"]]


def test_ordinary_https_url_preserves_components_without_high_risk_warnings() -> None:
    raw = "https://www.example.com/login?next=/home#section"
    result = parse_url(raw)

    assert result["raw"] == raw
    assert result["normalized"] == raw
    assert result["scheme"] == "https"
    assert result["host"] == "www.example.com"
    assert result["host_ascii"] == "www.example.com"
    assert result["path"] == "/login"
    assert result["query"] == "next=/home"
    assert result["fragment"] == "section"
    assert result["port"] is None
    assert result["is_ip_literal"] is False
    assert result["has_embedded_credentials"] is False
    assert WarningCode.MISSING_SCHEME not in _codes(result)
    assert WarningCode.EMBEDDED_CREDENTIALS not in _codes(result)
    assert WarningCode.IP_LITERAL_HOST not in _codes(result)
    assert WarningCode.UNUSUAL_PORT not in _codes(result)


def test_ordinary_http_url_with_standard_port_80_is_not_unusual() -> None:
    result = parse_url("http://example.com:80/index.html")

    assert result["scheme"] == "http"
    assert result["host"] == "example.com"
    assert result["port"] == 80
    assert WarningCode.UNUSUAL_PORT not in _codes(result)
    assert WarningCode.SCHEME_PORT_MISMATCH not in _codes(result)


def test_missing_scheme_defaults_to_http_and_preserves_raw() -> None:
    raw = "example.com/reset-password"
    result = parse_url(raw)

    assert result["raw"] == raw
    assert result["normalized"] == "http://example.com/reset-password"
    assert result["scheme"] == "http"
    assert result["host"] == "example.com"
    assert result["path"] == "/reset-password"
    assert WarningCode.MISSING_SCHEME in _codes(result)


def test_protocol_relative_url_defaults_to_http_scheme() -> None:
    raw = "//cdn.example.com/app.js"
    result = parse_url(raw)

    assert result["raw"] == raw
    assert result["normalized"] == "http://cdn.example.com/app.js"
    assert result["host"] == "cdn.example.com"
    assert WarningCode.MISSING_SCHEME in _codes(result)


def test_missing_scheme_does_not_rewrite_already_schemed_urls() -> None:
    raw = "HTTPS://Example.COM/a"
    result = parse_url(raw)

    assert result["raw"] == raw
    assert result["normalized"] == raw
    assert result["scheme"] == "https"
    assert result["host"] == "example.com"
    assert WarningCode.MISSING_SCHEME not in _codes(result)


def test_embedded_credentials_userinfo_are_detected_and_password_is_redacted() -> None:
    raw = "https://alice:secret@example.com/mail"
    result = parse_url(raw)

    assert result["has_embedded_credentials"] is True
    assert result["username"] == "alice"
    assert result["has_password"] is True
    assert "secret" not in result.values()
    assert "secret" not in str(result["warnings"])
    assert WarningCode.EMBEDDED_CREDENTIALS in _codes(result)
    cred_warning = next(
        item for item in result["warnings"] if item["code"] == WarningCode.EMBEDDED_CREDENTIALS
    )
    assert cred_warning["severity"] == "high"
    assert cred_warning["evidence"]["has_password"] is True


def test_embedded_credentials_decoy_domain_as_username() -> None:
    """Classic cloaking: visible 'paypal.com' is userinfo, real host is elsewhere."""
    raw = "https://paypal.com@evil.example/login"
    result = parse_url(raw)

    assert result["has_embedded_credentials"] is True
    assert result["username"] == "paypal.com"
    assert result["host"] == "evil.example"
    assert result["has_password"] is False
    assert WarningCode.EMBEDDED_CREDENTIALS in _codes(result)


def test_ipv4_literal_host_is_flagged() -> None:
    raw = "http://192.0.2.10/wp-login.php"
    result = parse_url(raw)

    assert result["host"] == "192.0.2.10"
    assert result["is_ip_literal"] is True
    assert result["ip_version"] == 4
    assert result["host_ascii"] == "192.0.2.10"
    assert WarningCode.IP_LITERAL_HOST in _codes(result)
    assert WarningCode.PUNYCODE_HOST not in _codes(result)
    assert WarningCode.IDN_HOST not in _codes(result)


def test_ipv6_literal_host_is_flagged() -> None:
    raw = "http://[2001:db8::1]/status"
    result = parse_url(raw)

    assert result["is_ip_literal"] is True
    assert result["ip_version"] == 6
    assert result["host"] == "2001:db8::1"
    assert result["path"] == "/status"
    assert WarningCode.IP_LITERAL_HOST in _codes(result)


def test_unusual_port_is_flagged() -> None:
    raw = "https://example.com:8443/admin"
    result = parse_url(raw)

    assert result["port"] == 8443
    assert WarningCode.UNUSUAL_PORT in _codes(result)
    assert WarningCode.SCHEME_PORT_MISMATCH in _codes(result)


def test_https_on_port_443_is_not_unusual() -> None:
    result = parse_url("https://example.com:443/")

    assert result["port"] == 443
    assert WarningCode.UNUSUAL_PORT not in _codes(result)
    assert WarningCode.SCHEME_PORT_MISMATCH not in _codes(result)


def test_http_on_non_default_standard_port_443_is_mismatch_but_not_unusual() -> None:
    result = parse_url("http://example.com:443/")

    assert result["port"] == 443
    assert WarningCode.UNUSUAL_PORT not in _codes(result)
    assert WarningCode.SCHEME_PORT_MISMATCH in _codes(result)


def test_invalid_port_emits_invalid_port_warning() -> None:
    result = parse_url("http://example.com:99999/")

    assert result["port"] is None
    assert WarningCode.INVALID_PORT in _codes(result)


def test_punycode_hostname_is_decoded_via_idna() -> None:
    raw = "http://xn--bcher-kva.example/catalog"
    result = parse_url(raw)

    assert result["host"] == "xn--bcher-kva.example"
    assert result["host_ascii"] == "xn--bcher-kva.example"
    assert result["host_unicode"] == "bücher.example"
    assert WarningCode.PUNYCODE_HOST in _codes(result)
    puny = next(item for item in result["warnings"] if item["code"] == WarningCode.PUNYCODE_HOST)
    assert puny["evidence"]["host_unicode"] == "bücher.example"


def test_unicode_idn_hostname_is_encoded_via_idna() -> None:
    raw = "http://münchen.example/tickets"
    result = parse_url(raw)

    assert result["host"] == "münchen.example"
    assert result["host_ascii"] == "xn--mnchen-3ya.example"
    assert result["host_unicode"] == "münchen.example"
    assert WarningCode.IDN_HOST in _codes(result)
    assert WarningCode.PUNYCODE_HOST not in _codes(result)


def test_empty_and_whitespace_inputs() -> None:
    empty = parse_url("")
    blank = parse_url("   ")

    assert empty["host"] is None
    assert WarningCode.EMPTY_INPUT in _codes(empty)
    assert WarningCode.EMPTY_INPUT in _codes(blank)
    assert blank["raw"] == "   "


def test_none_input_returns_empty_input_warning() -> None:
    result = parse_url(None)

    assert result["raw"] == ""
    assert WarningCode.EMPTY_INPUT in _codes(result)


def test_non_string_input_is_coerced() -> None:
    result = parse_url(12345)

    assert result["raw"] == "12345"
    assert WarningCode.INVALID_TYPE in _codes(result)
    assert WarningCode.MISSING_SCHEME in _codes(result)


def test_oversized_input_is_rejected_without_parsing() -> None:
    raw = "http://example.com/" + ("a" * (MAX_URL_LENGTH))
    result = parse_url(raw)

    assert len(raw) > MAX_URL_LENGTH
    assert result["normalized"] is None
    assert result["host"] is None
    assert WarningCode.INPUT_TOO_LONG in _codes(result)


def test_empty_host_warning_for_scheme_only() -> None:
    result = parse_url("http:///path-only")

    assert result["path"] == "/path-only"
    assert WarningCode.EMPTY_HOST in _codes(result)


def test_ipv6_literal_with_unusual_port() -> None:
    result = parse_url("https://[2001:db8::8]:8080/health")

    assert result["is_ip_literal"] is True
    assert result["ip_version"] == 6
    assert result["port"] == 8080
    assert WarningCode.IP_LITERAL_HOST in _codes(result)
    assert WarningCode.UNUSUAL_PORT in _codes(result)


def test_raw_string_is_never_mutated_when_scheme_is_injected() -> None:
    raw = "  phishing-target.example/login  "
    result = parse_url(raw)

    assert result["raw"] == raw
    assert result["normalized"] == "http://phishing-target.example/login"
    assert result["host"] == "phishing-target.example"


def test_warning_records_have_required_shape() -> None:
    result = parse_url("example.com:8080")

    assert result["warnings"]
    for item in result["warnings"]:
        assert set(item) == {"code", "severity", "message", "evidence"}
        assert isinstance(item["evidence"], dict)
        assert item["severity"] in {"low", "medium", "high"}


@pytest.mark.parametrize(
    "raw,expected_host",
    [
        ("http://EXAMPLE.COM", "example.com"),
        ("http://example.com.", "example.com"),
        ("http://127.0.0.1", "127.0.0.1"),
    ],
)
def test_host_normalization_cases(raw: str, expected_host: str) -> None:
    result = parse_url(raw)
    assert result["host"] == expected_host
