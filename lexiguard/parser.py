"""Secure, fully local URL parser for LexiGuard static analysis.

This module never performs network I/O, DNS resolution, or URL rendering.
It only tokenizes a caller-supplied string and records structured evidence.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, TypedDict
from urllib.parse import urlparse

import idna
from idna.core import IDNAError

# Hard cap to bound memory/CPU on adversarial input. Analysis is static only.
MAX_URL_LENGTH = 8192

# Ports that are ordinary for browser HTTP(S). Any other explicit port is unusual.
STANDARD_WEB_PORTS = frozenset({80, 443})

SCHEME_DEFAULT_PORT = {
    "http": 80,
    "https": 443,
}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)


class WarningRecord(TypedDict):
    code: str
    severity: str
    message: str
    evidence: dict[str, Any]


class ParseResult(TypedDict):
    raw: str
    normalized: str | None
    scheme: str | None
    username: str | None
    has_password: bool
    host: str | None
    host_ascii: str | None
    host_unicode: str | None
    port: int | None
    path: str
    query: str
    fragment: str
    is_ip_literal: bool
    ip_version: int | None
    has_embedded_credentials: bool
    warnings: list[WarningRecord]


class WarningCode:
    EMPTY_INPUT = "EMPTY_INPUT"
    INPUT_TOO_LONG = "INPUT_TOO_LONG"
    INVALID_TYPE = "INVALID_TYPE"
    MISSING_SCHEME = "MISSING_SCHEME"
    EMBEDDED_CREDENTIALS = "EMBEDDED_CREDENTIALS"
    IP_LITERAL_HOST = "IP_LITERAL_HOST"
    UNUSUAL_PORT = "UNUSUAL_PORT"
    SCHEME_PORT_MISMATCH = "SCHEME_PORT_MISMATCH"
    INVALID_PORT = "INVALID_PORT"
    PUNYCODE_HOST = "PUNYCODE_HOST"
    IDN_HOST = "IDN_HOST"
    IDNA_ERROR = "IDNA_ERROR"
    EMPTY_HOST = "EMPTY_HOST"


def _warning(
    code: str,
    severity: str,
    message: str,
    **evidence: Any,
) -> WarningRecord:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "evidence": dict(evidence),
    }


def _empty_result(raw: str, warnings: list[WarningRecord]) -> ParseResult:
    return {
        "raw": raw,
        "normalized": None,
        "scheme": None,
        "username": None,
        "has_password": False,
        "host": None,
        "host_ascii": None,
        "host_unicode": None,
        "port": None,
        "path": "",
        "query": "",
        "fragment": "",
        "is_ip_literal": False,
        "ip_version": None,
        "has_embedded_credentials": False,
        "warnings": warnings,
    }


def _ensure_scheme(candidate: str, warnings: list[WarningRecord]) -> str:
    """Prefix a scheme when the input has no RFC 3986 scheme."""
    if candidate.startswith("//"):
        warnings.append(
            _warning(
                WarningCode.MISSING_SCHEME,
                "low",
                "Protocol-relative URL had no scheme; defaulted to http.",
                applied_scheme="http",
            )
        )
        return "http:" + candidate

    if _SCHEME_RE.match(candidate):
        # "http:example.com" (no slashes) is a scheme, but unusable as a web URL.
        # Leave it to urlparse; still not a missing-scheme case.
        return candidate

    warnings.append(
        _warning(
            WarningCode.MISSING_SCHEME,
            "low",
            "URL had no scheme; defaulted to http:// for local analysis.",
            applied_scheme="http",
        )
    )
    return "http://" + candidate


def _parse_ip_literal(host: str) -> tuple[bool, int | None]:
    if not host:
        return False, None
    candidate = host.strip().removeprefix("[").removesuffix("]")
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        if _IPV4_RE.match(candidate):
            return True, 4
        return False, None
    return True, parsed_ip.version


def _has_punycode_label(host: str) -> bool:
    return any(label.lower().startswith("xn--") for label in host.split("."))


def _redact_netloc(netloc: str) -> str:
    """Strip passwords from authority evidence so they are never stored."""
    if "@" not in netloc:
        return netloc
    userinfo, _, hostpart = netloc.rpartition("@")
    if ":" in userinfo:
        user, _, _password = userinfo.partition(":")
        return f"{user}:***@{hostpart}"
    return f"{userinfo}@{hostpart}"


def _idna_forms(host: str, warnings: list[WarningRecord]) -> tuple[str | None, str | None]:
    """Return (ascii/punycode, unicode) host forms without contacting a resolver."""
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
        unicode_host = idna.decode(ascii_host, uts46=True)
    except IDNAError as exc:
        warnings.append(
            _warning(
                WarningCode.IDNA_ERROR,
                "medium",
                "Hostname failed IDNA/Punycode conversion.",
                error=str(exc),
                host=host,
            )
        )
        return None, host
    except UnicodeError as exc:
        warnings.append(
            _warning(
                WarningCode.IDNA_ERROR,
                "medium",
                "Hostname failed Unicode processing during IDNA conversion.",
                error=str(exc),
                host=host,
            )
        )
        return None, host

    if _has_punycode_label(host):
        warnings.append(
            _warning(
                WarningCode.PUNYCODE_HOST,
                "medium",
                "Hostname contains Punycode (xn--) labels.",
                host=host,
                host_ascii=ascii_host,
                host_unicode=unicode_host,
            )
        )
    elif any(ord(ch) > 127 for ch in host):
        warnings.append(
            _warning(
                WarningCode.IDN_HOST,
                "medium",
                "Hostname is an internationalized domain name; stored ASCII and Unicode forms.",
                host=host,
                host_ascii=ascii_host,
                host_unicode=unicode_host,
            )
        )

    return ascii_host, unicode_host


def parse_url(raw_url: object) -> ParseResult:
    """Parse a URL string into a structured evidence object.

    The original caller-supplied string is always preserved in ``raw``.
    Missing schemes are defaulted to ``http://`` (or ``http:`` for
    protocol-relative input). Passwords are never returned in cleartext.
    """
    warnings: list[WarningRecord] = []

    if raw_url is None:
        return _empty_result(
            "",
            [
                _warning(
                    WarningCode.EMPTY_INPUT,
                    "low",
                    "No URL string was provided.",
                )
            ],
        )

    if not isinstance(raw_url, str):
        warnings.append(
            _warning(
                WarningCode.INVALID_TYPE,
                "low",
                "Input was not a string; coerced with str().",
                python_type=type(raw_url).__name__,
            )
        )
        raw = str(raw_url)
    else:
        raw = raw_url

    if raw.strip() == "":
        return _empty_result(
            raw,
            [
                _warning(
                    WarningCode.EMPTY_INPUT,
                    "low",
                    "URL string is empty or whitespace-only.",
                )
            ],
        )

    if len(raw) > MAX_URL_LENGTH:
        warnings.append(
            _warning(
                WarningCode.INPUT_TOO_LONG,
                "medium",
                "URL exceeds the maximum length accepted for analysis.",
                length=len(raw),
                max_length=MAX_URL_LENGTH,
            )
        )
        return _empty_result(raw, warnings)

    candidate = raw.strip()
    normalized = _ensure_scheme(candidate, warnings)
    parsed = urlparse(normalized)

    scheme = parsed.scheme.lower() or None
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    netloc = parsed.netloc
    has_embedded_credentials = "@" in netloc
    username = parsed.username
    has_password = parsed.password is not None
    if has_embedded_credentials:
        warnings.append(
            _warning(
                WarningCode.EMBEDDED_CREDENTIALS,
                "high",
                "Authority contains embedded credentials ('userinfo@host'), a common cloaking pattern.",
                username=username,
                has_password=has_password,
                netloc=_redact_netloc(netloc),
            )
        )

    host = parsed.hostname
    # urlparse lowercases hostname; keep the authority host as parsed.
    if host is not None:
        host = host.rstrip(".")

    is_ip_literal = False
    ip_version: int | None = None
    host_ascii: str | None = None
    host_unicode: str | None = None

    if not host:
        warnings.append(
            _warning(
                WarningCode.EMPTY_HOST,
                "medium",
                "URL has no hostname in the authority component.",
                netloc=netloc,
            )
        )
    else:
        is_ip_literal, ip_version = _parse_ip_literal(host)
        if is_ip_literal:
            warnings.append(
                _warning(
                    WarningCode.IP_LITERAL_HOST,
                    "high",
                    "Hostname is a direct IP literal rather than a domain name.",
                    host=host,
                    ip_version=ip_version,
                )
            )
            host_ascii = host.strip("[]")
            host_unicode = host_ascii
        else:
            host_ascii, host_unicode = _idna_forms(host, warnings)

    port: int | None = None
    try:
        port = parsed.port
    except ValueError:
        warnings.append(
            _warning(
                WarningCode.INVALID_PORT,
                "medium",
                "Port component is not a valid TCP port number.",
                netloc=netloc,
            )
        )

    if port is not None:
        if port not in STANDARD_WEB_PORTS:
            warnings.append(
                _warning(
                    WarningCode.UNUSUAL_PORT,
                    "medium",
                    "Explicit port is not a standard web port (80 or 443).",
                    port=port,
                    scheme=scheme,
                )
            )
        expected = SCHEME_DEFAULT_PORT.get(scheme or "")
        if expected is not None and port != expected:
            warnings.append(
                _warning(
                    WarningCode.SCHEME_PORT_MISMATCH,
                    "low",
                    "Explicit port does not match the default port for the URL scheme.",
                    port=port,
                    scheme=scheme,
                    expected_port=expected,
                )
            )

    return {
        "raw": raw,
        "normalized": normalized,
        "scheme": scheme,
        "username": username,
        "has_password": has_password,
        "host": host,
        "host_ascii": host_ascii,
        "host_unicode": host_unicode,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "is_ip_literal": is_ip_literal,
        "ip_version": ip_version,
        "has_embedded_credentials": has_embedded_credentials,
        "warnings": warnings,
    }
