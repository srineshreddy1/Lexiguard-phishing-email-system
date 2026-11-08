"""Local feature extraction and policy checks for LexiGuard.

All analysis is static. This module never performs DNS, sockets, or HTTP.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any, TypedDict
from urllib.parse import unquote

from lexiguard.parser import WarningRecord, _warning

# High-risk lure tokens commonly used in credential-harvesting paths/queries.
PHISHING_KEYWORDS: tuple[str, ...] = (
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "signin",
    "banking",
)

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_INT_RE = re.compile(r"^0[xX][0-9A-Fa-f]+$")
_OCT_INT_RE = re.compile(r"^0[0-7]+$")
_DEC_INT_RE = re.compile(r"^[0-9]+$")
_HEX_OCTET_RE = re.compile(r"^0[xX][0-9A-Fa-f]+$")
_OCT_OCTET_RE = re.compile(r"^0[0-7]+$")
_DEC_OCTET_RE = re.compile(r"^[0-9]+$")
_CANONICAL_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
_KEYWORD_RE = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(k) for k in PHISHING_KEYWORDS) + r")(?![a-z0-9])",
    re.IGNORECASE,
)


class PolicyCode:
    OBFUSCATED_IP = "OBFUSCATED_IP"
    BACKSLASH_CONFUSION = "BACKSLASH_CONFUSION"
    PHISHING_KEYWORD = "PHISHING_KEYWORD"
    INVALID_PARSE_INPUT = "INVALID_PARSE_INPUT"


class FeatureSet(TypedDict):
    hostname_length: int
    path_length: int
    query_length: int
    hostname_depth: int
    subdomain_count: int
    label_count: int
    shannon_entropy: float
    hostname_entropy: float
    dot_count: int
    hyphen_count: int
    digit_count: int
    percent_encoding_count: int


class FeatureResult(TypedDict):
    features: FeatureSet
    policy_violations: list[WarningRecord]


def _empty_features() -> FeatureSet:
    return {
        "hostname_length": 0,
        "path_length": 0,
        "query_length": 0,
        "hostname_depth": 0,
        "subdomain_count": 0,
        "label_count": 0,
        "shannon_entropy": 0.0,
        "hostname_entropy": 0.0,
        "dot_count": 0,
        "hyphen_count": 0,
        "digit_count": 0,
        "percent_encoding_count": 0,
    }


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _decode_repeated(value: str, *, max_rounds: int = 3) -> str:
    """Percent-decode locally a bounded number of times (no fetching)."""
    current = value
    for _ in range(max_rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _parse_numeric_part(part: str, *, allow_hex: bool, allow_octal: bool) -> tuple[int, str] | None:
    """Parse one IPv4 component. Returns (value, notation) or None."""
    token = part.strip()
    if not token:
        return None
    try:
        if allow_hex and _HEX_OCTET_RE.fullmatch(token):
            return int(token, 16), "hex"
        if allow_octal and _OCT_OCTET_RE.fullmatch(token):
            return int(token, 8), "octal"
        if _DEC_OCTET_RE.fullmatch(token):
            # Leading zeros on a multi-digit decimal are treated as octal by some clients.
            if allow_octal and len(token) > 1 and token.startswith("0"):
                return int(token, 8), "octal"
            return int(token, 10), "decimal"
    except ValueError:
        return None
    return None


def _obfuscated_ipv4(host: str) -> tuple[str, str, list[str]] | None:
    """Return (canonical, form, notations) if host is a non-canonical IPv4 encoding.

    Detects dword decimal/hex/octal hosts and dotted mixed radix forms that
    browsers historically coerce to an address without a DNS lookup.
    """
    candidate = host.strip().removeprefix("[").removesuffix("]").rstrip(".")
    if not candidate:
        return None

    # Canonical dotted-decimal / IPv6 literals are already covered in Phase 1.
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None:
        return None

    notations: list[str] = []

    if "." not in candidate:
        form: str | None = None
        value: int | None = None
        try:
            if _HEX_INT_RE.fullmatch(candidate):
                value = int(candidate, 16)
                form = "hex_dword"
                notations.append("hex")
            elif _OCT_INT_RE.fullmatch(candidate):
                value = int(candidate, 8)
                form = "octal_dword"
                notations.append("octal")
            elif _DEC_INT_RE.fullmatch(candidate):
                value = int(candidate, 10)
                form = "decimal_dword"
                notations.append("decimal")
        except ValueError:
            return None
        if value is None or form is None or not 0 <= value <= 0xFFFFFFFF:
            return None
        canonical = str(ipaddress.IPv4Address(value))
        return canonical, form, notations

    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    values: list[int] = []
    for part in parts:
        parsed_part = _parse_numeric_part(part, allow_hex=True, allow_octal=True)
        if parsed_part is None:
            return None
        number, notation = parsed_part
        values.append(number)
        if notation not in notations:
            notations.append(notation)

    # Reject purely canonical four-octet decimal (should already be excluded above).
    if (
        len(parts) == 4
        and notations == ["decimal"]
        and _CANONICAL_IPV4_RE.fullmatch(candidate)
    ):
        return None

    try:
        if len(values) == 1:
            if not 0 <= values[0] <= 0xFFFFFFFF:
                return None
            packed = values[0]
        elif len(values) == 2:
            if not 0 <= values[0] <= 255 or not 0 <= values[1] <= 0xFFFFFF:
                return None
            packed = (values[0] << 24) | values[1]
        elif len(values) == 3:
            if not 0 <= values[0] <= 255 or not 0 <= values[1] <= 255 or not 0 <= values[2] <= 0xFFFF:
                return None
            packed = (values[0] << 24) | (values[1] << 16) | values[2]
        else:
            if any(not 0 <= octet <= 255 for octet in values):
                return None
            packed = (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
        canonical = str(ipaddress.IPv4Address(packed))
    except (ValueError, OverflowError):
        return None

    if "hex" in notations:
        form = "dotted_hex"
    elif "octal" in notations:
        form = "dotted_octal"
    else:
        form = "dotted_compressed"

    return canonical, form, notations


def _hostname_shape(host: str, *, is_ip_literal: bool) -> tuple[int, int, int]:
    """Return (label_count, hostname_depth, subdomain_count)."""
    if not host or is_ip_literal:
        return 0, 0, 0
    labels = [label for label in host.strip(".").split(".") if label]
    label_count = len(labels)
    depth = label_count
    subdomain_count = max(0, label_count - 2)
    return label_count, depth, subdomain_count


def _collect_backslash_locations(parsed_url: dict[str, Any]) -> list[str]:
    """Identify backslash characters in authority, host, or path delimiter locations.
    Backslashes inside query parameter values (e.g. JSON strings) do not confuse host routing.
    """
    locations: list[str] = []
    for field in ("host", "host_ascii", "host_unicode", "username", "path"):
        value = parsed_url.get(field)
        if isinstance(value, str) and "\\" in value:
            locations.append(field)
    for field in ("raw", "normalized"):
        value = parsed_url.get(field)
        if isinstance(value, str) and "\\" in value:
            before_query = value.split("?", 1)[0]
            if "\\" in before_query:
                locations.append(field)
    return list(dict.fromkeys(locations))


def _keyword_hits(*parts: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for part in parts:
        if not part:
            continue
        for match in _KEYWORD_RE.finditer(part):
            token = match.group(1).lower()
            if token not in seen:
                seen.add(token)
                found.append(token)
        decoded = _decode_repeated(part)
        if decoded != part:
            for match in _KEYWORD_RE.finditer(decoded):
                token = match.group(1).lower()
                if token not in seen:
                    seen.add(token)
                    found.append(token)
    return found


def _compute_features(parsed_url: dict[str, Any]) -> FeatureSet:
    host = parsed_url.get("host") or ""
    if not isinstance(host, str):
        host = str(host)
    path = parsed_url.get("path") or ""
    query = parsed_url.get("query") or ""
    if not isinstance(path, str):
        path = str(path)
    if not isinstance(query, str):
        query = str(query)

    is_ip_literal = bool(parsed_url.get("is_ip_literal"))
    label_count, depth, subdomain_count = _hostname_shape(host, is_ip_literal=is_ip_literal)
    encoded_blob = "".join(
        part
        for part in (host, path, query, parsed_url.get("raw") or "")
        if isinstance(part, str)
    )

    return {
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "hostname_depth": depth,
        "subdomain_count": subdomain_count,
        "label_count": label_count,
        "shannon_entropy": round(_shannon_entropy(host), 6),
        "hostname_entropy": round(_shannon_entropy(host), 6),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "digit_count": sum(ch.isdigit() for ch in host),
        "percent_encoding_count": len(_PERCENT_RE.findall(encoded_blob)),
    }


def extract_features(parsed_url: dict[str, Any] | None) -> FeatureResult:
    """Derive quantitative features and policy violations from a parse result.

    Parameters
    ----------
    parsed_url:
        Dictionary produced by ``lexiguard.parser.parse_url``. Unexpected
        shapes are tolerated; analysis degrades to empty features plus an
        input-policy warning instead of raising.
    """
    violations: list[WarningRecord] = []

    if not isinstance(parsed_url, dict):
        violations.append(
            _warning(
                PolicyCode.INVALID_PARSE_INPUT,
                "medium",
                "Feature extraction received a non-dictionary parse result.",
                python_type=type(parsed_url).__name__,
            )
        )
        return {"features": _empty_features(), "policy_violations": violations}

    try:
        features = _compute_features(parsed_url)
    except Exception as exc:  # noqa: BLE001 — stay local and never crash the CLI
        violations.append(
            _warning(
                PolicyCode.INVALID_PARSE_INPUT,
                "medium",
                "Feature extraction failed while computing metrics.",
                error=type(exc).__name__,
            )
        )
        return {"features": _empty_features(), "policy_violations": violations}

    host = parsed_url.get("host")
    host_text = host if isinstance(host, str) else ""
    is_ip_literal = bool(parsed_url.get("is_ip_literal"))

    if host_text and not is_ip_literal:
        obfuscated = _obfuscated_ipv4(host_text)
        if obfuscated is not None:
            canonical, form, notations = obfuscated
            violations.append(
                _warning(
                    PolicyCode.OBFUSCATED_IP,
                    "high",
                    "Hostname uses a non-canonical numeric encoding that browsers may treat as an IP address.",
                    host=host_text,
                    canonical_ipv4=canonical,
                    form=form,
                    notations=notations,
                )
            )

    slash_fields = _collect_backslash_locations(parsed_url)
    if slash_fields:
        raw = parsed_url.get("raw") if isinstance(parsed_url.get("raw"), str) else ""
        violations.append(
            _warning(
                PolicyCode.BACKSLASH_CONFUSION,
                "high",
                "Backslash characters present in the URL, which can confuse authority versus path parsing.",
                fields=slash_fields,
                backslash_count=raw.count("\\") if raw else sum(
                    str(parsed_url.get(field) or "").count("\\") for field in slash_fields
                ),
            )
        )

    path = parsed_url.get("path") if isinstance(parsed_url.get("path"), str) else ""
    query = parsed_url.get("query") if isinstance(parsed_url.get("query"), str) else ""
    matched = _keyword_hits(path, query)
    if matched:
        violations.append(
            _warning(
                PolicyCode.PHISHING_KEYWORD,
                "medium",
                "Path or query contains high-risk phishing lure keywords.",
                matched_terms=matched,
                path=path,
                query=query,
            )
        )

    return {"features": features, "policy_violations": violations}
