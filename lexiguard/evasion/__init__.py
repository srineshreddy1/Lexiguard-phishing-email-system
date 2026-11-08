"""Local anti-evasion sanitizers and HTML inspection (no network I/O)."""

from lexiguard.evasion.html_guard import (
    EvasionFlag,
    HtmlEvasionReport,
    HtmlViolation,
    extract_hrefs,
    inspect_html,
    strip_html,
)
from lexiguard.evasion.unicode_guard import sanitize_text, sanitize_url

__all__ = [
    "EvasionFlag",
    "HtmlEvasionReport",
    "HtmlViolation",
    "extract_hrefs",
    "inspect_html",
    "sanitize_text",
    "sanitize_url",
    "strip_html",
]
