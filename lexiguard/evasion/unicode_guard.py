"""Strip steganographic and bidi Unicode from untrusted text.

This module is purely local. It does not fetch, render, or resolve URLs.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width / format chars used to hide dots, @, and homograph glue.
_INVISIBLE = {
    "\u00ad",  # soft hyphen
    "\u180e",  # mongolian vowel separator
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero width no-break space
}

_BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_INVISIBLE_RE = re.compile("|".join(re.escape(ch) for ch in sorted(_INVISIBLE)))


def sanitize_text(value: str | None) -> str:
    """Remove zero-width, bidi-override, and other format characters."""
    if not value:
        return ""
    try:
        text = unicodedata.normalize("NFC", str(value))
        text = _INVISIBLE_RE.sub("", text)
        text = _BIDI_RE.sub("", text)
        text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
        return text
    except Exception:
        return ""


def sanitize_url(value: str | None) -> str:
    """Sanitize a single URL candidate before static parsing."""
    return sanitize_text(value).strip()
