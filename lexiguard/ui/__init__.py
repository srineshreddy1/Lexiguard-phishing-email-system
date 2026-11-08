"""LexiGuard User Interface & Plain-English Security Translation Layer."""

from __future__ import annotations

from lexiguard.ui.translator import (
    explain_risk_score,
    get_plain_english_verdict,
    translate_report,
    translate_violation,
)

__all__ = [
    "explain_risk_score",
    "get_plain_english_verdict",
    "translate_report",
    "translate_violation",
]
