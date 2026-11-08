"""Compatibility package for engine entry points used by the gateway."""

from lexiguard.core.features import extract_features
from lexiguard.core.parser import parse_url
from lexiguard.core.scorer import Verdict, score_risk

__all__ = ["Verdict", "extract_features", "parse_url", "score_risk"]
