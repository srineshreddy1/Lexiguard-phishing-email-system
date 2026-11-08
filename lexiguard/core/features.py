"""Re-export of Phase 2 feature extraction for core imports."""

from lexiguard.features import (
    FeatureResult,
    FeatureSet,
    PHISHING_KEYWORDS,
    PolicyCode,
    extract_features,
)

__all__ = [
    "FeatureResult",
    "FeatureSet",
    "PHISHING_KEYWORDS",
    "PolicyCode",
    "extract_features",
]
