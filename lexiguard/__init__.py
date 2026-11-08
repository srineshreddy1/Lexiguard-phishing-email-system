"""LexiGuard: local static-analysis phishing detection."""

from __future__ import annotations

import os
from pathlib import Path


def load_env(env_path: Path | str | None = None) -> dict[str, str]:
    """Load key-value environment variables from .env file into os.environ."""
    target: Path | None = None
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_file():
            target = p
    else:
        candidates = [
            Path.cwd() / ".env",
            Path(__file__).resolve().parent.parent / ".env",
            Path.home() / ".lexiguard" / ".env",
        ]
        target = next((p for p in candidates if p.exists() and p.is_file()), None)

    loaded: dict[str, str] = {}
    if not target:
        return loaded

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
                        loaded[key] = val
    except Exception:
        pass
    return loaded


# Automatically load environment variables from .env on package initialization
load_env()

from lexiguard.features import extract_features
from lexiguard.parser import parse_url
from lexiguard.scorer import Verdict, score_risk

__all__ = ["extract_features", "load_env", "parse_url", "score_risk", "Verdict"]
__version__ = "0.1.0"
