"""Unit tests for LexiGuard OSINT Threat Seeder."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lexiguard.db.database import get_db_stats, lookup_threat
from lexiguard.db.seed_intel import (
    CURATED_SEED_INDICATORS,
    fetch_live_urlhaus_recent,
    is_db_seeded,
    seed_threat_intel,
)


class TestSeedIntel:
    def test_seed_threat_intel_populates_database(self, tmp_path: Path) -> None:
        db_file = tmp_path / "seed_test.db"
        assert not is_db_seeded(db_file)

        count = seed_threat_intel(db_path=db_file, force=False)
        assert count == len(CURATED_SEED_INDICATORS)
        assert is_db_seeded(db_file)

        # Check a seeded hash
        match = lookup_threat("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", db_path=db_file)
        assert match is not None
        assert match["verdict"] == "MALICIOUS"
        assert match["source"] == "osint_seed"

    def test_seed_prevents_duplicate_run_without_force(self, tmp_path: Path) -> None:
        db_file = tmp_path / "dup_test.db"
        first_count = seed_threat_intel(db_path=db_file, force=False)
        assert first_count > 0

        # Second run without force does nothing
        second_count = seed_threat_intel(db_path=db_file, force=False)
        assert second_count == 0

        # With force=True, re-seeds
        force_count = seed_threat_intel(db_path=db_file, force=True)
        assert force_count == len(CURATED_SEED_INDICATORS)

    def test_fetch_live_urlhaus_offline_graceful_handling(self) -> None:
        # Mocking network failure
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            results = fetch_live_urlhaus_recent(timeout=1)
            assert results == []
