"""Unit tests for Phase 6: LexiGuard SQLite Threat Memory & Audit Ledger.

Validates WAL mode concurrency configuration, scans ledger persistence,
threat intelligence cache upserts, hit counter increments, TTL expiration,
and schema migration resilience.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from lexiguard.db.database import (
    clear_expired_threats,
    get_db_stats,
    get_recent_scans,
    log_scan,
    lookup_threat,
    remember_threat,
    _connect,
)


class TestDatabaseInitialization:
    def test_creates_tables_and_indexes(self, tmp_path: Path) -> None:
        db_file = tmp_path / "init_test.db"
        conn = _connect(db_file)
        try:
            # Check scans table
            scans_info = conn.execute("PRAGMA table_info(scans)").fetchall()
            col_names = [row[1] for row in scans_info]
            assert "id" in col_names
            assert "message_id" in col_names
            assert "verdict" in col_names
            assert "risk_score" in col_names
            assert "urls_json" in col_names

            # Check threat_intel table
            intel_info = conn.execute("PRAGMA table_info(threat_intel)").fetchall()
            intel_cols = [row[1] for row in intel_info]
            assert "indicator" in intel_cols
            assert "verdict" in intel_cols
            assert "source" in intel_cols
            assert "expires_at" in intel_cols
            assert "hit_count" in intel_cols

            # Check journal mode is WAL
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"
        finally:
            conn.close()


class TestLogScan:
    def test_log_scan_basic_and_retrieval(self, tmp_path: Path) -> None:
        db_file = tmp_path / "scans.db"
        scan_id = log_scan(
            message_id="msg_101",
            sender="analyst@soc.corp",
            subject="Incident Report #441",
            verdict="MALICIOUS",
            risk_score=9,
            urls=["https://phishing.example.com/login", "http://0x7f000001/payload"],
            excerpt="Urgent credentials verification needed",
            extra={"incident_id": "inc_abc_123", "quarantine": True},
            db_path=db_file,
        )
        assert scan_id > 0

        scans = get_recent_scans(limit=10, db_path=db_file)
        assert len(scans) == 1
        record = scans[0]
        assert record["id"] == scan_id
        assert record["message_id"] == "msg_101"
        assert record["verdict"] == "MALICIOUS"
        assert record["risk_score"] == 9
        assert len(record["urls"]) == 2
        assert record["extra"]["incident_id"] == "inc_abc_123"

    def test_log_scan_default_fallbacks(self, tmp_path: Path) -> None:
        db_file = tmp_path / "fallbacks.db"
        # No message_id, provided raw_input and target_type URL
        scan_id = log_scan(
            target_type="URL",
            raw_input="https://suspicious-target.xyz/login",
            verdict="SUSPICIOUS",
            risk_score=4,
            db_path=db_file,
        )
        assert scan_id > 0
        scans = get_recent_scans(limit=5, db_path=db_file)
        assert len(scans) == 1
        assert scans[0]["message_id"] == "https://suspicious-target.xyz/login"
        assert scans[0]["urls"] == ["https://suspicious-target.xyz/login"]
        assert scans[0]["excerpt"] == "https://suspicious-target.xyz/login"

    def test_log_scan_truncates_oversized_excerpt(self, tmp_path: Path) -> None:
        db_file = tmp_path / "trunc.db"
        huge_text = "A" * 5000
        log_scan(
            message_id="trunc_msg",
            excerpt=huge_text,
            db_path=db_file,
        )
        scans = get_recent_scans(limit=1, db_path=db_file)
        assert len(scans[0]["excerpt"]) == 2048

    def test_get_recent_scans_ordering_and_limit(self, tmp_path: Path) -> None:
        db_file = tmp_path / "ordering.db"
        for i in range(1, 6):
            log_scan(message_id=f"msg_{i}", risk_score=i, db_path=db_file)

        scans = get_recent_scans(limit=3, db_path=db_file)
        assert len(scans) == 3
        # ID descending (newest first)
        assert scans[0]["message_id"] == "msg_5"
        assert scans[1]["message_id"] == "msg_4"
        assert scans[2]["message_id"] == "msg_3"


class TestThreatMemory:
    def test_remember_and_lookup_threat(self, tmp_path: Path) -> None:
        db_file = tmp_path / "intel.db"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # Not found initially
        assert lookup_threat(sha256, db_path=db_file) is None

        # Insert threat
        remember_threat(
            indicator=sha256,
            indicator_type="sha256",
            verdict="MALICIOUS",
            source="virustotal",
            evidence={"positives": 18, "total": 70},
            db_path=db_file,
        )

        match = lookup_threat(sha256, db_path=db_file)
        assert match is not None
        assert match["indicator"] == sha256
        assert match["indicator_type"] == "sha256"
        assert match["verdict"] == "MALICIOUS"
        assert match["source"] == "virustotal"
        assert match["hit_count"] == 1
        assert match["evidence"]["positives"] == 18

    def test_hit_counter_increments_on_repeat(self, tmp_path: Path) -> None:
        db_file = tmp_path / "hits.db"
        domain = "phish-corp-portal.com"

        remember_threat(
            indicator=domain,
            indicator_type="domain",
            verdict="MALICIOUS",
            db_path=db_file,
        )
        assert lookup_threat(domain, db_path=db_file)["hit_count"] == 1

        remember_threat(
            indicator=domain,
            indicator_type="domain",
            verdict="MALICIOUS",
            db_path=db_file,
        )
        assert lookup_threat(domain, db_path=db_file)["hit_count"] == 2

    def test_expiration_behavior(self, tmp_path: Path) -> None:
        db_file = tmp_path / "expire.db"
        past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

        # Expired indicator
        remember_threat(
            indicator="192.0.2.1",
            indicator_type="ip",
            verdict="SUSPICIOUS",
            expires_at=past_time,
            db_path=db_file,
        )
        # Active indicator
        remember_threat(
            indicator="198.51.100.1",
            indicator_type="ip",
            verdict="MALICIOUS",
            expires_at=future_time,
            db_path=db_file,
        )

        # Lookup with ignore_expired=True (default)
        assert lookup_threat("192.0.2.1", db_path=db_file) is None
        assert lookup_threat("198.51.100.1", db_path=db_file) is not None

        # Lookup with ignore_expired=False retrieves expired record
        expired_match = lookup_threat("192.0.2.1", db_path=db_file, ignore_expired=False)
        assert expired_match is not None
        assert expired_match["indicator"] == "192.0.2.1"

    def test_clear_expired_threats(self, tmp_path: Path) -> None:
        db_file = tmp_path / "purge.db"
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

        remember_threat(indicator="dead.cc", indicator_type="domain", verdict="MALICIOUS", expires_at=past, db_path=db_file)
        remember_threat(indicator="alive.cc", indicator_type="domain", verdict="MALICIOUS", expires_at=future, db_path=db_file)
        remember_threat(indicator="permanent.cc", indicator_type="domain", verdict="MALICIOUS", db_path=db_file)

        deleted = clear_expired_threats(db_path=db_file)
        assert deleted == 1

        # dead.cc is removed, others remain
        assert lookup_threat("dead.cc", db_path=db_file, ignore_expired=False) is None
        assert lookup_threat("alive.cc", db_path=db_file) is not None
        assert lookup_threat("permanent.cc", db_path=db_file) is not None

    def test_lookup_empty_or_whitespace_returns_none(self, tmp_path: Path) -> None:
        db_file = tmp_path / "empty.db"
        assert lookup_threat("", db_path=db_file) is None
        assert lookup_threat("   ", db_path=db_file) is None


class TestDatabaseStatsAndMigration:
    def test_get_db_stats(self, tmp_path: Path) -> None:
        db_file = tmp_path / "stats.db"
        # Non-existent file returns 0, 0
        assert get_db_stats(tmp_path / "not_there.db") == (0, 0)

        log_scan(message_id="s1", db_path=db_file)
        log_scan(message_id="s2", db_path=db_file)
        remember_threat(indicator="bad.org", indicator_type="domain", verdict="MALICIOUS", db_path=db_file)

        scans_count, intel_count = get_db_stats(db_file)
        assert scans_count == 2
        assert intel_count == 1

    def test_schema_migration_resilience(self, tmp_path: Path) -> None:
        """Simulate an older database missing source and expires_at columns."""
        db_file = tmp_path / "old_schema.db"
        # Create table with minimal columns
        conn = sqlite3.connect(str(db_file))
        conn.execute(
            """
            CREATE TABLE threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                indicator_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hit_count INTEGER NOT NULL DEFAULT 1,
                evidence_json TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO threat_intel VALUES (1, 'old.test', 'domain', 'MALICIOUS', '2026-01-01', '2026-01-01', 1, '{}')"
        )
        conn.commit()
        conn.close()

        # Connect through our library which runs _migrate_schema
        migrated_conn = _connect(db_file)
        try:
            cols = [row[1] for row in migrated_conn.execute("PRAGMA table_info(threat_intel)").fetchall()]
            assert "source" in cols
            assert "expires_at" in cols
        finally:
            migrated_conn.close()

        # Can now lookup old records cleanly
        record = lookup_threat("old.test", db_path=db_file)
        assert record is not None
        assert record["indicator"] == "old.test"
        assert record["source"] == "local"
