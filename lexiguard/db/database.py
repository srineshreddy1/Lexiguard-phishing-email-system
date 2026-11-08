"""SQLite persistence and threat memory ledger for the LexiGuard Security Gateway.

Provides high-concurrency WAL-mode SQLite storage for:
- Scan audit logs (scans table): immutable record of evaluated messages, URLs,
  extracted features, risk scores, verdicts, and automated remediation actions.
- Threat intelligence memory (threat_intel table): self-learning cache of known
  malicious indicators (SHA-256 file hashes, domain names, URLs, IP addresses)
  with hit counts, confidence verdicts, source attribution, and expiration.

Thread-safe, crash-resilient, and optimized for concurrent reader/writer access
via Write-Ahead Logging (WAL) and busy timeout handlers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
from typing import Any


def _get_default_db_path() -> Path:
    """Resolve cross-platform default database path."""
    env_path = os.environ.get("LEXIGUARD_DB_PATH")
    if env_path and env_path.strip():
        return Path(env_path.strip())
    # Cross-platform default relative to repository root
    project_root = Path(__file__).resolve().parent.parent.parent
    return project_root / "lexiguard.db"


DEFAULT_DB_PATH = _get_default_db_path()

_SCANS_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL,
    sender TEXT,
    subject TEXT,
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    urls_json TEXT,
    excerpt TEXT,
    extra_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
"""

_INTEL_DDL = """
CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL UNIQUE,
    indicator_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'local',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    hit_count INTEGER NOT NULL DEFAULT 1,
    evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel(indicator);
"""


def _utc_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Ensure backwards compatibility by adding missing columns to existing tables."""
    try:
        cur = conn.execute("PRAGMA table_info(threat_intel)")
        existing_cols = {row[1] for row in cur.fetchall()}
        if existing_cols:
            if "source" not in existing_cols:
                conn.execute("ALTER TABLE threat_intel ADD COLUMN source TEXT NOT NULL DEFAULT 'local'")
            if "expires_at" not in existing_cols:
                conn.execute("ALTER TABLE threat_intel ADD COLUMN expires_at TEXT")
    except Exception:
        pass


def _connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Initialize an optimized SQLite connection with Write-Ahead Logging (WAL) enabled."""
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")

    # Enable Write-Ahead Logging (WAL) for high concurrency read/writes
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")

    conn.executescript(_SCANS_DDL)
    conn.executescript(_INTEL_DDL)
    _migrate_schema(conn)
    return conn


def log_scan(
    *,
    message_id: str = "",
    sender: str = "",
    subject: str = "",
    verdict: str = "SAFE",
    risk_score: int = 0,
    urls: list[str] | None = None,
    excerpt: str = "",
    extra: dict[str, Any] | None = None,
    db_path: Path | str | None = None,
    target_type: str = "",
    raw_input: str = "",
    summary: dict[str, Any] | None = None,
    **kwargs: Any,
) -> int:
    """Insert one scan audit record into the scans ledger table.

    Args:
        message_id: Unique message, scan, or resource ID.
        sender: Sender email address or originator ID.
        subject: Subject line or input description.
        verdict: Categorical verdict (SAFE, SUSPICIOUS, MALICIOUS).
        risk_score: Integer risk score (0-10+).
        urls: List of evaluated URLs.
        excerpt: Sanitized body or text excerpt (truncated to 2048 chars).
        extra: Additional forensic metadata, policy violations, or response details.
        db_path: Custom SQLite database path. Defaults to DEFAULT_DB_PATH.
        target_type: Target category (URL, ATTACHMENT, EMAIL).
        raw_input: Raw candidate input if message_id is not provided.
        summary: Optional high-level score breakdown summary dict.

    Returns:
        The generated integer scan ID (primary key rowid).
    """
    if not message_id:
        message_id = raw_input or target_type or "manual_scan"
    if not excerpt and raw_input:
        excerpt = raw_input
    if not urls and target_type == "URL" and raw_input:
        urls = [raw_input]

    extra_data = dict(extra or {})
    if summary:
        extra_data["summary"] = summary
    if target_type:
        extra_data["target_type"] = target_type

    conn = _connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO scans (
                message_id, sender, subject, verdict, risk_score,
                urls_json, excerpt, extra_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                sender,
                subject,
                verdict,
                int(risk_score),
                json.dumps(urls or [], ensure_ascii=False),
                (excerpt or "")[:2048],
                json.dumps(extra_data, ensure_ascii=False),
                _utc_now(),
            ),
        )
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()


def get_recent_scans(
    limit: int = 50,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve recent scan audit records from SQLite, newest first.

    Args:
        limit: Maximum number of rows to retrieve.
        db_path: Database path override.

    Returns:
        List of dictionaries with decoded URLs and metadata dictionaries.
    """
    try:
        conn = _connect(db_path)
        try:
            cursor = conn.execute(
                """
                SELECT id, message_id, sender, subject, verdict, risk_score,
                       urls_json, excerpt, extra_json, created_at
                FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            rows = cursor.fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                try:
                    urls = json.loads(row[6]) if row[6] else []
                except Exception:
                    urls = []
                try:
                    extra = json.loads(row[8]) if row[8] else {}
                except Exception:
                    extra = {}
                results.append({
                    "id": row[0],
                    "message_id": row[1],
                    "sender": row[2],
                    "subject": row[3],
                    "verdict": row[4],
                    "risk_score": row[5],
                    "urls": urls,
                    "excerpt": row[7],
                    "extra": extra,
                    "created_at": row[9],
                })
            return results
        finally:
            conn.close()
    except Exception:
        return []


def remember_threat(
    *,
    indicator: str,
    indicator_type: str,
    verdict: str,
    evidence: dict[str, Any] | None = None,
    source: str = "local",
    expires_at: str | None = None,
    db_path: Path | str | None = None,
) -> None:
    """Upsert an indicator into the local threat_intel memory table.

    Increments the hit counter and updates `last_seen` on repeated observations.

    Args:
        indicator: The unique indicator string (e.g. SHA-256 hash, domain, URL, IP).
        indicator_type: Indicator type (sha256, domain, url, ip).
        verdict: Categorical verdict (MALICIOUS, SUSPICIOUS, SAFE).
        evidence: Associated threat details or detection rule evidence.
        source: Intelligence origin (local, virustotal, google_webrisk).
        expires_at: Optional ISO 8601 expiration timestamp.
        db_path: Database path override.
    """
    if not indicator or not indicator.strip():
        return

    clean_indicator = indicator.strip()
    now = _utc_now()
    evidence_json = json.dumps(evidence or {}, ensure_ascii=False)

    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO threat_intel (
                indicator, indicator_type, verdict, source,
                first_seen, last_seen, expires_at, hit_count, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                last_seen = excluded.last_seen,
                verdict = excluded.verdict,
                source = excluded.source,
                expires_at = COALESCE(excluded.expires_at, threat_intel.expires_at),
                hit_count = hit_count + 1,
                evidence_json = excluded.evidence_json
            """,
            (clean_indicator, indicator_type, verdict, source, now, now, expires_at, evidence_json),
        )
        conn.commit()
    finally:
        conn.close()


def lookup_threat(
    indicator: str,
    db_path: Path | str | None = None,
    ignore_expired: bool = True,
) -> dict[str, Any] | None:
    """Look up an indicator in the threat_intel cache.

    Args:
        indicator: Target indicator string (SHA-256, domain, URL).
        db_path: Database path override.
        ignore_expired: If True, returns None if the cached record has expired.

    Returns:
        Structured dictionary if found and active, else None.
    """
    if not indicator or not indicator.strip():
        return None

    clean_indicator = indicator.strip()
    try:
        conn = _connect(db_path)
        try:
            cursor = conn.execute(
                """
                SELECT indicator, indicator_type, verdict, source,
                       first_seen, last_seen, expires_at, hit_count, evidence_json
                FROM threat_intel
                WHERE indicator = ?
                """,
                (clean_indicator,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            expires_at = row[6]
            if ignore_expired and expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at)
                    if datetime.now(timezone.utc) > exp_dt:
                        return None
                except Exception:
                    pass

            evidence = {}
            if row[8]:
                try:
                    evidence = json.loads(row[8])
                except Exception:
                    evidence = {}

            return {
                "indicator": row[0],
                "indicator_type": row[1],
                "verdict": row[2],
                "source": row[3],
                "first_seen": row[4],
                "last_seen": row[5],
                "expires_at": expires_at,
                "hit_count": row[7],
                "evidence": evidence,
            }
        finally:
            conn.close()
    except Exception:
        return None


def get_db_stats(db_path: Path | str | None = None) -> tuple[int, int]:
    """Retrieve total scan count and cached threat indicator count."""
    try:
        resolved_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
        if str(resolved_path) != ":memory:" and not resolved_path.exists():
            return 0, 0
        conn = _connect(db_path)
        try:
            scans_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            intel_count = conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
            return int(scans_count), int(intel_count)
        finally:
            conn.close()
    except Exception:
        return 0, 0


def clear_expired_threats(db_path: Path | str | None = None) -> int:
    """Purge expired threat indicators from the threat_intel table."""
    now = _utc_now()
    try:
        conn = _connect(db_path)
        try:
            cur = conn.execute(
                "DELETE FROM threat_intel WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()
    except Exception:
        return 0
