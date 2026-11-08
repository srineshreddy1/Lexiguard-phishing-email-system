"""Unit tests for LexiGuard Reports Exporter (Phase 5.2 / Option 3).

Verifies CSV export formatting, HTML report generation, edge cases with empty
or non-existent databases, and XSS sanitization.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
import sqlite3

import pytest

from lexiguard.db.database import log_scan
from lexiguard.reports.exporter import (
    export_scans_to_csv,
    export_scans_to_html_report,
)


@pytest.fixture
def populated_db(tmp_path: Path) -> Path:
    """Fixture providing a temporary SQLite database with diverse scan records."""
    db_file = tmp_path / "test_reporting.db"

    log_scan(
        message_id="msg_001",
        sender="attacker@evil.example",
        subject="Urgent Payroll Notification",
        verdict="MALICIOUS",
        risk_score=9,
        urls=["http://0x7f000001/verify", "https://phish.cc/token"],
        excerpt="Suspicious urgent payroll prompt with IP address",
        extra={"target_type": "URL", "phase": "test"},
        db_path=db_file,
    )
    log_scan(
        message_id="msg_002",
        sender="finance@partner.org",
        subject="Q3 Quarterly Audit",
        verdict="SUSPICIOUS",
        risk_score=5,
        urls=["https://partner.org/reports/audit"],
        excerpt="Document with unknown macro format",
        extra={"target_type": "ATTACHMENT"},
        db_path=db_file,
    )
    log_scan(
        message_id="msg_003",
        sender="security@corp.example",
        subject="Monthly System Status",
        verdict="SAFE",
        risk_score=0,
        urls=["https://internal.corp.example/status"],
        excerpt="Verified internal infrastructure newsletter",
        extra={"target_type": "URL"},
        db_path=db_file,
    )
    return db_file


class TestExportScansToCSV:
    def test_export_empty_db_returns_header_only(self, tmp_path: Path) -> None:
        empty_db = tmp_path / "empty.db"
        csv_str = export_scans_to_csv(empty_db)
        lines = csv_str.strip().splitlines()
        assert len(lines) == 1
        assert "Scan ID,Message ID,Sender,Subject,Verdict" in lines[0]

    def test_export_missing_file_returns_header_only(self, tmp_path: Path) -> None:
        missing_db = tmp_path / "non_existent.db"
        csv_str = export_scans_to_csv(missing_db)
        lines = csv_str.strip().splitlines()
        assert len(lines) == 1

    def test_export_populated_db(self, populated_db: Path) -> None:
        csv_str = export_scans_to_csv(populated_db)
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)

        assert len(rows) == 3
        # Check reverse ID order (newest first)
        assert rows[0]["Message ID"] == "msg_003"
        assert rows[0]["Verdict"] == "SAFE"
        assert rows[0]["Risk Score"] == "0"

        assert rows[2]["Message ID"] == "msg_001"
        assert rows[2]["Verdict"] == "MALICIOUS"
        assert rows[2]["Risk Score"] == "9"
        assert "0x7f000001" in rows[2]["URLs"]

    def test_export_limit_respected(self, populated_db: Path) -> None:
        csv_str = export_scans_to_csv(populated_db, limit=2)
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert len(rows) == 2


class TestExportScansToHTMLReport:
    def test_html_report_structure(self, populated_db: Path) -> None:
        html_doc = export_scans_to_html_report(populated_db)

        assert "<!DOCTYPE html>" in html_doc
        assert "#0f172a" in html_doc  # Dark mode background
        assert "LexiGuard Enterprise Security Audit Report" in html_doc
        assert "MALICIOUS" in html_doc
        assert "SUSPICIOUS" in html_doc
        assert "SAFE" in html_doc
        assert "attacker@evil.example" in html_doc
        assert "Urgent Payroll Notification" in html_doc

    def test_html_report_empty_state(self, tmp_path: Path) -> None:
        empty_db = tmp_path / "empty.db"
        html_doc = export_scans_to_html_report(empty_db)

        assert "No scan audit records found" in html_doc
        assert '<div class="metric-value">0</div>' in html_doc

    def test_html_report_xss_sanitization(self, tmp_path: Path) -> None:
        xss_db = tmp_path / "xss.db"
        log_scan(
            message_id="msg_xss",
            sender="attacker<img src=x onerror=alert(1)>@test.org",
            subject="<script>alert('xss')</script>",
            verdict="MALICIOUS",
            risk_score=10,
            excerpt="<b>Bold Attack</b>",
            db_path=xss_db,
        )

        html_doc = export_scans_to_html_report(xss_db)
        assert "<script>alert('xss')</script>" not in html_doc
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_doc
        assert "<img src=x" not in html_doc
        assert "&lt;b&gt;Bold Attack&lt;/b&gt;" in html_doc
