"""LexiGuard Audit & Incident Report Exporter (Phase 5.2 / Option 3).

Provides robust export utilities for SQLite scan audit logs:
- CSV export for SIEM ingestion, Excel spreadsheets, and data analytics.
- Self-contained, professional HTML compliance reports featuring dark-mode
  styling (#0f172a), high-contrast security severity badges, and aggregate
  risk metrics suitable for browser printing / PDF generation.
"""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
import sqlite3
from typing import Any

from lexiguard.db.database import DEFAULT_DB_PATH


def _resolve_db_path(db_path: str | Path | None) -> Path:
    """Normalize database path input, defaulting to DEFAULT_DB_PATH."""
    if db_path is None or not str(db_path).strip():
        return DEFAULT_DB_PATH
    return Path(db_path)


def _fetch_scan_rows(
    db_path: str | Path | None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Query recent scan rows safely from SQLite database.

    Returns an empty list if the database file is absent or the table is empty.
    """
    resolved_path = _resolve_db_path(db_path)
    if not resolved_path.exists():
        return []

    try:
        conn = sqlite3.connect(str(resolved_path), timeout=5)
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
                    "message_id": row[1] or "",
                    "sender": row[2] or "",
                    "subject": row[3] or "",
                    "verdict": row[4] or "UNKNOWN",
                    "risk_score": int(row[5] or 0),
                    "urls": urls,
                    "excerpt": row[7] or "",
                    "extra": extra,
                    "created_at": row[9] or "",
                })
            return results
        finally:
            conn.close()
    except Exception:
        return []


def export_scans_to_csv(
    db_path: str | Path | None = None,
    limit: int = 500,
) -> str:
    """Export scan records from the SQLite database to a RFC 4180 CSV string.

    Args:
        db_path: Path to the SQLite database. Defaults to project root lexiguard.db.
        limit:   Maximum number of recent records to retrieve.

    Returns:
        Formatted CSV string containing headers and scan records.
    """
    fieldnames = [
        "Scan ID",
        "Message ID",
        "Sender",
        "Subject",
        "Verdict",
        "Risk Score",
        "Timestamp",
        "Summary Excerpt",
        "URLs Count",
        "URLs",
    ]

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(fieldnames)

    records = _fetch_scan_rows(db_path, limit=limit)
    for r in records:
        urls_joined = "; ".join(r["urls"]) if r["urls"] else ""
        writer.writerow([
            r["id"],
            r["message_id"],
            r["sender"],
            r["subject"],
            r["verdict"],
            r["risk_score"],
            r["created_at"],
            r["excerpt"][:500] if r["excerpt"] else "",
            len(r["urls"]),
            urls_joined,
        ])

    return output.getvalue()


def export_scans_to_html_report(
    db_path: str | Path | None = None,
    limit: int = 100,
    title: str = "LexiGuard Enterprise Security Audit Report",
) -> str:
    """Generate a self-contained, publication-ready HTML compliance report.

    Features:
    - Dark-mode executive styling (#0f172a background).
    - Summary metrics: total scans, malicious/suspicious/safe counts, avg risk.
    - Security severity badges (MALICIOUS: red, SUSPICIOUS: amber, SAFE: emerald).
    - Full HTML escaping to prevent XSS.
    - Optimized print media styles for seamless browser PDF export.

    Args:
        db_path: Path to the SQLite database. Defaults to DEFAULT_DB_PATH.
        limit:   Maximum number of recent records to include.
        title:   Document heading and title.

    Returns:
        Full HTML document string with inline CSS.
    """
    records = _fetch_scan_rows(db_path, limit=limit)

    total_scans = len(records)
    malicious_count = sum(1 for r in records if r["verdict"].upper() == "MALICIOUS")
    suspicious_count = sum(1 for r in records if r["verdict"].upper() == "SUSPICIOUS")
    safe_count = sum(1 for r in records if r["verdict"].upper() == "SAFE")
    other_count = total_scans - (malicious_count + suspicious_count + safe_count)

    avg_score = (
        sum(r["risk_score"] for r in records) / total_scans if total_scans > 0 else 0.0
    )

    # Build table rows
    table_rows_html = []
    if not records:
        table_rows_html.append(
            '<tr><td colspan="7" class="empty-state">No scan audit records found in the database.</td></tr>'
        )
    else:
        for r in records:
            verdict_upper = r["verdict"].upper()
            if verdict_upper == "MALICIOUS":
                badge_class = "badge-malicious"
                badge_text = "🚨 MALICIOUS"
            elif verdict_upper == "SUSPICIOUS":
                badge_class = "badge-suspicious"
                badge_text = "⚠️ SUSPICIOUS"
            elif verdict_upper == "SAFE":
                badge_class = "badge-safe"
                badge_text = "✅ SAFE"
            else:
                badge_class = "badge-neutral"
                badge_text = html.escape(verdict_upper)

            score_color = "#ef4444" if r["risk_score"] >= 8 else ("#f59e0b" if r["risk_score"] >= 3 else "#10b981")

            excerpt_clean = html.escape(r["excerpt"][:200] + ("..." if len(r["excerpt"]) > 200 else "")) if r["excerpt"] else "&mdash;"
            sender_clean = html.escape(r["sender"]) if r["sender"] else "&mdash;"
            subject_clean = html.escape(r["subject"]) if r["subject"] else html.escape(r["message_id"])

            row_html = f"""
            <tr>
                <td class="col-id">#{r["id"]}</td>
                <td class="col-time">{html.escape(r["created_at"])}</td>
                <td class="col-verdict"><span class="badge {badge_class}">{badge_text}</span></td>
                <td class="col-score" style="color: {score_color}; font-weight: 700;">{r["risk_score"]}/10</td>
                <td class="col-sender">{sender_clean}</td>
                <td class="col-subject">{subject_clean}</td>
                <td class="col-excerpt">{excerpt_clean}</td>
            </tr>
            """
            table_rows_html.append(row_html.strip())

    rows_joined = "\n".join(table_rows_html)

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --bg-table-row: #1e293b;
            --bg-table-alt: #162032;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --color-malicious: #ef4444;
            --color-suspicious: #f59e0b;
            --color-safe: #10b981;
            --color-accent: #38bdf8;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            padding: 32px 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }}
        .header-title h1 {{
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .header-title p {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 4px;
        }}
        .header-badge {{
            background: #0369a1;
            color: #e0f2fe;
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: transform 0.15s ease;
        }}
        .metric-value {{
            font-size: 2rem;
            font-weight: 800;
            margin-top: 6px;
            color: var(--text-main);
        }}
        .metric-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}
        .metric-card.malicious .metric-value {{ color: var(--color-malicious); }}
        .metric-card.suspicious .metric-value {{ color: var(--color-suspicious); }}
        .metric-card.safe .metric-value {{ color: var(--color-safe); }}
        .metric-card.avg .metric-value {{ color: var(--color-accent); }}

        .table-container {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow-x: auto;
            margin-bottom: 32px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
            text-align: left;
        }}
        th {{
            background-color: #0d1527;
            color: var(--text-muted);
            font-weight: 600;
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            white-space: nowrap;
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-main);
            vertical-align: middle;
        }}
        tr:nth-child(even) {{
            background-color: var(--bg-table-alt);
        }}
        tr:hover {{
            background-color: #273549;
        }}
        .col-id {{ font-family: monospace; color: var(--text-muted); font-size: 0.8rem; }}
        .col-time {{ font-size: 0.8rem; color: var(--text-muted); white-space: nowrap; }}
        .col-score {{ font-family: monospace; font-size: 0.9rem; }}
        .col-sender {{ max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .col-subject {{ max-width: 240px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .col-excerpt {{ font-size: 0.8rem; color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.03em;
            white-space: nowrap;
        }}
        .badge-malicious {{
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.4);
        }}
        .badge-suspicious {{
            background: rgba(245, 158, 11, 0.2);
            color: #fde68a;
            border: 1px solid rgba(245, 158, 11, 0.4);
        }}
        .badge-safe {{
            background: rgba(16, 185, 129, 0.2);
            color: #a7f3d0;
            border: 1px solid rgba(16, 185, 129, 0.4);
        }}
        .badge-neutral {{
            background: rgba(148, 163, 184, 0.2);
            color: #cbd5e1;
            border: 1px solid rgba(148, 163, 184, 0.4);
        }}
        .empty-state {{
            text-align: center;
            padding: 48px 16px;
            color: var(--text-muted);
            font-style: italic;
        }}
        .footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
        @media print {{
            body {{
                background-color: #ffffff;
                color: #0f172a;
                padding: 16px;
            }}
            .header-title h1 {{ color: #0f172a; }}
            .metric-card {{
                background-color: #f8fafc;
                border: 1px solid #cbd5e1;
            }}
            .metric-value {{ color: #0f172a; }}
            .table-container {{
                border: 1px solid #cbd5e1;
            }}
            th {{
                background-color: #f1f5f9;
                color: #475569;
            }}
            td {{
                color: #0f172a;
                border-bottom: 1px solid #e2e8f0;
            }}
            tr:nth-child(even) {{ background-color: #f8fafc; }}
            .badge-malicious {{ background: #fee2e2; color: #991b1b; border-color: #f87171; }}
            .badge-suspicious {{ background: #fef3c7; color: #92400e; border-color: #fbbf24; }}
            .badge-safe {{ background: #d1fae5; color: #065f46; border-color: #34d399; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>🛡️ {html.escape(title)}</h1>
                <p>Enterprise Incident Response & Continuous Security Audit Log</p>
            </div>
            <div class="header-badge">LexiGuard SecOps v1.0</div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Audited Events</div>
                <div class="metric-value">{total_scans}</div>
            </div>
            <div class="metric-card malicious">
                <div class="metric-label">Malicious Incidents</div>
                <div class="metric-value">{malicious_count}</div>
            </div>
            <div class="metric-card suspicious">
                <div class="metric-label">Suspicious Threats</div>
                <div class="metric-value">{suspicious_count}</div>
            </div>
            <div class="metric-card safe">
                <div class="metric-label">Verified Safe</div>
                <div class="metric-value">{safe_count}</div>
            </div>
            <div class="metric-card avg">
                <div class="metric-label">Average Risk Score</div>
                <div class="metric-value">{avg_score:.1f}/10</div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Scan ID</th>
                        <th>Timestamp (UTC)</th>
                        <th>Verdict</th>
                        <th>Risk</th>
                        <th>Sender</th>
                        <th>Subject / Resource</th>
                        <th>Audit Excerpt</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_joined}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by <b>LexiGuard Enterprise Security Gateway</b> &bull; Confidential Security Audit Document
        </div>
    </div>
</body>
</html>
"""
    return report_html
