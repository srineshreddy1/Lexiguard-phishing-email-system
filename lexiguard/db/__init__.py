"""Local SQLite persistence for scan history and threat intel."""

from lexiguard.db.database import get_recent_scans, log_scan, lookup_threat, remember_threat

__all__ = ["get_recent_scans", "log_scan", "lookup_threat", "remember_threat"]
