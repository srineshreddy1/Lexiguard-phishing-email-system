#!/usr/bin/env python3
"""LexiGuard Enterprise Security Gateway — On-Demand Local Launcher.

Initializes the high-concurrency WAL-mode SQLite database, bootstraps initial
OSINT threat intelligence memory (no-zero-start), and launches the Streamlit
SecOps web dashboard.

Cross-platform: Windows, macOS, Linux.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

# Ensure UTF-8 console output encoding on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure LexiGuard project root is in Python module search path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def check_python_version() -> None:
    """Ensure runtime is Python 3.10 or newer."""
    if sys.version_info < (3, 10):
        sys.stderr.write(
            f"ERROR: LexiGuard requires Python 3.10+, but found Python "
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}\n"
        )
        sys.exit(1)


def bootstrap_database() -> None:
    """Initialize WAL-mode SQLite database and seed initial OSINT threat memory."""
    print("🛡️  Initializing LexiGuard Threat Memory & Audit Ledger...")
    try:
        from lexiguard.db.database import DEFAULT_DB_PATH, get_db_stats
        from lexiguard.db.seed_intel import seed_threat_intel

        # Seed OSINT threat intelligence if not already present
        seeded_count = seed_threat_intel(db_path=DEFAULT_DB_PATH, force=False)
        total_scans, total_threats = get_db_stats(db_path=DEFAULT_DB_PATH)

        if seeded_count > 0:
            print(f"✓ Bootstrapped {seeded_count} curated threat indicators into local memory.")
        print(f"✓ Database active: {DEFAULT_DB_PATH} (Scans: {total_scans}, Threats: {total_threats})")
    except Exception as exc:
        print(f"⚠️  Database initialization warning: {exc}")


def launch_dashboard() -> None:
    """Launch the Streamlit web dashboard application."""
    app_path = PROJECT_ROOT / "app.py"
    if not app_path.exists():
        sys.stderr.write(f"ERROR: Cannot find dashboard entrypoint at {app_path}\n")
        sys.exit(1)

    print("\n🚀 Launching LexiGuard SecOps Dashboard on local interface...")
    print("   Press Ctrl+C in this terminal to stop the application.\n")

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.headless=false",
        "--theme.base=dark",
        "--theme.backgroundColor=#0b0f19",
        "--theme.secondaryBackgroundColor=#1e293b",
        "--theme.textColor=#e2e8f0",
        "--theme.primaryColor=#00E5FF",
    ]

    # Forward any extra command line arguments
    if len(sys.argv) > 1:
        cmd.extend(sys.argv[1:])

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n🛑 LexiGuard gateway stopped by user. Goodbye!")
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(f"\nStreamlit exited with returncode {exc.returncode}\n")
        sys.exit(exc.returncode)


def main() -> None:
    """Main launcher entrypoint."""
    check_python_version()
    bootstrap_database()
    launch_dashboard()


if __name__ == "__main__":
    main()
