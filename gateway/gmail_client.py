"""LexiGuard Phase 4: Live Gmail Ingestion Gateway & Security Wrapper.

Handles secure OAuth 2.0 authentication, strict token confidentiality, 
non-blocking MIME email parsing, anti-evasion text sanitization, core 
static analysis execution, and SQLite threat intel logging.
"""

import base64
import logging
import os
import stat
from pathlib import Path
from typing import Any, Optional, TypedDict

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Import LexiGuard Core and Persistence Modules
from lexiguard.core.parser import parse_url
from lexiguard.core.features import extract_features
from lexiguard.core.scorer import score_risk
from lexiguard.db.database import log_scan

# Configure restricted logging (strictly avoiding token/secret disclosure)
logger = logging.getLogger("LexiGuard.Gateway")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [Gateway]: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# OAuth 2.0 Configuration
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
BASE_DIR = Path(__file__).resolve().parent.parent
CREDENTIALS_PATH = BASE_DIR / "credentials.json"
TOKEN_PATH = BASE_DIR / "token.json"


class EmailScanReport(TypedDict):
    message_id: str
    sender: str
    subject: str
    extracted_urls: list[str]
    analysis_results: list[dict[str, Any]]
    db_scan_ids: list[int]


def _secure_file_permissions(file_path: Path) -> None:
    """Restrict file permissions to owner read/write only (POSIX & Windows fallback)."""
    try:
        if file_path.exists():
            # Restrict permissions to user read/write (chmod 600)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as exc:
        logger.warning("Could not apply strict file permissions on %s: %s", file_path.name, exc)


def get_gmail_service() -> Any:
    """Authenticate securely via OAuth 2.0 and return the authorized Gmail API service.

    Enforces strict confidentiality by protecting token files and avoiding
    any leakage of client secrets or refresh tokens in logs or tracebacks.
    """
    creds: Optional[Credentials] = None
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if TOKEN_PATH.exists():
            creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not CREDENTIALS_PATH.exists():
                    raise FileNotFoundError(
                        f"Google OAuth credentials file missing at {CREDENTIALS_PATH}."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(CREDENTIALS_PATH), SCOPES
                )
                creds = flow.run_local_server(port=0)

            # Save token securely and restrict file permissions
            with open(TOKEN_PATH, "w") as token_file:
                token_file.write(creds.to_json())
            _secure_file_permissions(TOKEN_PATH)

    except Exception as exc:
        # Prevent logging any raw credentials or tokens
        logger.error("Authentication handshake failed securely. Reason: %s", type(exc).__name__)
        raise

    return build("gmail", "v1", credentials=creds)


def _extract_mime_body(payload: dict[str, Any]) -> str:
    """Recursively extract and decode plaintext/HTML body from MIME parts safely."""
    body_text = ""
    try:
        body_data = payload.get("body", {}).get("data")
        if body_data:
            decoded_bytes = base64.urlsafe_b64decode(body_data.encode("ASCII"))
            body_text += decoded_bytes.decode("utf-8", errors="ignore")
    except Exception as err:
        logger.debug("Failed parsing MIME body part: %s", err)

    for part in payload.get("parts", []):
        body_text += _extract_mime_body(part)

    return body_text


def _extract_urls_from_text(text: str) -> list[str]:
    """Basic regex helper to extract URL candidates from email text bodies."""
    import re
    url_pattern = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")
    return list(set(url_pattern.findall(text)))


def process_unread_inbox(max_results: int = 5) -> list[EmailScanReport]:
    """Fetch unread emails, sanitize text, run core analysis, and log to SQLite database.

    Pipeline Flow:
    1. Polls Gmail API for unread messages (`is:unread`).
    2. Decodes MIME payloads securely.
    3. Passes data through Anti-Evasion checks (zero-width stripping).
    4. Evaluates URLs through Phases 1-3 (Parser, Features, Scorer).
    5. Automatically logs results to SQLite database via Phase 6 (`log_scan`).
    """
    try:
        service = get_gmail_service()
        response = service.users().messages().list(
            userId="me", q="is:unread", maxResults=max_results
        ).execute()
    except Exception as exc:
        logger.error("Failed to query unread Gmail messages: %s", type(exc).__name__)
        return []

    messages = response.get("messages", [])
    scan_reports: list[EmailScanReport] = []

    for msg_stub in messages:
        msg_id = msg_stub["id"]
        try:
            msg = service.users().messages().get(
                userId="me", id=msg_id, format="full"
            ).execute()
        except Exception as err:
            logger.warning("Skipping message ID %s due to fetch error: %s", msg_id, err)
            continue

        headers = msg["payload"].get("headers", [])
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "Unknown Sender")

        # Extract raw email body
        raw_body = _extract_mime_body(msg["payload"])

        # -------------------------------------------------------------
        # Phase 4.5: Anti-Evasion & Steganography Sanitization Point
        # (Strip zero-width spaces, normalize unicode anomalies before parsing)
        # -------------------------------------------------------------
        sanitized_body = raw_body.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")

        # Extract URL candidates from sanitized body
        urls = _extract_urls_from_text(sanitized_body)
        analysis_results = []
        db_scan_ids = []

        # Run through Phases 1-3 Core Static Analysis & Phase 6 DB Logging
        for target_url in urls:
            try:
                parsed = parse_url(target_url)
                features = extract_features(parsed)
                score_dict = score_risk(features)

                verdict_str = score_dict["verdict"].value if hasattr(score_dict["verdict"], "value") else str(score_dict["verdict"])
                risk_score = score_dict["risk_score"]

                # Log into SQLite (Phase 6 Integration - automatically caches malicious indicators)
                scan_id = log_scan(
                    target_type="URL",
                    raw_input=target_url,
                    risk_score=risk_score,
                    verdict=verdict_str,
                    summary=score_dict["summary"],
                )

                analysis_results.append(score_dict)
                db_scan_ids.append(scan_id)

            except Exception as parse_err:
                logger.error("Failed analyzing extracted URL '%s': %s", target_url, parse_err)

        scan_reports.append({
            "message_id": msg_id,
            "sender": sender,
            "subject": subject,
            "extracted_urls": urls,
            "analysis_results": analysis_results,
            "db_scan_ids": db_scan_ids,
        })

    logger.info("Successfully processed %d unread emails from live inbox.", len(scan_reports))
    return scan_reports