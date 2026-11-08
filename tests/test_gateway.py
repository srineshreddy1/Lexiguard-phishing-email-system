"""Unit tests for LexiGuard GmailClient gateway integration."""

from __future__ import annotations

import base64
from pathlib import Path

from lexiguard.gateway.attachments import AttachmentVerdict
from lexiguard.gateway.gmail_client import GmailClient


def test_gmail_client_inspects_html_and_attachment(tmp_path: Path) -> None:
    test_db = tmp_path / "test_gateway.db"
    client = GmailClient(db_path=test_db)

    # Simulated email with microscopic font evasion and a disguised PE executable attachment
    html_content = '<p>Hello world <span style="font-size: 1px">Secret Spam Noise</span></p>'
    html_b64 = base64.urlsafe_b64encode(html_content.encode("utf-8")).decode("ascii")

    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 64
    att_b64 = base64.urlsafe_b64encode(fake_pdf).decode("ascii")

    msg = {
        "id": "msg_test_001",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "attacker@evil.example"},
                {"name": "Subject", "value": "Urgent Invoice Attached"},
            ],
            "parts": [
                {
                    "mimeType": "text/html",
                    "filename": "",
                    "body": {"data": html_b64},
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {"data": att_b64, "size": len(fake_pdf)},
                },
            ],
        },
    }

    result = client.inspect_message_payload(msg)

    assert result["message_id"] == "msg_test_001"
    assert result["sender"] == "attacker@evil.example"
    assert result["subject"] == "Urgent Invoice Attached"
    assert result["verdict"] == "MALICIOUS"
    assert result["html_report"] is not None
    assert result["html_report"]["has_evasion"] is True
    assert len(result["attachment_reports"]) == 1

    att_rep = result["attachment_reports"][0]
    assert att_rep["filename"] == "invoice.pdf"
    assert att_rep["verdict"] == AttachmentVerdict.MALICIOUS
    assert any(v["code"] == "TYPE_MISMATCH_EXECUTABLE_AS_PDF" for v in att_rep["violations"])

    # Verify DB was created and scan logged
    assert test_db.exists()


def test_gmail_client_universal_trust_legitimate_email(tmp_path: Path) -> None:
    test_db = tmp_path / "test_gateway_auth.db"
    client = GmailClient(db_path=test_db)

    # Legitimate corporate email with preview preheader and account-verify link
    html_content = '<p>Hi! <span style="font-size: 0px">Hidden preview snippet</span></p><a href="https://www.linkedin.com/comm/mynetwork/invite-accept">Accept Invitation</a>'
    html_b64 = base64.urlsafe_b64encode(html_content.encode("utf-8")).decode("ascii")

    msg_auth = {
        "id": "msg_linkedin_001",
        "payload": {
            "mimeType": "text/html",
            "headers": [
                {"name": "From", "value": "Saloni Shakya <invitations@linkedin.com>"},
                {"name": "Subject", "value": "I want to connect"},
                {"name": "Authentication-Results", "value": "mx.google.com; dkim=pass header.i=@linkedin.com; spf=pass smtp.mailfrom=invitations@linkedin.com; dmarc=pass"},
            ],
            "body": {"data": html_b64},
            "parts": [],
        },
    }

    result = client.inspect_message_payload(msg_auth)
    assert result["verdict"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["is_universally_trusted"] is True


def test_gmail_client_detects_display_name_spoofing(tmp_path: Path) -> None:
    test_db = tmp_path / "test_gateway_spoof.db"
    client = GmailClient(db_path=test_db)

    html_content = '<p>Please click <a href="https://unrelated-domain.xyz/verify">here to verify</a></p>'
    html_b64 = base64.urlsafe_b64encode(html_content.encode("utf-8")).decode("ascii")

    msg_spoof = {
        "id": "msg_spoof_002",
        "payload": {
            "mimeType": "text/html",
            "headers": [
                {"name": "From", "value": '"PayPal Security" <alert@unrelated-bad-domain.xyz>'},
                {"name": "Subject", "value": "Account suspended"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=pass; dkim=pass"},
            ],
            "body": {"data": html_b64},
            "parts": [],
        },
    }

    result = client.inspect_message_payload(msg_spoof)
    assert result["is_universally_trusted"] is False
    assert result["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_gmail_client_small_business_esp_trust(tmp_path: Path) -> None:
    test_db = tmp_path / "test_gateway_esp.db"
    client = GmailClient(db_path=test_db)

    html_content = '<p>Confirm your signup at <a href="https://startup.io/verify?token=123">Verify Email</a></p>'
    html_b64 = base64.urlsafe_b64encode(html_content.encode("utf-8")).decode("ascii")

    msg_startup = {
        "id": "msg_startup_003",
        "payload": {
            "mimeType": "text/html",
            "headers": [
                {"name": "From", "value": '"Startup Team" <hello@startup.io>'},
                {"name": "Subject", "value": "Welcome to Startup"},
                {"name": "Authentication-Results", "value": "mx.google.com; dkim=pass header.i=@sendgrid.net; spf=pass smtp.mailfrom=bounces.sendgrid.net; dmarc=pass"},
            ],
            "body": {"data": html_b64},
            "parts": [],
        },
    }

    result = client.inspect_message_payload(msg_startup)
    assert result["verdict"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["is_universally_trusted"] is True
