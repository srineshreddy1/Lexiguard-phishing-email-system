"""Unit tests for LexiGuard gateway attachment extraction and security inspection."""

from __future__ import annotations

import base64
from email.message import EmailMessage
import io
from pathlib import Path
import zipfile

from lexiguard.db.database import remember_threat
from lexiguard.gateway.attachments import (
    AttachmentVerdict,
    compute_hashes,
    detect_file_signature,
    extract_attachments,
    extract_attachments_from_gmail_payload,
    extract_attachments_from_mime,
    inspect_all_attachments,
    inspect_attachment,
    remember_attachment_threat,
)


def test_authentic_pdf_is_safe() -> None:
    pdf_bytes = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    report = inspect_attachment(pdf_bytes, filename="invoice.pdf", claimed_mime="application/pdf")
    assert report["verdict"] == AttachmentVerdict.SAFE
    assert report["metadata"]["detected_format"] == "PDF"
    assert report["metadata"]["is_executable"] is False
    assert len(report["metadata"]["sha256"]) == 64
    assert len(report["violations"]) == 0


def test_disguised_pe_executable_as_pdf() -> None:
    # MZ header disguised as .pdf
    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 128
    report = inspect_attachment(fake_pdf, filename="statement.pdf", claimed_mime="application/pdf")
    assert report["verdict"] == AttachmentVerdict.MALICIOUS
    assert report["metadata"]["detected_format"] == "PE_EXECUTABLE"
    assert report["metadata"]["is_executable"] is True

    codes = [v["code"] for v in report["violations"]]
    assert "TYPE_MISMATCH_EXECUTABLE_AS_PDF" in codes
    crit = next(v for v in report["violations"] if v["code"] == "TYPE_MISMATCH_EXECUTABLE_AS_PDF")
    assert crit["severity"] == "critical"


def test_disguised_pe_executable_as_image() -> None:
    fake_png = b"MZ\x90\x00" + b"\x00" * 64
    report = inspect_attachment(fake_png, filename="avatar.png", claimed_mime="image/png")
    assert report["verdict"] == AttachmentVerdict.MALICIOUS
    codes = [v["code"] for v in report["violations"]]
    assert "TYPE_MISMATCH_EXECUTABLE_AS_IMAGE" in codes


def test_double_extension_spoof() -> None:
    content = b"MZ\x90\x00"
    report = inspect_attachment(content, filename="urgent_invoice.pdf.exe")
    assert report["verdict"] == AttachmentVerdict.MALICIOUS
    assert report["metadata"]["has_double_extension"] is True
    codes = [v["code"] for v in report["violations"]]
    assert "DOUBLE_EXTENSION_SPOOF" in codes
    assert "DANGEROUS_EXECUTABLE_EXTENSION" in codes


def test_rtlo_extension_spoof() -> None:
    # Right-to-Left Override character spoofing
    content = b"%PDF-1.4"
    report = inspect_attachment(content, filename="resume\u202eexe.pdf")
    assert report["verdict"] == AttachmentVerdict.MALICIOUS
    assert report["metadata"]["has_rtlo_spoof"] is True
    codes = [v["code"] for v in report["violations"]]
    assert "RTLO_EXTENSION_SPOOF" in codes


def test_zero_width_filename_character() -> None:
    content = b"%PDF-1.4"
    report = inspect_attachment(content, filename="ticket\u200b.pdf")
    assert report["metadata"]["has_zero_width_extension"] is True
    codes = [v["code"] for v in report["violations"]]
    assert "ZERO_WIDTH_FILENAME" in codes


def test_direct_dangerous_extension() -> None:
    for name in ("script.vbs", "payload.scr", "install.bat", "run.ps1", "agent.hta"):
        report = inspect_attachment(b"dummy code", filename=name)
        assert report["verdict"] == AttachmentVerdict.MALICIOUS
        codes = [v["code"] for v in report["violations"]]
        assert "DANGEROUS_EXECUTABLE_EXTENSION" in codes


def test_authentic_png_image() -> None:
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32
    report = inspect_attachment(png_bytes, filename="logo.png", claimed_mime="image/png")
    assert report["verdict"] == AttachmentVerdict.SAFE
    assert report["metadata"]["detected_format"] == "PNG"
    assert report["metadata"]["is_executable"] is False


def test_zip_containing_dangerous_executable() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("clean_doc.txt", b"Hello world")
        zf.writestr("hidden_virus.exe", b"MZ\x00\x00")
    data = buf.getvalue()

    report = inspect_attachment(data, filename="documents.zip", claimed_mime="application/zip")
    assert report["verdict"] == AttachmentVerdict.MALICIOUS
    codes = [v["code"] for v in report["violations"]]
    assert "ARCHIVE_CONTAINS_EXECUTABLE" in codes


def test_macro_enabled_office_document() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", b"<w:document/>")
        zf.writestr("word/vbaProject.bin", b"VBA macro payload bytes")
    data = buf.getvalue()

    report = inspect_attachment(data, filename="invoice.docx", claimed_mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    assert report["verdict"] in (AttachmentVerdict.SUSPICIOUS, AttachmentVerdict.MALICIOUS)
    assert report["metadata"]["is_macro_enabled"] is True
    codes = [v["code"] for v in report["violations"]]
    assert "MACRO_ENABLED_DOCUMENT" in codes


def test_gmail_api_json_extraction() -> None:
    raw_b64 = base64.urlsafe_b64encode(b"%PDF-1.7 confidential report").decode("ascii")
    gmail_payload = {
        "id": "18a999",
        "payload": {
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "filename": "",
                    "body": {"data": base64.urlsafe_b64encode(b"Body text").decode("ascii")},
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "quarterly_results.pdf",
                    "body": {"data": raw_b64, "size": len(raw_b64)},
                },
            ],
        },
    }
    extracted = extract_attachments(gmail_payload)
    assert len(extracted) == 1
    assert extracted[0].filename == "quarterly_results.pdf"
    assert extracted[0].content == b"%PDF-1.7 confidential report"


def test_mime_email_message_extraction() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Important contract"
    msg["From"] = "legal@corp.example"
    msg["To"] = "ciso@corp.example"
    msg.set_content("Please sign and return.")
    msg.add_attachment(b"%PDF-1.5 agreement content", maintype="application", subtype="pdf", filename="agreement.pdf")

    extracted = extract_attachments(msg)
    assert len(extracted) == 1
    assert extracted[0].filename == "agreement.pdf"
    assert extracted[0].content == b"%PDF-1.5 agreement content"


def test_cryptographic_hashes_and_virustotal() -> None:
    sample = b"Test payload bytes for hashing"
    hashes = compute_hashes(sample)
    assert hashes["sha256"] == "e3f2788ea038d2fdcfc0e1c5b2c8f92043cb6431d9f05f3e12c73ebb7f599c76"
    assert hashes["md5"] == "237c26f92c7feef1b6143ca11ab80ca7"
    assert hashes["sha1"] == "55d0f41d4550a200e32fcbe9a8d8ba83e1d7c9a9"
    assert "https://www.virustotal.com/gui/file/" in hashes["virustotal_url"]


def test_threat_intel_memory_integration(tmp_path: Path) -> None:
    test_db = tmp_path / "test_lexiguard.db"
    malicious_bytes = b"bad_malware_payload_12345"
    mal_hash = compute_hashes(malicious_bytes)["sha256"]

    # Pre-seed threat intelligence database with known malicious hash
    remember_threat(
        indicator=mal_hash,
        indicator_type="sha256",
        verdict="MALICIOUS",
        evidence={"family": "Trojan.Dropper"},
        db_path=test_db,
    )

    # Inspect attachment referencing the pre-seeded DB
    report = inspect_attachment(
        malicious_bytes,
        filename="safe_look.txt",
        db_path=test_db,
    )
    assert report["verdict"] == AttachmentVerdict.MALICIOUS
    codes = [v["code"] for v in report["violations"]]
    assert "KNOWN_MALICIOUS_HASH" in codes
    assert report["threat_intel_match"] is not None
    assert report["threat_intel_match"]["verdict"] == "MALICIOUS"
