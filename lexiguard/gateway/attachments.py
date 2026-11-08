"""Attachment extraction and static file-security inspection for email gateways.

Extracts attachments from Gmail API message resources and RFC 822 MIME payloads,
verifies file signatures via magic-byte header analysis, detects disguised
executables, double-extension spoofing, RTLO Unicode tampering, embedded macros,
archive payload hazards, and calculates cryptographic digests for threat memory
and VirusTotal integration.

All inspection is strictly static and performed in-memory without filesystem execution.
"""

from __future__ import annotations

import base64
import email
from email.message import EmailMessage
from enum import Enum
import hashlib
import io
import json
from pathlib import Path
import re
import unicodedata
import zipfile
from typing import Any, NamedTuple, TypedDict

from lexiguard.db.database import lookup_threat, remember_threat


class AttachmentVerdict(str, Enum):
    """Categorical security verdict for inspected attachments."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class AttachmentViolation(TypedDict):
    """Structured policy violation for an attachment hazard."""

    code: str
    severity: str  # "low", "medium", "high", "critical"
    message: str
    evidence: dict[str, Any]


class AttachmentMetadata(TypedDict):
    """Normalized technical metadata and cryptographic digests for an attachment."""

    filename: str
    sanitized_filename: str
    declared_extension: str
    declared_mime_type: str
    detected_mime_type: str
    detected_format: str
    size_bytes: int
    sha256: str
    md5: str
    sha1: str
    virustotal_url: str
    is_executable: bool
    is_archive: bool
    is_macro_enabled: bool
    has_double_extension: bool
    has_rtlo_spoof: bool
    has_zero_width_extension: bool


class AttachmentReport(TypedDict):
    """Complete security inspection report for an attachment."""

    filename: str
    verdict: AttachmentVerdict
    risk_score: int
    metadata: AttachmentMetadata
    violations: list[AttachmentViolation]
    threat_intel_match: dict[str, Any] | None


class ExtractedAttachment(NamedTuple):
    """In-memory representation of an extracted email attachment."""

    filename: str
    content: bytes
    claimed_mime_type: str
    size_bytes: int
    attachment_id: str | None = None


# High-risk executable and script extensions
DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1", ".hta",
    ".cpl", ".msc", ".msi", ".msp", ".reg", ".inf", ".application",
    ".gadget", ".jar", ".dll", ".sys", ".drv", ".bin",
}

# Macro-enabled Microsoft Office extensions
MACRO_EXTENSIONS: set[str] = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm",
    ".ppam", ".ppsm", ".sldm",
}

# Archive and disk image formats
ARCHIVE_EXTENSIONS: set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".img", ".vhd", ".vhdx", ".cab", ".ace",
}

# Standard document extensions expected to not contain native executables
DOCUMENT_EXTENSIONS: set[str] = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".rtf", ".txt", ".csv",
}

# Image extensions
IMAGE_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp", ".webp",
    ".svg", ".ico", ".tiff", ".tif",
}

_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|rtf)\.(exe|scr|pif|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|cpl|msi|jar)$",
    re.IGNORECASE,
)
_ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}


class SignatureDefinition(NamedTuple):
    """Magic byte specification for binary signature matching."""

    name: str
    mime_type: str
    is_executable: bool
    is_archive: bool
    extensions: set[str]
    magic_bytes: bytes | list[bytes]
    offset: int = 0


_SIGNATURE_DB: list[SignatureDefinition] = [
    # Windows PE Executables (.exe, .dll, .sys, .scr, .cpl)
    SignatureDefinition(
        name="PE_EXECUTABLE",
        mime_type="application/x-dosexec",
        is_executable=True,
        is_archive=False,
        extensions={".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
        magic_bytes=b"MZ",
        offset=0,
    ),
    # Linux ELF Executables
    SignatureDefinition(
        name="ELF_EXECUTABLE",
        mime_type="application/x-executable",
        is_executable=True,
        is_archive=False,
        extensions={".elf", ".bin", ".so"},
        magic_bytes=b"\x7fELF",
        offset=0,
    ),
    # Mach-O Executables
    SignatureDefinition(
        name="MACHO_EXECUTABLE",
        mime_type="application/x-mach-binary",
        is_executable=True,
        is_archive=False,
        extensions={".dylib", ".macho"},
        magic_bytes=[
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
        ],
        offset=0,
    ),
    # Windows Shortcut (.lnk)
    SignatureDefinition(
        name="WINDOWS_LNK",
        mime_type="application/x-ms-shortcut",
        is_executable=True,
        is_archive=False,
        extensions={".lnk"},
        magic_bytes=b"\x4c\x00\x00\x00",
        offset=0,
    ),
    # PDF Documents
    SignatureDefinition(
        name="PDF",
        mime_type="application/pdf",
        is_executable=False,
        is_archive=False,
        extensions={".pdf"},
        magic_bytes=b"%PDF",
        offset=0,
    ),
    # PNG Images
    SignatureDefinition(
        name="PNG",
        mime_type="image/png",
        is_executable=False,
        is_archive=False,
        extensions={".png"},
        magic_bytes=b"\x89PNG\r\n\x1a\n",
        offset=0,
    ),
    # JPEG Images
    SignatureDefinition(
        name="JPEG",
        mime_type="image/jpeg",
        is_executable=False,
        is_archive=False,
        extensions={".jpg", ".jpeg", ".jpe"},
        magic_bytes=b"\xff\xd8\xff",
        offset=0,
    ),
    # GIF Images
    SignatureDefinition(
        name="GIF",
        mime_type="image/gif",
        is_executable=False,
        is_archive=False,
        extensions={".gif"},
        magic_bytes=[b"GIF87a", b"GIF89a"],
        offset=0,
    ),
    # BMP Images
    SignatureDefinition(
        name="BMP",
        mime_type="image/bmp",
        is_executable=False,
        is_archive=False,
        extensions={".bmp"},
        magic_bytes=b"BM",
        offset=0,
    ),
    # ZIP Archives & Office OpenXML
    SignatureDefinition(
        name="ZIP_OR_OFFICE",
        mime_type="application/zip",
        is_executable=False,
        is_archive=True,
        extensions={".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".docm", ".xlsm"},
        magic_bytes=[b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
        offset=0,
    ),
    # Microsoft Compound File Binary Format (OLE CFBF)
    SignatureDefinition(
        name="OLE_CFBF",
        mime_type="application/x-ole-storage",
        is_executable=False,
        is_archive=False,
        extensions={".doc", ".xls", ".ppt", ".msg", ".msi"},
        magic_bytes=b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        offset=0,
    ),
    # 7-Zip Archives
    SignatureDefinition(
        name="7Z",
        mime_type="application/x-7z-compressed",
        is_executable=False,
        is_archive=True,
        extensions={".7z"},
        magic_bytes=b"7z\xbc\xaf\x27\x1c",
        offset=0,
    ),
    # RAR Archives
    SignatureDefinition(
        name="RAR",
        mime_type="application/x-rar-compressed",
        is_executable=False,
        is_archive=True,
        extensions={".rar"},
        magic_bytes=[b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
        offset=0,
    ),
    # GZIP
    SignatureDefinition(
        name="GZIP",
        mime_type="application/gzip",
        is_executable=False,
        is_archive=True,
        extensions={".gz", ".tgz"},
        magic_bytes=b"\x1f\x8b",
        offset=0,
    ),
    # TAR (offset 257)
    SignatureDefinition(
        name="TAR",
        mime_type="application/x-tar",
        is_executable=False,
        is_archive=True,
        extensions={".tar"},
        magic_bytes=b"ustar",
        offset=257,
    ),
    # RTF
    SignatureDefinition(
        name="RTF",
        mime_type="application/rtf",
        is_executable=False,
        is_archive=False,
        extensions={".rtf"},
        magic_bytes=b"{\\rtf",
        offset=0,
    ),
]


def detect_file_signature(content: bytes) -> tuple[str, str, bool, bool]:
    """Identify true format, mime_type, is_executable, is_archive from magic bytes.

    Args:
        content: Raw attachment bytes.

    Returns:
        tuple of (format_name, detected_mime_type, is_executable, is_archive)
    """
    if not content:
        return ("EMPTY", "application/x-empty", False, False)

    for sig in _SIGNATURE_DB:
        patterns = sig.magic_bytes if isinstance(sig.magic_bytes, list) else [sig.magic_bytes]
        for pat in patterns:
            end = sig.offset + len(pat)
            if len(content) >= end and content[sig.offset:end] == pat:
                return (sig.name, sig.mime_type, sig.is_executable, sig.is_archive)

    # Check for ISO 9660 image
    for iso_offset in (32768, 34816, 36864):
        if len(content) >= iso_offset + 5 and content[iso_offset:iso_offset + 5] == b"CD001":
            return ("ISO_IMAGE", "application/x-iso9660-image", False, True)

    # Check for shell scripts
    if content.startswith(b"#!"):
        return ("SHELL_SCRIPT", "text/x-shellscript", True, False)

    # Check if printable text / HTML / XML
    sample = content[:1024]
    try:
        sample_str = sample.decode("utf-8")
        if re.search(r"<!doctype\s+html|<html", sample_str, re.IGNORECASE):
            return ("HTML_DOCUMENT", "text/html", False, False)
        if sample_str.startswith("<?xml"):
            return ("XML_DOCUMENT", "application/xml", False, False)
        if all(c in "\r\n\t\b\f" or (32 <= ord(c) < 127) for c in sample_str):
            return ("PLAIN_TEXT", "text/plain", False, False)
    except UnicodeDecodeError:
        pass

    return ("UNKNOWN_BINARY", "application/octet-stream", False, False)


def compute_hashes(content: bytes) -> dict[str, str]:
    """Compute SHA-256, MD5, and SHA-1 cryptographic hashes of payload content.

    Args:
        content: Raw attachment bytes.

    Returns:
        Dictionary with sha256, md5, sha1 hex strings, and a VirusTotal URL.
    """
    sha256 = hashlib.sha256(content).hexdigest().lower()
    md5 = hashlib.md5(content).hexdigest().lower()
    sha1 = hashlib.sha1(content).hexdigest().lower()
    return {
        "sha256": sha256,
        "md5": md5,
        "sha1": sha1,
        "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def _safe_b64decode(data_str: str) -> bytes:
    """Safely decode base64 / base64url data with missing padding."""
    cleaned = data_str.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    padding = (4 - (len(cleaned) % 4)) % 4
    padded = cleaned + ("=" * padding)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return base64.b64decode(padded)


def extract_attachments_from_gmail_payload(payload: dict[str, Any]) -> list[ExtractedAttachment]:
    """Recursively extract attachments from a Gmail API message resource dictionary.

    Args:
        payload: Full Gmail API message dict or payload dict.

    Returns:
        List of ExtractedAttachment instances with filename, bytes, and MIME types.
    """
    attachments: list[ExtractedAttachment] = []

    def _walk_part(part: dict[str, Any]) -> None:
        filename = part.get("filename", "").strip()
        mime_type = part.get("mimeType", "application/octet-stream").strip()
        body = part.get("body", {})
        data_str = body.get("data")
        att_id = body.get("attachmentId")
        size = body.get("size", 0)

        # Check Content-Disposition header
        headers = {h.get("name", "").lower(): h.get("value", "") for h in part.get("headers", [])}
        disp = headers.get("content-disposition", "")

        is_attachment = (
            bool(filename)
            or disp.lower().startswith("attachment")
            or "filename=" in disp.lower()
            or (bool(att_id) and mime_type not in ("text/plain", "text/html"))
        )

        if is_attachment:
            content_bytes = b""
            if data_str:
                try:
                    content_bytes = _safe_b64decode(data_str)
                except Exception:
                    content_bytes = b""
            effective_filename = filename or f"attachment_{len(attachments) + 1}.bin"
            effective_size = len(content_bytes) if content_bytes else size
            attachments.append(
                ExtractedAttachment(
                    filename=effective_filename,
                    content=content_bytes,
                    claimed_mime_type=mime_type,
                    size_bytes=effective_size,
                    attachment_id=att_id,
                )
            )

        # Recurse child parts
        for sub_part in part.get("parts", []):
            _walk_part(sub_part)

    if "payload" in payload:
        _walk_part(payload["payload"])
    else:
        _walk_part(payload)

    return attachments


def extract_attachments_from_mime(
    mime_msg: EmailMessage | email.message.Message | bytes | str,
) -> list[ExtractedAttachment]:
    """Extract attachments from a standard Python email message or raw MIME bytes.

    Args:
        mime_msg: EmailMessage, email.message.Message, or raw bytes / str.

    Returns:
        List of ExtractedAttachment instances.
    """
    if isinstance(mime_msg, (bytes, str)):
        if isinstance(mime_msg, str):
            msg = email.message_from_string(mime_msg)
        else:
            msg = email.message_from_bytes(mime_msg)
    else:
        msg = mime_msg

    attachments: list[ExtractedAttachment] = []
    idx = 1
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disp = part.get("Content-Disposition", "")
        if filename or disp.lower().startswith("attachment"):
            content = part.get_payload(decode=True) or b""
            effective_name = filename or f"attachment_{idx}.bin"
            attachments.append(
                ExtractedAttachment(
                    filename=effective_name,
                    content=content,
                    claimed_mime_type=part.get_content_type(),
                    size_bytes=len(content),
                )
            )
            idx += 1
    return attachments


def extract_attachments(source: Any) -> list[ExtractedAttachment]:
    """Polymorphic attachment extractor supporting Gmail JSON dict, EmailMessage, or raw MIME bytes."""
    if isinstance(source, dict):
        return extract_attachments_from_gmail_payload(source)
    return extract_attachments_from_mime(source)


def inspect_attachment(
    attachment: ExtractedAttachment | bytes,
    filename: str = "",
    claimed_mime: str = "",
    db_path: Path | None = None,
) -> AttachmentReport:
    """Inspect an attachment for disguised executables, extension anomalies, macros, and hashes.

    Args:
        attachment: ExtractedAttachment tuple or raw content bytes.
        filename: Optional filename (used if attachment is raw bytes).
        claimed_mime: Optional claimed MIME type.
        db_path: Path to local SQLite threat intel database.

    Returns:
        Structured AttachmentReport containing verdict, risk score, metadata, and violations.
    """
    if isinstance(attachment, bytes):
        content = attachment
        file_name = filename or "unnamed.bin"
        mime_type = claimed_mime or "application/octet-stream"
    else:
        content = attachment.content
        file_name = attachment.filename or filename or "unnamed.bin"
        mime_type = attachment.claimed_mime_type or claimed_mime or "application/octet-stream"

    violations: list[AttachmentViolation] = []
    hashes = compute_hashes(content)
    sha256 = hashes["sha256"]
    size_bytes = len(content)

    # 1. Filename sanitization & anomaly analysis
    has_rtlo = "\u202e" in file_name
    has_zero_width = any(ch in file_name for ch in _ZERO_WIDTH_CHARS)
    clean_name = unicodedata.normalize("NFC", file_name)
    clean_name = "".join(ch for ch in clean_name if ch not in _ZERO_WIDTH_CHARS and ch != "\u202e")

    # Double extension check (e.g. invoice.pdf.exe)
    has_double_ext = bool(_DOUBLE_EXT_RE.search(clean_name))

    # Declared extension
    path_obj = Path(clean_name)
    declared_ext = path_obj.suffix.lower()

    # 2. Magic byte inspection
    fmt_name, detected_mime, is_executable, is_archive = detect_file_signature(content)
    is_macro_enabled = declared_ext in MACRO_EXTENSIONS

    # Deep inspection for archives and Office documents
    if fmt_name == "ZIP_OR_OFFICE" and content:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                total_uncompressed = 0
                for info in zf.infolist():
                    total_uncompressed += info.file_size
                    entry_name = info.filename.lower()

                    # Check for embedded VBA project
                    if "vbaproject.bin" in entry_name:
                        is_macro_enabled = True

                    # Check for dangerous executables inside archive
                    entry_ext = Path(entry_name).suffix
                    if entry_ext in DANGEROUS_EXTENSIONS:
                        violations.append(
                            {
                                "code": "ARCHIVE_CONTAINS_EXECUTABLE",
                                "severity": "critical",
                                "message": f"Archive contains dangerous executable entry: {info.filename}",
                                "evidence": {"entry": info.filename, "entry_size": info.file_size},
                            }
                        )

                # Compression bomb check
                is_zip_bomb = False
                if total_uncompressed > 100 * 1024 * 1024:
                    is_zip_bomb = True
                elif size_bytes > 1024 and (total_uncompressed / max(1, size_bytes)) > 100.0:
                    is_zip_bomb = True

                if is_zip_bomb:
                    violations.append(
                        {
                            "code": "ZIP_BOMB_DETECTED",
                            "severity": "critical",
                            "message": "Potential zip bomb / decompression exhaustion attack detected",
                            "evidence": {"compressed": size_bytes, "uncompressed": total_uncompressed},
                        }
                    )
        except zipfile.BadZipFile:
            violations.append(
                {
                    "code": "CORRUPTED_ARCHIVE",
                    "severity": "medium",
                    "message": "Corrupted or malformed ZIP payload",
                    "evidence": {"declared_ext": declared_ext},
                }
            )

    # Legacy OLE2 CFBF macro check
    if fmt_name == "OLE_CFBF" and content:
        if b"VBA" in content or b"_VBA_PROJECT" in content:
            is_macro_enabled = True

    # 3. Policy violations & Disguised extension checks
    # Type mismatch: Claimed PDF but executable header
    if declared_ext == ".pdf" and is_executable:
        violations.append(
            {
                "code": "TYPE_MISMATCH_EXECUTABLE_AS_PDF",
                "severity": "critical",
                "message": f"CRITICAL: Attachment claims to be PDF but contains executable header ({fmt_name})",
                "evidence": {
                    "declared_extension": declared_ext,
                    "detected_format": fmt_name,
                    "magic_bytes": content[:8].hex(),
                },
            }
        )
    elif declared_ext in IMAGE_EXTENSIONS and is_executable:
        violations.append(
            {
                "code": "TYPE_MISMATCH_EXECUTABLE_AS_IMAGE",
                "severity": "critical",
                "message": f"CRITICAL: Image file disguised with executable header ({fmt_name})",
                "evidence": {
                    "declared_extension": declared_ext,
                    "detected_format": fmt_name,
                },
            }
        )
    elif declared_ext in DOCUMENT_EXTENSIONS and is_executable:
        violations.append(
            {
                "code": "TYPE_MISMATCH_EXECUTABLE_AS_DOCUMENT",
                "severity": "critical",
                "message": f"CRITICAL: Document file disguised with executable header ({fmt_name})",
                "evidence": {
                    "declared_extension": declared_ext,
                    "detected_format": fmt_name,
                },
            }
        )
    elif declared_ext == ".pdf" and fmt_name not in ("PDF", "EMPTY"):
        violations.append(
            {
                "code": "TYPE_MISMATCH",
                "severity": "high",
                "message": f"File claims .pdf extension but lacks %PDF header (detected {fmt_name})",
                "evidence": {"declared_extension": declared_ext, "detected_format": fmt_name},
            }
        )

    # Dangerous extension
    if declared_ext in DANGEROUS_EXTENSIONS:
        violations.append(
            {
                "code": "DANGEROUS_EXECUTABLE_EXTENSION",
                "severity": "critical",
                "message": f"Directly hazardous executable attachment extension: {declared_ext}",
                "evidence": {"extension": declared_ext},
            }
        )

    # Double extension spoofing
    if has_double_ext:
        violations.append(
            {
                "code": "DOUBLE_EXTENSION_SPOOF",
                "severity": "critical",
                "message": f"Dangerous double-extension spoofing pattern in filename: {clean_name}",
                "evidence": {"filename": clean_name},
            }
        )

    # RTLO spoofing
    if has_rtlo:
        violations.append(
            {
                "code": "RTLO_EXTENSION_SPOOF",
                "severity": "critical",
                "message": "Right-to-Left Override (RTLO) unicode extension spoofing detected",
                "evidence": {"raw_filename": file_name},
            }
        )

    # Zero-width filename injection
    if has_zero_width:
        violations.append(
            {
                "code": "ZERO_WIDTH_FILENAME",
                "severity": "medium",
                "message": "Zero-width unicode character hidden in attachment filename",
                "evidence": {"raw_filename": file_name},
            }
        )

    # Macro-enabled document
    if is_macro_enabled:
        sev = "critical" if declared_ext in (".docx", ".xlsx", ".pptx") else "high"
        violations.append(
            {
                "code": "MACRO_ENABLED_DOCUMENT",
                "severity": sev,
                "message": "Attachment contains active VBA macros or macro-enabled template",
                "evidence": {"declared_extension": declared_ext},
            }
        )

    # Empty payload
    if size_bytes == 0:
        violations.append(
            {
                "code": "EMPTY_ATTACHMENT",
                "severity": "low",
                "message": "Attachment payload contains 0 bytes",
                "evidence": {},
            }
        )

    # 4. Threat memory lookup
    threat_intel_match = None
    try:
        match = lookup_threat(sha256, db_path=db_path)
        if match:
            threat_intel_match = match
            if match.get("verdict") == "MALICIOUS":
                violations.append(
                    {
                        "code": "KNOWN_MALICIOUS_HASH",
                        "severity": "critical",
                        "message": "Attachment SHA-256 matches known malicious signature in Threat Intel memory",
                        "evidence": match,
                    }
                )
    except Exception:
        pass

    # 5. Risk score & Categorical Verdict
    score = 0
    has_critical = False
    has_high = False

    for v in violations:
        sev = v.get("severity", "medium")
        if sev == "critical":
            score += 10
            has_critical = True
        elif sev == "high":
            score += 5
            has_high = True
        elif sev == "medium":
            score += 2
        else:
            score += 1

    if has_critical or score >= 8:
        verdict = AttachmentVerdict.MALICIOUS
    elif has_high or score >= 3:
        verdict = AttachmentVerdict.SUSPICIOUS
    else:
        verdict = AttachmentVerdict.SAFE

    metadata: AttachmentMetadata = {
        "filename": file_name,
        "sanitized_filename": clean_name,
        "declared_extension": declared_ext,
        "declared_mime_type": mime_type,
        "detected_mime_type": detected_mime,
        "detected_format": fmt_name,
        "size_bytes": size_bytes,
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "virustotal_url": hashes["virustotal_url"],
        "is_executable": is_executable,
        "is_archive": is_archive,
        "is_macro_enabled": is_macro_enabled,
        "has_double_extension": has_double_ext,
        "has_rtlo_spoof": has_rtlo,
        "has_zero_width_extension": has_zero_width,
    }

    return {
        "filename": file_name,
        "verdict": verdict,
        "risk_score": score,
        "metadata": metadata,
        "violations": violations,
        "threat_intel_match": threat_intel_match,
    }


def inspect_all_attachments(
    source: Any,
    db_path: Path | None = None,
) -> list[AttachmentReport]:
    """Extract and inspect all attachments from a Gmail API dictionary or MIME source.

    Args:
        source: Gmail API JSON message dict, EmailMessage, or raw MIME bytes.
        db_path: Path to local SQLite threat intel database.

    Returns:
        List of AttachmentReport inspection results for each attachment found.
    """
    extracted = extract_attachments(source)
    return [inspect_attachment(att, db_path=db_path) for att in extracted]


def remember_attachment_threat(
    report: AttachmentReport,
    db_path: Path | None = None,
) -> None:
    """Save an identified malicious attachment hash to local threat intel memory.

    Args:
        report: Inspected AttachmentReport.
        db_path: Path to local SQLite threat intel database.
    """
    sha256 = report["metadata"]["sha256"]
    if not sha256:
        return
    remember_threat(
        indicator=sha256,
        indicator_type="sha256",
        verdict=report["verdict"].value,
        evidence={
            "filename": report["metadata"]["filename"],
            "detected_format": report["metadata"]["detected_format"],
            "risk_score": report["risk_score"],
            "violations": report["violations"],
            "virustotal_url": report["metadata"]["virustotal_url"],
        },
        db_path=db_path,
    )
