"""Live mailbox ingestion and attachment inspection gateway."""

from lexiguard.gateway.attachments import (
    AttachmentMetadata,
    AttachmentReport,
    AttachmentVerdict,
    AttachmentViolation,
    ExtractedAttachment,
    compute_hashes,
    detect_file_signature,
    extract_attachments,
    extract_attachments_from_gmail_payload,
    extract_attachments_from_mime,
    inspect_all_attachments,
    inspect_attachment,
    remember_attachment_threat,
)
from lexiguard.gateway.gmail_client import GmailClient

__all__ = [
    "AttachmentMetadata",
    "AttachmentReport",
    "AttachmentVerdict",
    "AttachmentViolation",
    "ExtractedAttachment",
    "GmailClient",
    "compute_hashes",
    "detect_file_signature",
    "extract_attachments",
    "extract_attachments_from_gmail_payload",
    "extract_attachments_from_mime",
    "inspect_all_attachments",
    "inspect_attachment",
    "remember_attachment_threat",
]
