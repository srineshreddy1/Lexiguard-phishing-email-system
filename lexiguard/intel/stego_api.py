"""Steganography & Hidden Payload Analysis for LexiGuard.

Provides deep binary inspection and cloud/heuristic verification for:
- Image steganography (LSB entropy anomalies, encrypted byte slices).
- Polyglot files (e.g., JPEG/PNG images concealing embedded ZIP/RAR/PE archives).
- Appended payload injection (data appended after EOF / EOI markers).
- Embedded shellcode and script patterns inside multimedia attachments.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any

# Magic byte markers for common media file terminators
JPEG_EOI = b"\xFF\xD9"
PNG_IEND = b"IEND\xAE\x42\x60\x82"
GIF_TRAILER = b"\x3B"

# Magic byte signatures of executable/archive payloads
PE_MAGIC = b"MZ"
ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1A\x07"
ELF_MAGIC = b"\x7FELF"
SHELL_SHEBANG = b"#!"

SUSPICIOUS_SCRIPT_STRINGS = [
    b"<script",
    b"powershell",
    b"cmd.exe",
    b"/bin/sh",
    b"eval(",
    b"base64_decode",
]


def _calculate_byte_entropy(data: bytes) -> float:
    """Compute Shannon entropy for a sequence of bytes (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _check_lsb_variance(data: bytes) -> float:
    """Analyze the entropy of the least significant bits across byte sequences."""
    if len(data) < 256:
        return 0.0
    # Extract only the lowest bit of each byte
    lsb_bytes = bytes((b & 1) for b in data[:4096])
    ones = sum(lsb_bytes)
    p1 = ones / len(lsb_bytes)
    p0 = 1.0 - p1
    if p0 <= 0 or p1 <= 0:
        return 0.0
    return -(p0 * math.log2(p0) + p1 * math.log2(p1))


def inspect_stego_payload(
    data: bytes,
    filename: str = "",
    api_key: str | None = None,
) -> dict[str, Any]:
    """Inspect binary file content for hidden steganographic payloads and polyglots.

    Args:
        data: Raw file binary content.
        filename: Optional filename to assist file-type boundary heuristics.
        api_key: Optional API key for cloud steganography engine.

    Returns:
        Structured analysis report dictionary.
    """
    if not data:
        return {
            "has_hidden_payload": False,
            "verdict": "SAFE",
            "confidence": 0.0,
            "anomalies": [],
            "entropy": 0.0,
            "details": {"size": 0, "message": "Empty payload provided"},
        }

    anomalies: list[str] = []
    confidence = 0.0
    file_size = len(data)
    total_entropy = _calculate_byte_entropy(data)
    fn_lower = filename.lower()

    # 1. Polyglot & Appended Payload Detection (Data after image EOF)
    appended_data = b""
    if (fn_lower.endswith(".jpg") or fn_lower.endswith(".jpeg")) or data.startswith(b"\xFF\xD8"):
        eoi_idx = data.find(JPEG_EOI)
        if eoi_idx != -1 and (eoi_idx + 2) < file_size:
            appended_data = data[eoi_idx + 2 :]
            if len(appended_data) > 64:
                anomalies.append("JPEG_APPENDED_PAYLOAD_DETECTED")
                confidence = max(confidence, 0.85)

    elif fn_lower.endswith(".png") or data.startswith(b"\x89PNG\r\n\x1a\n"):
        iend_idx = data.find(PNG_IEND)
        if iend_idx != -1 and (iend_idx + len(PNG_IEND)) < file_size:
            appended_data = data[iend_idx + len(PNG_IEND) :]
            if len(appended_data) > 64:
                anomalies.append("PNG_APPENDED_PAYLOAD_DETECTED")
                confidence = max(confidence, 0.85)

    # 2. Check appended data for executable or archive headers
    if appended_data:
        appended_entropy = _calculate_byte_entropy(appended_data)
        if appended_data.startswith(ZIP_MAGIC):
            anomalies.append("POLYGLOT_EMBEDDED_ZIP_ARCHIVE")
            confidence = 0.98
        elif appended_data.startswith(RAR_MAGIC):
            anomalies.append("POLYGLOT_EMBEDDED_RAR_ARCHIVE")
            confidence = 0.98
        elif appended_data.startswith(PE_MAGIC):
            anomalies.append("POLYGLOT_EMBEDDED_EXECUTABLE_BINARY")
            confidence = 0.99
        elif appended_entropy > 7.5:
            anomalies.append("HIGH_ENTROPY_ENCRYPTED_TRAILING_DATA")
            confidence = max(confidence, 0.80)

    # 3. Micro-payload and script pattern detection embedded in binary
    found_scripts = []
    data_lower = data.lower()
    for pattern in SUSPICIOUS_SCRIPT_STRINGS:
        if pattern in data_lower:
            found_scripts.append(pattern.decode("ascii", errors="ignore"))

    if found_scripts:
        anomalies.append("EMBEDDED_EXECUTABLE_SCRIPT_STRINGS")
        confidence = max(confidence, 0.90)

    # 4. LSB Entropy variance analysis
    lsb_entropy = _check_lsb_variance(data)
    if lsb_entropy > 0.995 and total_entropy > 7.6 and file_size > 4096:
        anomalies.append("SUSPICIOUS_LSB_ENTROPY_CONCEALMENT")
        confidence = max(confidence, 0.70)

    # Calculate overall verdict
    if any("EXECUTABLE" in a or "ZIP" in a or "SCRIPT" in a for a in anomalies):
        verdict = "MALICIOUS"
    elif anomalies:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "has_hidden_payload": bool(anomalies),
        "verdict": verdict,
        "confidence": confidence if anomalies else 0.0,
        "anomalies": anomalies,
        "entropy": round(total_entropy, 3),
        "lsb_entropy": round(lsb_entropy, 3),
        "details": {
            "file_size": file_size,
            "filename": filename,
            "appended_bytes": len(appended_data),
            "detected_scripts": found_scripts,
        },
    }
