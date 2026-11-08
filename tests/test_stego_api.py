"""Unit tests for LexiGuard Steganography & Polyglot Payload Analyzer."""

from __future__ import annotations

import pytest

from lexiguard.intel.stego_api import (
    JPEG_EOI,
    PE_MAGIC,
    PNG_IEND,
    ZIP_MAGIC,
    inspect_stego_payload,
)


class TestStegoApi:
    def test_empty_payload(self) -> None:
        res = inspect_stego_payload(b"", filename="empty.bin")
        assert res["has_hidden_payload"] is False
        assert res["verdict"] == "SAFE"

    def test_clean_synthetic_jpeg(self) -> None:
        # Standard clean JPEG with header and immediate EOI without trailing bytes
        clean_jpg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + b"\x00" * 128 + JPEG_EOI
        res = inspect_stego_payload(clean_jpg, filename="clean.jpg")
        assert res["has_hidden_payload"] is False
        assert res["verdict"] == "SAFE"

    def test_polyglot_jpeg_with_appended_zip(self) -> None:
        # JPEG EOI followed by a ZIP archive
        fake_zip = ZIP_MAGIC + b"\x14\x00\x00\x00" + b"\x00" * 80
        polyglot = b"\xFF\xD8\xFF\xE0JFIF" + b"\x00" * 64 + JPEG_EOI + fake_zip

        res = inspect_stego_payload(polyglot, filename="invoice.jpg")
        assert res["has_hidden_payload"] is True
        assert res["verdict"] == "MALICIOUS"
        assert "JPEG_APPENDED_PAYLOAD_DETECTED" in res["anomalies"]
        assert "POLYGLOT_EMBEDDED_ZIP_ARCHIVE" in res["anomalies"]
        assert res["confidence"] >= 0.95

    def test_polyglot_png_with_appended_executable(self) -> None:
        # PNG IEND followed by an MZ executable
        fake_pe = PE_MAGIC + b"\x90\x00\x03\x00" + b"\x00" * 100
        polyglot = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + PNG_IEND + fake_pe

        res = inspect_stego_payload(polyglot, filename="image.png")
        assert res["has_hidden_payload"] is True
        assert res["verdict"] == "MALICIOUS"
        assert "PNG_APPENDED_PAYLOAD_DETECTED" in res["anomalies"]
        assert "POLYGLOT_EMBEDDED_EXECUTABLE_BINARY" in res["anomalies"]

    def test_embedded_script_strings(self) -> None:
        # Binary containing hidden powershell execution code
        data = b"\x00\x01\x02" * 50 + b"powershell -encodedCommand aW52b2tl" + b"\x00" * 50
        res = inspect_stego_payload(data, filename="payload.bin")
        assert res["has_hidden_payload"] is True
        assert res["verdict"] == "MALICIOUS"
        assert "EMBEDDED_EXECUTABLE_SCRIPT_STRINGS" in res["anomalies"]
