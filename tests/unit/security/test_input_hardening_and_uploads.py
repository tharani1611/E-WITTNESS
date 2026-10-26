"""Unit tests for Phase 29 input hardening and secure upload validation foundations."""

from __future__ import annotations

import uuid

import pytest

from backend.app.core.exceptions import (
    BusinessRuleError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
)
from backend.app.core.upload import (
    detect_magic_bytes,
    generate_secure_storage_key,
    sanitize_filename,
    validate_file_magic_bytes,
    validate_upload_metadata,
)


@pytest.mark.unit
class TestFilenameSanitization:
    """Verify filename sanitization, traversal neutralization, and dangerous extension defense."""

    def test_benign_filenames_pass_cleanly(self) -> None:
        assert sanitize_filename("incident_report_2026.pdf") == "incident_report_2026.pdf"
        assert sanitize_filename("evidence-01.png") == "evidence-01.png"
        assert sanitize_filename("recording_interview.wav") == "recording_interview.wav"

    def test_path_traversal_and_directory_stripping(self) -> None:
        # Relative directory traversal stripped to basename
        assert sanitize_filename("../../etc/passwd.txt") == "passwd.txt"
        assert sanitize_filename("..\\..\\windows\\system32\\cmd.pdf") == "cmd.pdf"
        assert sanitize_filename("nested/subfolder/file.pdf") == "file.pdf"

    def test_null_bytes_and_control_chars_rejected(self) -> None:
        with pytest.raises(BusinessRuleError, match="null bytes"):
            sanitize_filename("exploit\x00.pdf")

        with pytest.raises(BusinessRuleError, match="control characters"):
            sanitize_filename("bad\x1fcharacter.pdf")

    def test_double_extension_executable_attacks_rejected(self) -> None:
        # Any forbidden extension in the segments triggers rejection
        with pytest.raises(BusinessRuleError, match="forbidden executable"):
            sanitize_filename("report.exe.pdf")

        with pytest.raises(BusinessRuleError, match="forbidden executable"):
            sanitize_filename("image.php.png")

        with pytest.raises(BusinessRuleError, match="forbidden executable"):
            sanitize_filename("script.sh.txt")

    def test_prohibited_characters_rejected(self) -> None:
        with pytest.raises(BusinessRuleError, match="special characters"):
            sanitize_filename("bad;file.pdf")

        with pytest.raises(BusinessRuleError, match="special characters"):
            sanitize_filename("injection$(whoami).png")

    def test_missing_or_empty_extension_rejected(self) -> None:
        with pytest.raises(BusinessRuleError, match="valid file extension"):
            sanitize_filename("no_extension_file")

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(BusinessRuleError):
            sanitize_filename("")


@pytest.mark.unit
class TestMagicByteInspection:
    """Verify raw file signature detection across authorized formats."""

    def test_pdf_magic_bytes_detected(self) -> None:
        data = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        assert detect_magic_bytes(data) == "application/pdf"
        assert validate_file_magic_bytes(data, "application/pdf") == "application/pdf"

    def test_png_magic_bytes_detected(self) -> None:
        data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        assert detect_magic_bytes(data) == "image/png"
        assert validate_file_magic_bytes(data, "image/png") == "image/png"

    def test_jpeg_magic_bytes_detected(self) -> None:
        data = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        assert detect_magic_bytes(data) == "image/jpeg"
        assert validate_file_magic_bytes(data, "image/jpeg") == "image/jpeg"

    def test_mp4_magic_bytes_detected(self) -> None:
        data = b"\x00\x00\x00\x20ftypmp42\x00\x00\x00\x00mp42isom"
        assert detect_magic_bytes(data) == "video/mp4"
        assert validate_file_magic_bytes(data, "video/mp4") == "video/mp4"

    def test_wav_magic_bytes_detected(self) -> None:
        data = b"RIFF\x24\x08\x00\x00WAVEfmt \x10\x00\x00\x00"
        assert detect_magic_bytes(data) == "audio/wav"
        assert validate_file_magic_bytes(data, "audio/wav") == "audio/wav"

    def test_text_plain_detected(self) -> None:
        data = b"Case notes: witness stated observation at 14:00."
        assert detect_magic_bytes(data) == "text/plain"
        assert validate_file_magic_bytes(data, "text/plain") == "text/plain"

    def test_mime_mismatch_rejected_with_415(self) -> None:
        pdf_data = b"%PDF-1.7"
        with pytest.raises(UnsupportedMediaTypeError, match="MIME type mismatch"):
            validate_file_magic_bytes(pdf_data, expected_content_type="image/png")

    def test_corrupted_or_executable_payload_rejected(self) -> None:
        exe_data = b"MZ\x90\x00\x03\x00\x00\x00"
        with pytest.raises(UnsupportedMediaTypeError):
            validate_file_magic_bytes(exe_data)

    def test_empty_payload_rejected(self) -> None:
        with pytest.raises(BusinessRuleError, match="empty"):
            validate_file_magic_bytes(b"")


@pytest.mark.unit
class TestUploadMetadataValidationAndStorageKey:
    """Verify upload metadata bounds and randomized storage keys."""

    def test_valid_metadata_succeeds(self) -> None:
        clean = validate_upload_metadata(
            filename="document.pdf",
            content_type="application/pdf",
            file_size=1024,
            max_file_size=10_000_000,
        )
        assert clean == "document.pdf"

    def test_oversized_file_rejected_with_413(self) -> None:
        with pytest.raises(PayloadTooLargeError):
            validate_upload_metadata(
                filename="huge.pdf",
                content_type="application/pdf",
                file_size=20_000_000,
                max_file_size=10_000_000,
            )

    def test_zero_or_negative_file_size_rejected(self) -> None:
        with pytest.raises(BusinessRuleError, match="greater than zero"):
            validate_upload_metadata(
                filename="empty.pdf",
                content_type="application/pdf",
                file_size=0,
                max_file_size=10_000_000,
            )

    def test_mismatched_extension_and_content_type_rejected(self) -> None:
        with pytest.raises(UnsupportedMediaTypeError, match="does not match authorized extensions"):
            validate_upload_metadata(
                filename="report.pdf",
                content_type="image/png",
                file_size=1024,
                max_file_size=10_000_000,
            )

    def test_generate_secure_storage_key_uses_case_id_and_random_uuid(self) -> None:
        case_id = uuid.uuid4()
        storage_key = generate_secure_storage_key(case_id, "malicious../../user-file.pdf")

        assert storage_key.startswith(f"cases/{case_id}/")
        assert storage_key.endswith(".pdf")
        # Ensure user filename is decoupled and not present
        assert "user-file" not in storage_key
        assert "malicious" not in storage_key
