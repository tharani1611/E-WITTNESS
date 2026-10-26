"""Unit tests for Phase 46: File validation, signatures, MIME types, streaming validation, and quotas."""

from __future__ import annotations

from uuid import uuid4

import pytest

from backend.app.core.evidence import (
    DEFAULT_MAX_DEPARTMENT_EVIDENCE_BYTES,
    DEFAULT_MAX_INCIDENT_EVIDENCE_BYTES,
    DEFAULT_MAX_USER_EVIDENCE_BYTES,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
)
from backend.app.core.upload import (
    ALLOWED_MEDIA_TYPES,
    FORBIDDEN_EXTENSIONS,
    detect_magic_bytes,
    sanitize_filename,
    validate_file_magic_bytes,
    validate_stream_chunk_and_size,
    validate_upload_metadata,
)


class TestFileValidationPrimitives:
    """Phase 46: Media types, sanitization, and magic signature detection tests."""

    def test_media_type_allowlist(self) -> None:
        assert "application/pdf" in ALLOWED_MEDIA_TYPES
        assert "image/png" in ALLOWED_MEDIA_TYPES
        assert "image/jpeg" in ALLOWED_MEDIA_TYPES
        assert "image/webp" in ALLOWED_MEDIA_TYPES
        assert "audio/mpeg" in ALLOWED_MEDIA_TYPES
        assert "audio/wav" in ALLOWED_MEDIA_TYPES
        assert "video/mp4" in ALLOWED_MEDIA_TYPES
        assert "text/plain" in ALLOWED_MEDIA_TYPES
        assert "text/csv" in ALLOWED_MEDIA_TYPES

        assert "application/x-msdownload" not in ALLOWED_MEDIA_TYPES
        assert "application/x-sh" not in ALLOWED_MEDIA_TYPES
        assert "text/javascript" not in ALLOWED_MEDIA_TYPES

    def test_forbidden_extensions_blacklist(self) -> None:
        assert ".exe" in FORBIDDEN_EXTENSIONS
        assert ".sh" in FORBIDDEN_EXTENSIONS
        assert ".php" in FORBIDDEN_EXTENSIONS
        assert ".py" in FORBIDDEN_EXTENSIONS
        assert ".bat" in FORBIDDEN_EXTENSIONS

    def test_sanitize_filename(self) -> None:
        assert sanitize_filename("simple.pdf") == "simple.pdf"
        assert sanitize_filename("../../../etc/passwd.png") == "passwd.png"
        assert sanitize_filename("..\\..\\windows\\system32\\cmd.jpg") == "cmd.jpg"

    def test_sanitize_filename_rejects_empty_or_dangerous(self) -> None:
        with pytest.raises(BusinessRuleError):
            sanitize_filename("")

        with pytest.raises(BusinessRuleError):
            sanitize_filename("   ")

        with pytest.raises(BusinessRuleError):
            sanitize_filename("malicious.php.png")  # Forbidden extension segment

    def test_validate_upload_metadata_success(self) -> None:
        clean = validate_upload_metadata(
            filename="lab_results.pdf",
            content_type="application/pdf",
            file_size=1024 * 1024,
            max_file_size=10 * 1024 * 1024,
        )
        assert clean == "lab_results.pdf"

    def test_validate_upload_metadata_rejects_disallowed_extension(self) -> None:
        with pytest.raises(UnsupportedMediaTypeError) as exc_info:
            validate_upload_metadata(
                filename="document.txt",
                content_type="application/pdf",
                file_size=1024,
                max_file_size=10000,
            )
        assert exc_info.value.code == "UNSUPPORTED_MEDIA_TYPE"

    def test_validate_upload_metadata_rejects_disallowed_media_type(self) -> None:
        with pytest.raises(UnsupportedMediaTypeError) as exc_info:
            validate_upload_metadata(
                filename="script.sh",
                content_type="application/x-sh",
                file_size=1024,
                max_file_size=10000,
            )
        assert exc_info.value.code == "UNSUPPORTED_MEDIA_TYPE"

    def test_validate_upload_metadata_rejects_size_limits(self) -> None:
        with pytest.raises(BusinessRuleError):
            validate_upload_metadata(
                filename="valid.pdf",
                content_type="application/pdf",
                file_size=0,
                max_file_size=10000,
            )

        with pytest.raises(PayloadTooLargeError) as exc_info_large:
            validate_upload_metadata(
                filename="valid.pdf",
                content_type="application/pdf",
                file_size=20000,
                max_file_size=10000,
            )
        assert exc_info_large.value.code == "PAYLOAD_TOO_LARGE"

    def test_detect_magic_bytes_signatures(self) -> None:
        # PDF
        assert detect_magic_bytes(b"%PDF-1.4\n...") == "application/pdf"
        # JPEG
        assert detect_magic_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF") == "image/jpeg"
        # PNG
        assert detect_magic_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR") == "image/png"
        # WebP
        assert detect_magic_bytes(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
        # MP3 (ID3v2)
        assert detect_magic_bytes(b"ID3\x03\x00\x00\x00\x00\x00\x00") == "audio/mpeg"
        # MP3 (MPEG sync frame)
        assert detect_magic_bytes(b"\xff\xfb\x90\x44\x00\x00\x00\x00") == "audio/mpeg"
        # MP4 (ftyp)
        assert detect_magic_bytes(b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00") == "video/mp4"
        # WAV
        assert detect_magic_bytes(b"RIFF\x24\x00\x00\x00WAVEfmt ") == "audio/wav"
        # Plain text
        assert detect_magic_bytes(b"Hello world, this is evidence notes.\n") == "text/plain"
        # Unknown/binary
        assert detect_magic_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07") is None

    def test_validate_file_magic_bytes(self) -> None:
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        assert validate_file_magic_bytes(png_data, "image/png") == "image/png"

        # Mismatch: PNG data with declared PDF
        with pytest.raises(UnsupportedMediaTypeError) as exc_info:
            validate_file_magic_bytes(png_data, "application/pdf")
        assert exc_info.value.code == "UNSUPPORTED_MEDIA_TYPE"


class TestStreamingValidation:
    """Phase 46: Streaming chunk and incremental size enforcement."""

    def test_streaming_chunk_validation_success(self) -> None:
        chunk1 = b"A" * 500
        chunk2 = b"B" * 500

        total = validate_stream_chunk_and_size(chunk1, total_bytes_read=0, max_allowed_bytes=1500)
        assert total == 500

        total = validate_stream_chunk_and_size(
            chunk2, total_bytes_read=total, max_allowed_bytes=1500
        )
        assert total == 1000

    def test_streaming_chunk_rejects_exceeding_max_file_size(self) -> None:
        chunk = b"X" * 2000
        with pytest.raises(PayloadTooLargeError) as exc_info:
            validate_stream_chunk_and_size(
                chunk,
                total_bytes_read=0,
                max_allowed_bytes=1000,
            )
        assert exc_info.value.code == "PAYLOAD_TOO_LARGE"


class TestQuotaEnforcement:
    """Phase 46: Cumulative quota verification tests."""

    @pytest.mark.asyncio
    async def test_assert_within_quotas_incident_exceeded(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from backend.app.services.evidence import EvidenceService

        evidence_repo = MagicMock()
        evidence_repo.get_cumulative_size_by_incident = AsyncMock(
            return_value=DEFAULT_MAX_INCIDENT_EVIDENCE_BYTES - 100
        )
        evidence_repo.get_cumulative_size_by_user = AsyncMock(return_value=1000)
        evidence_repo.get_cumulative_size_by_department = AsyncMock(return_value=1000)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=MagicMock(),
            storage_client=MagicMock(),
            settings=MagicMock(),
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await svc._assert_within_quotas(
                incident_id=uuid4(),
                uploader_id=uuid4(),
                department_id=uuid4(),
                additional_bytes=200,  # exceeds by 100 bytes
            )
        assert exc_info.value.code == "INCIDENT_QUOTA_EXCEEDED"

    @pytest.mark.asyncio
    async def test_assert_within_quotas_user_exceeded(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from backend.app.services.evidence import EvidenceService

        evidence_repo = MagicMock()
        evidence_repo.get_cumulative_size_by_incident = AsyncMock(return_value=1000)
        evidence_repo.get_cumulative_size_by_user = AsyncMock(
            return_value=DEFAULT_MAX_USER_EVIDENCE_BYTES - 50
        )
        evidence_repo.get_cumulative_size_by_department = AsyncMock(return_value=1000)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=MagicMock(),
            storage_client=MagicMock(),
            settings=MagicMock(),
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await svc._assert_within_quotas(
                incident_id=uuid4(),
                uploader_id=uuid4(),
                department_id=uuid4(),
                additional_bytes=100,  # exceeds by 50 bytes
            )
        assert exc_info.value.code == "USER_QUOTA_EXCEEDED"

    @pytest.mark.asyncio
    async def test_assert_within_quotas_department_exceeded(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from backend.app.services.evidence import EvidenceService

        evidence_repo = MagicMock()
        evidence_repo.get_cumulative_size_by_incident = AsyncMock(return_value=1000)
        evidence_repo.get_cumulative_size_by_user = AsyncMock(return_value=1000)
        evidence_repo.get_cumulative_size_by_department = AsyncMock(
            return_value=DEFAULT_MAX_DEPARTMENT_EVIDENCE_BYTES - 10
        )

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=MagicMock(),
            storage_client=MagicMock(),
            settings=MagicMock(),
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await svc._assert_within_quotas(
                incident_id=uuid4(),
                uploader_id=uuid4(),
                department_id=uuid4(),
                additional_bytes=50,  # exceeds by 40 bytes
            )
        assert exc_info.value.code == "DEPARTMENT_QUOTA_EXCEEDED"

    @pytest.mark.asyncio
    async def test_assert_within_quotas_success(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from backend.app.services.evidence import EvidenceService

        evidence_repo = MagicMock()
        evidence_repo.get_cumulative_size_by_incident = AsyncMock(return_value=1000)
        evidence_repo.get_cumulative_size_by_user = AsyncMock(return_value=1000)
        evidence_repo.get_cumulative_size_by_department = AsyncMock(return_value=1000)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=MagicMock(),
            storage_client=MagicMock(),
            settings=MagicMock(),
        )

        await svc._assert_within_quotas(
            incident_id=uuid4(),
            uploader_id=uuid4(),
            department_id=uuid4(),
            additional_bytes=1000,
        )
