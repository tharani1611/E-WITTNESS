"""Unit tests for Phase 48 & 49: Resumable multipart uploads, authorized retrieval, and controlled downloads."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from backend.app.config.settings import Environment, Settings
from backend.app.core.evidence import (
    EvidenceStatus,
    ScanStatus,
    UploadSessionStatus,
    UploadStatus,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.core.incident import IncidentStatus
from backend.app.infrastructure.scanner import MockMalwareScanner
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.models.evidence import EvidenceAttachment, UploadSession
from backend.app.models.incident import Incident
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.evidence import (
    MultipartPartCompleteItem,
    MultipartUploadCompleteRequest,
    MultipartUploadInitRequest,
)
from backend.app.services.evidence import EvidenceService


def _make_principal(
    user_id: UUID | None = None,
    role_code: str = RoleCode.STUDENT.value,
    department_id: UUID | None = None,
    email: str = "reporter@ewitness.edu",
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email=email,
        full_name="Principal User",
        account_status="active",
        is_active=True,
        role_code=role_code,
        department_id=department_id,
        session_id=uuid4(),
    )


def _make_test_settings() -> Settings:
    return Settings(
        _env_file=None,
        ENVIRONMENT=Environment.TESTING,
        DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        REDIS_URL="redis://localhost:6379/15",
        STORAGE_ENDPOINT_URL="http://127.0.0.1:9000/ewitness-test",
        STORAGE_BUCKET_NAME="ewitness-test-bucket",
        STORAGE_ACCESS_KEY=SecretStr("test_access_key_isolated"),
        STORAGE_SECRET_KEY=SecretStr("test_secret_key_isolated_value"),
        AUTH_SECRET_KEY=SecretStr("test_only_signing_key_with_sufficient_length_32_plus"),
    )


class TestMultipartUploads:
    """Phase 48: Resumable / multipart upload initialization, assembly, and abort."""

    @pytest.mark.asyncio
    async def test_initiate_multipart_upload_success(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        incident_id = uuid4()
        user_id = uuid4()
        dept_id = uuid4()

        payload = MultipartUploadInitRequest(
            filename="surveillance_tape.mp4",
            content_type="video/mp4",
            file_size_bytes=10_485_760,
            part_size_bytes=5_242_880,
        )

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            reporter_id=user_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)
        evidence_repo.get_cumulative_size_by_incident = AsyncMock(return_value=0)
        evidence_repo.get_cumulative_size_by_user = AsyncMock(return_value=0)
        evidence_repo.get_cumulative_size_by_department = AsyncMock(return_value=0)

        mock_session = UploadSession(
            id=uuid4(),
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            storage_key="incidents/test/video.mp4",
            original_filename="surveillance_tape.mp4",
            declared_mime_type="video/mp4",
            expected_size_bytes=10_485_760,
            upload_id="mp_upload_id_123",
            total_parts=2,
            part_size_bytes=5_242_880,
            session_status=UploadSessionStatus.ACTIVE.value,
            expires_at=datetime.now(UTC) + timedelta(minutes=60),
        )
        evidence_repo.create_upload_session = AsyncMock(return_value=mock_session)
        evidence_repo.create_attachment = AsyncMock()

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
        )

        principal = _make_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        resp = await svc.initiate_multipart_upload(incident_id, payload, principal)

        assert resp.total_parts == 2
        assert len(resp.part_urls) == 2
        assert resp.part_urls[0].part_number == 1
        assert resp.part_urls[1].part_number == 2
        assert "/multipart/" in resp.part_urls[0].upload_url
        assert "/part/1" in resp.part_urls[0].upload_url

    @pytest.mark.asyncio
    async def test_complete_multipart_upload_rejects_missing_parts(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        session_id = uuid4()
        incident_id = uuid4()
        user_id = uuid4()
        dept_id = uuid4()

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            reporter_id=user_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)

        upload_session = UploadSession(
            id=session_id,
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            storage_key="incidents/test/video.mp4",
            original_filename="surveillance_tape.mp4",
            declared_mime_type="video/mp4",
            expected_size_bytes=10_485_760,
            upload_id="mp_upload_123",
            total_parts=2,
            session_status=UploadSessionStatus.ACTIVE.value,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        evidence_repo.get_upload_session = AsyncMock(return_value=upload_session)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
        )

        principal = _make_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        complete_req = MultipartUploadCompleteRequest(
            parts=[MultipartPartCompleteItem(part_number=1, etag="etag1")]
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await svc.complete_multipart_upload(session_id, complete_req, principal)
        assert exc_info.value.code in {"MULTIPART_PARTS_MISMATCH", "INCOMPLETE_PARTS"}

    @pytest.mark.asyncio
    async def test_complete_multipart_upload_end_to_end_in_memory(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        session_id = uuid4()
        incident_id = uuid4()
        user_id = uuid4()
        dept_id = uuid4()
        key = "incidents/test/audio.wav"

        upload_id = await storage_client.initiate_multipart_upload(key, "audio/wav")

        part1_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00"
        etag1 = await storage_client.put_part(key, upload_id, 1, part1_bytes)

        part2_bytes = b"\x01\x00\x01\x00\x44\xac\x00\x00data\x00\x00\x00\x00"
        etag2 = await storage_client.put_part(key, upload_id, 2, part2_bytes)

        total_bytes = len(part1_bytes) + len(part2_bytes)

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            reporter_id=user_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)

        upload_session = UploadSession(
            id=session_id,
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            storage_key=key,
            original_filename="audio.wav",
            declared_mime_type="audio/wav",
            expected_size_bytes=total_bytes,
            upload_id=upload_id,
            total_parts=2,
            session_status=UploadSessionStatus.ACTIVE.value,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        evidence_repo.get_upload_session = AsyncMock(return_value=upload_session)
        evidence_repo.update_upload_session = AsyncMock()

        mock_created_att = EvidenceAttachment(
            id=uuid4(),
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            upload_session_id=session_id,
            storage_key=key,
            original_filename="audio.wav",
            declared_mime_type="audio/wav",
            detected_mime_type="audio/wav",
            file_size_bytes=total_bytes,
            sha256_hash="dummyhash",
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        evidence_repo.create_attachment = AsyncMock(return_value=mock_created_att)
        evidence_repo.get_attachment_by_session_id = AsyncMock(return_value=mock_created_att)
        evidence_repo.update_attachment = AsyncMock(return_value=mock_created_att)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
            scanner=MockMalwareScanner(),
        )

        principal = _make_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        complete_req = MultipartUploadCompleteRequest(
            parts=[
                MultipartPartCompleteItem(part_number=1, etag=etag1),
                MultipartPartCompleteItem(part_number=2, etag=etag2),
            ]
        )

        att = await svc.complete_multipart_upload(session_id, complete_req, principal)
        assert att.upload_status == "completed"
        assert att.evidence_status == "attached"
        assert att.scan_status == "clean"

        assembled = await storage_client.get_object_bytes(key)
        assert assembled == part1_bytes + part2_bytes

    @pytest.mark.asyncio
    async def test_abort_multipart_upload_marks_cancelled(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        session_id = uuid4()
        incident_id = uuid4()
        user_id = uuid4()
        dept_id = uuid4()
        key = "incidents/test/abort_me.mp4"

        upload_id = await storage_client.initiate_multipart_upload(key, "video/mp4")

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            reporter_id=user_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)

        upload_session = UploadSession(
            id=session_id,
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            storage_key=key,
            original_filename="abort_me.mp4",
            declared_mime_type="video/mp4",
            expected_size_bytes=1000,
            upload_id=upload_id,
            session_status=UploadSessionStatus.ACTIVE.value,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        evidence_repo.get_upload_session = AsyncMock(return_value=upload_session)
        evidence_repo.update_upload_session = AsyncMock()
        evidence_repo.get_attachment_by_session_id = AsyncMock(return_value=None)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
        )

        principal = _make_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        await svc.abort_multipart_upload(session_id, principal)
        assert upload_session.session_status == UploadSessionStatus.CANCELLED.value


class TestEvidenceControlledRetrieval:
    """Phase 49: Authorized retrieval, controlled downloads, and quarantine denial."""

    @pytest.mark.asyncio
    async def test_generate_download_url_clean_success(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        att_id = uuid4()
        incident_id = uuid4()
        user_id = uuid4()
        dept_id = uuid4()
        key = "incidents/test/photo.png"

        # Pre-seed object in storage so verify_object_exists returns True
        await storage_client.put_object(key, b"fake_png_data", "image/png")

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            reporter_id=user_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)

        att = EvidenceAttachment(
            id=att_id,
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            storage_key=key,
            original_filename="photo.png",
            declared_mime_type="image/png",
            detected_mime_type="image/png",
            file_size_bytes=1024,
            upload_status="completed",
            evidence_status="attached",
            scan_status="clean",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        evidence_repo.get_attachment_by_id = AsyncMock(return_value=att)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
        )

        principal = _make_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        resp = await svc.generate_download_url(att_id, principal, expires_in_seconds=300)

        assert "incidents/test/photo.png" in resp.download_url
        assert resp.filename == "photo.png"
        assert resp.content_type == "image/png"
        assert resp.file_size_bytes == 1024

    @pytest.mark.asyncio
    async def test_generate_download_url_quarantined_denied(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        att_id = uuid4()
        incident_id = uuid4()
        user_id = uuid4()
        dept_id = uuid4()

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            reporter_id=user_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)

        att = EvidenceAttachment(
            id=att_id,
            incident_id=incident_id,
            uploader_id=user_id,
            department_id=dept_id,
            storage_key="incidents/test/eicar.pdf",
            original_filename="eicar.pdf",
            declared_mime_type="application/pdf",
            detected_mime_type="application/pdf",
            file_size_bytes=68,
            upload_status="completed",
            evidence_status="quarantined",
            scan_status="infected",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        evidence_repo.get_attachment_by_id = AsyncMock(return_value=att)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
        )

        # Even Dept Admin cannot download quarantined infected evidence!
        principal = _make_principal(
            user_id=uuid4(),
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await svc.generate_download_url(att_id, principal)
        assert exc_info.value.code == "EVIDENCE_NOT_RELEASED"
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_generate_download_url_cross_department_denied(self) -> None:
        evidence_repo = MagicMock()
        incident_repo = MagicMock()
        storage_client = InMemoryStorageClient("http://127.0.0.1:9000/ewitness-test")
        settings = _make_test_settings()

        att_id = uuid4()
        incident_id = uuid4()
        dept_alpha = uuid4()
        dept_beta = uuid4()

        incident = Incident(
            id=incident_id,
            department_id=dept_alpha,
            reporter_id=uuid4(),
            status=IncidentStatus.SUBMITTED.value,
        )
        incident_repo.get_by_id = AsyncMock(return_value=incident)

        att = EvidenceAttachment(
            id=att_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_alpha,
            storage_key="incidents/test/photo.png",
            original_filename="photo.png",
            declared_mime_type="image/png",
            file_size_bytes=100,
            upload_status="completed",
            evidence_status="attached",
            scan_status="clean",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        evidence_repo.get_attachment_by_id = AsyncMock(return_value=att)

        svc = EvidenceService(
            evidence_repo=evidence_repo,
            incident_repo=incident_repo,
            storage_client=storage_client,
            settings=settings,
        )

        principal = _make_principal(
            user_id=uuid4(),
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_beta,
        )

        # Anti-enumeration: returns ResourceNotFoundError (404)
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.generate_download_url(att_id, principal)
        assert exc_info.value.code == "INCIDENT_NOT_FOUND"


class TestEvidenceServiceEdgeCasesAndBranches:
    """Branch and error condition unit tests for EvidenceService."""

    @pytest.mark.asyncio
    async def test_complete_upload_session_branches(self) -> None:
        evidence_repo = AsyncMock()
        incident_repo = AsyncMock()
        storage_client = InMemoryStorageClient()
        settings = _make_test_settings()
        svc = EvidenceService(evidence_repo, incident_repo, storage_client, settings)

        sess_id = uuid4()
        inc_id = uuid4()
        user_id = uuid4()
        principal = _make_principal(user_id=user_id)

        # 1. Session not found
        evidence_repo.get_upload_session.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.complete_upload_session(sess_id, principal, incident_id=inc_id)
        assert exc_info.value.code == "UPLOAD_SESSION_NOT_FOUND"

        # 2. Incident not found
        sess = UploadSession(
            id=sess_id,
            incident_id=inc_id,
            uploader_id=user_id,
            session_status=UploadSessionStatus.ACTIVE.value,
            storage_key="test/key.png",
            declared_mime_type="image/png",
            expected_size_bytes=10,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        evidence_repo.get_upload_session.return_value = sess
        incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_info.value.code == "INCIDENT_NOT_FOUND"

        # 3. Idempotent completion if already completed
        incident = Incident(id=inc_id, reporter_id=user_id, status=IncidentStatus.SUBMITTED.value)
        incident_repo.get_by_id.return_value = incident
        sess.session_status = UploadSessionStatus.COMPLETED.value
        att = EvidenceAttachment(
            id=uuid4(),
            incident_id=inc_id,
            uploader_id=user_id,
            department_id=uuid4(),
            original_filename="test.png",
            declared_mime_type="image/png",
            file_size_bytes=10,
            upload_status="completed",
            evidence_status="attached",
            scan_status="clean",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        evidence_repo.get_attachment_by_session_id.return_value = att
        res = await svc.complete_upload_session(sess_id, principal)
        assert res.id == att.id

        # 4. Inactive session
        sess.session_status = UploadSessionStatus.CANCELLED.value
        with pytest.raises(BusinessRuleError) as exc_biz1:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_biz1.value.code == "UPLOAD_SESSION_INACTIVE"

        # 5. Expired session
        sess.session_status = UploadSessionStatus.ACTIVE.value
        sess.expires_at = datetime.now(UTC) - timedelta(minutes=5)
        with pytest.raises(BusinessRuleError) as exc_biz2:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_biz2.value.code == "UPLOAD_SESSION_EXPIRED"

        # 6. Object missing in storage
        sess.session_status = UploadSessionStatus.ACTIVE.value
        sess.expires_at = datetime.now(UTC) + timedelta(minutes=15)
        with pytest.raises(ResourceNotFoundError) as exc_res3:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_res3.value.code == "OBJECT_NOT_FOUND"

        # 7. Empty payload
        storage_client.store_mock_object(sess.storage_key, b"", "image/png")
        with pytest.raises(BusinessRuleError) as exc_biz3:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_biz3.value.code == "EMPTY_PAYLOAD"

        # 8. Payload size mismatch
        storage_client.store_mock_object(sess.storage_key, b"short", "image/png")
        sess.expected_size_bytes = 100
        with pytest.raises(BusinessRuleError) as exc_biz4:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_biz4.value.code == "PAYLOAD_SIZE_MISMATCH"

        # 9. Attachment missing
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        storage_client.store_mock_object(sess.storage_key, png_data, "image/png")
        sess.expected_size_bytes = len(png_data)
        evidence_repo.get_attachment_by_session_id.return_value = None
        evidence_repo.get_attachment_by_storage_key.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_res4:
            await svc.complete_upload_session(sess_id, principal)
        assert exc_res4.value.code == "ATTACHMENT_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_complete_multipart_upload_branches(self) -> None:
        evidence_repo = AsyncMock()
        incident_repo = AsyncMock()
        storage_client = InMemoryStorageClient()
        settings = _make_test_settings()
        svc = EvidenceService(evidence_repo, incident_repo, storage_client, settings)

        sess_id = uuid4()
        inc_id = uuid4()
        user_id = uuid4()
        principal = _make_principal(user_id=user_id)
        req = MultipartUploadCompleteRequest(
            parts=[MultipartPartCompleteItem(part_number=1, etag="etag1")]
        )

        # 1. Session not found
        evidence_repo.get_upload_session.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.complete_multipart_upload(sess_id, req, principal, incident_id=inc_id)
        assert exc_info.value.code == "UPLOAD_SESSION_NOT_FOUND"

        # 2. Incident not found
        sess = UploadSession(
            id=sess_id,
            incident_id=inc_id,
            uploader_id=user_id,
            session_status=UploadSessionStatus.ACTIVE.value,
            storage_key="test/key.mp4",
            declared_mime_type="video/mp4",
            expected_size_bytes=100,
            upload_id="upload_xyz",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        evidence_repo.get_upload_session.return_value = sess
        incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.complete_multipart_upload(sess_id, req, principal)
        assert exc_info.value.code == "INCIDENT_NOT_FOUND"

        # 3. Not a multipart session
        incident = Incident(id=inc_id, reporter_id=user_id, status=IncidentStatus.SUBMITTED.value)
        incident_repo.get_by_id.return_value = incident
        sess.total_parts = None
        with pytest.raises(BusinessRuleError) as exc_biz_mp0:
            await svc.complete_multipart_upload(sess_id, req, principal)
        assert exc_biz_mp0.value.code == "NOT_MULTIPART_SESSION"

        # 4. Session inactive
        sess.total_parts = 2
        sess.session_status = UploadSessionStatus.CANCELLED.value
        with pytest.raises(BusinessRuleError) as exc_biz_mp1:
            await svc.complete_multipart_upload(sess_id, req, principal)
        assert exc_biz_mp1.value.code == "UPLOAD_SESSION_INACTIVE"

        # 5. Incomplete parts count
        sess.session_status = UploadSessionStatus.ACTIVE.value
        with pytest.raises(BusinessRuleError) as exc_biz_mp2:
            await svc.complete_multipart_upload(sess_id, req, principal)
        assert exc_biz_mp2.value.code == "INCOMPLETE_PARTS"

        # 6. Session expired
        req_full = MultipartUploadCompleteRequest(
            parts=[
                MultipartPartCompleteItem(part_number=1, etag="etag1"),
                MultipartPartCompleteItem(part_number=2, etag="etag2"),
            ]
        )
        sess.expires_at = datetime.now(UTC) - timedelta(minutes=5)
        with pytest.raises(BusinessRuleError) as exc_biz_mp3:
            await svc.complete_multipart_upload(sess_id, req_full, principal)
        assert exc_biz_mp3.value.code == "UPLOAD_SESSION_EXPIRED"

    @pytest.mark.asyncio
    async def test_abort_multipart_upload_branches(self) -> None:
        evidence_repo = AsyncMock()
        incident_repo = AsyncMock()
        storage_client = InMemoryStorageClient()
        settings = _make_test_settings()
        svc = EvidenceService(evidence_repo, incident_repo, storage_client, settings)

        sess_id = uuid4()
        inc_id = uuid4()
        user_id = uuid4()
        principal = _make_principal(user_id=user_id)

        # 1. Session not found
        evidence_repo.get_upload_session.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.abort_multipart_upload(sess_id, principal, incident_id=inc_id)
        assert exc_info.value.code == "UPLOAD_SESSION_NOT_FOUND"

        # 2. Inactive session returns silently
        sess = UploadSession(
            id=sess_id,
            incident_id=inc_id,
            uploader_id=user_id,
            session_status=UploadSessionStatus.CANCELLED.value,
            storage_key="test/key.mp4",
            upload_id="upload_xyz",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        evidence_repo.get_upload_session.return_value = sess
        incident = Incident(id=inc_id, reporter_id=user_id, status=IncidentStatus.SUBMITTED.value)
        incident_repo.get_by_id.return_value = incident
        await svc.abort_multipart_upload(sess_id, principal)

    @pytest.mark.asyncio
    async def test_generate_download_url_branches(self) -> None:
        evidence_repo = AsyncMock()
        incident_repo = AsyncMock()
        storage_client = InMemoryStorageClient()
        settings = _make_test_settings()
        svc = EvidenceService(evidence_repo, incident_repo, storage_client, settings)

        att_id = uuid4()
        inc_id = uuid4()
        user_id = uuid4()
        principal = _make_principal(user_id=user_id)

        # 1. Attachment not found
        evidence_repo.get_attachment_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.generate_download_url(att_id, principal, incident_id=inc_id)
        assert exc_info.value.code == "ATTACHMENT_NOT_FOUND"

        # 2. Attachment infected -> EVIDENCE_NOT_RELEASED
        att = EvidenceAttachment(
            id=att_id,
            incident_id=inc_id,
            uploader_id=user_id,
            department_id=uuid4(),
            storage_key="test/key.png",
            original_filename="key.png",
            declared_mime_type="image/png",
            file_size_bytes=100,
            upload_status="completed",
            evidence_status="quarantined",
            scan_status="infected",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        evidence_repo.get_attachment_by_id.return_value = att
        incident = Incident(id=inc_id, reporter_id=user_id, status=IncidentStatus.SUBMITTED.value)
        incident_repo.get_by_id.return_value = incident
        with pytest.raises(BusinessRuleError) as exc_biz_dl:
            await svc.generate_download_url(att_id, principal)
        assert exc_biz_dl.value.code == "EVIDENCE_NOT_RELEASED"

        # 3. Incident not found
        att.evidence_status = "attached"
        att.scan_status = "clean"
        incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await svc.generate_download_url(att_id, principal)
        assert exc_info.value.code == "INCIDENT_NOT_FOUND"
