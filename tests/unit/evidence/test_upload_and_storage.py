"""Unit tests for evidence domain models, S3 SigV4 storage abstraction, and EvidenceService (Phases 43-45)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.evidence import (
    EvidenceStatus,
    UploadSessionStatus,
    UploadStatus,
    parse_evidence_status,
    parse_upload_session_status,
    parse_upload_status,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from backend.app.core.identity import RoleCode
from backend.app.core.incident import IncidentStatus
from backend.app.infrastructure.storage import (
    InMemoryStorageClient,
    S3StorageClient,
)
from backend.app.models.evidence import EvidenceAttachment, UploadSession
from backend.app.models.incident import Incident
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.evidence import (
    UploadSessionCreateRequest,
)
from backend.app.services.evidence import EvidenceService


class TestEvidenceDomainPrimitives:
    """Phase 43 & 44: Evidence domain enum parsing and validation unit tests."""

    def test_upload_status_parsing(self) -> None:
        assert parse_upload_status("pending") == UploadStatus.PENDING
        assert parse_upload_status("  COMPLETED  ") == UploadStatus.COMPLETED
        assert parse_upload_status("failed") == UploadStatus.FAILED
        assert parse_upload_status("cancelled") == UploadStatus.CANCELLED

        with pytest.raises(BusinessRuleError) as exc_info:
            parse_upload_status("unknown")
        assert exc_info.value.code == "INVALID_UPLOAD_STATUS"
        assert exc_info.value.status_code == 422

    def test_evidence_status_parsing(self) -> None:
        assert parse_evidence_status("attached") == EvidenceStatus.ATTACHED
        assert parse_evidence_status("QUARANTINED") == EvidenceStatus.QUARANTINED
        assert parse_evidence_status("sealed") == EvidenceStatus.SEALED

        with pytest.raises(BusinessRuleError) as exc_info:
            parse_evidence_status("invalid")
        assert exc_info.value.code == "INVALID_EVIDENCE_STATUS"

    def test_upload_session_status_parsing(self) -> None:
        assert parse_upload_session_status("active") == UploadSessionStatus.ACTIVE
        assert parse_upload_session_status("COMPLETED") == UploadSessionStatus.COMPLETED
        assert parse_upload_session_status("expired") == UploadSessionStatus.EXPIRED
        assert parse_upload_session_status("cancelled") == UploadSessionStatus.CANCELLED

        with pytest.raises(BusinessRuleError) as exc_info:
            parse_upload_session_status("invalid")
        assert exc_info.value.code == "INVALID_SESSION_STATUS"


class TestEvidenceSchemasValidation:
    """Phase 43 & 44: Evidence Pydantic schema validation tests."""

    def test_upload_session_create_request_valid(self) -> None:
        req = UploadSessionCreateRequest(
            filename="document.pdf",
            content_type="application/pdf",
            file_size_bytes=1048576,
        )
        assert req.filename == "document.pdf"
        assert req.content_type == "application/pdf"
        assert req.file_size_bytes == 1048576

    def test_upload_session_create_request_rejects_zero_or_negative_size(self) -> None:
        with pytest.raises(ValidationError):
            UploadSessionCreateRequest(
                filename="doc.pdf",
                content_type="application/pdf",
                file_size_bytes=0,
            )

        with pytest.raises(ValidationError):
            UploadSessionCreateRequest(
                filename="doc.pdf",
                content_type="application/pdf",
                file_size_bytes=-100,
            )

    def test_upload_session_create_request_rejects_empty_filename(self) -> None:
        with pytest.raises(ValidationError):
            UploadSessionCreateRequest(
                filename="   ",
                content_type="application/pdf",
                file_size_bytes=1024,
            )


class TestS3StorageClientSigV4:
    """Phase 45: Unit tests for S3 storage client with standard AWS SigV4 pre-signing."""

    @pytest.fixture
    def s3_client(self, test_settings: Settings) -> S3StorageClient:
        return S3StorageClient(test_settings)

    def test_generate_presigned_upload_creates_valid_sigv4_url(
        self,
        s3_client: S3StorageClient,
    ) -> None:
        key = "incidents/123/evidence/photo.jpg"
        mime = "image/jpeg"
        upload_data = s3_client.generate_presigned_upload_url(
            storage_key=key,
            content_type=mime,
            expires_in_seconds=900,
        )

        assert upload_data.upload_method == "PUT"
        parsed = urlparse(upload_data.upload_url)
        assert parsed.scheme in {"https", "http"}
        assert key in parsed.path

        # Verify SigV4 query parameters
        qs = parse_qs(parsed.query)
        assert qs["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
        assert "X-Amz-Credential" in qs
        assert "X-Amz-Date" in qs
        assert qs["X-Amz-Expires"] == ["900"]
        assert "X-Amz-SignedHeaders" in qs
        assert "X-Amz-Signature" in qs
        assert len(qs["X-Amz-Signature"][0]) == 64

        # Verify required headers
        assert upload_data.headers["Content-Type"] == mime

    def test_generate_presigned_download_creates_valid_sigv4_url(
        self,
        s3_client: S3StorageClient,
    ) -> None:
        key = "incidents/123/evidence/photo.jpg"
        download_url = s3_client.generate_presigned_download_url(
            storage_key=key,
            expires_in_seconds=600,
        )

        parsed = urlparse(download_url)
        assert parsed.scheme in {"https", "http"}
        qs = parse_qs(parsed.query)
        assert qs["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
        assert qs["X-Amz-Expires"] == ["600"]
        assert "X-Amz-Signature" in qs


class TestInMemoryStorageClient:
    """Phase 45: In-memory storage client test double unit tests."""

    async def test_in_memory_storage_lifecycle(self) -> None:
        client = InMemoryStorageClient(endpoint_url="https://test-storage.local")
        key = "test/evidence/file.txt"

        # 1. Generate presigned upload
        upload = client.generate_presigned_upload_url(storage_key=key, content_type="text/plain")
        assert upload.upload_method == "PUT"
        assert key in upload.upload_url
        assert not await client.verify_object_exists(key)

        # 2. Simulate upload
        content = b"E-WITNESS incident evidence contents"
        client.store_mock_object(key, content, "text/plain")
        assert await client.verify_object_exists(key)

        # 3. Inspect metadata
        meta = await client.get_object_metadata(key)
        assert meta is not None
        assert meta.content_length == len(content)
        assert meta.content_type == "text/plain"
        assert meta.etag != ""

        # 4. Generate download URL
        download_url = client.generate_presigned_download_url(key)
        assert key in download_url

        # 5. Delete object
        assert await client.delete_object(key) is True
        assert not await client.verify_object_exists(key)
        assert await client.get_object_metadata(key) is None


class TestEvidenceServiceUnit:
    """Phase 44: Evidence service layer unit tests with mocked repositories."""

    @pytest.fixture
    def mock_evidence_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def in_memory_storage(self) -> InMemoryStorageClient:
        return InMemoryStorageClient()

    @pytest.fixture
    def evidence_service(
        self,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        in_memory_storage: InMemoryStorageClient,
        test_settings: Settings,
    ) -> EvidenceService:
        return EvidenceService(
            mock_evidence_repo,
            mock_incident_repo,
            in_memory_storage,
            test_settings,
        )

    @pytest.fixture
    def caller_principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="reporter@university.edu",
            full_name="Reporter User",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    async def test_create_upload_session_success(
        self,
        evidence_service: EvidenceService,
        mock_incident_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        incident_id = uuid4()
        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-11223344",
            title="Broken window",
            description="Window broken in dorm hall.",
            category="property_damage_theft",
            location="Dorm A",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        def _mock_create_session(sess: UploadSession) -> UploadSession:
            sess.id = uuid4()
            sess.created_at = datetime.now(UTC)
            sess.updated_at = datetime.now(UTC)
            return sess

        mock_evidence_repo.create_upload_session.side_effect = _mock_create_session

        payload = UploadSessionCreateRequest(
            filename="window_broken.jpg",
            content_type="image/jpeg",
            file_size_bytes=524288,
        )

        resp = await evidence_service.create_upload_session(incident_id, payload, caller_principal)
        assert resp.upload_url != ""
        assert resp.upload_method == "PUT"
        assert resp.original_filename == "window_broken.jpg"
        assert resp.storage_key.startswith(f"incidents/{incident.id}/")
        assert resp.expected_size_bytes == 524288
        assert "image/jpeg" in resp.upload_headers["Content-Type"]

    async def test_create_upload_session_rejects_closed_incident(
        self,
        evidence_service: EvidenceService,
        mock_incident_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        incident_id = uuid4()
        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-11223344",
            title="Old closed report",
            description="Window broken in dorm hall.",
            category="property_damage_theft",
            location="Dorm A",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.CLOSED.value,
            reporter_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        payload = UploadSessionCreateRequest(
            filename="window.jpg",
            content_type="image/jpeg",
            file_size_bytes=1024,
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await evidence_service.create_upload_session(incident_id, payload, caller_principal)
        assert exc_info.value.code == "INCIDENT_CLOSED_ATTACHMENT"

    async def test_create_upload_session_rejects_unauthorized_submitter(
        self,
        evidence_service: EvidenceService,
        mock_incident_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        incident_id = uuid4()
        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-11223344",
            title="Someone else's report",
            description="Window broken in dorm hall.",
            category="property_damage_theft",
            location="Dorm A",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=uuid4(),  # Different reporter
            department_id=caller_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        payload = UploadSessionCreateRequest(
            filename="window.jpg",
            content_type="image/jpeg",
            file_size_bytes=1024,
        )

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await evidence_service.create_upload_session(incident_id, payload, caller_principal)
        assert exc_info.value.code == "INCIDENT_NOT_FOUND"

    async def test_get_upload_session_scoping(
        self,
        evidence_service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        session_id = uuid4()
        incident_id = uuid4()
        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-11223344",
            title="Broken window",
            description="Window broken in dorm hall.",
            category="property_damage_theft",
            location="Dorm A",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        upload_sess = UploadSession(
            id=session_id,
            incident_id=incident_id,
            uploader_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            storage_key="incidents/1/evidence/file.pdf",
            original_filename="file.pdf",
            declared_mime_type="application/pdf",
            expected_size_bytes=1024,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            session_status=UploadSessionStatus.ACTIVE.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_evidence_repo.get_upload_session.return_value = upload_sess

        result = await evidence_service.get_upload_session(session_id, caller_principal)
        assert result.session_id == session_id
        assert result.original_filename == "file.pdf"

        # Another user from different department gets 404
        diff_user = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="other@univ.edu",
            full_name="Other User",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError):
            await evidence_service.get_upload_session(session_id, diff_user)

    async def test_create_upload_session_no_permission(
        self,
        evidence_service: EvidenceService,
    ) -> None:
        guest = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="guest@univ.edu",
            full_name="Guest User",
            account_status="active",
            is_active=True,
            role_code="ROLE_GUEST",
            department_id=uuid4(),
            session_id=uuid4(),
        )
        req = UploadSessionCreateRequest(
            filename="doc.pdf", content_type="application/pdf", file_size_bytes=100
        )
        with pytest.raises(PermissionDeniedError):
            await evidence_service.create_upload_session(uuid4(), req, guest)

    async def test_get_upload_session_not_found_and_expired(
        self,
        evidence_service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        # Session not found
        mock_evidence_repo.get_upload_session.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await evidence_service.get_upload_session(uuid4(), caller_principal)

        # Incident not found
        sess = UploadSession(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            storage_key="test-key",
            original_filename="test.png",
            declared_mime_type="image/png",
            expected_size_bytes=100,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            session_status=UploadSessionStatus.ACTIVE.value,
        )
        mock_evidence_repo.get_upload_session.return_value = sess
        mock_incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await evidence_service.get_upload_session(sess.id, caller_principal)

        # Expired session
        incident = Incident(
            id=sess.incident_id,
            reporter_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        mock_incident_repo.get_by_id.return_value = incident
        sess.expires_at = datetime.now(UTC) - timedelta(minutes=10)
        sess.session_status = UploadSessionStatus.ACTIVE.value
        mock_evidence_repo.update_upload_session.side_effect = lambda s: s

        expired_resp = await evidence_service.get_upload_session(sess.id, caller_principal)
        assert expired_resp.session_status == UploadSessionStatus.EXPIRED.value
        assert expired_resp.upload_url == ""

    async def test_service_from_session(self, test_settings: Settings) -> None:
        mock_session = AsyncMock()
        srv = EvidenceService.from_session(mock_session, test_settings)
        assert isinstance(srv, EvidenceService)
        assert srv.settings == test_settings

    async def test_list_attachments_flow(
        self,
        evidence_service: EvidenceService,
        mock_incident_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        incident_id = uuid4()
        # 1. Incident not found
        mock_incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await evidence_service.list_attachments(incident_id, caller_principal)

        # 2. Incident visible
        incident = Incident(
            id=incident_id,
            reporter_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_attachment = EvidenceAttachment(
            id=uuid4(),
            incident_id=incident_id,
            uploader_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            storage_key=f"incidents/{incident_id}/file.png",
            original_filename="file.png",
            declared_mime_type="image/png",
            file_size_bytes=1000,
            evidence_status=EvidenceStatus.ATTACHED.value,
            upload_status=UploadStatus.COMPLETED.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_evidence_repo.list_attachments_by_incident.return_value = [mock_attachment]

        attachments = await evidence_service.list_attachments(incident_id, caller_principal)
        assert len(attachments) == 1
        assert attachments[0].original_filename == "file.png"

    async def test_get_attachment_flow(
        self,
        evidence_service: EvidenceService,
        mock_incident_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        caller_principal: AuthenticatedPrincipal,
    ) -> None:
        att_id = uuid4()
        # 1. Attachment not found
        mock_evidence_repo.get_attachment_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await evidence_service.get_attachment(att_id, caller_principal)

        # 2. Attachment found, but incident not found
        mock_attachment = EvidenceAttachment(
            id=att_id,
            incident_id=uuid4(),
            uploader_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            storage_key=f"incidents/{uuid4()}/file.png",
            original_filename="file.png",
            declared_mime_type="image/png",
            file_size_bytes=1000,
            evidence_status=EvidenceStatus.ATTACHED.value,
            upload_status=UploadStatus.COMPLETED.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_evidence_repo.get_attachment_by_id.return_value = mock_attachment
        mock_incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await evidence_service.get_attachment(att_id, caller_principal)

        # 3. Success
        incident = Incident(
            id=mock_attachment.incident_id,
            reporter_id=caller_principal.user_id,
            department_id=caller_principal.department_id,
            status=IncidentStatus.SUBMITTED.value,
        )
        mock_incident_repo.get_by_id.return_value = incident
        ret = await evidence_service.get_attachment(att_id, caller_principal)
        assert ret.id == att_id

    async def test_assert_can_attach_evidence_rules(
        self,
        evidence_service: EvidenceService,
    ) -> None:
        dept_id = uuid4()
        reporter_id = uuid4()
        incident = Incident(
            id=uuid4(),
            department_id=dept_id,
            reporter_id=reporter_id,
            status=IncidentStatus.SUBMITTED.value,
        )

        # Super admin
        super_admin = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="super@univ.edu",
            full_name="Super Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
            session_id=uuid4(),
        )
        evidence_service._assert_can_attach_evidence(incident, super_admin)

        # Dept admin own dept
        dept_admin = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="admin@univ.edu",
            full_name="Dept Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            session_id=uuid4(),
        )
        evidence_service._assert_can_attach_evidence(incident, dept_admin)

        # Dept admin other dept
        diff_admin = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="otheradmin@univ.edu",
            full_name="Other Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError):
            evidence_service._assert_can_attach_evidence(incident, diff_admin)

        # Student not reporter
        other_student = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="otherst@univ.edu",
            full_name="Other Student",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
            session_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError):
            evidence_service._assert_can_attach_evidence(incident, other_student)

        # Student reporter on closed incident
        student_reporter = AuthenticatedPrincipal(
            user_id=reporter_id,
            email="reporter@univ.edu",
            full_name="Reporter Student",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
            session_id=uuid4(),
        )
        incident_closed = Incident(
            id=uuid4(),
            department_id=dept_id,
            reporter_id=reporter_id,
            status=IncidentStatus.CLOSED.value,
        )
        with pytest.raises(BusinessRuleError) as exc:
            evidence_service._assert_can_attach_evidence(incident_closed, student_reporter)
        assert exc.value.code == "INCIDENT_CLOSED_ATTACHMENT"

        # Unknown role
        unknown_user = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="unknown@univ.edu",
            full_name="Unknown",
            account_status="active",
            is_active=True,
            role_code="ROLE_GUEST",
            department_id=dept_id,
            session_id=uuid4(),
        )
        with pytest.raises(PermissionDeniedError):
            evidence_service._assert_can_attach_evidence(incident, unknown_user)


class TestInMemoryStorageClientUnit:
    """Unit tests for the InMemoryStorageClient mock."""

    async def test_in_memory_storage_operations(self) -> None:
        client = InMemoryStorageClient()
        key = "incidents/test-key.txt"
        data = b"hello evidence world"

        # Initially does not exist
        assert await client.verify_object_exists(key) is False
        assert await client.get_object_metadata(key) is None
        assert await client.delete_object(key) is False

        # Store mock object
        client.store_mock_object(key, data, "text/plain")
        assert await client.verify_object_exists(key) is True

        meta = await client.get_object_metadata(key)
        assert meta is not None
        assert meta.content_length == len(data)
        assert meta.content_type == "text/plain"
        assert meta.etag is not None

        # Download URL
        d_url = client.generate_presigned_download_url(key)
        assert "download" in d_url

        # Delete
        assert await client.delete_object(key) is True
        assert await client.verify_object_exists(key) is False


class TestS3StorageClientUnit:
    """Unit tests for S3StorageClient HTTP methods with mocked transport."""

    @pytest.fixture
    def s3_client(self, test_settings: Settings) -> S3StorageClient:
        return S3StorageClient(test_settings)

    async def test_verify_object_exists_branches(self, s3_client: S3StorageClient) -> None:
        # 200 OK
        with patch("httpx.AsyncClient.head", return_value=httpx.Response(200)):
            assert await s3_client.verify_object_exists("file.pdf") is True

        # 404 Not Found
        with patch("httpx.AsyncClient.head", return_value=httpx.Response(404)):
            assert await s3_client.verify_object_exists("file.pdf") is False

        # 500 Unexpected
        with patch("httpx.AsyncClient.head", return_value=httpx.Response(500)):
            assert await s3_client.verify_object_exists("file.pdf") is False

        # Request error
        with (
            patch("httpx.AsyncClient.head", side_effect=httpx.RequestError("network timeout")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.verify_object_exists("file.pdf")

    async def test_get_object_metadata_branches(self, s3_client: S3StorageClient) -> None:
        # 200 OK
        headers = {"Content-Length": "1024", "Content-Type": "image/jpeg", "ETag": '"abc123etag"'}
        with patch("httpx.AsyncClient.head", return_value=httpx.Response(200, headers=headers)):
            meta = await s3_client.get_object_metadata("pic.jpg")
            assert meta is not None
            assert meta.content_length == 1024
            assert meta.content_type == "image/jpeg"
            assert meta.etag == "abc123etag"

        # 404 Not Found
        with patch("httpx.AsyncClient.head", return_value=httpx.Response(404)):
            assert await s3_client.get_object_metadata("missing.jpg") is None

        # 503 Server error
        with (
            patch("httpx.AsyncClient.head", return_value=httpx.Response(500)),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.get_object_metadata("pic.jpg")

        # Request error
        with (
            patch("httpx.AsyncClient.head", side_effect=httpx.RequestError("conn failed")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.get_object_metadata("pic.jpg")

    async def test_delete_object_branches(self, s3_client: S3StorageClient) -> None:
        # 204 Deleted
        with patch("httpx.AsyncClient.delete", return_value=httpx.Response(204)):
            assert await s3_client.delete_object("file.pdf") is True

        # 404 Not found
        with patch("httpx.AsyncClient.delete", return_value=httpx.Response(404)):
            assert await s3_client.delete_object("file.pdf") is False

        # Request error
        with (
            patch("httpx.AsyncClient.delete", side_effect=httpx.RequestError("conn reset")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.delete_object("file.pdf")

    async def test_initiate_multipart_upload_branches(self, s3_client: S3StorageClient) -> None:
        # Success 200 with UploadId
        xml = "<InitiateMultipartUploadResult><UploadId>upload_xyz_123</UploadId></InitiateMultipartUploadResult>"
        with patch("httpx.AsyncClient.post", return_value=httpx.Response(200, text=xml)):
            upload_id = await s3_client.initiate_multipart_upload(
                "incidents/video.mp4", "video/mp4"
            )
            assert upload_id == "upload_xyz_123"

        # 200 with malformed XML
        with (
            patch(
                "httpx.AsyncClient.post", return_value=httpx.Response(200, text="<Error></Error>")
            ),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.initiate_multipart_upload("incidents/video.mp4", "video/mp4")

        # 500 error
        with (
            patch("httpx.AsyncClient.post", return_value=httpx.Response(500)),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.initiate_multipart_upload("incidents/video.mp4", "video/mp4")

        # Request error
        with (
            patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("timeout")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.initiate_multipart_upload("incidents/video.mp4", "video/mp4")

    async def test_generate_presigned_part_upload_url(self, s3_client: S3StorageClient) -> None:
        url = s3_client.generate_presigned_part_upload_url(
            "incidents/video.mp4",
            upload_id="upload_xyz_123",
            part_number=1,
            expires_in_seconds=600,
        )
        assert "partNumber=1" in url
        assert "uploadId=upload_xyz_123" in url
        assert "X-Amz-Signature=" in url

    async def test_complete_multipart_upload_branches(self, s3_client: S3StorageClient) -> None:
        headers = {"Content-Length": "2048", "Content-Type": "video/mp4", "ETag": '"final_etag"'}
        parts = [{"part_number": 1, "etag": "etag1"}, {"part_number": 2, "etag": "etag2"}]

        # Success with metadata
        with (
            patch("httpx.AsyncClient.post", return_value=httpx.Response(200)),
            patch("httpx.AsyncClient.head", return_value=httpx.Response(200, headers=headers)),
        ):
            meta = await s3_client.complete_multipart_upload(
                "incidents/video.mp4", "upload_xyz_123", parts
            )
            assert meta.content_length == 2048
            assert meta.content_type == "video/mp4"

        # 500 status on complete
        with (
            patch("httpx.AsyncClient.post", return_value=httpx.Response(500)),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.complete_multipart_upload(
                "incidents/video.mp4", "upload_xyz_123", parts
            )

        # 200 on complete but None metadata
        with (
            patch("httpx.AsyncClient.post", return_value=httpx.Response(200)),
            patch("httpx.AsyncClient.head", return_value=httpx.Response(404)),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.complete_multipart_upload(
                "incidents/video.mp4", "upload_xyz_123", parts
            )

        # Request error
        with (
            patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("network down")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.complete_multipart_upload(
                "incidents/video.mp4", "upload_xyz_123", parts
            )

    async def test_abort_multipart_upload_branches(self, s3_client: S3StorageClient) -> None:
        # Success 204
        with patch("httpx.AsyncClient.delete", return_value=httpx.Response(204)):
            assert (
                await s3_client.abort_multipart_upload("incidents/video.mp4", "upload_xyz_123")
                is True
            )

        # 500
        with patch("httpx.AsyncClient.delete", return_value=httpx.Response(500)):
            assert (
                await s3_client.abort_multipart_upload("incidents/video.mp4", "upload_xyz_123")
                is False
            )

        # Request error
        with (
            patch("httpx.AsyncClient.delete", side_effect=httpx.RequestError("aborted")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.abort_multipart_upload("incidents/video.mp4", "upload_xyz_123")

    async def test_get_object_bytes_branches(self, s3_client: S3StorageClient) -> None:
        # Success 200
        with patch(
            "httpx.AsyncClient.get",
            return_value=httpx.Response(200, content=b"evidence data bytes"),
        ):
            data = await s3_client.get_object_bytes("incidents/photo.jpg")
            assert data == b"evidence data bytes"

        # 404 Not Found
        with (
            patch("httpx.AsyncClient.get", return_value=httpx.Response(404)),
            pytest.raises(ResourceNotFoundError),
        ):
            await s3_client.get_object_bytes("incidents/missing.jpg")

        # 500 Server error
        with (
            patch("httpx.AsyncClient.get", return_value=httpx.Response(500)),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.get_object_bytes("incidents/photo.jpg")

        # Request error
        with (
            patch("httpx.AsyncClient.get", side_effect=httpx.RequestError("conn fail")),
            pytest.raises(ServiceUnavailableError),
        ):
            await s3_client.get_object_bytes("incidents/photo.jpg")
