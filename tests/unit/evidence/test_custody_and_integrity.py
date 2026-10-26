"""Unit tests for Phases 51-54: SHA-256 calculation, provenance separation, chain-of-custody ledger, and integrity verification."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.evidence import (
    INTEGRITY_DISCLAIMER,
    CustodyActionType,
    EvidenceStatus,
    IntegrityVerificationStatus,
    ScanStatus,
    UploadSessionStatus,
    UploadStatus,
    compute_custody_event_hash,
)
from backend.app.core.exceptions import (
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.core.incident import IncidentStatus
from backend.app.infrastructure.scanner import MockMalwareScanner
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.models.evidence import EvidenceAttachment, EvidenceCustodyEvent, UploadSession
from backend.app.models.incident import Incident
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.evidence import (
    CompensatingEventCreateRequest,
)
from backend.app.services.evidence import EvidenceService


class TestCustodyAndIntegrityDomainPrimitives:
    """Phases 51-54: Primitives, hashes, and chain-of-custody hash calculations."""

    def test_integrity_disclaimer_content(self) -> None:
        assert "bit-level integrity" in INTEGRITY_DISCLAIMER
        assert "NOT prove the legal authenticity" in INTEGRITY_DISCLAIMER

    def test_compute_custody_event_hash_deterministic(self) -> None:
        evidence_id = uuid4()
        actor_id = uuid4()
        ts_iso = "2026-10-14T02:00:00Z"
        sha = hashlib.sha256(b"sample bytes").hexdigest()

        hash1 = compute_custody_event_hash(
            evidence_id=evidence_id,
            sequence_number=1,
            action_type=CustodyActionType.INGESTED.value,
            timestamp_iso=ts_iso,
            actor_id=actor_id,
            evidence_sha256=sha,
            previous_event_hash=None,
            details="Initial ingestion",
        )

        hash2 = compute_custody_event_hash(
            evidence_id=evidence_id,
            sequence_number=1,
            action_type=CustodyActionType.INGESTED.value,
            timestamp_iso=ts_iso,
            actor_id=actor_id,
            evidence_sha256=sha,
            previous_event_hash=None,
            details="Initial ingestion",
        )
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_compute_custody_event_hash_chain_changes(self) -> None:
        evidence_id = uuid4()
        actor_id = uuid4()
        ts_iso = "2026-10-14T02:00:00Z"
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        genesis_hash = compute_custody_event_hash(
            evidence_id=evidence_id,
            sequence_number=1,
            action_type=CustodyActionType.INGESTED.value,
            timestamp_iso=ts_iso,
            actor_id=actor_id,
            evidence_sha256=sha,
            previous_event_hash=None,
            details="Genesis event",
        )

        event2_hash = compute_custody_event_hash(
            evidence_id=evidence_id,
            sequence_number=2,
            action_type=CustodyActionType.HASH_VERIFIED.value,
            timestamp_iso=ts_iso,
            actor_id=actor_id,
            evidence_sha256=sha,
            previous_event_hash=genesis_hash,
            details="Verified",
        )
        assert genesis_hash != event2_hash

        # Tampered predecessor hash produces completely different outcome
        tampered_event2_hash = compute_custody_event_hash(
            evidence_id=evidence_id,
            sequence_number=2,
            action_type=CustodyActionType.HASH_VERIFIED.value,
            timestamp_iso=ts_iso,
            actor_id=actor_id,
            evidence_sha256=sha,
            previous_event_hash="0000000000000000000000000000000000000000000000000000000000000000",
            details="Verified",
        )
        assert event2_hash != tampered_event2_hash

    def test_compensating_event_request_validation(self) -> None:
        target_id = uuid4()
        req = CompensatingEventCreateRequest(
            target_event_id=target_id,
            justification_reason="Correction of typographical label in custody notes.",
            details="Amended chain record.",
        )
        assert req.target_event_id == target_id
        assert "typographical" in req.justification_reason

        with pytest.raises(ValidationError):
            CompensatingEventCreateRequest(
                target_event_id=target_id,
                justification_reason="abc",  # min length 5
            )


class TestEvidenceCustodyAndIntegrityService:
    """Phases 51-54: Service level tests for custody ledger, hash calculation, provenance, and integrity checks."""

    @pytest.fixture
    def mock_evidence_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def storage_client(self) -> InMemoryStorageClient:
        return InMemoryStorageClient("memory://ewitness-vault")

    @pytest.fixture
    def mock_scanner(self) -> MockMalwareScanner:
        return MockMalwareScanner(default_status=ScanStatus.CLEAN)

    @pytest.fixture
    def service(
        self,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        storage_client: InMemoryStorageClient,
        test_settings: Settings,
        mock_scanner: MockMalwareScanner,
    ) -> EvidenceService:
        return EvidenceService(
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=storage_client,
            settings=test_settings,
            scanner=mock_scanner,
        )

    @pytest.fixture
    def dept_id(self) -> UUID:
        return uuid4()

    @pytest.fixture
    def student_principal(self, dept_id: UUID) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="student@university.edu",
            full_name="Student Uploader",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def dept_admin_principal(self, dept_id: UUID) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="admin@university.edu",
            full_name="Dept Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            session_id=uuid4(),
        )

    @pytest.mark.asyncio
    async def test_complete_upload_session_calculates_hash_and_records_custody(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        storage_client: InMemoryStorageClient,
        student_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        session_id = uuid4()
        storage_key = f"incidents/{incident_id}/photo.png"
        payload_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        expected_sha = hashlib.sha256(payload_bytes).hexdigest()

        # Seed storage with bytes
        await storage_client.put_object(storage_key, payload_bytes, "image/png")

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="Incident Title",
            description="Incident narrative",
            category="safety_hazard",
            severity="medium",
            status=IncidentStatus.SUBMITTED.value,
            location="Room 101",
            occurred_at=datetime.now(UTC),
            reporter_id=student_principal.user_id,
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        session = UploadSession(
            id=session_id,
            incident_id=incident_id,
            uploader_id=student_principal.user_id,
            department_id=dept_id,
            storage_key=storage_key,
            original_filename="photo.png",
            declared_mime_type="image/png",
            expected_size_bytes=len(payload_bytes),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            session_status=UploadSessionStatus.ACTIVE.value,
        )
        attachment = EvidenceAttachment(
            id=uuid4(),
            incident_id=incident_id,
            uploader_id=student_principal.user_id,
            department_id=dept_id,
            upload_session_id=session_id,
            original_filename="photo.png",
            storage_key=storage_key,
            declared_mime_type="image/png",
            file_size_bytes=len(payload_bytes),
            upload_status=UploadStatus.PENDING.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.PENDING.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_upload_session.return_value = session
        mock_incident_repo.get_by_id.return_value = incident
        mock_evidence_repo.get_attachment_by_session_id.return_value = attachment
        mock_evidence_repo.update_upload_session.return_value = session
        mock_evidence_repo.update_attachment.return_value = attachment
        mock_evidence_repo.get_latest_custody_event.return_value = None
        mock_evidence_repo.create_custody_event.return_value = None

        res = await service.complete_upload_session(
            session_id=session_id,
            principal=student_principal,
            uploader_ip="192.168.1.100",
            user_agent="EvidenceClient/1.0",
        )

        assert res.sha256_hash == expected_sha
        assert res.hash_sha256 == expected_sha
        assert attachment.sha256_hash == expected_sha
        assert attachment.ingested_at is not None
        assert attachment.uploader_ip == "192.168.1.100"
        assert attachment.user_agent == "EvidenceClient/1.0"

        # Verify two custody events recorded: INGESTED and SEALED
        assert mock_evidence_repo.create_custody_event.call_count == 2
        calls = mock_evidence_repo.create_custody_event.call_args_list
        ingested_event = calls[0][0][0]
        sealed_event = calls[1][0][0]

        assert ingested_event.action_type == CustodyActionType.INGESTED.value
        assert ingested_event.sequence_number == 1
        assert ingested_event.previous_event_hash is None
        assert ingested_event.evidence_sha256 == expected_sha

        assert sealed_event.action_type == CustodyActionType.SEALED.value
        assert sealed_event.sequence_number == 1  # latest mocked as None in loop
        assert sealed_event.evidence_sha256 == expected_sha

    @pytest.mark.asyncio
    async def test_verify_evidence_integrity_clean_match(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        storage_client: InMemoryStorageClient,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()
        storage_key = f"incidents/{incident_id}/doc.pdf"
        payload_bytes = b"%PDF-1.4\n" + b"A" * 200
        trusted_sha = hashlib.sha256(payload_bytes).hexdigest()

        await storage_client.put_object(storage_key, payload_bytes, "application/pdf")

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="PDF Incident",
            description="PDF Incident Description",
            category="academic_misconduct",
            severity="medium",
            status=IncidentStatus.SUBMITTED.value,
            location="Library",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="doc.pdf",
            storage_key=storage_key,
            declared_mime_type="application/pdf",
            file_size_bytes=len(payload_bytes),
            sha256_hash=trusted_sha,
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident
        mock_evidence_repo.get_latest_custody_event.return_value = None
        mock_evidence_repo.create_custody_event.return_value = None

        report = await service.verify_evidence_integrity(attachment_id, dept_admin_principal)

        assert report.status == IntegrityVerificationStatus.VERIFIED_MATCH.value
        assert report.is_tampered is False
        assert report.stored_sha256 == trusted_sha
        assert report.computed_sha256 == trusted_sha
        assert report.disclaimer == INTEGRITY_DISCLAIMER

        # Verified event recorded
        mock_evidence_repo.create_custody_event.assert_called_once()
        event = mock_evidence_repo.create_custody_event.call_args[0][0]
        assert event.action_type == CustodyActionType.HASH_VERIFIED.value

    @pytest.mark.asyncio
    async def test_verify_evidence_integrity_tamper_detected(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        storage_client: InMemoryStorageClient,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()
        storage_key = f"incidents/{incident_id}/doc.pdf"
        original_bytes = b"%PDF-1.4\nOriginal Evidence"
        trusted_sha = hashlib.sha256(original_bytes).hexdigest()

        # Simulate storage payload tampering after ingestion
        tampered_bytes = b"%PDF-1.4\nTampered Altered Evidence"
        await storage_client.put_object(storage_key, tampered_bytes, "application/pdf")

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="PDF Incident",
            description="PDF Incident Description",
            category="academic_misconduct",
            severity="medium",
            status=IncidentStatus.SUBMITTED.value,
            location="Library",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="doc.pdf",
            storage_key=storage_key,
            declared_mime_type="application/pdf",
            file_size_bytes=len(original_bytes),
            sha256_hash=trusted_sha,
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident
        mock_evidence_repo.get_latest_custody_event.return_value = None
        mock_evidence_repo.create_custody_event.return_value = None

        report = await service.verify_evidence_integrity(attachment_id, dept_admin_principal)

        assert report.status == IntegrityVerificationStatus.TAMPER_DETECTED.value
        assert report.is_tampered is True
        assert report.stored_sha256 == trusted_sha
        assert report.computed_sha256 != trusted_sha
        assert report.disclaimer == INTEGRITY_DISCLAIMER

        # Tamper detected custody event recorded
        mock_evidence_repo.create_custody_event.assert_called_once()
        event = mock_evidence_repo.create_custody_event.call_args[0][0]
        assert event.action_type == CustodyActionType.TAMPER_DETECTED.value

    @pytest.mark.asyncio
    async def test_verify_evidence_integrity_storage_missing(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        storage_client: InMemoryStorageClient,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()
        storage_key = f"incidents/{incident_id}/missing.pdf"

        # Do NOT put object in storage_client to simulate missing object

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="PDF Incident",
            description="PDF Incident Description",
            category="academic_misconduct",
            severity="medium",
            status=IncidentStatus.SUBMITTED.value,
            location="Library",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="missing.pdf",
            storage_key=storage_key,
            declared_mime_type="application/pdf",
            file_size_bytes=100,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident
        mock_evidence_repo.get_latest_custody_event.return_value = None
        mock_evidence_repo.create_custody_event.return_value = None

        report = await service.verify_evidence_integrity(attachment_id, dept_admin_principal)

        assert report.status == IntegrityVerificationStatus.STORAGE_MISSING.value
        assert report.is_tampered is True
        assert report.computed_sha256 is None

    @pytest.mark.asyncio
    async def test_verify_evidence_integrity_unverified_incomplete_upload(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="Incomplete",
            description="Detail",
            category="other",
            severity="low",
            status=IncidentStatus.SUBMITTED.value,
            location="Hall",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="pending.png",
            storage_key="incidents/test/pending.png",
            declared_mime_type="image/png",
            file_size_bytes=100,
            sha256_hash=None,
            upload_status=UploadStatus.PENDING.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.PENDING.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident

        report = await service.verify_evidence_integrity(attachment_id, dept_admin_principal)

        assert report.status == IntegrityVerificationStatus.UNVERIFIED.value
        assert report.is_tampered is False
        assert report.details is not None and "incomplete or pending" in report.details

    @pytest.mark.asyncio
    async def test_compensating_custody_event_administrative_correction(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()
        target_event_id = uuid4()

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="Incident Title",
            description="Incident narrative",
            category="other",
            severity="medium",
            status=IncidentStatus.SUBMITTED.value,
            location="Room 101",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="evidence.png",
            storage_key="incidents/test/evidence.png",
            declared_mime_type="image/png",
            file_size_bytes=100,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        target_event = EvidenceCustodyEvent(
            id=target_event_id,
            evidence_id=attachment_id,
            incident_id=incident_id,
            department_id=dept_id,
            sequence_number=1,
            action_type=CustodyActionType.INGESTED.value,
            actor_id=uuid4(),
            actor_role="student",
            timestamp=datetime.now(UTC),
            evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            previous_event_hash=None,
            event_hash="hash1",
            details="Original event details",
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident
        mock_evidence_repo.get_custody_event_by_id.return_value = target_event
        mock_evidence_repo.get_latest_custody_event.return_value = target_event

        created_event = EvidenceCustodyEvent(
            id=uuid4(),
            evidence_id=attachment_id,
            incident_id=incident_id,
            department_id=dept_id,
            sequence_number=2,
            action_type=CustodyActionType.COMPENSATING_CORRECTION.value,
            actor_id=dept_admin_principal.user_id,
            actor_role=dept_admin_principal.role_code,
            actor_department_id=dept_admin_principal.department_id,
            timestamp=datetime.now(UTC),
            evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            previous_event_hash="hash1",
            event_hash="hash2",
            details="Correction made to clarify initial capture time.",
            compensates_event_id=target_event_id,
            compensation_reason="Typographical error corrected in intake record.",
        )
        mock_evidence_repo.create_custody_event.return_value = created_event

        req = CompensatingEventCreateRequest(
            target_event_id=target_event_id,
            justification_reason="Typographical error corrected in intake record.",
            details="Correction made to clarify initial capture time.",
        )

        res = await service.create_compensating_custody_event(
            attachment_id, req, dept_admin_principal
        )

        assert res.action_type == CustodyActionType.COMPENSATING_CORRECTION.value
        assert res.compensates_event_id == target_event_id
        assert res.compensation_reason == "Typographical error corrected in intake record."

    @pytest.mark.asyncio
    async def test_compensating_custody_event_forbidden_for_student(
        self,
        service: EvidenceService,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        req = CompensatingEventCreateRequest(
            target_event_id=uuid4(),
            justification_reason="Unauthorized student trying to alter history.",
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await service.create_compensating_custody_event(uuid4(), req, student_principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    async def test_get_evidence_provenance_distinguishes_observed_facts_from_declarations(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()
        ingested_time = datetime.now(UTC) - timedelta(hours=1)
        client_reported_time = datetime.now(UTC) - timedelta(days=2)

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="Incident Title",
            description="Incident narrative",
            category="other",
            severity="medium",
            status=IncidentStatus.SUBMITTED.value,
            location="Room 101",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="untrusted_original_file.exe.jpg",
            declared_mime_type="image/jpeg",
            detected_mime_type="image/jpeg",
            file_size_bytes=2048,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            scan_details="Clean",
            ingested_at=ingested_time,
            client_reported_at=client_reported_time,
            uploader_ip="10.0.0.5",
            user_agent="EvidenceCaptureApp/2.0",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident

        prov = await service.get_evidence_provenance(attachment_id, dept_admin_principal)

        # Observed facts are server-verified
        assert (
            prov.observed_facts["sha256_hash"]
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert prov.observed_facts["file_size_bytes"] == 2048
        assert prov.observed_facts["detected_mime_type"] == "image/jpeg"
        assert prov.observed_facts["uploader_ip"] == "10.0.0.5"
        assert prov.observed_facts["user_agent"] == "EvidenceCaptureApp/2.0"
        assert prov.observed_facts["ingested_at"] == ingested_time.isoformat()

        # User declarations are unverified assertions
        assert prov.user_declarations["original_filename"] == "untrusted_original_file.exe.jpg"
        assert prov.user_declarations["declared_mime_type"] == "image/jpeg"
        assert prov.user_declarations["client_reported_at"] == client_reported_time.isoformat()

    @pytest.mark.asyncio
    async def test_get_custody_ledger_isolation(
        self,
        service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        attachment_id = uuid4()
        other_user_id = uuid4()

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-TEST",
            title="Other user incident",
            description="Detail",
            category="other",
            severity="low",
            status=IncidentStatus.SUBMITTED.value,
            location="Room 101",
            occurred_at=datetime.now(UTC),
            reporter_id=other_user_id,
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            uploader_id=other_user_id,
            department_id=dept_id,
            original_filename="secret.png",
            declared_mime_type="image/png",
            file_size_bytes=100,
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_evidence_repo.get_attachment_by_id.return_value = attachment
        mock_incident_repo.get_by_id.return_value = incident

        # Student cannot view custody ledger of other user's incident (404)
        with pytest.raises(ResourceNotFoundError):
            await service.get_custody_ledger(attachment_id, student_principal)
