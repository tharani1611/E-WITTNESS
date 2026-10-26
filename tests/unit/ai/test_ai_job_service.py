"""Unit tests for Phase 65: Asynchronous AI Video Analysis Processing Jobs."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from ai_services.violence_detection.classifier import MockVideoClassifier
from backend.app.core.ai import AIErrorCategory, AIJobStatus
from backend.app.core.audit import AuditAction
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    UnsupportedMediaTypeError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.ai import AIAnalysisJob
from backend.app.models.evidence import EvidenceAttachment
from backend.app.schemas.ai import AIJobSubmitRequest
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.ai_job import AIAnalysisJobService
from tests.unit.ai.test_video_preprocessing import _build_minimal_mp4_bytes


@pytest.mark.unit
class TestAIAnalysisJobService:
    """Verify AIAnalysisJobService lifecycle, department isolation, pipeline execution, and failures."""

    @pytest.fixture
    def department_a_id(self) -> uuid4:
        return uuid4()

    @pytest.fixture
    def department_b_id(self) -> uuid4:
        return uuid4()

    @pytest.fixture
    def principal_investigator(self, department_a_id: uuid4) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="investigator@dept-a.edu",
            full_name="Investigator Dave",
            account_status="active",
            is_active=True,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=department_a_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def principal_investigator_b(self, department_b_id: uuid4) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="investigator@dept-b.edu",
            full_name="Investigator Eve",
            account_status="active",
            is_active=True,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=department_b_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def principal_super_admin(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="admin@campus.edu",
            full_name="Super Admin Bob",
            account_status="active",
            is_active=True,
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
            session_id=uuid4(),
        )

    @pytest.fixture
    def principal_student(self, department_a_id: uuid4) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="student@campus.edu",
            full_name="Student Charlie",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=department_a_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def mock_job_repo(self) -> AsyncMock:
        repo = AsyncMock()
        repo.create.side_effect = lambda j: j
        repo.update.side_effect = lambda j: j
        repo.get_by_id.return_value = None
        repo.get_by_id_unscoped.return_value = None
        repo.list_for_department.return_value = []
        repo.list_all_unscoped.return_value = []
        repo.count_for_department.return_value = 0
        return repo

    @pytest.fixture
    def mock_evidence_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_storage(self) -> AsyncMock:
        storage = AsyncMock()
        storage.get_object_bytes.return_value = _build_minimal_mp4_bytes(duration_seconds=10.0)
        return storage

    @pytest.fixture
    def mock_audit_repo(self) -> AsyncMock:
        return AsyncMock()

    async def test_submit_analysis_job_success(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
        department_a_id: uuid4,
    ) -> None:
        evidence = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=principal_investigator.user_id,
            department_id=department_a_id,
            original_filename="security_cam.mp4",
            storage_key="evidence/cam_1.mp4",
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            file_size_bytes=1024,
            upload_status="completed",
            evidence_status="active",
            scan_status="clean",
        )
        mock_evidence_repo.get_attachment_by_id.return_value = evidence

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            audit_repo=mock_audit_repo,
        )

        payload = AIJobSubmitRequest(evidence_id=evidence.id)
        job_read = await service.submit_analysis_job(payload, principal_investigator)

        assert job_read.status == AIJobStatus.QUEUED.value
        assert job_read.progress_percent == 0
        assert job_read.evidence_id == evidence.id
        assert job_read.department_id == department_a_id

        mock_job_repo.create.assert_awaited_once()
        mock_audit_repo.append_event.assert_awaited_once()
        assert (
            mock_audit_repo.append_event.call_args.kwargs["action"]
            == AuditAction.AI_JOB_SUBMITTED.value
        )

    async def test_submit_analysis_job_rejects_unfinalized_evidence(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
        department_a_id: uuid4,
    ) -> None:
        evidence = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=principal_investigator.user_id,
            department_id=department_a_id,
            original_filename="incomplete.mp4",
            storage_key="evidence/inc.mp4",
            declared_mime_type="video/mp4",
            file_size_bytes=100,
            upload_status="pending",
        )
        mock_evidence_repo.get_attachment_by_id.return_value = evidence

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            audit_repo=mock_audit_repo,
        )

        payload = AIJobSubmitRequest(evidence_id=evidence.id)
        with pytest.raises(BusinessRuleError, match="not finalized"):
            await service.submit_analysis_job(payload, principal_investigator)

    async def test_submit_analysis_job_rejects_non_video_file(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
        department_a_id: uuid4,
    ) -> None:
        evidence = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=principal_investigator.user_id,
            department_id=department_a_id,
            original_filename="notes.pdf",
            storage_key="evidence/doc.pdf",
            declared_mime_type="application/pdf",
            detected_mime_type="application/pdf",
            file_size_bytes=500,
            upload_status="completed",
        )
        mock_evidence_repo.get_attachment_by_id.return_value = evidence

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            audit_repo=mock_audit_repo,
        )

        payload = AIJobSubmitRequest(evidence_id=evidence.id)
        with pytest.raises(UnsupportedMediaTypeError, match="not a supported video file"):
            await service.submit_analysis_job(payload, principal_investigator)

    async def test_submit_analysis_job_enforces_department_isolation(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
        department_b_id: uuid4,
    ) -> None:
        """User from Department A cannot submit an AI job on Department B's evidence."""
        evidence = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=uuid4(),
            department_id=department_b_id,
            original_filename="secret_cam.mp4",
            storage_key="evidence/dept_b/cam.mp4",
            declared_mime_type="video/mp4",
            file_size_bytes=1000,
            upload_status="completed",
        )
        mock_evidence_repo.get_attachment_by_id.return_value = evidence

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            audit_repo=mock_audit_repo,
        )

        payload = AIJobSubmitRequest(evidence_id=evidence.id)
        with pytest.raises(PermissionDeniedError, match="belongs to a different department"):
            await service.submit_analysis_job(payload, principal_investigator)

    async def test_student_cannot_submit_analysis_job(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_student: AuthenticatedPrincipal,
    ) -> None:
        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            audit_repo=mock_audit_repo,
        )
        payload = AIJobSubmitRequest(evidence_id=uuid4())
        with pytest.raises(PermissionDeniedError):
            await service.submit_analysis_job(payload, principal_student)

    async def test_execute_job_end_to_end_pipeline_success(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        department_a_id: uuid4,
    ) -> None:
        evidence_id = uuid4()
        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=evidence_id,
            incident_id=uuid4(),
            department_id=department_a_id,
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
            progress_percent=0,
            model_name="mock-model",
            model_version="1.0.0",
        )
        mock_job_repo.get_by_id_unscoped.return_value = job

        evidence = EvidenceAttachment(
            id=evidence_id,
            incident_id=job.incident_id,
            uploader_id=job.submitted_by_id,
            department_id=department_a_id,
            original_filename="camera.mp4",
            storage_key="evidence/cam.mp4",
            file_size_bytes=1000,
        )
        mock_evidence_repo.get_attachment_by_id.return_value = evidence

        # Classifier fixture
        classifier = MockVideoClassifier(
            is_violence_detected=True,
            violence_score=0.91,
        )

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            classifier=classifier,
            audit_repo=mock_audit_repo,
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.SUCCEEDED.value
        assert result.progress_percent == 100
        assert result.result_summary is not None
        assert result.result_summary["is_violence_detected"] is True
        assert result.result_summary["violence_score"] == 0.91
        assert result.result_summary["confidence_is_uncalibrated"] is True
        assert len(result.result_summary["detected_segments"]) == 1

        # Verify audit records for start and completion
        audit_actions = [
            call.kwargs["action"] for call in mock_audit_repo.append_event.call_args_list
        ]
        assert AuditAction.AI_JOB_STARTED.value in audit_actions
        assert AuditAction.AI_JOB_COMPLETED.value in audit_actions

    async def test_execute_job_model_unavailable_fails_safely(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        department_a_id: uuid4,
    ) -> None:
        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=department_a_id,
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
        )
        mock_job_repo.get_by_id_unscoped.return_value = job

        evidence = EvidenceAttachment(
            id=job.evidence_id,
            incident_id=job.incident_id,
            uploader_id=job.submitted_by_id,
            department_id=department_a_id,
            original_filename="camera.mp4",
            storage_key="evidence/cam.mp4",
            file_size_bytes=1000,
        )
        mock_evidence_repo.get_attachment_by_id.return_value = evidence

        # Classifier with is_ready_override=False simulates missing runtime/weights
        classifier = MockVideoClassifier(is_ready_override=False)

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            classifier=classifier,
            audit_repo=mock_audit_repo,
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.FAILED.value
        assert result.error_category == AIErrorCategory.MODEL_UNAVAILABLE.value
        assert "No synthetic or fabricated" in (result.error_message or "")

        audit_actions = [
            call.kwargs["action"] for call in mock_audit_repo.append_event.call_args_list
        ]
        assert AuditAction.AI_JOB_FAILED.value in audit_actions

    async def test_execute_job_corrupted_video_fails_safely(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        department_a_id: uuid4,
    ) -> None:
        mock_storage.get_object_bytes.return_value = b"corrupted non-mp4 content"

        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=department_a_id,
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
        )
        mock_job_repo.get_by_id_unscoped.return_value = job
        mock_evidence_repo.get_attachment_by_id.return_value = EvidenceAttachment(
            id=job.evidence_id,
            incident_id=job.incident_id,
            uploader_id=job.submitted_by_id,
            department_id=department_a_id,
            original_filename="bad.mp4",
            storage_key="bad.mp4",
            file_size_bytes=24,
        )

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            classifier=MockVideoClassifier(),
            audit_repo=mock_audit_repo,
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.FAILED.value
        assert result.error_category == AIErrorCategory.UNSUPPORTED_FORMAT.value

    async def test_cancel_job_lifecycle(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
        department_a_id: uuid4,
    ) -> None:
        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=department_a_id,
            submitted_by_id=principal_investigator.user_id,
            status=AIJobStatus.QUEUED.value,
        )
        mock_job_repo.get_by_id.return_value = job

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
            audit_repo=mock_audit_repo,
        )

        # Cancel queued job
        cancelled = await service.cancel_job(job.id, principal_investigator)
        assert cancelled.status == AIJobStatus.CANCELLED.value

        # Attempting to cancel already cancelled job raises ConflictError
        with pytest.raises(ConflictError, match="already in terminal state"):
            await service.cancel_job(job.id, principal_investigator)

    async def test_get_and_list_jobs_department_scoping(
        self,
        mock_job_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
        principal_super_admin: AuthenticatedPrincipal,
        department_a_id: uuid4,
    ) -> None:
        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=department_a_id,
            submitted_by_id=principal_investigator.user_id,
            status=AIJobStatus.SUCCEEDED.value,
        )
        mock_job_repo.get_by_id.return_value = job
        mock_job_repo.get_by_id_unscoped.return_value = job
        mock_job_repo.list_for_department.return_value = [job]
        mock_job_repo.count_for_department.return_value = 1
        mock_job_repo.list_all_unscoped.return_value = [job]

        service = AIAnalysisJobService(
            job_repo=mock_job_repo,
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage,
        )

        # Scoped retrieval
        read = await service.get_job(job.id, principal_investigator)
        assert read.id == job.id

        # Super admin retrieval
        admin_read = await service.get_job(job.id, principal_super_admin)
        assert admin_read.id == job.id

        # List jobs
        items, total = await service.list_jobs(principal_investigator)
        assert len(items) == 1
        assert total == 1
