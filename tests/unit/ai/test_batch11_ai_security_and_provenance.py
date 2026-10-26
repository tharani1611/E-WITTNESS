"""Unit tests for Phase 106: AI Inference Security, Worker Hardening, Model Provenance & Guardrails.

Verifies:
1. Strict model allowlisting and version pinning.
2. Rejection of path traversal and untrusted model targets.
3. Duplicate active job submission rejection (idempotency & race prevention).
4. Department-level concurrency quotas preventing worker exhaustion.
5. Inference execution timeout handling and typed failure categorization.
6. Sanitized error messages preventing internal path or credential leakage.
7. Model artifact base directory containment and cryptographic integrity verification.
8. Non-negotiable prohibition of automated biometric face matching.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from ai_services.violence_detection.classifier import (
    PretrainedVideoClassifierProvider,
)
from backend.app.config.settings import Environment, Settings
from backend.app.core.ai import (
    APPROVED_AI_MODELS,
    AIErrorCategory,
    AIJobStatus,
    validate_model_provenance,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
)
from backend.app.models.ai import AIAnalysisJob
from backend.app.models.evidence import EvidenceAttachment
from backend.app.schemas.ai import AIJobSubmitRequest
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.ai_job import AIAnalysisJobService


class TestBatch11ModelProvenanceAndInputValidation:
    """Verifies model allowlisting, path traversal protection, and schema validation."""

    def test_model_provenance_validation_approved_models(self) -> None:
        """Validate that all approved model names and versions pass provenance verification."""
        for model_name, versions in APPROVED_AI_MODELS.items():
            for version in versions:
                # Must not raise
                validate_model_provenance(model_name, version)

    def test_model_provenance_validation_rejects_unapproved_model(self) -> None:
        """Validate that unapproved model names are strictly rejected."""
        with pytest.raises(ValueError, match="not in approved AI model catalog"):
            validate_model_provenance("untrusted-model", "1.0.0")

    def test_model_provenance_validation_rejects_unapproved_version(self) -> None:
        """Validate that unapproved versions for an approved model are rejected."""
        with pytest.raises(ValueError, match="not approved for model"):
            validate_model_provenance("violence-classifier", "9.9.9")

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "models/violence-classifier",
            "classifier\x00extra",
            "violence;rm -rf /",
            "violence|cat /etc/shadow",
        ],
    )
    def test_model_provenance_validation_rejects_path_traversal(self, malicious_name: str) -> None:
        """Validate that path traversal, separators, or shell injection tokens are blocked."""
        with pytest.raises(ValueError, match="forbidden path traversal characters"):
            validate_model_provenance(malicious_name, "0.1.0")

    def test_ai_job_submit_request_schema_enforces_provenance(self) -> None:
        """Verify Pydantic validation rejects unapproved models at the API schema boundary."""
        # Valid request
        req = AIJobSubmitRequest(
            evidence_id=uuid4(),
            model_name="violence-classifier",
            model_version="0.1.0",
        )
        assert req.model_name == "violence-classifier"

        # Invalid model request
        with pytest.raises(ValidationError):
            AIJobSubmitRequest(
                evidence_id=uuid4(),
                model_name="../../bad/model",
                model_version="0.1.0",
            )


class TestBatch11AIJobQueueAndWorkerHardening:
    """Verifies duplicate prevention, concurrency quotas, timeouts, and error sanitization."""

    @pytest.fixture
    def mock_principal(self) -> AuthenticatedPrincipal:
        dept_id = uuid4()
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="investigator@ewitness.local",
            full_name="Investigator Test User",
            account_status="active",
            is_active=True,
            role_code="ROLE_INVESTIGATOR",
            department_id=dept_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def mock_service_dependencies(self) -> dict[str, MagicMock]:
        return {
            "job_repo": AsyncMock(),
            "evidence_repo": AsyncMock(),
            "incident_repo": AsyncMock(),
            "storage_client": AsyncMock(),
            "classifier": MagicMock(),
            "audit_repo": AsyncMock(),
            "segment_repo": AsyncMock(),
        }

    async def test_submit_analysis_job_duplicate_active_job_rejected(
        self,
        mock_principal: AuthenticatedPrincipal,
        mock_service_dependencies: dict[str, MagicMock],
    ) -> None:
        """Submitting an AI job for an attachment with an active job raises ConflictError."""
        job_repo = mock_service_dependencies["job_repo"]
        evidence_repo = mock_service_dependencies["evidence_repo"]

        evidence = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            department_id=mock_principal.department_id,
            original_filename="video.mp4",
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            upload_status="completed",
        )
        evidence_repo.get_attachment_by_id.return_value = evidence

        # Simulate existing queued job
        existing_job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=evidence.id,
            department_id=mock_principal.department_id,
            status=AIJobStatus.QUEUED.value,
        )
        job_repo.get_active_job_for_evidence.return_value = existing_job

        service = AIAnalysisJobService(
            job_repo=job_repo,
            evidence_repo=evidence_repo,
            incident_repo=mock_service_dependencies["incident_repo"],
            storage_client=mock_service_dependencies["storage_client"],
            classifier=mock_service_dependencies["classifier"],
            audit_repo=mock_service_dependencies["audit_repo"],
        )

        request = AIJobSubmitRequest(
            evidence_id=evidence.id,
            model_name="violence-classifier",
            model_version="0.1.0",
        )

        with pytest.raises(ConflictError) as exc_info:
            await service.submit_analysis_job(request, mock_principal)

        assert exc_info.value.code == "ACTIVE_JOB_EXISTS"

    async def test_submit_analysis_job_quota_exceeded_rejected(
        self,
        mock_principal: AuthenticatedPrincipal,
        mock_service_dependencies: dict[str, MagicMock],
    ) -> None:
        """Exceeding department concurrent active job quota raises BusinessRuleError."""
        job_repo = mock_service_dependencies["job_repo"]
        evidence_repo = mock_service_dependencies["evidence_repo"]

        evidence = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            department_id=mock_principal.department_id,
            original_filename="video.mp4",
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            upload_status="completed",
        )
        evidence_repo.get_attachment_by_id.return_value = evidence
        job_repo.get_active_job_for_evidence.return_value = None

        # Simulate 5 already active jobs for this department
        job_repo.count_active_for_department.return_value = 5

        service = AIAnalysisJobService(
            job_repo=job_repo,
            evidence_repo=evidence_repo,
            incident_repo=mock_service_dependencies["incident_repo"],
            storage_client=mock_service_dependencies["storage_client"],
            classifier=mock_service_dependencies["classifier"],
            audit_repo=mock_service_dependencies["audit_repo"],
        )

        request = AIJobSubmitRequest(
            evidence_id=evidence.id,
            model_name="violence-classifier",
            model_version="0.1.0",
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await service.submit_analysis_job(request, mock_principal)

        assert exc_info.value.code == "AI_JOB_QUOTA_EXCEEDED"

    async def test_execute_job_handles_timeout_cleanly(
        self,
        mock_service_dependencies: dict[str, MagicMock],
    ) -> None:
        """Inference timeout cleanly transitions job to FAILED with RESOURCE_EXHAUSTED."""
        job_repo = mock_service_dependencies["job_repo"]
        audit_repo = mock_service_dependencies["audit_repo"]

        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
            model_name="violence-classifier",
            model_version="0.1.0",
        )
        job_repo.get_by_id_unscoped.return_value = job
        job_repo.update.side_effect = lambda j: j

        # Simulate TimeoutError during storage retrieval
        mock_service_dependencies["evidence_repo"].get_attachment_by_id.side_effect = TimeoutError(
            "Storage request timed out"
        )

        service = AIAnalysisJobService(
            job_repo=job_repo,
            evidence_repo=mock_service_dependencies["evidence_repo"],
            incident_repo=mock_service_dependencies["incident_repo"],
            storage_client=mock_service_dependencies["storage_client"],
            classifier=mock_service_dependencies["classifier"],
            audit_repo=audit_repo,
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.FAILED.value
        assert result.error_category == AIErrorCategory.RESOURCE_EXHAUSTED.value
        assert "timed out" in (result.error_message or "").lower()
        audit_repo.append_event.assert_called()

    async def test_execute_job_sanitizes_internal_error_messages(
        self,
        mock_service_dependencies: dict[str, MagicMock],
    ) -> None:
        """Unexpected internal exceptions are sanitized to prevent leaking database strings or credentials."""
        job_repo = mock_service_dependencies["job_repo"]
        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
            model_name="violence-classifier",
            model_version="0.1.0",
        )
        job_repo.get_by_id_unscoped.return_value = job
        job_repo.update.side_effect = lambda j: j

        # Simulate raw database connection failure containing credentials
        mock_service_dependencies["evidence_repo"].get_attachment_by_id.side_effect = RuntimeError(
            "FATAL: connection to db at 10.0.0.5:5432 failed; password=Secret123!"
        )

        service = AIAnalysisJobService(
            job_repo=job_repo,
            evidence_repo=mock_service_dependencies["evidence_repo"],
            incident_repo=mock_service_dependencies["incident_repo"],
            storage_client=mock_service_dependencies["storage_client"],
            classifier=mock_service_dependencies["classifier"],
            audit_repo=mock_service_dependencies["audit_repo"],
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.FAILED.value
        assert result.error_category == AIErrorCategory.INTERNAL_ERROR.value
        assert (
            result.error_message == "An unexpected internal error occurred during video analysis."
        )
        assert "Secret123!" not in (result.error_message or "")


class TestBatch11PretrainedModelArtifactSecurity:
    """Verifies model loading boundaries, integrity verification, and biometric prohibitions."""

    def test_classifier_weights_integrity_verification(self, tmp_path: Path) -> None:
        """Classifier verifies expected SHA-256 digest of weights file."""
        weights_file = tmp_path / "model.pt"
        weights_file.write_bytes(b"VALID_PRETRAINED_MODEL_TENSORS")
        import hashlib

        expected_hash = hashlib.sha256(b"VALID_PRETRAINED_MODEL_TENSORS").hexdigest()

        # 1. Matching hash -> integrity verified
        provider = PretrainedVideoClassifierProvider(
            weights_path=weights_file,
            expected_sha256=expected_hash,
            allowed_base_dir=tmp_path,
        )
        assert provider._integrity_verified is True
        assert provider._weights_loaded is True

        # 2. Corrupted / mismatched hash -> rejected
        bad_provider = PretrainedVideoClassifierProvider(
            weights_path=weights_file,
            expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
            allowed_base_dir=tmp_path,
        )
        assert bad_provider._integrity_verified is False
        assert bad_provider._weights_loaded is False
        assert bad_provider.is_ready() is False

    def test_classifier_weights_rejects_path_traversal(self, tmp_path: Path) -> None:
        """Classifier rejects weights paths outside configured base directory."""
        trusted_dir = tmp_path / "trusted"
        trusted_dir.mkdir()
        untrusted_dir = tmp_path / "untrusted"
        untrusted_dir.mkdir()

        bad_weights = untrusted_dir / "evil_model.pt"
        bad_weights.write_bytes(b"EVIL_WEIGHTS")

        provider = PretrainedVideoClassifierProvider(
            weights_path=bad_weights,
            allowed_base_dir=trusted_dir,
        )
        assert provider._weights_loaded is False
        assert provider.is_ready() is False

    def test_biometric_matching_strictly_disabled_in_production(self) -> None:
        """Production configuration strictly forbids BIOMETRIC_MATCHING_ENABLED=True."""
        valid_prod = {
            "_env_file": None,
            "ENVIRONMENT": Environment.PRODUCTION,
            "DEBUG": False,
            "DB_ECHO": False,
            "LOG_LEVEL": "INFO",
            "LOG_FORMAT": "json",
            "LOG_REDACT_SENSITIVE": True,
            "CORS_ALLOWED_ORIGINS": ["https://portal.ewitness.edu"],
            "ALLOWED_HOSTS": ["api.ewitness.edu"],
            "DATABASE_URL": "postgresql+asyncpg://ewitness_prod:K9mP2vL8nQ5!zR4~wX7*bC1_yT6@db.internal.ewitness.edu:5432/ewitness_prod",
            "REDIS_URL": "rediss://:R8kM3pL9vN2!qW6~zX4*cB7_jF5@redis.internal.ewitness.edu:6379/0",
            "STORAGE_ENDPOINT_URL": "https://s3.us-east-1.amazonaws.com",
            "STORAGE_BUCKET_NAME": "ewitness-evidence-prod-vault",
            "STORAGE_REGION": "us-east-1",
            "STORAGE_ACCESS_KEY": "AKIA9X7P4M2L8Q5N3R6W",
            "STORAGE_SECRET_KEY": "Zx8#Qp3$Lm9@Vn5!Kw2&Yr7*Bt4^Hc6%Jd1_Fg0",
            "STORAGE_USE_SSL": True,
            "STORAGE_VERIFY_TLS": True,
            "AUTH_SECRET_KEY": "vN9#mK4$pL8@qW2!zX7&cB5*rT1^yU6%hJ3_gF0-dS8+aE5",
            "AUTH_ALGORITHM": "HS256",
            "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES": 15,
            "AUTH_REFRESH_TOKEN_EXPIRE_DAYS": 7,
            "ENFORCE_SSL": True,
            "SECURITY_HEADERS_ENABLED": True,
            "BIOMETRIC_MATCHING_ENABLED": True,  # FORBIDDEN
        }

        with pytest.raises(
            ValidationError, match="BIOMETRIC_MATCHING_ENABLED=True is strictly forbidden"
        ):
            Settings(**valid_prod)
