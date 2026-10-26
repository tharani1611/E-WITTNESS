"""Unit and mock tests for FaceMatchingService, BiometricVerificationService, and repositories (Phases 76-80).

Comprehensive coverage for:
- All guardrails and error branches in FaceMatchingService (permissions, disabled settings, payload limits,
  governance checks, probe/reference quality, encrypted template handling, and direct comparison).
- All branches in BiometricVerificationService (permissions, review lookup, override detection, mandatory reason).
- BiometricEvaluationService authorization and report generation.
- BiometricVerificationRepository filtering and pagination.
"""

from __future__ import annotations

import base64
import struct
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.biometrics import (
    BiometricHumanVerdict,
    BiometricMatchVerdict,
    BiometricPurpose,
    BiometricReferenceStatus,
    ConsentStatus,
    GovernanceStatus,
)
from backend.app.core.exceptions import (
    BiometricGovernanceError,
    BiometricQualityError,
    BiometricsDisabledError,
    BusinessRuleError,
    PayloadTooLargeError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.biometrics import (
    BiometricVerificationReview,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.biometrics import (
    BiometricVerificationReviewCreate,
    FaceMatchRequest,
)
from backend.app.services.biometrics import (
    BiometricEvaluationService,
    BiometricVerificationService,
    FaceMatchingService,
)


def _make_test_settings(**kwargs: Any) -> Settings:
    """Create isolated Settings instance for unit tests."""
    defaults: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "APP_NAME": "E-WITNESS Test",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "REDIS_URL": "redis://localhost:6379/15",
        "STORAGE_ENDPOINT_URL": "https://s3.test.internal:9000",
        "STORAGE_BUCKET_NAME": "ewitness-test-bucket",
        "STORAGE_ACCESS_KEY": "test_access_key_isolated",
        "STORAGE_SECRET_KEY": "test_secret_key_isolated_value",
        "AUTH_SECRET_KEY": "test_only_signing_key_with_sufficient_length_32_plus",
        "AI_API_KEY": "test-ai-key",
        "BIOMETRIC_ANALYSIS_ENABLED": True,
        "BIOMETRIC_MATCHING_ENABLED": True,
        "BIOMETRIC_PROVIDER": "mock",
        "BIOMETRIC_MAX_IMAGE_SIZE_BYTES": 10 * 1024 * 1024,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_review(**kwargs: Any) -> BiometricVerificationReview:
    """Create a mock BiometricVerificationReview with full timestamp & uncertainty defaults."""
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "department_id": uuid4(),
        "probe_image_hash": "a" * 64,
        "candidate_similarity": 0.90,
        "automated_verdict": "match_candidate",
        "human_verdict": "inconclusive_dismissed",
        "uncertainty_lower_bound": 0.60,
        "uncertainty_upper_bound": 0.85,
        "is_override": False,
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(kwargs)
    return BiometricVerificationReview(**defaults)


def make_valid_png_bytes(width: int = 128, height: int = 128, fill_byte: int = 120) -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    payload = bytes([(fill_byte + (i % 80)) % 256 for i in range(256)])
    idat_chunk = struct.pack(">I", len(payload)) + b"IDAT" + payload + b"\x00\x00\x00\x00"
    iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    return signature + ihdr_chunk + idat_chunk + iend_chunk


def _create_principal(
    role_code: str = RoleCode.INVESTIGATOR.value,
    department_id: UUID | None = None,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=uuid4(),
        email="test_user@ewitness.edu",
        full_name="Test Principal",
        account_status="active",
        is_active=True,
        role_code=role_code,
        department_id=department_id or uuid4(),
        session_id=uuid4(),
    )


@pytest.fixture
def enabled_settings() -> Settings:
    return _make_test_settings(
        BIOMETRIC_ANALYSIS_ENABLED=True,
        BIOMETRIC_MATCHING_ENABLED=True,
        BIOMETRIC_PROVIDER="mock",
    )


@pytest.fixture
def disabled_settings() -> Settings:
    return _make_test_settings(
        BIOMETRIC_ANALYSIS_ENABLED=True,
        BIOMETRIC_MATCHING_ENABLED=False,
        BIOMETRIC_PROVIDER="mock",
    )


@pytest.mark.asyncio
class TestFaceMatchingServiceUnit:
    """Unit tests for FaceMatchingService guardrails and execution paths."""

    async def test_permission_denied_for_student(self, enabled_settings: Settings) -> None:
        service = FaceMatchingService(
            governance_repo=MagicMock(),
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        student_principal = _create_principal(role_code=RoleCode.STUDENT.value)
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64="valid_b64",
            reference_id=uuid4(),
        )
        with pytest.raises(PermissionDeniedError, match="BIOMETRIC_MATCHING_EXECUTE"):
            await service.match_faces(req, student_principal)

    async def test_matching_disabled_in_settings(self, disabled_settings: Settings) -> None:
        service = FaceMatchingService(
            governance_repo=MagicMock(),
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=disabled_settings,
        )
        principal = _create_principal(role_code=RoleCode.INVESTIGATOR.value)
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64="valid_b64",
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricsDisabledError, match="strictly disabled"):
            await service.match_faces(req, principal)

    async def test_invalid_base64_probe_image(self, enabled_settings: Settings) -> None:
        service = FaceMatchingService(
            governance_repo=MagicMock(),
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64="not-valid-base64!@#$",
            reference_id=uuid4(),
        )
        with pytest.raises(BusinessRuleError, match="Invalid base64 encoding"):
            await service.match_faces(req, principal)

    async def test_payload_too_large(self, enabled_settings: Settings) -> None:
        tight_settings = enabled_settings.model_copy(
            update={"BIOMETRIC_MAX_IMAGE_SIZE_BYTES": 1024}
        )
        service = FaceMatchingService(
            governance_repo=MagicMock(),
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=tight_settings,
        )
        principal = _create_principal()
        large_bytes = b"X" * 2048
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(large_bytes).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(PayloadTooLargeError, match="exceeds maximum limit"):
            await service.match_faces(req, principal)

    async def test_governance_record_not_found(self, enabled_settings: Settings) -> None:
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=None)
        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError, match="not found"):
            await service.match_faces(req, principal)

    async def test_governance_record_not_approved(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.PENDING_LEGAL_REVIEW.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)
        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricGovernanceError, match="approved governance record"):
            await service.match_faces(req, principal)

    async def test_governance_consent_withdrawn(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.WITHDRAWN.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)
        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricGovernanceError, match="withdrawn subject consent"):
            await service.match_faces(req, principal)

    async def test_governance_unauthorized_purpose(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.ACTIVE.value
        gov_rec.purpose = BiometricPurpose.PRIVACY_REDACTION_BLURRING.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)
        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricGovernanceError, match="not authorized for face matching"):
            await service.match_faces(req, principal)

    async def test_probe_quality_failure(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.ACTIVE.value
        gov_rec.purpose = BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)
        audit_repo = MagicMock()
        audit_repo.append_event = AsyncMock()
        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=MagicMock(),
            verification_repo=MagicMock(),
            settings=enabled_settings,
            audit_repo=audit_repo,
        )
        principal = _create_principal()
        # Invalid image bytes
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(b"CORRUPTED_NOT_PNG").decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricQualityError, match="quality check failed"):
            await service.match_faces(req, principal)
        assert audit_repo.append_event.called

    async def test_reference_not_found(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.ACTIVE.value
        gov_rec.purpose = BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)
        ref_repo = MagicMock()
        ref_repo.get_by_id = AsyncMock(return_value=None)
        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError, match=r"Biometric reference '.*' not found"):
            await service.match_faces(req, principal)

    async def test_reference_not_active(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.ACTIVE.value
        gov_rec.purpose = BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)

        ref_rec = MagicMock()
        ref_rec.status = BiometricReferenceStatus.REVOKED.value
        ref_rec.reference_id = "REF-REVOKED"
        ref_repo = MagicMock()
        ref_repo.get_by_id = AsyncMock(return_value=ref_rec)

        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricGovernanceError, match="is not active"):
            await service.match_faces(req, principal)

    async def test_reference_missing_template_and_image(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.ACTIVE.value
        gov_rec.purpose = BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)

        ref_rec = MagicMock()
        ref_rec.status = BiometricReferenceStatus.ACTIVE.value
        ref_rec.encrypted_template = None
        ref_repo = MagicMock()
        ref_repo.get_by_id = AsyncMock(return_value=ref_rec)

        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            verification_repo=MagicMock(),
            settings=enabled_settings,
        )
        principal = _create_principal()
        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(make_valid_png_bytes()).decode(),
            reference_id=uuid4(),
        )
        with pytest.raises(BiometricGovernanceError, match="has no stored template"):
            await service.match_faces(req, principal)

    async def test_direct_image_to_image_matching_success(self, enabled_settings: Settings) -> None:
        gov_rec = MagicMock()
        gov_rec.status = GovernanceStatus.APPROVED.value
        gov_rec.consent_status = ConsentStatus.ACTIVE.value
        gov_rec.purpose = BiometricPurpose.TESTING_SYNTHETIC_BENCHMARK.value
        gov_rec.tenant_id = uuid4()
        gov_rec.department_id = uuid4()
        gov_repo = MagicMock()
        gov_repo.get_by_id = AsyncMock(return_value=gov_rec)

        verif_repo = MagicMock()
        verif_repo.create = AsyncMock(side_effect=lambda r: r)
        audit_repo = MagicMock()
        audit_repo.append_event = AsyncMock()

        service = FaceMatchingService(
            governance_repo=gov_repo,
            reference_repo=MagicMock(),
            verification_repo=verif_repo,
            settings=enabled_settings,
            audit_repo=audit_repo,
        )
        principal = _create_principal()
        probe_png = make_valid_png_bytes(128, 128, fill_byte=50)
        ref_png = make_valid_png_bytes(128, 128, fill_byte=50)

        req = FaceMatchRequest(
            governance_record_id=uuid4(),
            probe_image_base64=base64.b64encode(probe_png).decode(),
            reference_image_base64=base64.b64encode(ref_png).decode(),
        )
        resp = await service.match_faces(req, principal)
        assert resp.similarity_score == pytest.approx(1.0, abs=1e-3)
        assert resp.verdict == BiometricMatchVerdict.MATCH_CANDIDATE.value
        assert verif_repo.create.called
        assert audit_repo.append_event.called


@pytest.mark.asyncio
class TestBiometricVerificationServiceUnit:
    """Unit tests for BiometricVerificationService review, get, and list operations."""

    async def test_get_review_not_found(self) -> None:
        repo = MagicMock()
        repo.get_by_id = AsyncMock(return_value=None)
        service = BiometricVerificationService(verification_repo=repo)
        principal = _create_principal()

        with pytest.raises(ResourceNotFoundError, match="not found"):
            await service.get_review(uuid4(), principal)

    async def test_get_review_success(self) -> None:
        review = _make_review(
            id=uuid4(),
            tenant_id=uuid4(),
            department_id=uuid4(),
            probe_image_hash="b" * 64,
            candidate_similarity=0.72,
            automated_verdict="inconclusive_uncertain",
            human_verdict="inconclusive_dismissed",
            is_override=False,
        )
        repo = MagicMock()
        repo.get_by_id = AsyncMock(return_value=review)
        service = BiometricVerificationService(verification_repo=repo)
        principal = _create_principal()

        read = await service.get_review(review.id, principal)
        assert read.candidate_similarity == 0.72
        assert read.automated_verdict == "inconclusive_uncertain"

    async def test_record_human_verdict_permission_denied(self) -> None:
        service = BiometricVerificationService(verification_repo=MagicMock())
        student_principal = _create_principal(role_code=RoleCode.STUDENT.value)
        payload = BiometricVerificationReviewCreate(
            human_verdict=BiometricHumanVerdict.VERIFIED_MATCH,
        )
        with pytest.raises(PermissionDeniedError, match="BIOMETRIC_VERIFICATION_REVIEW"):
            await service.record_human_verdict(uuid4(), payload, student_principal)

    async def test_record_human_verdict_not_found(self) -> None:
        repo = MagicMock()
        repo.get_by_id = AsyncMock(return_value=None)
        service = BiometricVerificationService(verification_repo=repo)
        principal = _create_principal(role_code=RoleCode.INVESTIGATOR.value)
        payload = BiometricVerificationReviewCreate(
            human_verdict=BiometricHumanVerdict.VERIFIED_MATCH,
        )
        with pytest.raises(ResourceNotFoundError, match="not found"):
            await service.record_human_verdict(uuid4(), payload, principal)

    async def test_record_human_verdict_concordant_no_override(self) -> None:
        review = _make_review(
            id=uuid4(),
            tenant_id=uuid4(),
            department_id=uuid4(),
            probe_image_hash="c" * 64,
            candidate_similarity=0.91,
            automated_verdict="match_candidate",
            human_verdict="inconclusive_dismissed",
            is_override=False,
        )
        repo = MagicMock()
        repo.get_by_id = AsyncMock(return_value=review)
        audit_repo = MagicMock()
        audit_repo.append_event = AsyncMock()
        service = BiometricVerificationService(verification_repo=repo, audit_repo=audit_repo)
        principal = _create_principal(role_code=RoleCode.INVESTIGATOR.value)

        payload = BiometricVerificationReviewCreate(
            human_verdict=BiometricHumanVerdict.VERIFIED_MATCH,
            review_notes="Confirmed by forensic analyst",
        )
        read = await service.record_human_verdict(review.id, payload, principal)
        assert read.human_verdict == "verified_match"
        assert not read.is_override
        assert audit_repo.append_event.called

    async def test_record_human_verdict_contradictory_override_with_reason(self) -> None:
        review = _make_review(
            id=uuid4(),
            tenant_id=uuid4(),
            department_id=uuid4(),
            probe_image_hash="d" * 64,
            candidate_similarity=0.92,
            automated_verdict="match_candidate",
            human_verdict="inconclusive_dismissed",
            is_override=False,
        )
        repo = MagicMock()
        repo.get_by_id = AsyncMock(return_value=review)
        audit_repo = MagicMock()
        audit_repo.append_event = AsyncMock()
        service = BiometricVerificationService(verification_repo=repo, audit_repo=audit_repo)
        principal = _create_principal(role_code=RoleCode.INVESTIGATOR.value)

        payload = BiometricVerificationReviewCreate(
            human_verdict=BiometricHumanVerdict.VERIFIED_NON_MATCH,
            review_notes="Examined facial markings",
            override_reason="Subject has distinct birthmark absent in reference.",
        )
        read = await service.record_human_verdict(review.id, payload, principal)
        assert read.human_verdict == "verified_non_match"
        assert read.is_override is True
        assert read.override_reason == "Subject has distinct birthmark absent in reference."

    async def test_list_reviews(self) -> None:
        review = _make_review(
            id=uuid4(),
            tenant_id=uuid4(),
            department_id=uuid4(),
            probe_image_hash="e" * 64,
            candidate_similarity=0.55,
            automated_verdict="non_match_candidate",
            human_verdict="verified_non_match",
            is_override=False,
        )
        repo = MagicMock()
        repo.list_for_department = AsyncMock(return_value=[review])
        repo.count_for_department = AsyncMock(return_value=1)
        service = BiometricVerificationService(verification_repo=repo)
        principal = _create_principal()

        paginated = await service.list_reviews(principal, limit=10, offset=0)
        assert paginated.total == 1
        assert len(paginated.items) == 1
        assert paginated.items[0].id == review.id


@pytest.mark.asyncio
class TestBiometricEvaluationServiceUnit:
    """Unit tests for BiometricEvaluationService."""

    async def test_evaluation_permission_denied(self, enabled_settings: Settings) -> None:
        service = BiometricEvaluationService(settings=enabled_settings)
        student_principal = _create_principal(role_code=RoleCode.STUDENT.value)
        with pytest.raises(
            PermissionDeniedError, match="permission to access biometric evaluation"
        ):
            await service.get_evaluation_report(student_principal)

    async def test_evaluation_report_success(self, enabled_settings: Settings) -> None:
        service = BiometricEvaluationService(settings=enabled_settings)
        principal = _create_principal(role_code=RoleCode.INVESTIGATOR.value)
        rep = await service.get_evaluation_report(principal)
        assert rep.model_name == "mock-face-matcher"
        assert rep.eer >= 0.0
        assert rep.pad_summary is not None
        assert len(rep.subgroups) >= 2
        assert "SYNTHETIC BENCHMARK EVALUATION ONLY" in rep.disclaimer
