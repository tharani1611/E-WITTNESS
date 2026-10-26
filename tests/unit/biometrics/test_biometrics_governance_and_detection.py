"""Unit tests for Biometric Privacy, Governance, Reference Registry, and Face Detection (Phases 71-75).

Verifies:
- Phase 71: 8-point biometric readiness checklist evaluation and fail-closed NO-GO gating.
- Phase 72: Permitted use case validation, prohibited purpose rejection, and audit action definitions.
- Phase 73: Biometric governance lifecycle, notice/consent recording, and cascading reference revocation.
- Phase 74: Restricted reference registry, SHA-256 digest computation, template encryption at rest,
            and zero-leakage read DTO contracts.
- Phase 75: Approved face-detection protocol, fail-closed disabled provider, pure-Python image header
            and dimension inspector (PNG, JPEG, WebP), and disclaimer enforcement.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from ai_services.face_detection.detector import (
    MAX_IMAGE_BYTES,
    DisabledFaceDetectorProvider,
    LocalFaceDetectorProvider,
    MockFaceDetectorProvider,
    get_face_detector,
    inspect_image_dimensions_and_format,
)
from ai_services.face_detection.protocol import (
    DetectedFace,
    FaceDetectionOptions,
)
from backend.app.config.settings import Settings
from backend.app.core.biometrics import (
    BIOMETRIC_ADVISORY_DISCLAIMER,
    MANDATORY_READINESS_CHECKLIST_ITEMS,
    BiometricLawfulBasis,
    BiometricPurpose,
    BiometricReadinessState,
    BiometricReferenceStatus,
    ConsentStatus,
    GovernanceStatus,
    ProhibitedBiometricPurpose,
    compute_template_sha256,
    evaluate_biometric_readiness_checklist,
    validate_biometric_purpose,
)
from backend.app.core.exceptions import (
    BiometricGovernanceError,
    BiometricsDisabledError,
    ModelUnavailableError,
    PayloadTooLargeError,
    PermissionDeniedError,
    ResourceNotFoundError,
    UnsupportedMediaTypeError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.biometrics import BiometricGovernanceRecord, BiometricReference
from backend.app.repositories.biometrics import (
    BiometricGovernanceRepository,
    BiometricReferenceRepository,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.biometrics import (
    BiometricConsentWithdrawRequest,
    BiometricGovernanceCreate,
    BiometricGovernanceReviewRequest,
    BiometricReferenceCreate,
    BiometricReferenceRead,
    BiometricReferenceRevokeRequest,
    FaceDetectionResponse,
)
from backend.app.services.biometrics import (
    BiometricGovernanceService,
    BiometricReferenceService,
    FaceDetectionService,
)

# ---------------------------------------------------------------------------
# Synthetic Image Generators (Pure Python, No 3rd Party Packages)
# ---------------------------------------------------------------------------


def _create_minimal_png_bytes(width: int = 64, height: int = 64) -> bytes:
    """Synthesize a valid minimal PNG byte stream with IHDR chunk."""
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_length = struct.pack(">I", len(ihdr_data))
    ihdr_type = b"IHDR"
    ihdr_crc = struct.pack(">I", 0x12345678)
    return signature + ihdr_length + ihdr_type + ihdr_data + ihdr_crc


def _create_minimal_jpeg_bytes(width: int = 80, height: int = 60, marker: bytes = b"\xc0") -> bytes:
    """Synthesize a valid minimal JPEG byte stream with SOI and SOF0/SOF2 marker."""
    soi = b"\xff\xd8"
    sof_marker = b"\xff" + marker
    sof_length = struct.pack(">H", 11)
    sof_data = b"\x08" + struct.pack(">HH", height, width) + b"\x01\x01\x11"
    eoi = b"\xff\xd9"
    return soi + sof_marker + sof_length + sof_data + eoi


def _create_minimal_webp_vp8_bytes(width: int = 120, height: int = 90) -> bytes:
    """Synthesize a valid minimal lossy WebP VP8 byte stream."""
    riff_header = b"RIFF"
    file_size = struct.pack("<I", 36)
    webp_sig = b"WEBP"
    vp8_fourcc = b"VP8 "
    chunk_size = struct.pack("<I", 14)
    keyframe = b"\x00\x00\x00\x9d\x01\x2a"
    dim_data = struct.pack("<HH", width & 0x3FFF, height & 0x3FFF)
    return riff_header + file_size + webp_sig + vp8_fourcc + chunk_size + keyframe + dim_data


def _create_minimal_webp_vp8l_bytes(width: int = 100, height: int = 80) -> bytes:
    """Synthesize a valid minimal lossless WebP VP8L byte stream."""
    riff_header = b"RIFF"
    file_size = struct.pack("<I", 36)
    webp_sig = b"WEBP"
    vp8l_fourcc = b"VP8L"
    chunk_size = struct.pack("<I", 14)
    signature = b"\x2f"
    packed_dims = (width - 1) | ((height - 1) << 14)
    dim_bytes = struct.pack("<I", packed_dims)
    return (
        riff_header
        + file_size
        + webp_sig
        + vp8l_fourcc
        + chunk_size
        + signature
        + dim_bytes
        + b"\x00" * 9
    )


def _create_minimal_webp_vp8x_bytes(width: int = 200, height: int = 150) -> bytes:
    """Synthesize a valid minimal extended WebP VP8X byte stream."""
    riff_header = b"RIFF"
    file_size = struct.pack("<I", 38)
    webp_sig = b"WEBP"
    vp8x_fourcc = b"VP8X"
    chunk_size = struct.pack("<I", 18)
    flags = b"\x00\x00\x00\x00"
    width_bytes = (width - 1).to_bytes(3, "little")
    height_bytes = (height - 1).to_bytes(3, "little")
    return (
        riff_header
        + file_size
        + webp_sig
        + vp8x_fourcc
        + chunk_size
        + flags
        + width_bytes
        + height_bytes
        + b"\x00" * 8
    )


def _make_test_settings(**kwargs: Any) -> Settings:
    """Create isolated Settings instance for unit tests."""
    defaults: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "REDIS_URL": "redis://localhost:6379/15",
        "STORAGE_ENDPOINT_URL": "https://s3.test.internal:9000",
        "STORAGE_BUCKET_NAME": "ewitness-test-bucket",
        "STORAGE_ACCESS_KEY": "test_access_key_isolated",
        "STORAGE_SECRET_KEY": "test_secret_key_isolated_value",
        "AUTH_SECRET_KEY": "test_only_signing_key_with_sufficient_length_32_plus",
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_test_principal(
    user_id: UUID | None = None,
    role_code: str = RoleCode.DEPT_ADMIN.value,
    department_id: UUID | None = None,
    email: str = "test@ewitness.edu",
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email=email,
        full_name="Test Principal",
        account_status="active",
        is_active=True,
        role_code=role_code,
        department_id=department_id,
        session_id=uuid4(),
    )


# ---------------------------------------------------------------------------
# Phase 71 Tests: Privacy & Legal Feasibility Assessment
# ---------------------------------------------------------------------------


class TestPhase71PrivacyAndLegalFeasibility:
    """Unit tests for Phase 71 readiness checklist and fail-closed NO-GO evaluation."""

    def test_readiness_checklist_full_compliance(self) -> None:
        """When all 8 mandatory checklist items are verified, state is GO."""
        checklist = dict.fromkeys(MANDATORY_READINESS_CHECKLIST_ITEMS, True)
        state, missing = evaluate_biometric_readiness_checklist(checklist)

        assert state == BiometricReadinessState.GO
        assert len(missing) == 0

    def test_readiness_checklist_missing_single_item_fails_closed(self) -> None:
        """If even one item is unverified or missing, state is NO_GO and deployment is gated."""
        checklist = dict.fromkeys(MANDATORY_READINESS_CHECKLIST_ITEMS, True)
        checklist["production_matching_lock"] = False

        state, missing = evaluate_biometric_readiness_checklist(checklist)

        assert state == BiometricReadinessState.NO_GO
        assert "production_matching_lock" in missing
        assert len(missing) == 1

    def test_readiness_checklist_empty_is_not_ready(self) -> None:
        """An empty or unverified checklist must fail closed."""
        state, missing = evaluate_biometric_readiness_checklist({})

        assert state == BiometricReadinessState.NO_GO
        assert len(missing) == 8


# ---------------------------------------------------------------------------
# Phase 72 Tests: Permitted Use Cases, Prohibitions, and Authorization
# ---------------------------------------------------------------------------


class TestPhase72PermittedUseCasesAndProhibitions:
    """Unit tests for Phase 72 purpose validation and prohibited purpose blocking."""

    @pytest.mark.parametrize(
        "purpose",
        [
            BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
            BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW,
            BiometricPurpose.PRIVACY_REDACTION_BLURRING,
            BiometricPurpose.TESTING_SYNTHETIC_BENCHMARK,
            "explicit_consent_reference_enrollment",
            "authorized_investigative_manual_review",
            "privacy_redaction_blurring",
            "testing_synthetic_benchmark",
        ],
    )
    def test_permitted_purposes_accepted(self, purpose: str | BiometricPurpose) -> None:
        """Explicitly permitted biometric purposes must pass validation without raising."""
        val = purpose.value if isinstance(purpose, BiometricPurpose) else purpose
        validate_biometric_purpose(val)

    @pytest.mark.parametrize(
        "prohibited_purpose",
        [
            ProhibitedBiometricPurpose.MASS_SURVEILLANCE_CROWD_SCANNING,
            ProhibitedBiometricPurpose.AUTONOMOUS_PUNITIVE_DECISION,
            ProhibitedBiometricPurpose.EMOTION_OR_SENTIMENT_INFERENCE,
            ProhibitedBiometricPurpose.DEMOGRAPHIC_PROFILING,
            ProhibitedBiometricPurpose.COVERT_UNAUTHORIZED_TRACKING,
            "mass_surveillance_crowd_scanning",
            "autonomous_punitive_decision",
            "emotion_or_sentiment_inference",
            "demographic_profiling",
            "covert_unauthorized_tracking",
        ],
    )
    def test_prohibited_purposes_raise_governance_error(
        self, prohibited_purpose: str | ProhibitedBiometricPurpose
    ) -> None:
        """Statutorily prohibited biometric purposes must be rejected with ValueError."""
        val = (
            prohibited_purpose.value
            if isinstance(prohibited_purpose, ProhibitedBiometricPurpose)
            else prohibited_purpose
        )
        with pytest.raises(ValueError) as exc_info:
            validate_biometric_purpose(val)
        assert "prohibited" in str(exc_info.value).lower()

    def test_unrecognized_purpose_raises_governance_error(self) -> None:
        """Arbitrary or unapproved purposes outside the schema must be rejected."""
        with pytest.raises(ValueError) as exc_info:
            validate_biometric_purpose("unapproved_commercial_resale")
        assert "invalid biometric purpose" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Phase 73 & 74 Tests: Governance Lifecycle, Registry, and Cryptographic Invariants
# ---------------------------------------------------------------------------


class TestPhase73And74GovernanceAndRegistry:
    """Unit tests for Phase 73 governance lifecycle and Phase 74 restricted registry."""

    def test_compute_template_sha256(self) -> None:
        """SHA-256 digest computation must match deterministic hash of raw template bytes."""
        payload = b"synthetic_biometric_embedding_vector_128d"
        expected_hash = hashlib.sha256(payload).hexdigest()

        computed = compute_template_sha256(payload)
        assert computed == expected_hash
        assert len(computed) == 64

    def test_compute_template_sha256_empty_bytes_raises_error(self) -> None:
        """Empty template bytes must raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            compute_template_sha256(b"")
        assert "cannot be empty" in str(exc_info.value)

    def test_biometric_reference_read_dto_zero_template_leakage(self) -> None:
        """BiometricReferenceRead DTO must never define or expose template payload attributes."""
        fields = BiometricReferenceRead.model_fields.keys()
        assert "template_payload" not in fields
        assert "template_payload_encrypted" not in fields
        assert "encrypted_template" not in fields
        assert "embedding" not in fields
        assert "vector" not in fields

        assert "id" in fields
        assert "template_digest" in fields
        assert "status" in fields
        assert "governance_record_id" in fields

    def test_biometric_governance_create_validation(self) -> None:
        """BiometricGovernanceCreate must validate lawful basis and require notice version."""
        subject_id = uuid4()
        payload = BiometricGovernanceCreate(
            subject_user_id=subject_id,
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT,
            notice_version="2026.1",
            retention_days=30,
        )
        assert payload.subject_user_id == subject_id
        assert payload.purpose == BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT
        assert payload.lawful_basis == BiometricLawfulBasis.EXPLICIT_CONSENT
        assert payload.retention_days == 30

    @pytest.mark.asyncio
    async def test_governance_service_create_and_validation_branches(self) -> None:
        """Test authorization, consent verification, and non-consent bases in create_governance_record."""
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()

        service = BiometricGovernanceService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        user_id = uuid4()

        # 1. Caller unauthorized (student trying to register someone else's record)
        student_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )
        other_user = uuid4()
        bad_req = BiometricGovernanceCreate(
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT,
            subject_user_id=other_user,
            consent_confirmed=True,
        )
        with pytest.raises(PermissionDeniedError):
            await service.create_governance_record(bad_req, student_principal)

        # 2. Explicit consent missing affirmative confirmation
        admin_principal = _make_test_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )
        missing_consent_req = BiometricGovernanceCreate(
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT,
            subject_user_id=user_id,
            consent_confirmed=False,
        )
        with pytest.raises(BiometricGovernanceError) as exc:
            await service.create_governance_record(missing_consent_req, admin_principal)
        assert "affirmative" in str(exc.value).lower()

        # 3. Explicit consent missing subject_user_id
        no_subject_req = BiometricGovernanceCreate(
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT,
            subject_user_id=None,
            consent_confirmed=True,
        )
        with pytest.raises(BiometricGovernanceError) as exc:
            await service.create_governance_record(no_subject_req, admin_principal)
        assert "subject_user_id" in str(exc.value).lower()

        # 4. Non-consent lawful basis (e.g. SUBSTANTIAL_PUBLIC_INTEREST)
        public_interest_req = BiometricGovernanceCreate(
            purpose=BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW,
            lawful_basis=BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST,
            retention_days=45,
        )
        mock_created = MagicMock(spec=BiometricGovernanceRecord)
        mock_created.id = uuid4()
        mock_created.tenant_id = dept_id
        mock_created.department_id = dept_id
        mock_created.policy_version = "1.0.0"
        mock_created.purpose = BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value
        mock_created.lawful_basis = BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST.value
        mock_created.notice_version = "1.0.0"
        mock_created.subject_user_id = None
        mock_created.status = GovernanceStatus.PENDING_LEGAL_REVIEW.value
        mock_created.consent_status = None
        mock_created.consented_at = None
        mock_created.withdrawn_at = None
        mock_created.approved_by_id = None
        mock_created.approved_at = None
        mock_created.legal_review_notes = None
        mock_created.retention_days = 45
        mock_created.retention_expires_at = datetime.now(UTC) + timedelta(days=45)
        mock_created.created_at = datetime.now(UTC)
        mock_created.updated_at = datetime.now(UTC)

        gov_repo.create.return_value = mock_created
        res = await service.create_governance_record(public_interest_req, admin_principal)
        assert res.purpose == BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value
        assert audit_repo.append_event.call_count >= 1

    @pytest.mark.asyncio
    async def test_governance_service_list_and_get(self) -> None:
        """Verify list_governance_records and get_governance_record logic."""
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()

        service = BiometricGovernanceService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        admin_principal = _make_test_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )
        super_principal = _make_test_principal(
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
        )

        gov_repo.list_for_department.return_value = []
        gov_repo.count_for_department.return_value = 0

        # List for dept admin
        res_dept = await service.list_governance_records(admin_principal, status="approved")
        assert res_dept.total == 0

        # List for super admin
        res_super = await service.list_governance_records(super_principal)
        assert res_super.total == 0

        # Get not found
        gov_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.get_governance_record(uuid4(), admin_principal)

    @pytest.mark.asyncio
    async def test_governance_service_review_record(self) -> None:
        """Verify review_governance_record updates status and records audit event."""
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()

        service = BiometricGovernanceService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        record_id = uuid4()
        admin_principal = _make_test_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )

        # 1. Record not found
        gov_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.review_governance_record(
                record_id,
                BiometricGovernanceReviewRequest(
                    decision="approved", legal_review_notes="Notes here"
                ),
                admin_principal,
            )

        # 2. Valid review approval
        now = datetime.now(UTC)
        record = BiometricGovernanceRecord(
            id=record_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
            lawful_basis=BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST.value,
            notice_version="1.0.0",
            status=GovernanceStatus.PENDING_LEGAL_REVIEW.value,
            consent_status=None,
            retention_days=60,
            retention_expires_at=now + timedelta(days=60),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = record

        updated = await service.review_governance_record(
            record_id,
            BiometricGovernanceReviewRequest(
                decision="approved", legal_review_notes="Counsel approval confirmed"
            ),
            admin_principal,
        )
        assert updated.status == GovernanceStatus.APPROVED.value
        assert record.approved_by_id == admin_principal.user_id
        assert audit_repo.append_event.call_count >= 1

    @pytest.mark.asyncio
    async def test_reference_service_list_and_get(self) -> None:
        """Verify list_references, get_reference, and self-service checks."""
        ref_repo = AsyncMock()
        gov_repo = AsyncMock()
        audit_repo = AsyncMock()

        service = BiometricReferenceService(
            reference_repo=ref_repo,
            governance_repo=gov_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        user_id = uuid4()
        admin_principal = _make_test_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )
        student_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        ref_repo.list_for_department.return_value = []
        ref_repo.count_for_department.return_value = 0

        # List references
        res = await service.list_references(admin_principal)
        assert res.total == 0

        # Get not found
        ref_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.get_reference(uuid4(), admin_principal)

        # Get own reference as student
        ref_id = uuid4()
        now = datetime.now(UTC)
        ref_record = BiometricReference(
            id=ref_id,
            reference_id="REF-BIO-001",
            tenant_id=dept_id,
            department_id=dept_id,
            subject_user_id=user_id,
            governance_record_id=uuid4(),
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            status=BiometricReferenceStatus.ACTIVE.value,
            template_digest="a" * 64,
            enrolled_by_id=user_id,
            enrolled_at=now,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        ref_repo.get_by_id.return_value = ref_record

        read_dto = await service.get_reference(ref_id, student_principal)
        assert read_dto.id == ref_id
        assert read_dto.subject_user_id == user_id

        # Student unauthorized to view other student's reference
        other_student = _make_test_principal(
            user_id=uuid4(),
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )
        with pytest.raises(PermissionDeniedError):
            await service.get_reference(ref_id, other_student)

    @pytest.mark.asyncio
    async def test_reference_service_revoke_lifecycle(self) -> None:
        """Verify revoke_reference idempotency, permission enforcement, and template wiping."""
        ref_repo = AsyncMock()
        gov_repo = AsyncMock()
        audit_repo = AsyncMock()

        service = BiometricReferenceService(
            reference_repo=ref_repo,
            governance_repo=gov_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        user_id = uuid4()
        admin_principal = _make_test_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )
        ref_id = uuid4()
        now = datetime.now(UTC)

        ref_record = BiometricReference(
            id=ref_id,
            reference_id="REF-BIO-001",
            tenant_id=dept_id,
            department_id=dept_id,
            subject_user_id=user_id,
            governance_record_id=uuid4(),
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            status=BiometricReferenceStatus.ACTIVE.value,
            template_digest="a" * 64,
            encrypted_template="encrypted_blob",
            enrolled_by_id=admin_principal.user_id,
            enrolled_at=now,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        ref_repo.get_by_id.return_value = ref_record

        # 1. Unauthorized caller
        other_user = _make_test_principal(
            user_id=uuid4(),
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )
        with pytest.raises(PermissionDeniedError):
            await service.revoke_reference(
                ref_id,
                BiometricReferenceRevokeRequest(reason="Unauthorized attempt"),
                other_user,
            )

        # 2. Authorized revocation by admin
        res = await service.revoke_reference(
            ref_id,
            BiometricReferenceRevokeRequest(reason="Routine administrative rotation"),
            admin_principal,
        )
        assert res.status == BiometricReferenceStatus.REVOKED.value
        assert ref_record.encrypted_template is None
        assert audit_repo.append_event.call_count >= 1

        # 3. Idempotent return on already revoked reference
        res2 = await service.revoke_reference(
            ref_id,
            BiometricReferenceRevokeRequest(reason="Second attempt"),
            admin_principal,
        )
        assert res2.status == BiometricReferenceStatus.REVOKED.value

    @pytest.mark.asyncio
    async def test_reference_enrollment_under_unapproved_governance_raises_error(self) -> None:
        """Enrolling a reference under a PENDING or WITHDRAWN governance record must fail."""
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()

        unapproved_record = MagicMock(spec=BiometricGovernanceRecord)
        unapproved_record.id = uuid4()
        unapproved_record.department_id = uuid4()
        unapproved_record.status = GovernanceStatus.PENDING_LEGAL_REVIEW.value
        unapproved_record.consent_status = ConsentStatus.ACTIVE.value
        gov_repo.get_by_id.return_value = unapproved_record

        service = BiometricReferenceService(
            reference_repo=ref_repo,
            governance_repo=gov_repo,
            audit_repo=audit_repo,
        )

        principal = _make_test_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=unapproved_record.department_id,
        )

        create_dto = BiometricReferenceCreate(
            governance_record_id=unapproved_record.id,
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
            template_digest="a" * 64,
            encrypted_template="encrypted_base64_blob",
        )

        with pytest.raises(BiometricGovernanceError) as exc_info:
            await service.enroll_reference(create_dto, principal)

        assert "unapproved" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_cascading_revocation_on_consent_withdrawal(self) -> None:
        """Withdrawing consent must mark governance record REVOKED and cascade revocation to active references."""
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()

        dept_id = uuid4()
        gov_id = uuid4()
        subj_id = uuid4()

        now = datetime.now(UTC)
        record = BiometricGovernanceRecord(
            id=gov_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            subject_user_id=subj_id,
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.ACTIVE.value,
            consented_at=now - timedelta(days=1),
            withdrawn_at=None,
            approved_by_id=uuid4(),
            approved_at=now - timedelta(days=1),
            legal_review_notes="Approved for research",
            retention_days=90,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        gov_repo.get_by_id.return_value = record

        # Mock active references to cascade revoke
        active_ref1 = MagicMock(spec=BiometricReference)
        active_ref1.id = uuid4()
        active_ref1.department_id = dept_id
        active_ref1.reference_id = "REF-BIO-001"
        active_ref1.status = BiometricReferenceStatus.ACTIVE.value
        active_ref1.encrypted_template = "sensitive_data_1"

        active_ref2 = MagicMock(spec=BiometricReference)
        active_ref2.id = uuid4()
        active_ref2.department_id = dept_id
        active_ref2.reference_id = "REF-BIO-002"
        active_ref2.status = BiometricReferenceStatus.ACTIVE.value
        active_ref2.encrypted_template = "sensitive_data_2"

        ref_repo.list_active_by_governance_record.return_value = [active_ref1, active_ref2]

        gov_service = BiometricGovernanceService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            audit_repo=audit_repo,
        )

        principal = _make_test_principal(
            user_id=subj_id,
            email="student@ewitness.edu",
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )

        withdraw_req = BiometricConsentWithdrawRequest(
            reason="Student exercised right to be forgotten"
        )
        await gov_service.withdraw_consent(gov_id, withdraw_req, principal)

        assert record.status == GovernanceStatus.REVOKED.value
        assert record.consent_status == ConsentStatus.WITHDRAWN.value

        # Verify cascading reference revocation and template wiping
        assert active_ref1.status == BiometricReferenceStatus.REVOKED.value
        assert active_ref1.encrypted_template is None
        assert active_ref2.status == BiometricReferenceStatus.REVOKED.value
        assert active_ref2.encrypted_template is None

        # Verify audit calls were emitted for references and consent
        assert audit_repo.append_event.call_count >= 3


# ---------------------------------------------------------------------------
# Phase 75 Tests: Approved Face Detection Component & Image Inspection
# ---------------------------------------------------------------------------


class TestPhase75ApprovedFaceDetection:
    """Unit tests for Phase 75 face detection protocols, image inspection, and providers."""

    def test_inspect_valid_png_dimensions(self) -> None:
        """Valid PNG byte stream must correctly extract width, height, and format."""
        png_bytes = _create_minimal_png_bytes(width=320, height=240)
        width, height, fmt = inspect_image_dimensions_and_format(png_bytes)

        assert width == 320
        assert height == 240
        assert fmt == "png"

    def test_inspect_valid_jpeg_dimensions(self) -> None:
        """Valid JPEG byte stream with SOF0/SOF2 marker must correctly extract dimensions."""
        jpeg_bytes = _create_minimal_jpeg_bytes(width=80, height=60, marker=b"\xc0")
        width, height, fmt = inspect_image_dimensions_and_format(jpeg_bytes)

        assert width == 80
        assert height == 60
        assert fmt == "jpeg"

        # Progressive JPEG with SOF2 marker
        jpeg_prog = _create_minimal_jpeg_bytes(width=160, height=120, marker=b"\xc2")
        w_prog, h_prog, fmt_prog = inspect_image_dimensions_and_format(jpeg_prog)
        assert w_prog == 160
        assert h_prog == 120
        assert fmt_prog == "jpeg"

    def test_inspect_valid_webp_dimensions(self) -> None:
        """Valid WebP VP8, VP8L, and VP8X byte streams must correctly extract dimensions."""
        # Lossy VP8
        webp_vp8 = _create_minimal_webp_vp8_bytes(width=120, height=90)
        w, h, fmt = inspect_image_dimensions_and_format(webp_vp8)
        assert w == 120
        assert h == 90
        assert fmt == "webp"

        # Lossless VP8L
        webp_vp8l = _create_minimal_webp_vp8l_bytes(width=100, height=80)
        w_l, h_l, fmt_l = inspect_image_dimensions_and_format(webp_vp8l)
        assert w_l == 100
        assert h_l == 80
        assert fmt_l == "webp"

        # Extended VP8X
        webp_vp8x = _create_minimal_webp_vp8x_bytes(width=200, height=150)
        w_x, h_x, fmt_x = inspect_image_dimensions_and_format(webp_vp8x)
        assert w_x == 200
        assert h_x == 150
        assert fmt_x == "webp"

    def test_inspect_unsupported_or_corrupted_header_raises_error(self) -> None:
        """Arbitrary non-image bytes must raise UnsupportedMediaTypeError."""
        corrupted = b"NOT_AN_IMAGE_FILE_HEADER_XYZ1234567890"
        with pytest.raises(UnsupportedMediaTypeError) as exc_info:
            inspect_image_dimensions_and_format(corrupted)
        assert "unsupported" in str(exc_info.value).lower()

    def test_inspect_image_exceeds_max_bytes_raises_value_error(self) -> None:
        """Images exceeding max byte limit or empty must raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            inspect_image_dimensions_and_format(b"")
        assert "cannot be empty" in str(exc_info.value).lower()

        large_payload = b"\x00" * (MAX_IMAGE_BYTES + 10)
        with pytest.raises(ValueError) as exc_info:
            inspect_image_dimensions_and_format(large_payload)
        assert "exceeds maximum permitted limit" in str(exc_info.value).lower()

    def test_face_detection_options_and_detected_face_validations(self) -> None:
        """Test invariant assertions on options and detected face bounding box coordinates."""
        # Options range checks
        with pytest.raises(ValueError):
            FaceDetectionOptions(confidence_threshold=1.5)
        with pytest.raises(ValueError):
            FaceDetectionOptions(max_faces=0)
        with pytest.raises(ValueError):
            FaceDetectionOptions(min_face_size_pixels=2)

        # Coordinate range checks
        with pytest.raises(ValueError):
            DetectedFace(bounding_box=(-0.1, 0.0, 0.5, 0.5), confidence=0.8)
        # ymin >= ymax
        with pytest.raises(ValueError):
            DetectedFace(bounding_box=(0.6, 0.2, 0.4, 0.8), confidence=0.8)
        # xmin >= xmax
        with pytest.raises(ValueError):
            DetectedFace(bounding_box=(0.1, 0.8, 0.5, 0.2), confidence=0.8)
        # confidence out of range
        with pytest.raises(ValueError):
            DetectedFace(bounding_box=(0.1, 0.1, 0.5, 0.5), confidence=1.2)

    def test_disabled_face_detector_provider_fails_closed(self) -> None:
        """DisabledFaceDetectorProvider must unconditionally raise BiometricsDisabledError."""
        provider = DisabledFaceDetectorProvider()
        png_bytes = _create_minimal_png_bytes(64, 64)

        with pytest.raises(BiometricsDisabledError) as exc_info:
            provider.detect_faces(png_bytes)

        assert "disabled" in str(exc_info.value).lower()
        assert exc_info.value.status_code == 403

    def test_mock_face_detector_provider_synthetic_output(self) -> None:
        """MockFaceDetectorProvider returns synthetic bounding boxes and disclaimer without external models."""
        provider = MockFaceDetectorProvider()
        png_bytes = _create_minimal_png_bytes(320, 240)
        options = FaceDetectionOptions(confidence_threshold=0.5, max_faces=5)

        result = provider.detect_faces(png_bytes, options)

        assert result.image_width == 320
        assert result.image_height == 240
        assert result.face_count >= 1
        assert len(result.detected_faces) == result.face_count
        assert BIOMETRIC_ADVISORY_DISCLAIMER in result.disclaimer

        for face in result.detected_faces:
            assert len(face.bounding_box) == 4
            ymin, xmin, ymax, xmax = face.bounding_box
            assert 0.0 <= ymin < ymax <= 1.0
            assert 0.0 <= xmin < xmax <= 1.0
            assert face.confidence >= 0.5

    def test_local_face_detector_provider_fails_closed_without_weights(self) -> None:
        """LocalFaceDetectorProvider fails closed with ModelUnavailableError to prevent network downloads."""
        provider = LocalFaceDetectorProvider()
        png_bytes = _create_minimal_png_bytes(64, 64)

        with pytest.raises(ModelUnavailableError) as exc_info:
            provider.detect_faces(png_bytes)

        assert "weights" in str(exc_info.value).lower()

    def test_get_face_detector_factory(self) -> None:
        """Factory function correctly instantiates provider corresponding to settings."""
        assert isinstance(
            get_face_detector(enabled=False, provider="disabled"),
            DisabledFaceDetectorProvider,
        )
        assert isinstance(
            get_face_detector(enabled=False, provider="mock"),
            DisabledFaceDetectorProvider,
        )
        assert isinstance(
            get_face_detector(enabled=True, provider="mock"),
            MockFaceDetectorProvider,
        )
        assert isinstance(
            get_face_detector(enabled=True, provider="local"),
            LocalFaceDetectorProvider,
        )

    @pytest.mark.asyncio
    async def test_face_detection_service_governance_and_permission_checks(self) -> None:
        """Verify FaceDetectionService permission gating, purpose verification, and fail-closed branches."""
        gov_repo = AsyncMock()
        audit_repo = AsyncMock()
        settings = _make_test_settings(
            BIOMETRIC_ANALYSIS_ENABLED=True,
            BIOMETRIC_DETECTION_ENABLED=True,
            BIOMETRIC_PROVIDER="mock",
        )
        service = FaceDetectionService(
            governance_repo=gov_repo,
            settings=settings,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        gov_id = uuid4()
        png_bytes = _create_minimal_png_bytes(100, 100)

        # 1. Caller lacks BIOMETRIC_DETECTION_EXECUTE
        student_principal = _make_test_principal(
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )
        with pytest.raises(PermissionDeniedError):
            await service.detect_faces(png_bytes, gov_id, student_principal)

        investigator_principal = _make_test_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
        )

        # 2. Disabled in settings
        disabled_service = FaceDetectionService(
            governance_repo=gov_repo,
            settings=_make_test_settings(
                BIOMETRIC_ANALYSIS_ENABLED=False,
                BIOMETRIC_DETECTION_ENABLED=False,
            ),
            audit_repo=audit_repo,
        )
        with pytest.raises(BiometricsDisabledError):
            await disabled_service.detect_faces(png_bytes, gov_id, investigator_principal)

        # 3. Governance record not found
        gov_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.detect_faces(png_bytes, gov_id, investigator_principal)

        # 4. Governance record not approved
        now = datetime.now(UTC)
        unapproved_record = BiometricGovernanceRecord(
            id=gov_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
            lawful_basis=BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST.value,
            notice_version="1.0.0",
            status=GovernanceStatus.PENDING_LEGAL_REVIEW.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = unapproved_record
        with pytest.raises(BiometricGovernanceError) as exc:
            await service.detect_faces(png_bytes, gov_id, investigator_principal)
        assert "requires an approved governance record" in str(exc.value).lower()

        # 5. Governance record purpose not permitted for detection
        wrong_purpose_record = BiometricGovernanceRecord(
            id=gov_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.ACTIVE.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = wrong_purpose_record
        with pytest.raises(BiometricGovernanceError) as exc:
            await service.detect_faces(png_bytes, gov_id, investigator_principal)
        assert "not authorized for face detection" in str(exc.value).lower()

        # 6. Governance record consent withdrawn
        withdrawn_record = BiometricGovernanceRecord(
            id=gov_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.WITHDRAWN.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = withdrawn_record
        with pytest.raises(BiometricGovernanceError) as exc:
            await service.detect_faces(png_bytes, gov_id, investigator_principal)
        assert "withdrawn" in str(exc.value).lower()

        # 7. Payload too large
        oversized_service = FaceDetectionService(
            governance_repo=gov_repo,
            settings=_make_test_settings(
                BIOMETRIC_ANALYSIS_ENABLED=True,
                BIOMETRIC_DETECTION_ENABLED=True,
                BIOMETRIC_MAX_IMAGE_SIZE_BYTES=1024,
            ),
            audit_repo=audit_repo,
        )
        with pytest.raises(PayloadTooLargeError):
            await oversized_service.detect_faces(b"\x00" * 2048, gov_id, investigator_principal)

        # 8. Successful execution
        approved_record = BiometricGovernanceRecord(
            id=gov_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
            lawful_basis=BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=None,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = approved_record

        resp = await service.detect_faces(png_bytes, gov_id, investigator_principal)
        assert isinstance(resp, FaceDetectionResponse)
        assert resp.face_count >= 1
        assert audit_repo.append_event.call_count >= 1


class TestBiometricsRepositoriesUnit:
    """Unit tests for BiometricGovernanceRepository and BiometricReferenceRepository."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.add = MagicMock()
        sess.flush = AsyncMock()
        return sess

    async def test_governance_repo_create_and_get(self, mock_session: AsyncMock) -> None:
        repo = BiometricGovernanceRepository(mock_session)
        rec_id = uuid4()
        dept_id = uuid4()
        record = BiometricGovernanceRecord(
            id=rec_id,
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.PRIVACY_REDACTION_BLURRING.value,
            lawful_basis=BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            retention_days=30,
            retention_expires_at=datetime.now(UTC) + timedelta(days=30),
        )

        created = await repo.create(record)
        assert created == record
        mock_session.add.assert_called_once_with(record)
        mock_session.flush.assert_awaited_once()

        # get_by_id with department_id
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = record
        mock_session.execute.return_value = mock_result
        fetched = await repo.get_by_id(rec_id, department_id=dept_id)
        assert fetched == record

        # get_by_id without department_id
        fetched_global = await repo.get_by_id(rec_id)
        assert fetched_global == record

    async def test_governance_repo_list_and_count(self, mock_session: AsyncMock) -> None:
        repo = BiometricGovernanceRepository(mock_session)
        dept_id = uuid4()

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        # list with department and status
        items = await repo.list_for_department(
            department_id=dept_id, status=GovernanceStatus.APPROVED.value, limit=10, offset=0
        )
        assert items == []

        # list without department and without status
        items_all = await repo.list_for_department(limit=10, offset=0)
        assert items_all == []

        # count with department and status
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 5
        mock_session.execute.return_value = mock_count_result

        cnt = await repo.count_for_department(
            department_id=dept_id, status=GovernanceStatus.APPROVED.value
        )
        assert cnt == 5

        # count without department and without status
        cnt_all = await repo.count_for_department()
        assert cnt_all == 5

    async def test_reference_repo_create_and_get(self, mock_session: AsyncMock) -> None:
        repo = BiometricReferenceRepository(mock_session)
        ref_id = uuid4()
        dept_id = uuid4()
        ref = BiometricReference(
            id=ref_id,
            reference_id="REF-BIO-TEST",
            tenant_id=dept_id,
            department_id=dept_id,
            governance_record_id=uuid4(),
            purpose=BiometricPurpose.PRIVACY_REDACTION_BLURRING.value,
            status=BiometricReferenceStatus.ACTIVE.value,
            template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            encrypted_template="enc_data",
            enrolled_by_id=uuid4(),
            enrolled_at=datetime.now(UTC),
            retention_expires_at=datetime.now(UTC) + timedelta(days=30),
        )

        created = await repo.create(ref)
        assert created == ref
        mock_session.add.assert_called_once_with(ref)
        mock_session.flush.assert_awaited_once()

        # get_by_id with department_id
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = ref
        mock_session.execute.return_value = mock_result
        fetched = await repo.get_by_id(ref_id, department_id=dept_id)
        assert fetched == ref

        # get_by_id without department_id
        fetched_global = await repo.get_by_id(ref_id)
        assert fetched_global == ref

        # get_by_opaque_id with and without department_id
        fetched_opaque = await repo.get_by_opaque_id("REF-BIO-TEST", department_id=dept_id)
        assert fetched_opaque == ref
        fetched_opaque_global = await repo.get_by_opaque_id("REF-BIO-TEST")
        assert fetched_opaque_global == ref

    async def test_reference_repo_list_and_count(self, mock_session: AsyncMock) -> None:
        repo = BiometricReferenceRepository(mock_session)
        dept_id = uuid4()
        gov_id = uuid4()

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        # list with department and status
        items = await repo.list_for_department(
            department_id=dept_id, status=BiometricReferenceStatus.ACTIVE.value, limit=10, offset=0
        )
        assert items == []

        # list without department and without status
        items_all = await repo.list_for_department(limit=10, offset=0)
        assert items_all == []

        # list_active_by_governance_record
        active_items = await repo.list_active_by_governance_record(gov_id)
        assert active_items == []

        # count with department and status
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 3
        mock_session.execute.return_value = mock_count_result

        cnt = await repo.count_for_department(
            department_id=dept_id, status=BiometricReferenceStatus.ACTIVE.value
        )
        assert cnt == 3

        # count without department and without status
        cnt_all = await repo.count_for_department()
        assert cnt_all == 3


class TestBiometricsServicesExhaustiveUnit:
    """Exhaustive edge-case and error branch tests for biometric services."""

    async def test_service_from_session_factories(self) -> None:
        mock_session = AsyncMock()
        settings = _make_test_settings()

        gov_service = BiometricGovernanceService.from_session(mock_session)
        assert isinstance(gov_service, BiometricGovernanceService)

        ref_service = BiometricReferenceService.from_session(mock_session)
        assert isinstance(ref_service, BiometricReferenceService)

        det_service = FaceDetectionService.from_session(mock_session, settings)
        assert isinstance(det_service, FaceDetectionService)

    async def test_governance_service_edge_cases(self) -> None:
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()
        service = BiometricGovernanceService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        user_id = uuid4()
        now = datetime.now(UTC)

        investigator_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
        )
        dept_admin_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )

        # 1. review_governance_record lacks permission
        with pytest.raises(PermissionDeniedError):
            await service.review_governance_record(
                uuid4(),
                BiometricGovernanceReviewRequest(
                    decision=GovernanceStatus.APPROVED.value,
                    legal_review_notes="Approved",
                ),
                investigator_principal,
            )

        # 2. review_governance_record not found
        gov_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.review_governance_record(
                uuid4(),
                BiometricGovernanceReviewRequest(
                    decision=GovernanceStatus.APPROVED.value,
                    legal_review_notes="Approved",
                ),
                dept_admin_principal,
            )

        # 3. withdraw_consent not found
        gov_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.withdraw_consent(
                uuid4(),
                BiometricConsentWithdrawRequest(reason="Subject requested"),
                investigator_principal,
            )

        # 4. withdraw_consent unauthorized caller (not subject and not reviewer)
        other_user_id = uuid4()
        record = BiometricGovernanceRecord(
            id=uuid4(),
            tenant_id=dept_id,
            department_id=dept_id,
            subject_user_id=other_user_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.ACTIVE.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = record
        with pytest.raises(PermissionDeniedError):
            await service.withdraw_consent(
                record.id,
                BiometricConsentWithdrawRequest(reason="Random person"),
                investigator_principal,
            )

        # 5. withdraw_consent already withdrawn (idempotent)
        withdrawn_rec = BiometricGovernanceRecord(
            id=uuid4(),
            tenant_id=dept_id,
            department_id=dept_id,
            subject_user_id=user_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.WITHDRAWN.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = withdrawn_rec
        res = await service.withdraw_consent(
            withdrawn_rec.id,
            BiometricConsentWithdrawRequest(reason="Already done"),
            investigator_principal,
        )
        assert res.consent_status == ConsentStatus.WITHDRAWN.value

        # 6. Service without audit_repo
        service_no_audit = BiometricGovernanceService(
            governance_repo=gov_repo,
            reference_repo=ref_repo,
            audit_repo=None,
        )
        gov_repo.create.return_value = record
        created_no_audit = await service_no_audit.create_governance_record(
            BiometricGovernanceCreate(
                policy_version="1.0.0",
                purpose=BiometricPurpose.PRIVACY_REDACTION_BLURRING,
                lawful_basis=BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST,
                notice_version="1.0.0",
                retention_days=30,
            ),
            dept_admin_principal,
        )
        assert created_no_audit.id == record.id

        # 7. Explicit consent creation with subject_user_id and confirmation
        gov_repo.create.return_value = record
        consent_created = await service.create_governance_record(
            BiometricGovernanceCreate(
                policy_version="1.0.0",
                purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT,
                notice_version="1.0.0",
                subject_user_id=user_id,
                consent_confirmed=True,
                retention_days=30,
            ),
            dept_admin_principal,
        )
        assert consent_created.id == record.id

        # 8. get_governance_record success
        gov_repo.get_by_id.return_value = record
        fetched_rec = await service.get_governance_record(record.id, dept_admin_principal)
        assert fetched_rec.id == record.id

    async def test_reference_service_edge_cases(self) -> None:
        gov_repo = AsyncMock()
        ref_repo = AsyncMock()
        audit_repo = AsyncMock()
        service = BiometricReferenceService(
            reference_repo=ref_repo,
            governance_repo=gov_repo,
            audit_repo=audit_repo,
        )

        dept_id = uuid4()
        user_id = uuid4()
        now = datetime.now(UTC)

        student_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
        )
        investigator_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
        )
        dept_admin_principal = _make_test_principal(
            user_id=user_id,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
        )

        # 0. investigator lacks reference management permission
        with pytest.raises(PermissionDeniedError):
            await service.enroll_reference(
                BiometricReferenceCreate(
                    subject_user_id=uuid4(),
                    governance_record_id=uuid4(),
                    purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                    template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    encrypted_template="encrypted_template_payload",
                ),
                investigator_principal,
            )

        # 1. enroll_reference: student cannot enroll reference for another user
        with pytest.raises(PermissionDeniedError):
            await service.enroll_reference(
                BiometricReferenceCreate(
                    subject_user_id=uuid4(),
                    governance_record_id=uuid4(),
                    purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                    template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    encrypted_template="encrypted_template_payload",
                ),
                student_principal,
            )

        # 2. enroll_reference: governance record not found
        gov_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.enroll_reference(
                BiometricReferenceCreate(
                    subject_user_id=user_id,
                    governance_record_id=uuid4(),
                    purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                    template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    encrypted_template="encrypted_template_payload",
                ),
                student_principal,
            )

        # 3. enroll_reference: governance record consent withdrawn
        withdrawn_gov = BiometricGovernanceRecord(
            id=uuid4(),
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.WITHDRAWN.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
        )
        gov_repo.get_by_id.return_value = withdrawn_gov
        with pytest.raises(BiometricGovernanceError) as exc:
            await service.enroll_reference(
                BiometricReferenceCreate(
                    subject_user_id=user_id,
                    governance_record_id=withdrawn_gov.id,
                    purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                    template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    encrypted_template="encrypted_template_payload",
                ),
                student_principal,
            )
        assert "withdrawn" in str(exc.value).lower()

        # 4. revoke_reference: not found
        ref_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.revoke_reference(
                uuid4(),
                BiometricReferenceRevokeRequest(reason="Revoke"),
                student_principal,
            )

        # 5. revoke_reference: student cannot revoke someone else's reference
        other_ref = BiometricReference(
            id=uuid4(),
            reference_id="REF-BIO-OTHER",
            tenant_id=dept_id,
            department_id=dept_id,
            subject_user_id=uuid4(),
            governance_record_id=uuid4(),
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            status=BiometricReferenceStatus.ACTIVE.value,
            template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            encrypted_template="enc_data",
            enrolled_by_id=uuid4(),
            enrolled_at=now,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        ref_repo.get_by_id.return_value = other_ref
        with pytest.raises(PermissionDeniedError):
            await service.revoke_reference(
                other_ref.id,
                BiometricReferenceRevokeRequest(reason="Not authorized"),
                student_principal,
            )

        # 6. revoke_reference: already revoked idempotent return
        already_revoked = BiometricReference(
            id=uuid4(),
            reference_id="REF-BIO-REVOKED",
            tenant_id=dept_id,
            department_id=dept_id,
            subject_user_id=user_id,
            governance_record_id=uuid4(),
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            status=BiometricReferenceStatus.REVOKED.value,
            template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            encrypted_template="enc_data",
            enrolled_by_id=user_id,
            enrolled_at=now,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        ref_repo.get_by_id.return_value = already_revoked
        rev_res = await service.revoke_reference(
            already_revoked.id,
            BiometricReferenceRevokeRequest(reason="Already revoked"),
            student_principal,
        )
        assert rev_res.status == BiometricReferenceStatus.REVOKED.value

        # 7. get_reference: not found
        ref_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.get_reference(uuid4(), student_principal)

        # 8. get_reference: student cannot view someone else's reference
        ref_repo.get_by_id.return_value = other_ref
        with pytest.raises(PermissionDeniedError):
            await service.get_reference(other_ref.id, student_principal)

        # 9. Service without audit_repo
        service_no_audit = BiometricReferenceService(
            reference_repo=ref_repo,
            governance_repo=gov_repo,
            audit_repo=None,
        )
        valid_gov = BiometricGovernanceRecord(
            id=uuid4(),
            tenant_id=dept_id,
            department_id=dept_id,
            policy_version="1.0.0",
            purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
            lawful_basis=BiometricLawfulBasis.EXPLICIT_CONSENT.value,
            notice_version="1.0.0",
            status=GovernanceStatus.APPROVED.value,
            consent_status=ConsentStatus.ACTIVE.value,
            retention_days=30,
            retention_expires_at=now + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        gov_repo.get_by_id.return_value = valid_gov
        ref_repo.create.return_value = other_ref
        ref_out = await service_no_audit.enroll_reference(
            BiometricReferenceCreate(
                subject_user_id=dept_admin_principal.user_id,
                governance_record_id=valid_gov.id,
                purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                encrypted_template="encrypted_payload",
            ),
            dept_admin_principal,
        )
        assert ref_out.id == other_ref.id

        # 10. Service with audit_repo enrollment event check
        enrolled_with_audit = await service.enroll_reference(
            BiometricReferenceCreate(
                subject_user_id=dept_admin_principal.user_id,
                governance_record_id=valid_gov.id,
                purpose=BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT,
                template_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                encrypted_template="encrypted_payload",
            ),
            dept_admin_principal,
        )
        assert enrolled_with_audit.id == other_ref.id
        assert audit_repo.append_event.called
