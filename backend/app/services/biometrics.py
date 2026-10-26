"""Domain services for Biometric Governance, Reference Registry, and Face Detection (Phases 71-75).

Enforces:
- Deny-by-default access control and department/tenant isolation.
- Pre-condition checks requiring affirmative governance and unrevoked consent.
- Complete cascading revocation upon consent withdrawal.
- Zero raw biometric data leakage into audit logs or API read responses.
- Fail-closed face detection execution under approved governance records only.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from ai_services.face_detection.detector import get_face_detector
from ai_services.face_matching.evaluation import (
    evaluate_biometric_matching_benchmark,
)
from ai_services.face_matching.protocol import FaceFeatureVector, get_face_matcher
from ai_services.face_matching.quality import assess_face_image_quality
from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_any_permission, has_permission
from backend.app.core.biometric_crypto import BiometricKeyManager, get_biometric_key_manager
from backend.app.core.biometrics import (
    BiometricHumanVerdict,
    BiometricMatchVerdict,
    BiometricPurpose,
    BiometricReferenceStatus,
    ConsentStatus,
    GovernanceStatus,
    validate_biometric_purpose,
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
from backend.app.models.biometrics import (
    BiometricGovernanceRecord,
    BiometricReference,
    BiometricVerificationReview,
)
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.biometrics import (
    BiometricGovernanceRepository,
    BiometricReferenceRepository,
    BiometricVerificationRepository,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.biometrics import (
    BiometricConsentWithdrawRequest,
    BiometricEvaluationSummaryRead,
    BiometricGovernanceCreate,
    BiometricGovernanceRead,
    BiometricGovernanceReviewRequest,
    BiometricReferenceCreate,
    BiometricReferenceRead,
    BiometricReferenceRevokeRequest,
    BiometricVerificationReviewCreate,
    BiometricVerificationReviewRead,
    DetectedFaceRead,
    FaceDetectionResponse,
    FaceMatchRequest,
    FaceMatchResponse,
    PaginatedBiometricGovernanceRead,
    PaginatedBiometricReferenceRead,
    PaginatedBiometricVerificationReviewRead,
)


class BiometricGovernanceService:
    """Service managing biometric processing feasibility, legal reviews, and consent."""

    def __init__(
        self,
        governance_repo: BiometricGovernanceRepository,
        reference_repo: BiometricReferenceRepository,
        audit_repo: AuditRepository | None = None,
    ) -> None:
        self.governance_repo = governance_repo
        self.reference_repo = reference_repo
        self.audit_repo = audit_repo

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings | None = None,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> BiometricGovernanceService:
        """Construct BiometricGovernanceService bound to session."""
        return cls(
            governance_repo=BiometricGovernanceRepository(session),
            reference_repo=BiometricReferenceRepository(session),
            audit_repo=audit_repo or AuditRepository(session),
        )

    async def create_governance_record(
        self,
        request: BiometricGovernanceCreate,
        principal: AuthenticatedPrincipal,
    ) -> BiometricGovernanceRead:
        """Create a new biometric governance assessment and consent record (Phase 73)."""
        validate_biometric_purpose(request.purpose.value)

        # Authorization: Dept admin or super admin, or self-service if own consent
        is_self = (
            request.subject_user_id is not None and request.subject_user_id == principal.user_id
        )
        can_manage = has_any_permission(
            principal.role,
            [Permission.BIOMETRIC_GOVERNANCE_REVIEW, Permission.BIOMETRIC_REFERENCE_MANAGE_DEPT],
        ) or (is_self and has_permission(principal.role, Permission.BIOMETRIC_REFERENCE_MANAGE_OWN))

        if not can_manage:
            raise PermissionDeniedError(
                "Caller lacks authorization to register biometric governance records.",
                code="BIOMETRIC_GOVERNANCE_DENIED",
            )

        # Enforce consent validation rules
        consent_status: str | None = None
        consented_at: datetime | None = None

        if request.lawful_basis.value == "explicit_consent":
            if not request.consent_confirmed:
                raise BiometricGovernanceError(
                    "Affirmative consent confirmation is required when lawful basis is 'explicit_consent'."
                )
            if not request.subject_user_id:
                raise BiometricGovernanceError(
                    "A subject_user_id is required when registering explicit consent."
                )
            consent_status = ConsentStatus.ACTIVE.value
            consented_at = datetime.now(UTC)

        now = datetime.now(UTC)
        expires_at = now + timedelta(days=request.retention_days)

        record = BiometricGovernanceRecord(
            tenant_id=principal.department_id,
            department_id=principal.department_id,
            policy_version=request.policy_version,
            purpose=request.purpose.value,
            lawful_basis=request.lawful_basis.value,
            notice_version=request.notice_version,
            subject_user_id=request.subject_user_id,
            status=GovernanceStatus.PENDING_LEGAL_REVIEW.value,
            consent_status=consent_status,
            consented_at=consented_at,
            retention_days=request.retention_days,
            retention_expires_at=expires_at,
            legal_review_notes=request.legal_review_notes,
        )

        persisted = await self.governance_repo.create(record)

        if self.audit_repo:
            action = (
                AuditAction.BIOMETRIC_CONSENT_GRANTED.value
                if consent_status == ConsentStatus.ACTIVE.value
                else AuditAction.BIOMETRIC_POLICY_EVALUATED.value
            )
            await self.audit_repo.append_event(
                action=action,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.BIOMETRIC_GOVERNANCE.value,
                target_id=str(persisted.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "purpose": persisted.purpose,
                    "lawful_basis": persisted.lawful_basis,
                    "status": persisted.status,
                    "consent_status": persisted.consent_status,
                },
            )

        return BiometricGovernanceRead.model_validate(persisted)

    async def review_governance_record(
        self,
        record_id: UUID,
        request: BiometricGovernanceReviewRequest,
        principal: AuthenticatedPrincipal,
    ) -> BiometricGovernanceRead:
        """Record formal legal or administrative review verdict for a governance record (Phase 71 & 73)."""
        if not has_permission(principal.role, Permission.BIOMETRIC_GOVERNANCE_REVIEW):
            raise PermissionDeniedError(
                "Caller lacks BIOMETRIC_GOVERNANCE_REVIEW permission.",
                code="BIOMETRIC_REVIEW_DENIED",
            )

        record = await self.governance_repo.get_by_id(
            record_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if record is None:
            raise ResourceNotFoundError(
                f"Biometric governance record '{record_id}' not found.",
                code="GOVERNANCE_RECORD_NOT_FOUND",
            )

        old_status = record.status
        record.status = request.decision
        record.approved_by_id = principal.user_id
        record.approved_at = datetime.now(UTC)
        record.legal_review_notes = request.legal_review_notes

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_POLICY_EVALUATED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=record.department_id,
                target_type=AuditTargetType.BIOMETRIC_GOVERNANCE.value,
                target_id=str(record.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "old_status": old_status,
                    "new_status": request.decision,
                    "decision": request.decision,
                },
            )

        return BiometricGovernanceRead.model_validate(record)

    async def withdraw_consent(
        self,
        record_id: UUID,
        request: BiometricConsentWithdrawRequest,
        principal: AuthenticatedPrincipal,
    ) -> BiometricGovernanceRead:
        """Handle consent withdrawal and propagate cascading revocation to references (Phase 73)."""
        record = await self.governance_repo.get_by_id(
            record_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if record is None:
            raise ResourceNotFoundError(
                f"Biometric governance record '{record_id}' not found.",
                code="GOVERNANCE_RECORD_NOT_FOUND",
            )

        is_subject = (
            record.subject_user_id is not None and record.subject_user_id == principal.user_id
        )
        can_withdraw = is_subject or has_permission(
            principal.role, Permission.BIOMETRIC_GOVERNANCE_REVIEW
        )
        if not can_withdraw:
            raise PermissionDeniedError(
                "Only the data subject or an authorized reviewer can withdraw biometric consent.",
                code="CONSENT_WITHDRAWAL_DENIED",
            )

        # Idempotent return if already withdrawn
        if record.consent_status == ConsentStatus.WITHDRAWN.value:
            return BiometricGovernanceRead.model_validate(record)

        now = datetime.now(UTC)
        record.consent_status = ConsentStatus.WITHDRAWN.value
        record.withdrawn_at = now
        record.status = GovernanceStatus.REVOKED.value

        # Cascade revocation to all active references tied to this governance authorization
        active_refs = await self.reference_repo.list_active_by_governance_record(record_id)
        for ref in active_refs:
            ref.status = BiometricReferenceStatus.REVOKED.value
            ref.revoked_by_id = principal.user_id
            ref.revoked_at = now
            ref.revocation_reason = (
                f"Consent withdrawn by subject: {request.reason or 'User requested'}"
            )
            ref.encrypted_template = None  # Securely wipe ciphertext

            if self.audit_repo:
                await self.audit_repo.append_event(
                    action=AuditAction.BIOMETRIC_REFERENCE_REVOKED.value,
                    actor_id=principal.user_id,
                    actor_role=principal.role_code,
                    department_id=ref.department_id,
                    target_type=AuditTargetType.BIOMETRIC_REFERENCE.value,
                    target_id=str(ref.id),
                    outcome=AuditOutcome.SUCCESS.value,
                    details={
                        "reference_id": ref.reference_id,
                        "reason": "Consent withdrawal cascade",
                        "governance_record_id": str(record.id),
                    },
                )

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_CONSENT_REVOKED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=record.department_id,
                target_type=AuditTargetType.BIOMETRIC_GOVERNANCE.value,
                target_id=str(record.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "reason": request.reason,
                    "revoked_references_count": len(active_refs),
                },
            )

        return BiometricGovernanceRead.model_validate(record)

    async def get_governance_record(
        self,
        record_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> BiometricGovernanceRead:
        """Retrieve single governance record with department isolation."""
        record = await self.governance_repo.get_by_id(
            record_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if record is None:
            raise ResourceNotFoundError(
                f"Biometric governance record '{record_id}' not found.",
                code="GOVERNANCE_RECORD_NOT_FOUND",
            )
        return BiometricGovernanceRead.model_validate(record)

    async def list_governance_records(
        self,
        principal: AuthenticatedPrincipal,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedBiometricGovernanceRead:
        """List governance records for authenticated department."""
        dept_id = principal.department_id
        items = await self.governance_repo.list_for_department(
            department_id=dept_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        total = await self.governance_repo.count_for_department(
            department_id=dept_id,
            status=status,
        )
        return PaginatedBiometricGovernanceRead(
            items=[BiometricGovernanceRead.model_validate(i) for i in items],
            total=total,
            limit=limit,
            offset=offset,
        )


class BiometricReferenceService:
    """Service managing restricted biometric reference enrollment and lifecycle (Phase 74)."""

    def __init__(
        self,
        reference_repo: BiometricReferenceRepository,
        governance_repo: BiometricGovernanceRepository,
        audit_repo: AuditRepository | None = None,
    ) -> None:
        self.reference_repo = reference_repo
        self.governance_repo = governance_repo
        self.audit_repo = audit_repo

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings | None = None,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> BiometricReferenceService:
        """Construct BiometricReferenceService bound to session."""
        return cls(
            reference_repo=BiometricReferenceRepository(session),
            governance_repo=BiometricGovernanceRepository(session),
            audit_repo=audit_repo or AuditRepository(session),
        )

    async def enroll_reference(
        self,
        request: BiometricReferenceCreate,
        principal: AuthenticatedPrincipal,
    ) -> BiometricReferenceRead:
        """Enroll an approved biometric reference into the restricted registry (Phase 74)."""
        is_self = (
            request.subject_user_id is not None and request.subject_user_id == principal.user_id
        )
        can_manage = has_any_permission(
            principal.role,
            [
                Permission.BIOMETRIC_REFERENCE_MANAGE_DEPT,
                Permission.BIOMETRIC_REFERENCE_MANAGE_GLOBAL,
            ],
        ) or (is_self and has_permission(principal.role, Permission.BIOMETRIC_REFERENCE_MANAGE_OWN))

        if not can_manage:
            raise PermissionDeniedError(
                "Caller lacks authorization to enroll biometric references.",
                code="BIOMETRIC_ENROLLMENT_DENIED",
            )

        # Validate that the governance record is approved and active
        gov_record = await self.governance_repo.get_by_id(
            request.governance_record_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if gov_record is None:
            raise ResourceNotFoundError(
                f"Biometric governance record '{request.governance_record_id}' not found.",
                code="GOVERNANCE_RECORD_NOT_FOUND",
            )

        if gov_record.status != GovernanceStatus.APPROVED.value:
            raise BiometricGovernanceError(
                f"Cannot enroll reference under unapproved governance record (status: '{gov_record.status}').",
                code="GOVERNANCE_NOT_APPROVED",
            )

        if gov_record.consent_status == ConsentStatus.WITHDRAWN.value:
            raise BiometricGovernanceError(
                "Cannot enroll reference under withdrawn consent.",
                code="CONSENT_WITHDRAWN",
            )

        now = datetime.now(UTC)
        expires_at = now + timedelta(days=gov_record.retention_days)
        opaque_id = f"REF-BIO-{uuid4().hex[:12].upper()}"

        reference = BiometricReference(
            reference_id=opaque_id,
            tenant_id=principal.department_id,
            department_id=principal.department_id,
            subject_user_id=request.subject_user_id,
            governance_record_id=request.governance_record_id,
            purpose=request.purpose.value,
            status=BiometricReferenceStatus.ACTIVE.value,
            template_digest=request.template_digest,
            encrypted_template=request.encrypted_template,
            provenance_evidence_id=request.provenance_evidence_id,
            enrollment_notes=request.enrollment_notes,
            enrolled_by_id=principal.user_id,
            enrolled_at=now,
            retention_expires_at=expires_at,
        )

        persisted = await self.reference_repo.create(reference)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_REFERENCE_ENROLLED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.BIOMETRIC_REFERENCE.value,
                target_id=str(persisted.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "reference_id": persisted.reference_id,
                    "purpose": persisted.purpose,
                    "template_digest": persisted.template_digest,
                    "governance_record_id": str(persisted.governance_record_id),
                },
            )

        return BiometricReferenceRead.model_validate(persisted)

    async def revoke_reference(
        self,
        reference_id: UUID,
        request: BiometricReferenceRevokeRequest,
        principal: AuthenticatedPrincipal,
    ) -> BiometricReferenceRead:
        """Revoke an active biometric reference (Phase 74)."""
        reference = await self.reference_repo.get_by_id(
            reference_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if reference is None:
            raise ResourceNotFoundError(
                f"Biometric reference '{reference_id}' not found.",
                code="BIOMETRIC_REFERENCE_NOT_FOUND",
            )

        is_self = (
            reference.subject_user_id is not None and reference.subject_user_id == principal.user_id
        )
        can_manage = has_any_permission(
            principal.role,
            [
                Permission.BIOMETRIC_REFERENCE_MANAGE_DEPT,
                Permission.BIOMETRIC_REFERENCE_MANAGE_GLOBAL,
            ],
        ) or (is_self and has_permission(principal.role, Permission.BIOMETRIC_REFERENCE_MANAGE_OWN))

        if not can_manage:
            raise PermissionDeniedError(
                "Caller lacks authorization to revoke this biometric reference.",
                code="BIOMETRIC_REVOCATION_DENIED",
            )

        # Idempotent return if already revoked
        if reference.status == BiometricReferenceStatus.REVOKED.value:
            return BiometricReferenceRead.model_validate(reference)

        now = datetime.now(UTC)
        reference.status = BiometricReferenceStatus.REVOKED.value
        reference.revoked_by_id = principal.user_id
        reference.revoked_at = now
        reference.revocation_reason = request.reason
        reference.encrypted_template = None  # Securely purge ciphertext

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_REFERENCE_REVOKED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=reference.department_id,
                target_type=AuditTargetType.BIOMETRIC_REFERENCE.value,
                target_id=str(reference.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "reference_id": reference.reference_id,
                    "reason": request.reason,
                },
            )

        return BiometricReferenceRead.model_validate(reference)

    async def get_reference(
        self,
        reference_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> BiometricReferenceRead:
        """Retrieve biometric reference metadata without exposing template payload."""
        reference = await self.reference_repo.get_by_id(
            reference_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if reference is None:
            raise ResourceNotFoundError(
                f"Biometric reference '{reference_id}' not found.",
                code="BIOMETRIC_REFERENCE_NOT_FOUND",
            )

        is_self = (
            reference.subject_user_id is not None and reference.subject_user_id == principal.user_id
        )
        can_read = has_any_permission(
            principal.role,
            [
                Permission.BIOMETRIC_REFERENCE_READ_DEPT,
                Permission.BIOMETRIC_REFERENCE_READ_GLOBAL,
            ],
        ) or (is_self and has_permission(principal.role, Permission.BIOMETRIC_REFERENCE_READ_OWN))

        if not can_read:
            raise PermissionDeniedError(
                "Caller lacks authorization to view this biometric reference.",
                code="BIOMETRIC_READ_DENIED",
            )

        return BiometricReferenceRead.model_validate(reference)

    async def list_references(
        self,
        principal: AuthenticatedPrincipal,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedBiometricReferenceRead:
        """List references scoped to department."""
        dept_id = principal.department_id
        items = await self.reference_repo.list_for_department(
            department_id=dept_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        total = await self.reference_repo.count_for_department(
            department_id=dept_id,
            status=status,
        )
        return PaginatedBiometricReferenceRead(
            items=[BiometricReferenceRead.model_validate(i) for i in items],
            total=total,
            limit=limit,
            offset=offset,
        )


class FaceDetectionService:
    """Service executing approved face detection under verified governance (Phase 75)."""

    def __init__(
        self,
        governance_repo: BiometricGovernanceRepository,
        settings: Settings,
        audit_repo: AuditRepository | None = None,
    ) -> None:
        self.governance_repo = governance_repo
        self.settings = settings
        self.audit_repo = audit_repo

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> FaceDetectionService:
        """Construct FaceDetectionService bound to session and settings."""
        return cls(
            governance_repo=BiometricGovernanceRepository(session),
            settings=settings,
            audit_repo=audit_repo or AuditRepository(session),
        )

    async def detect_faces(
        self,
        image_bytes: bytes,
        governance_record_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> FaceDetectionResponse:
        """Execute face bounding-box detection (Phase 75)."""
        if not has_permission(principal.role, Permission.BIOMETRIC_DETECTION_EXECUTE):
            raise PermissionDeniedError(
                "Caller lacks BIOMETRIC_DETECTION_EXECUTE permission.",
                code="FACE_DETECTION_DENIED",
            )

        # Fail closed if disabled in settings
        if (
            not self.settings.BIOMETRIC_ANALYSIS_ENABLED
            or not self.settings.BIOMETRIC_DETECTION_ENABLED
        ):
            raise BiometricsDisabledError(
                "Face detection is disabled in system configuration.",
                code="BIOMETRICS_DISABLED",
            )

        if len(image_bytes) > self.settings.BIOMETRIC_MAX_IMAGE_SIZE_BYTES:
            raise PayloadTooLargeError(
                f"Image payload size ({len(image_bytes)} bytes) exceeds the maximum allowed limit "
                f"({self.settings.BIOMETRIC_MAX_IMAGE_SIZE_BYTES} bytes).",
                code="PAYLOAD_TOO_LARGE",
            )

        # Validate approved governance authorization
        gov_record = await self.governance_repo.get_by_id(
            governance_record_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if gov_record is None:
            raise ResourceNotFoundError(
                f"Biometric governance record '{governance_record_id}' not found.",
                code="GOVERNANCE_RECORD_NOT_FOUND",
            )

        if gov_record.status != GovernanceStatus.APPROVED.value:
            raise BiometricGovernanceError(
                f"Face detection requires an approved governance record; current status is '{gov_record.status}'.",
                code="GOVERNANCE_NOT_APPROVED",
            )

        if gov_record.consent_status == ConsentStatus.WITHDRAWN.value:
            raise BiometricGovernanceError(
                "Face detection cannot be executed under withdrawn subject consent.",
                code="CONSENT_WITHDRAWN",
            )

        permitted_purposes = {
            BiometricPurpose.PRIVACY_REDACTION_BLURRING.value,
            BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
            BiometricPurpose.TESTING_SYNTHETIC_BENCHMARK.value,
        }
        if gov_record.purpose not in permitted_purposes:
            raise BiometricGovernanceError(
                f"Governance record purpose '{gov_record.purpose}' is not authorized for face detection.",
                code="UNAUTHORIZED_BIOMETRIC_PURPOSE",
            )

        # Instantiate face detector provider
        detector = get_face_detector(
            enabled=self.settings.BIOMETRIC_DETECTION_ENABLED,
            provider=self.settings.BIOMETRIC_PROVIDER,
        )

        result = detector.detect_faces(image_bytes)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_DETECTION_EXECUTED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.BIOMETRIC_GOVERNANCE.value,
                target_id=str(gov_record.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "face_count": result.face_count,
                    "image_width": result.image_width,
                    "image_height": result.image_height,
                    "model_name": result.model_name,
                    "model_version": result.model_version,
                    "latency_ms": result.inference_latency_ms,
                },
            )

        return FaceDetectionResponse(
            detected_faces=[
                DetectedFaceRead(
                    bounding_box=f.bounding_box,
                    confidence=f.confidence,
                    landmarks=f.landmarks,
                )
                for f in result.detected_faces
            ],
            face_count=result.face_count,
            image_width=result.image_width,
            image_height=result.image_height,
            model_name=result.model_name,
            model_version=result.model_version,
            inference_latency_ms=result.inference_latency_ms,
            disclaimer=result.disclaimer,
            metadata=result.metadata,
        )


class FaceMatchingService:
    """Service executing advisory biometric matching with uncertainty bands and fail-closed controls (Phase 76-78)."""

    def __init__(
        self,
        governance_repo: BiometricGovernanceRepository,
        reference_repo: BiometricReferenceRepository,
        verification_repo: BiometricVerificationRepository,
        settings: Settings,
        audit_repo: AuditRepository | None = None,
        key_manager: BiometricKeyManager | None = None,
    ) -> None:
        self.governance_repo = governance_repo
        self.reference_repo = reference_repo
        self.verification_repo = verification_repo
        self.settings = settings
        self.audit_repo = audit_repo
        self.key_manager = key_manager or get_biometric_key_manager()

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        audit_repo: AuditRepository | None = None,
        key_manager: BiometricKeyManager | None = None,
    ) -> FaceMatchingService:
        return cls(
            governance_repo=BiometricGovernanceRepository(session),
            reference_repo=BiometricReferenceRepository(session),
            verification_repo=BiometricVerificationRepository(session),
            settings=settings,
            audit_repo=audit_repo or AuditRepository(session),
            key_manager=key_manager,
        )

    async def match_faces(
        self,
        payload: FaceMatchRequest,
        principal: AuthenticatedPrincipal,
    ) -> FaceMatchResponse:
        """Execute biometric face matching with uncertainty bands and audit logging (Phase 76 & 77)."""
        if not has_permission(principal.role, Permission.BIOMETRIC_MATCHING_EXECUTE):
            raise PermissionDeniedError(
                "Caller lacks BIOMETRIC_MATCHING_EXECUTE permission.",
                code="BIOMETRIC_MATCHING_DENIED",
            )

        if (
            not self.settings.BIOMETRIC_ANALYSIS_ENABLED
            or not self.settings.BIOMETRIC_MATCHING_ENABLED
        ):
            raise BiometricsDisabledError(
                "Biometric face matching is strictly disabled in system settings. "
                "Automated matching is prohibited in production and requires explicit legal approval.",
                code="BIOMETRIC_MATCHING_DISABLED",
            )

        try:
            probe_bytes = base64.b64decode(payload.probe_image_base64)
        except Exception as exc:
            raise BusinessRuleError("Invalid base64 encoding for probe image.") from exc

        if len(probe_bytes) > self.settings.BIOMETRIC_MAX_IMAGE_SIZE_BYTES:
            raise PayloadTooLargeError(
                f"Probe image size ({len(probe_bytes)} bytes) exceeds maximum limit "
                f"({self.settings.BIOMETRIC_MAX_IMAGE_SIZE_BYTES} bytes).",
                code="PAYLOAD_TOO_LARGE",
            )

        gov_record = await self.governance_repo.get_by_id(
            payload.governance_record_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if gov_record is None:
            raise ResourceNotFoundError(
                f"Biometric governance record '{payload.governance_record_id}' not found.",
                code="GOVERNANCE_RECORD_NOT_FOUND",
            )

        if gov_record.status != GovernanceStatus.APPROVED.value:
            raise BiometricGovernanceError(
                f"Face matching requires an approved governance record; current status is '{gov_record.status}'.",
                code="GOVERNANCE_NOT_APPROVED",
            )

        if gov_record.consent_status == ConsentStatus.WITHDRAWN.value:
            raise BiometricGovernanceError(
                "Face matching cannot be executed under withdrawn subject consent.",
                code="CONSENT_WITHDRAWN",
            )

        permitted_purposes = {
            BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
            BiometricPurpose.TESTING_SYNTHETIC_BENCHMARK.value,
        }
        if gov_record.purpose not in permitted_purposes:
            raise BiometricGovernanceError(
                f"Governance purpose '{gov_record.purpose}' is not authorized for face matching.",
                code="UNAUTHORIZED_BIOMETRIC_PURPOSE",
            )

        probe_quality = assess_face_image_quality(probe_bytes)
        if not probe_quality.is_acceptable:
            if self.audit_repo:
                await self.audit_repo.append_event(
                    action=AuditAction.BIOMETRIC_QUALITY_FAILED.value,
                    actor_id=principal.user_id,
                    actor_role=principal.role_code,
                    department_id=principal.department_id,
                    target_type=AuditTargetType.BIOMETRIC_GOVERNANCE.value,
                    target_id=str(gov_record.id),
                    outcome=AuditOutcome.FAILURE.value,
                    details={
                        "reason": probe_quality.reason,
                        "quality_status": probe_quality.status.value,
                    },
                )
            raise BiometricQualityError(
                f"Probe image quality check failed: {probe_quality.reason}",
                code="PROBE_IMAGE_QUALITY_INSUFFICIENT",
            )

        probe_hash = hashlib.sha256(probe_bytes).hexdigest()

        matcher = get_face_matcher(
            enabled=self.settings.BIOMETRIC_MATCHING_ENABLED,
            provider=self.settings.BIOMETRIC_PROVIDER,
        )
        probe_vector = matcher.extract_features(probe_bytes)

        ref_vector: FaceFeatureVector | None = None
        ref_record_id: UUID | None = None

        if payload.reference_id is not None:
            ref = await self.reference_repo.get_by_id(
                payload.reference_id,
                department_id=principal.department_id
                if principal.role_code != "SUPER_ADMIN"
                else None,
            )
            if ref is None:
                raise ResourceNotFoundError(
                    f"Biometric reference '{payload.reference_id}' not found.",
                    code="BIOMETRIC_REFERENCE_NOT_FOUND",
                )
            if ref.status != BiometricReferenceStatus.ACTIVE.value:
                raise BiometricGovernanceError(
                    f"Biometric reference '{ref.reference_id}' is not active (status: {ref.status}).",
                    code="BIOMETRIC_REFERENCE_INACTIVE",
                )
            ref_record_id = ref.id

            if ref.encrypted_template:
                decrypted_raw = self.key_manager.decrypt(ref.encrypted_template)

                if self.audit_repo:
                    await self.audit_repo.append_event(
                        action=AuditAction.BIOMETRIC_KEY_ACCESSED.value,
                        actor_id=principal.user_id,
                        actor_role=principal.role_code,
                        department_id=principal.department_id,
                        target_type=AuditTargetType.BIOMETRIC_REFERENCE.value,
                        target_id=str(ref.id),
                        outcome=AuditOutcome.SUCCESS.value,
                        details={"reference_id": ref.reference_id},
                    )

                try:
                    parsed = json.loads(decrypted_raw.decode("utf-8"))
                    if isinstance(parsed, list):
                        ref_vector = FaceFeatureVector(
                            vector=[float(x) for x in parsed],
                            dimension=len(parsed),
                            model_name=probe_vector.model_name,
                            model_version=probe_vector.model_version,
                        )
                except Exception:
                    ref_vector = matcher.extract_features(decrypted_raw)

            elif payload.reference_image_base64:
                ref_bytes = base64.b64decode(payload.reference_image_base64)
                ref_quality = assess_face_image_quality(ref_bytes)
                if not ref_quality.is_acceptable:
                    raise BiometricQualityError(
                        f"Reference image quality check failed: {ref_quality.reason}",
                        code="REFERENCE_IMAGE_QUALITY_INSUFFICIENT",
                    )
                ref_vector = matcher.extract_features(ref_bytes)
            else:
                raise BiometricGovernanceError(
                    "Selected biometric reference has no stored template and no reference image was provided.",
                    code="REFERENCE_TEMPLATE_MISSING",
                )

        elif payload.reference_image_base64:
            try:
                ref_bytes = base64.b64decode(payload.reference_image_base64)
            except Exception as exc:
                raise BusinessRuleError("Invalid base64 encoding for reference image.") from exc
            if len(ref_bytes) > self.settings.BIOMETRIC_MAX_IMAGE_SIZE_BYTES:
                raise PayloadTooLargeError("Reference image size exceeds limit.")
            ref_quality = assess_face_image_quality(ref_bytes)
            if not ref_quality.is_acceptable:
                raise BiometricQualityError(
                    f"Reference image quality check failed: {ref_quality.reason}",
                    code="REFERENCE_IMAGE_QUALITY_INSUFFICIENT",
                )
            ref_vector = matcher.extract_features(ref_bytes)

        if ref_vector is None:
            raise BusinessRuleError("Unable to derive reference features for matching.")

        match_result = matcher.match_faces(probe_vector, ref_vector)

        tenant_id = principal.department_id or gov_record.tenant_id
        department_id = principal.department_id or gov_record.department_id
        review_record = BiometricVerificationReview(
            id=uuid4(),
            tenant_id=tenant_id,
            department_id=department_id,
            incident_id=payload.incident_id,
            reference_id=ref_record_id,
            probe_image_hash=probe_hash,
            candidate_similarity=match_result.similarity_score,
            uncertainty_lower_bound=match_result.uncertainty_lower_bound,
            uncertainty_upper_bound=match_result.uncertainty_upper_bound,
            automated_verdict=match_result.verdict.value,
            human_verdict=BiometricHumanVerdict.INCONCLUSIVE_DISMISSED.value,
            is_override=False,
        )
        created_review = await self.verification_repo.create(review_record)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_MATCHING_EXECUTED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.BIOMETRIC_VERIFICATION.value,
                target_id=str(created_review.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "similarity_score": match_result.similarity_score,
                    "verdict": match_result.verdict.value,
                    "probe_hash": probe_hash,
                    "model_name": match_result.model_name,
                    "latency_ms": match_result.comparison_latency_ms,
                },
            )

        return FaceMatchResponse(
            similarity_score=match_result.similarity_score,
            verdict=match_result.verdict.value,
            uncertainty_lower_bound=match_result.uncertainty_lower_bound,
            uncertainty_upper_bound=match_result.uncertainty_upper_bound,
            probe_image_hash=probe_hash,
            verification_review_id=created_review.id,
            model_name=match_result.model_name,
            model_version=match_result.model_version,
            latency_ms=match_result.comparison_latency_ms,
            disclaimer=match_result.disclaimer,
            metadata=match_result.metadata,
        )


class BiometricVerificationService:
    """Service managing authorized human review and oversight of biometric candidates (Phase 77)."""

    def __init__(
        self,
        verification_repo: BiometricVerificationRepository,
        audit_repo: AuditRepository | None = None,
    ) -> None:
        self.verification_repo = verification_repo
        self.audit_repo = audit_repo

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings | None = None,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> BiometricVerificationService:
        return cls(
            verification_repo=BiometricVerificationRepository(session),
            audit_repo=audit_repo or AuditRepository(session),
        )

    async def get_review(
        self,
        review_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> BiometricVerificationReviewRead:
        """Fetch a single biometric verification review record."""
        review = await self.verification_repo.get_by_id(
            review_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if review is None:
            raise ResourceNotFoundError(
                f"Biometric verification review '{review_id}' not found.",
                code="VERIFICATION_REVIEW_NOT_FOUND",
            )
        return BiometricVerificationReviewRead.model_validate(review)

    async def list_reviews(
        self,
        principal: AuthenticatedPrincipal,
        *,
        incident_id: UUID | None = None,
        is_override: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedBiometricVerificationReviewRead:
        """List biometric verification review records scoped to department."""
        dept_id = principal.department_id if principal.role_code != "SUPER_ADMIN" else None
        items = await self.verification_repo.list_for_department(
            department_id=dept_id,
            incident_id=incident_id,
            is_override=is_override,
            limit=limit,
            offset=offset,
        )
        total = await self.verification_repo.count_for_department(
            department_id=dept_id,
            incident_id=incident_id,
            is_override=is_override,
        )
        return PaginatedBiometricVerificationReviewRead(
            items=[BiometricVerificationReviewRead.model_validate(r) for r in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    async def record_human_verdict(
        self,
        review_id: UUID,
        payload: BiometricVerificationReviewCreate,
        principal: AuthenticatedPrincipal,
    ) -> BiometricVerificationReviewRead:
        """Record authorized human determination with override audit logging (Phase 77)."""
        if not has_permission(principal.role, Permission.BIOMETRIC_VERIFICATION_REVIEW):
            raise PermissionDeniedError(
                "Caller lacks BIOMETRIC_VERIFICATION_REVIEW permission.",
                code="VERIFICATION_REVIEW_DENIED",
            )

        review = await self.verification_repo.get_by_id(
            review_id,
            department_id=principal.department_id if principal.role_code != "SUPER_ADMIN" else None,
        )
        if review is None:
            raise ResourceNotFoundError(
                f"Biometric verification review '{review_id}' not found.",
                code="VERIFICATION_REVIEW_NOT_FOUND",
            )

        is_override = False
        if (
            payload.human_verdict == BiometricHumanVerdict.REJECTED_OVERRIDE
            or (
                review.automated_verdict == BiometricMatchVerdict.MATCH_CANDIDATE.value
                and payload.human_verdict == BiometricHumanVerdict.VERIFIED_NON_MATCH
            )
            or (
                review.automated_verdict == BiometricMatchVerdict.NON_MATCH_CANDIDATE.value
                and payload.human_verdict == BiometricHumanVerdict.VERIFIED_MATCH
            )
        ):
            is_override = True

        if is_override and not (payload.override_reason and payload.override_reason.strip()):
            raise BusinessRuleError(
                "A documented override_reason is strictly required when overruling automated candidate results.",
                code="OVERRIDE_REASON_REQUIRED",
            )

        review.human_verdict = payload.human_verdict.value
        review.reviewer_id = principal.user_id
        review.reviewed_at = datetime.now(UTC)
        review.review_notes = payload.review_notes
        review.override_reason = payload.override_reason
        review.is_override = is_override

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.BIOMETRIC_VERIFICATION_RECORDED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.BIOMETRIC_VERIFICATION.value,
                target_id=str(review.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "human_verdict": payload.human_verdict.value,
                    "automated_verdict": review.automated_verdict,
                    "is_override": is_override,
                },
            )

        return BiometricVerificationReviewRead.model_validate(review)


class BiometricEvaluationService:
    """Service generating reproducible biometric evaluation summaries on synthetic benchmarks (Phase 79)."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def get_evaluation_report(
        self,
        principal: AuthenticatedPrincipal,
    ) -> BiometricEvaluationSummaryRead:
        """Generate evaluation benchmark summary with explicit synthetic disclaimers."""
        if not has_any_permission(
            principal.role,
            [
                Permission.BIOMETRIC_GOVERNANCE_REVIEW,
                Permission.BIOMETRIC_MATCHING_EXECUTE,
                Permission.BIOMETRIC_VERIFICATION_REVIEW,
            ],
        ):
            raise PermissionDeniedError(
                "Caller lacks permission to access biometric evaluation reports.",
                code="EVALUATION_REPORT_DENIED",
            )

        pairs = [
            (True, 0.95),
            (True, 0.92),
            (True, 0.88),
            (True, 0.86),
            (True, 0.78),
            (False, 0.15),
            (False, 0.22),
            (False, 0.35),
            (False, 0.55),
            (False, 0.68),
        ]
        subgroups = {
            "synthetic_subgroup_alpha": [(True, 0.92), (True, 0.88), (False, 0.20), (False, 0.30)],
            "synthetic_subgroup_beta": [(True, 0.90), (True, 0.85), (False, 0.25), (False, 0.35)],
        }
        pad_data = (50, 1, 50, 2)

        rep = evaluate_biometric_matching_benchmark(
            comparison_pairs=pairs,
            model_name="mock-face-matcher",
            model_version="1.0.0-test",
            failed_acquisitions=2,
            total_acquisition_attempts=12,
            presentation_attack_data=pad_data,
            subgroup_comparisons=subgroups,
        )

        pad_summary = None
        if rep.pad_metrics:
            pad_summary = {
                "apcer": rep.pad_metrics.apcer,
                "bpcer": rep.pad_metrics.bpcer,
                "total_attacks": rep.pad_metrics.total_attack_presentations,
                "total_bona_fide": rep.pad_metrics.total_bona_fide_presentations,
            }

        subgroup_data = [
            {
                "subgroup_name": s.subgroup_name,
                "sample_count": s.sample_count,
                "subgroup_fmr": s.subgroup_fmr,
                "subgroup_fnmr": s.subgroup_fnmr,
            }
            for s in rep.demographic_disparities
        ]

        return BiometricEvaluationSummaryRead(
            model_name=rep.model_name,
            model_version=rep.model_version,
            total_comparisons=rep.total_comparisons,
            fta_rate=rep.fta_rate,
            eer=rep.eer,
            eer_threshold=rep.eer_threshold,
            operational_fmr_at_085=rep.operational_fmr_at_085,
            operational_fnmr_at_085=rep.operational_fnmr_at_085,
            max_demographic_disparity_ratio=rep.max_demographic_disparity_ratio,
            disclaimer=rep.disclaimer,
            pad_summary=pad_summary,
            subgroups=subgroup_data,
        )
