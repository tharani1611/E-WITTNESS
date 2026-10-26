"""Domain service for AI dataset governance, licensing, and consent verification (Phase 62).

Enforces:
- Verification of dataset manifests against approved open licenses (SPDX allowlist).
- Strict separation of operational incident evidence from training datasets.
- Immutable dataset registration and authorized state transitions.
- Tamper-evident security audit logging for all dataset lifecycle operations.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.ai import (
    APPROVED_DATASET_LICENSES,
    DatasetConsentStatus,
    DatasetStatus,
    DatasetType,
    compute_manifest_sha256,
)
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.logging import get_logger
from backend.app.models.ai import AIDataset
from backend.app.models.base import utc_now
from backend.app.repositories.ai_dataset import AIDatasetRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.schemas.ai import (
    AIDatasetRead,
    DatasetRegisterRequest,
    DatasetReviewRequest,
)
from backend.app.schemas.auth import AuthenticatedPrincipal

logger = get_logger("services.ai_dataset")


class AIDatasetService:
    """Service managing dataset registration, provenance, licensing, and governance reviews."""

    def __init__(
        self,
        dataset_repo: AIDatasetRepository,
        audit_repo: AuditRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.dataset_repo = dataset_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> AIDatasetService:
        """Construct an AIDatasetService bound to the provided session."""
        return cls(
            dataset_repo=AIDatasetRepository(session),
            audit_repo=audit_repo or AuditRepository(session),
            settings=settings,
        )

    async def register_dataset(
        self,
        payload: DatasetRegisterRequest,
        principal: AuthenticatedPrincipal,
    ) -> AIDatasetRead:
        """Register a new AI benchmark or training dataset with verified licensing and provenance."""
        if not has_permission(principal.role, Permission.AI_DATASET_READ):
            raise PermissionDeniedError("Caller lacks permission to register datasets.")

        # 1. Verify license against approved allowlist
        clean_license = payload.license_id.strip()
        if clean_license not in APPROVED_DATASET_LICENSES:
            raise BusinessRuleError(
                f"License '{clean_license}' is not in approved dataset licenses: {sorted(APPROVED_DATASET_LICENSES)}",
                code="UNAPPROVED_DATASET_LICENSE",
            )

        # 2. Check for unique (name, version)
        existing = await self.dataset_repo.get_by_name_and_version(payload.name, payload.version)
        if existing is not None:
            raise ConflictError(
                f"Dataset '{payload.name}' version '{payload.version}' is already registered.",
                code="DATASET_ALREADY_EXISTS",
            )

        # 3. Separation of operational evidence from training data:
        # Reject any manifest item referencing internal operational storage prefixes
        for item in payload.manifest_items:
            lower_path = item.path.lower()
            if any(
                lower_path.startswith(prefix)
                for prefix in ("evidence/", "incidents/", "custody/", "audit/", "uploads/")
            ):
                raise BusinessRuleError(
                    f"Operational evidence file '{item.path}' cannot be imported into an "
                    "AI dataset without explicit de-identification and separate ethics approval.",
                    code="OPERATIONAL_EVIDENCE_ISOLATION_VIOLATION",
                )

        # 4. Calculate deterministic manifest SHA-256 digest
        manifest_dicts = [item.model_dump() for item in payload.manifest_items]
        manifest_sha256 = compute_manifest_sha256(manifest_dicts)

        dataset = AIDataset(
            name=payload.name,
            version=payload.version,
            dataset_type=payload.dataset_type.value,
            source_uri=payload.source_uri,
            license_id=clean_license,
            consent_status=payload.consent_status.value,
            provenance_details=json.dumps(payload.provenance_details),
            manifest_sha256=manifest_sha256,
            manifest_item_count=len(payload.manifest_items),
            manifest_payload=json.dumps(manifest_dicts),
            status=DatasetStatus.PENDING_REVIEW.value,
            created_by_id=principal.user_id,
        )
        created = await self.dataset_repo.create(dataset)

        # 5. Record security audit event
        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_DATASET_REGISTERED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.AI_DATASET.value,
                target_id=str(created.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "name": created.name,
                    "version": created.version,
                    "license_id": created.license_id,
                    "manifest_sha256": created.manifest_sha256,
                    "item_count": created.manifest_item_count,
                },
            )

        logger.info(
            "AI dataset registered",
            extra={
                "dataset_id": str(created.id),
                "dataset_name": created.name,
                "version": created.version,
                "manifest_sha256": created.manifest_sha256,
            },
        )

        return self._to_read_dto(created)

    async def review_dataset(
        self,
        dataset_id: UUID,
        payload: DatasetReviewRequest,
        principal: AuthenticatedPrincipal,
    ) -> AIDatasetRead:
        """Approve, reject, or withdraw a registered dataset (governance review)."""
        if not has_permission(principal.role, Permission.AI_DATASET_MANAGE):
            raise PermissionDeniedError("Caller lacks permission to review datasets.")

        dataset = await self.dataset_repo.get_by_id(dataset_id)
        if dataset is None:
            raise ResourceNotFoundError("Dataset not found.", code="DATASET_NOT_FOUND")

        # Validate lifecycle state transition
        current = dataset.status
        target = payload.decision

        if current == DatasetStatus.PENDING_REVIEW.value:
            if target not in (DatasetStatus.APPROVED.value, DatasetStatus.REJECTED.value):
                raise BusinessRuleError(
                    f"Pending dataset can only transition to 'approved' or 'rejected', not '{target}'.",
                    code="INVALID_DATASET_TRANSITION",
                )
        elif current == DatasetStatus.APPROVED.value:
            if target != DatasetStatus.WITHDRAWN.value:
                raise BusinessRuleError(
                    f"Approved dataset can only transition to 'withdrawn', not '{target}'.",
                    code="INVALID_DATASET_TRANSITION",
                )
        else:
            raise BusinessRuleError(
                f"Dataset in terminal state '{current}' cannot be transitioned to '{target}'.",
                code="INVALID_DATASET_TRANSITION",
            )

        dataset.status = target
        dataset.reviewed_by_id = principal.user_id
        dataset.reviewed_at = utc_now()
        dataset.review_notes = payload.review_notes

        updated = await self.dataset_repo.update(dataset)

        # Record audit event
        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_DATASET_REVIEWED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=principal.department_id,
                target_type=AuditTargetType.AI_DATASET.value,
                target_id=str(updated.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "previous_status": current,
                    "new_status": target,
                    "review_notes": payload.review_notes,
                },
            )

        logger.info(
            "AI dataset reviewed",
            extra={
                "dataset_id": str(updated.id),
                "decision": target,
                "reviewer_id": str(principal.user_id),
            },
        )

        return self._to_read_dto(updated)

    async def get_dataset(
        self,
        dataset_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> AIDatasetRead:
        """Fetch a single dataset record."""
        if not has_permission(principal.role, Permission.AI_DATASET_READ):
            raise PermissionDeniedError("Caller lacks permission to view datasets.")

        dataset = await self.dataset_repo.get_by_id(dataset_id)
        if dataset is None:
            raise ResourceNotFoundError("Dataset not found.", code="DATASET_NOT_FOUND")

        return self._to_read_dto(dataset)

    async def list_datasets(
        self,
        principal: AuthenticatedPrincipal,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[AIDatasetRead], int]:
        """List datasets with optional status filtering."""
        if not has_permission(principal.role, Permission.AI_DATASET_READ):
            raise PermissionDeniedError("Caller lacks permission to view datasets.")

        datasets = await self.dataset_repo.list_datasets(status=status, limit=limit, offset=offset)
        total = await self.dataset_repo.count_datasets(status=status)
        return [self._to_read_dto(d) for d in datasets], total

    def _to_read_dto(self, dataset: AIDataset) -> AIDatasetRead:
        now = utc_now()
        return AIDatasetRead(
            id=dataset.id or uuid4(),
            name=dataset.name,
            version=dataset.version,
            dataset_type=dataset.dataset_type or DatasetType.BENCHMARK.value,
            source_uri=dataset.source_uri,
            license_id=dataset.license_id,
            consent_status=dataset.consent_status or DatasetConsentStatus.CONSENTED.value,
            provenance_details=dataset.get_provenance_dict(),
            manifest_sha256=dataset.manifest_sha256,
            manifest_item_count=dataset.manifest_item_count
            if dataset.manifest_item_count is not None
            else 0,
            status=dataset.status or DatasetStatus.PENDING_REVIEW.value,
            reviewed_by_id=dataset.reviewed_by_id,
            reviewed_at=dataset.reviewed_at,
            review_notes=dataset.review_notes,
            created_by_id=dataset.created_by_id or uuid4(),
            created_at=dataset.created_at or now,
            updated_at=dataset.updated_at or now,
        )
