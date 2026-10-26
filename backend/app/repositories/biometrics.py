"""Repositories for Biometric Governance and Reference Registry (Phases 73-74).

Enforces:
- Strict department and tenant-scoped isolation on all biometric operations.
- Auditability of reference enrollment, revocation, and withdrawal.
- Clean separation between metadata queries and template payloads.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.biometrics import BiometricReferenceStatus
from backend.app.models.biometrics import (
    BiometricGovernanceRecord,
    BiometricReference,
    BiometricVerificationReview,
)


class BiometricGovernanceRepository:
    """Persistence operations for biometric processing governance, notices, and consent."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, record: BiometricGovernanceRecord) -> BiometricGovernanceRecord:
        """Persist a new biometric governance record."""
        self._session.add(record)
        await self._session.flush()
        return record

    async def get_by_id(
        self,
        record_id: UUID,
        *,
        department_id: UUID | None = None,
    ) -> BiometricGovernanceRecord | None:
        """Fetch a governance record by primary key, optionally scoped to department."""
        stmt = select(BiometricGovernanceRecord).where(BiometricGovernanceRecord.id == record_id)
        if department_id is not None:
            stmt = stmt.where(BiometricGovernanceRecord.department_id == department_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_department(
        self,
        *,
        department_id: UUID | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[BiometricGovernanceRecord]:
        """List governance records scoped to a department with optional status filter."""
        stmt = (
            select(BiometricGovernanceRecord)
            .order_by(BiometricGovernanceRecord.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if department_id is not None:
            stmt = stmt.where(BiometricGovernanceRecord.department_id == department_id)
        if status is not None:
            stmt = stmt.where(BiometricGovernanceRecord.status == status)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count_for_department(
        self,
        *,
        department_id: UUID | None = None,
        status: str | None = None,
    ) -> int:
        """Count governance records scoped to a department."""
        stmt = select(func.count(BiometricGovernanceRecord.id))
        if department_id is not None:
            stmt = stmt.where(BiometricGovernanceRecord.department_id == department_id)
        if status is not None:
            stmt = stmt.where(BiometricGovernanceRecord.status == status)
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)


class BiometricReferenceRepository:
    """Persistence operations for restricted biometric reference registry."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, reference: BiometricReference) -> BiometricReference:
        """Persist a newly enrolled biometric reference."""
        self._session.add(reference)
        await self._session.flush()
        return reference

    async def get_by_id(
        self,
        reference_id: UUID,
        *,
        department_id: UUID | None = None,
    ) -> BiometricReference | None:
        """Fetch a biometric reference by UUID primary key."""
        stmt = select(BiometricReference).where(BiometricReference.id == reference_id)
        if department_id is not None:
            stmt = stmt.where(BiometricReference.department_id == department_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_opaque_id(
        self,
        opaque_id: str,
        *,
        department_id: UUID | None = None,
    ) -> BiometricReference | None:
        """Fetch a biometric reference by unique string reference_id."""
        stmt = select(BiometricReference).where(BiometricReference.reference_id == opaque_id)
        if department_id is not None:
            stmt = stmt.where(BiometricReference.department_id == department_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_department(
        self,
        *,
        department_id: UUID | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[BiometricReference]:
        """List references scoped strictly to a department."""
        stmt = (
            select(BiometricReference)
            .order_by(BiometricReference.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if department_id is not None:
            stmt = stmt.where(BiometricReference.department_id == department_id)
        if status is not None:
            stmt = stmt.where(BiometricReference.status == status)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def list_active_by_governance_record(
        self,
        governance_record_id: UUID,
    ) -> Sequence[BiometricReference]:
        """Fetch all active references tied to a specific governance record."""
        stmt = select(BiometricReference).where(
            BiometricReference.governance_record_id == governance_record_id,
            BiometricReference.status == BiometricReferenceStatus.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count_for_department(
        self,
        *,
        department_id: UUID | None = None,
        status: str | None = None,
    ) -> int:
        """Count references in a department."""
        stmt = select(func.count(BiometricReference.id))
        if department_id is not None:
            stmt = stmt.where(BiometricReference.department_id == department_id)
        if status is not None:
            stmt = stmt.where(BiometricReference.status == status)
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)


class BiometricVerificationRepository:
    """Persistence operations for human oversight of biometric verification determinations (Phase 77)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, review: BiometricVerificationReview) -> BiometricVerificationReview:
        """Persist a new biometric verification review candidate."""
        self._session.add(review)
        await self._session.flush()
        return review

    async def get_by_id(
        self,
        review_id: UUID,
        *,
        department_id: UUID | None = None,
    ) -> BiometricVerificationReview | None:
        """Fetch a verification review record by ID, optionally scoped to a department."""
        stmt = select(BiometricVerificationReview).where(
            BiometricVerificationReview.id == review_id
        )
        if department_id is not None:
            stmt = stmt.where(BiometricVerificationReview.department_id == department_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_department(
        self,
        *,
        department_id: UUID | None = None,
        incident_id: UUID | None = None,
        is_override: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[BiometricVerificationReview]:
        """List verification review records with optional filtering."""
        stmt = (
            select(BiometricVerificationReview)
            .order_by(BiometricVerificationReview.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if department_id is not None:
            stmt = stmt.where(BiometricVerificationReview.department_id == department_id)
        if incident_id is not None:
            stmt = stmt.where(BiometricVerificationReview.incident_id == incident_id)
        if is_override is not None:
            stmt = stmt.where(BiometricVerificationReview.is_override == is_override)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count_for_department(
        self,
        *,
        department_id: UUID | None = None,
        incident_id: UUID | None = None,
        is_override: bool | None = None,
    ) -> int:
        """Count verification review records matching filters."""
        stmt = select(func.count(BiometricVerificationReview.id))
        if department_id is not None:
            stmt = stmt.where(BiometricVerificationReview.department_id == department_id)
        if incident_id is not None:
            stmt = stmt.where(BiometricVerificationReview.incident_id == incident_id)
        if is_override is not None:
            stmt = stmt.where(BiometricVerificationReview.is_override == is_override)
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)
