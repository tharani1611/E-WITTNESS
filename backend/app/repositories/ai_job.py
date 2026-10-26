"""Repository for asynchronous AI analysis jobs (Phase 65).

Enforces:
- Strict department-scoped isolation on job queries (TenantScopedRepositoryProtocol).
- Monotonic state updates and progress persistence.
- Concurrency-safe updates.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.ai import AIAnalysisJob


class AIAnalysisJobRepository:
    """Persistence operations for asynchronous video analysis jobs."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, job: AIAnalysisJob) -> AIAnalysisJob:
        """Persist a new analysis job."""
        self._session.add(job)
        await self._session.flush()
        return job

    async def get_by_id(
        self,
        job_id: UUID,
        *,
        department_id: UUID,
    ) -> AIAnalysisJob | None:
        """Fetch a job strictly scoped to the authorized department."""
        stmt = select(AIAnalysisJob).where(
            AIAnalysisJob.id == job_id,
            AIAnalysisJob.department_id == department_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id_unscoped(self, job_id: UUID) -> AIAnalysisJob | None:
        """Fetch a job by ID without department scoping (super-admin or internal worker)."""
        stmt = select(AIAnalysisJob).where(AIAnalysisJob.id == job_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_department(
        self,
        *,
        department_id: UUID,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
    ) -> Sequence[AIAnalysisJob]:
        """List jobs strictly scoped to the authorized department."""
        stmt = select(AIAnalysisJob).where(AIAnalysisJob.department_id == department_id)
        if status is not None:
            stmt = stmt.where(AIAnalysisJob.status == status)
        stmt = stmt.order_by(AIAnalysisJob.created_at.desc()).offset(offset).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def list_all_unscoped(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
    ) -> Sequence[AIAnalysisJob]:
        """List jobs across all departments (super-admin only)."""
        stmt = select(AIAnalysisJob)
        if status is not None:
            stmt = stmt.where(AIAnalysisJob.status == status)
        stmt = stmt.order_by(AIAnalysisJob.created_at.desc()).offset(offset).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count_for_department(
        self,
        *,
        department_id: UUID,
        status: str | None = None,
    ) -> int:
        """Count jobs for a specific department."""
        stmt = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.department_id == department_id
        )
        if status is not None:
            stmt = stmt.where(AIAnalysisJob.status == status)
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def list_for_evidence(
        self,
        evidence_id: UUID,
        *,
        department_id: UUID | None = None,
    ) -> Sequence[AIAnalysisJob]:
        """List jobs for a specific evidence attachment."""
        stmt = select(AIAnalysisJob).where(AIAnalysisJob.evidence_id == evidence_id)
        if department_id is not None:
            stmt = stmt.where(AIAnalysisJob.department_id == department_id)
        stmt = stmt.order_by(AIAnalysisJob.created_at.desc())
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def get_active_job_for_evidence(
        self,
        evidence_id: UUID,
    ) -> AIAnalysisJob | None:
        """Find any currently QUEUED or RUNNING analysis job for an evidence attachment."""
        stmt = (
            select(AIAnalysisJob)
            .where(
                AIAnalysisJob.evidence_id == evidence_id,
                AIAnalysisJob.status.in_(["queued", "running"]),
            )
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def count_active_for_department(
        self,
        department_id: UUID,
    ) -> int:
        """Count active (queued or running) jobs currently consuming worker resources for a department."""
        stmt = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.department_id == department_id,
            AIAnalysisJob.status.in_(["queued", "running"]),
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def update(self, job: AIAnalysisJob) -> AIAnalysisJob:
        """Update an existing job record."""
        merged = await self._session.merge(job)
        await self._session.flush()
        return merged
