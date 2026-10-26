"""Repository for AI dataset governance entities (Phase 62).

Enforces:
- Unique constraint checks on dataset name and version.
- Provenance and manifest persistence.
- Reviewer status updates and audit tracking.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.ai import AIDataset


class AIDatasetRepository:
    """Persistence operations for AI datasets."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, dataset: AIDataset) -> AIDataset:
        """Persist a new dataset entity."""
        self._session.add(dataset)
        await self._session.flush()
        return dataset

    async def get_by_id(self, dataset_id: UUID) -> AIDataset | None:
        """Fetch a dataset by its unique primary key."""
        stmt = select(AIDataset).where(AIDataset.id == dataset_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_name_and_version(self, name: str, version: str) -> AIDataset | None:
        """Fetch a dataset by its name and version."""
        stmt = select(AIDataset).where(
            AIDataset.name == name,
            AIDataset.version == version,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_datasets(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[AIDataset]:
        """List datasets with optional status filtering and pagination."""
        stmt = select(AIDataset)
        if status is not None:
            stmt = stmt.where(AIDataset.status == status)
        stmt = stmt.order_by(AIDataset.created_at.desc()).offset(offset).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def count_datasets(self, *, status: str | None = None) -> int:
        """Count total datasets matching optional status filter."""
        stmt = select(func.count(AIDataset.id))
        if status is not None:
            stmt = stmt.where(AIDataset.status == status)
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def update(self, dataset: AIDataset) -> AIDataset:
        """Update an existing dataset record."""
        merged = await self._session.merge(dataset)
        await self._session.flush()
        return merged
