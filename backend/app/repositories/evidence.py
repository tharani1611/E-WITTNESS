"""Evidence attachments and upload sessions database repository (Phases 43-44).

Enforces:
- Persistence and lookup of evidence attachment records.
- Management of short-lived upload authorization sessions.
- Transactional consistency between upload sessions and attached evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.evidence import UploadStatus
from backend.app.models.evidence import (
    EvidenceAttachment,
    EvidenceCustodyEvent,
    UploadSession,
)


class EvidenceRepository:
    """Async database repository for evidence attachments and upload sessions."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_attachment(self, attachment: EvidenceAttachment) -> EvidenceAttachment:
        """Persist a new evidence attachment metadata record."""
        self.session.add(attachment)
        await self.session.flush()
        return attachment

    async def get_attachment_by_id(self, attachment_id: UUID) -> EvidenceAttachment | None:
        """Retrieve an evidence attachment by primary key."""
        result = await self.session.execute(
            select(EvidenceAttachment).where(EvidenceAttachment.id == attachment_id)
        )
        return result.scalars().first()

    async def get_attachment_by_session_id(self, session_id: UUID) -> EvidenceAttachment | None:
        """Retrieve an evidence attachment associated with a specific upload session."""
        result = await self.session.execute(
            select(EvidenceAttachment).where(EvidenceAttachment.upload_session_id == session_id)
        )
        return result.scalars().first()

    async def get_attachment_by_storage_key(self, storage_key: str) -> EvidenceAttachment | None:
        """Retrieve an evidence attachment by unique storage object key."""
        result = await self.session.execute(
            select(EvidenceAttachment).where(EvidenceAttachment.storage_key == storage_key)
        )
        return result.scalars().first()

    async def list_attachments_by_incident(self, incident_id: UUID) -> Sequence[EvidenceAttachment]:
        """List all evidence attachments linked to a target incident."""
        result = await self.session.execute(
            select(EvidenceAttachment)
            .where(EvidenceAttachment.incident_id == incident_id)
            .order_by(EvidenceAttachment.created_at.asc())
        )
        return result.scalars().all()

    async def update_attachment(self, attachment: EvidenceAttachment) -> EvidenceAttachment:
        """Update an existing evidence attachment record."""
        self.session.add(attachment)
        await self.session.flush()
        return attachment

    async def create_upload_session(self, session: UploadSession) -> UploadSession:
        """Persist a new upload authorization session."""
        self.session.add(session)
        await self.session.flush()
        return session

    async def get_upload_session(self, session_id: UUID) -> UploadSession | None:
        """Retrieve an upload session by primary key."""
        result = await self.session.execute(
            select(UploadSession).where(UploadSession.id == session_id)
        )
        return result.scalars().first()

    async def get_upload_session_by_key(self, storage_key: str) -> UploadSession | None:
        """Retrieve an upload session by storage key."""
        result = await self.session.execute(
            select(UploadSession).where(UploadSession.storage_key == storage_key)
        )
        return result.scalars().first()

    async def get_upload_session_by_upload_id(self, upload_id: str) -> UploadSession | None:
        """Retrieve an upload session by its storage provider multipart upload ID."""
        result = await self.session.execute(
            select(UploadSession).where(UploadSession.upload_id == upload_id)
        )
        return result.scalars().first()

    async def update_upload_session(self, session: UploadSession) -> UploadSession:
        """Update an existing upload session."""
        self.session.add(session)
        await self.session.flush()
        return session

    async def get_cumulative_size_by_incident(self, incident_id: UUID) -> int:
        """Calculate cumulative bytes of all attachments belonging to an incident."""
        result = await self.session.execute(
            select(func.coalesce(func.sum(EvidenceAttachment.file_size_bytes), 0)).where(
                EvidenceAttachment.incident_id == incident_id,
                EvidenceAttachment.upload_status != UploadStatus.FAILED.value,
            )
        )
        return int(result.scalar_one())

    async def get_cumulative_size_by_user(self, user_id: UUID) -> int:
        """Calculate cumulative bytes of all attachments uploaded by a user."""
        result = await self.session.execute(
            select(func.coalesce(func.sum(EvidenceAttachment.file_size_bytes), 0)).where(
                EvidenceAttachment.uploader_id == user_id,
                EvidenceAttachment.upload_status != UploadStatus.FAILED.value,
            )
        )
        return int(result.scalar_one())

    async def get_cumulative_size_by_department(self, department_id: UUID) -> int:
        """Calculate cumulative bytes of all attachments across a department."""
        result = await self.session.execute(
            select(func.coalesce(func.sum(EvidenceAttachment.file_size_bytes), 0)).where(
                EvidenceAttachment.department_id == department_id,
                EvidenceAttachment.upload_status != UploadStatus.FAILED.value,
            )
        )
        return int(result.scalar_one())

    async def create_custody_event(self, event: EvidenceCustodyEvent) -> EvidenceCustodyEvent:
        """Persist a new append-only chain-of-custody ledger event."""
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_custody_events_for_attachment(
        self, evidence_id: UUID
    ) -> Sequence[EvidenceCustodyEvent]:
        """List all chain-of-custody ledger events for an evidence attachment in sequence."""
        result = await self.session.execute(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence_id)
            .order_by(EvidenceCustodyEvent.sequence_number.asc())
        )
        return result.scalars().all()

    async def get_latest_custody_event(self, evidence_id: UUID) -> EvidenceCustodyEvent | None:
        """Retrieve the most recent custody event for an evidence attachment."""
        result = await self.session.execute(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence_id)
            .order_by(EvidenceCustodyEvent.sequence_number.desc())
        )
        return result.scalars().first()

    async def get_custody_event_by_id(self, event_id: UUID) -> EvidenceCustodyEvent | None:
        """Retrieve a specific custody event by primary key."""
        result = await self.session.execute(
            select(EvidenceCustodyEvent).where(EvidenceCustodyEvent.id == event_id)
        )
        return result.scalars().first()
