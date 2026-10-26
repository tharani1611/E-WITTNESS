"""Evidence attachment and upload session persistence entities (Phases 43-44).

Enforces:
- Opaque, server-generated storage object keys.
- Separation of physical file storage from database metadata.
- Cryptographic hash storage and file verification metadata.
- Short-lived upload authorization session lifecycle.
- Relational integrity binding evidence to parent incidents, uploaders, and departments.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.evidence import (
    CustodyActionType,
    EvidenceStatus,
    ScanStatus,
    UploadSessionStatus,
    UploadStatus,
)
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.department import Department
    from backend.app.models.incident import Incident
    from backend.app.models.user import User


_UPLOAD_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in UploadStatus)
_EVIDENCE_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in EvidenceStatus)
_SESSION_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in UploadSessionStatus)
_SCAN_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in ScanStatus)
_CUSTODY_ACTION_VALUES = ", ".join(f"'{s.value}'" for s in CustodyActionType)


class EvidenceAttachment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Evidence file attachment metadata entity (`evidence_attachments` table)."""

    __tablename__ = "evidence_attachments"
    __table_args__ = (
        CheckConstraint(
            "file_size_bytes > 0",
            name="ck_evidence_attachments_size_positive",
        ),
        CheckConstraint(
            "sha256_hash IS NULL OR length(sha256_hash) = 64",
            name="ck_evidence_attachments_sha256_length",
        ),
        CheckConstraint(
            f"upload_status IN ({_UPLOAD_STATUS_VALUES})",
            name="ck_evidence_attachments_upload_status",
        ),
        CheckConstraint(
            f"evidence_status IN ({_EVIDENCE_STATUS_VALUES})",
            name="ck_evidence_attachments_evidence_status",
        ),
        CheckConstraint(
            f"scan_status IN ({_SCAN_STATUS_VALUES})",
            name="ck_evidence_attachments_scan_status",
        ),
    )

    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    uploader_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    upload_session_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("upload_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    storage_key: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        unique=True,
        index=True,
    )
    declared_mime_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    detected_mime_type: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        default=None,
    )
    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    sha256_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        default=None,
        index=True,
    )
    upload_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=UploadStatus.PENDING.value,
        server_default=UploadStatus.PENDING.value,
        index=True,
    )
    evidence_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=EvidenceStatus.ATTACHED.value,
        server_default=EvidenceStatus.ATTACHED.value,
        index=True,
    )
    scan_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ScanStatus.PENDING.value,
        server_default=ScanStatus.PENDING.value,
        index=True,
    )
    scanned_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )
    scan_details: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        default=None,
    )
    ingested_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
        index=True,
    )
    client_reported_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )
    uploader_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        default=None,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )

    # Relational associations
    incident: Mapped[Incident] = relationship(
        "Incident",
        back_populates="attachments",
        lazy="selectin",
    )
    uploader: Mapped[User] = relationship(
        "User",
        foreign_keys=[uploader_id],
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    upload_session: Mapped[UploadSession | None] = relationship(
        "UploadSession",
        foreign_keys=[upload_session_id],
        lazy="selectin",
    )
    custody_events: Mapped[list[EvidenceCustodyEvent]] = relationship(
        "EvidenceCustodyEvent",
        back_populates="evidence",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="EvidenceCustodyEvent.sequence_number",
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceAttachment id={self.id} incident_id={self.incident_id} "
            f"file={self.original_filename!r} status={self.upload_status!r}>"
        )


class UploadSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Authorized single-use evidence upload session entity (`upload_sessions` table)."""

    __tablename__ = "upload_sessions"
    __table_args__ = (
        CheckConstraint(
            "expected_size_bytes > 0",
            name="ck_upload_sessions_size_positive",
        ),
        CheckConstraint(
            f"session_status IN ({_SESSION_STATUS_VALUES})",
            name="ck_upload_sessions_status",
        ),
    )

    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    uploader_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    storage_key: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        unique=True,
        index=True,
    )
    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    declared_mime_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    expected_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )
    session_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=UploadSessionStatus.ACTIVE.value,
        server_default=UploadSessionStatus.ACTIVE.value,
        index=True,
    )
    upload_id: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        default=None,
        index=True,
    )
    total_parts: Mapped[int | None] = mapped_column(
        nullable=True,
        default=None,
    )
    part_size_bytes: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        default=None,
    )

    # Relational associations
    incident: Mapped[Incident] = relationship(
        "Incident",
        back_populates="upload_sessions",
        lazy="selectin",
    )
    uploader: Mapped[User] = relationship(
        "User",
        foreign_keys=[uploader_id],
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )

    def is_valid_at(self, moment: datetime) -> bool:
        """Return True if session is ACTIVE and unexpired at ``moment``."""
        return self.session_status == UploadSessionStatus.ACTIVE.value and self.expires_at > moment

    def __repr__(self) -> str:
        return (
            f"<UploadSession id={self.id} incident_id={self.incident_id} "
            f"status={self.session_status!r} expires_at={self.expires_at}>"
        )


class EvidenceCustodyEvent(UUIDPrimaryKeyMixin, Base):
    """Append-only chain-of-custody ledger event entity (`evidence_custody_events` table).

    Implements requirements EVI-004 and AUD-003:
    - Monotonically increasing sequence number per evidence item.
    - Explicit custody action types (INGESTED, HASH_VERIFIED, QUARANTINED, etc.).
    - Cryptographic hash chaining (`previous_event_hash` + event payload -> `event_hash`).
    - Immutable audit trail with support for linked compensating events.
    """

    __tablename__ = "evidence_custody_events"
    __table_args__ = (
        UniqueConstraint(
            "evidence_id",
            "sequence_number",
            name="uq_custody_events_evidence_sequence",
        ),
        Index("ix_custody_events_evidence_sequence", "evidence_id", "sequence_number"),
        CheckConstraint(
            "sequence_number > 0",
            name="ck_custody_events_sequence_positive",
        ),
        CheckConstraint(
            f"action_type IN ({_CUSTODY_ACTION_VALUES})",
            name="ck_custody_events_action_type",
        ),
    )

    evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_attachments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sequence_number: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    actor_role: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    actor_department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )
    evidence_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    previous_event_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    details: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
        default=None,
    )
    compensates_event_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_custody_events.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    compensation_reason: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )

    # Relational associations
    evidence: Mapped[EvidenceAttachment] = relationship(
        "EvidenceAttachment",
        back_populates="custody_events",
        lazy="selectin",
    )
    actor: Mapped[User] = relationship(
        "User",
        foreign_keys=[actor_id],
        lazy="selectin",
    )
    compensates_event: Mapped[EvidenceCustodyEvent | None] = relationship(
        "EvidenceCustodyEvent",
        remote_side="EvidenceCustodyEvent.id",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceCustodyEvent id={self.id} evidence_id={self.evidence_id} "
            f"seq={self.sequence_number} action={self.action_type!r}>"
        )
