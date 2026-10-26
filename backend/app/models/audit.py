"""Security audit event and evidence export persistence models (Phases 58-59).

Enforces:
- Append-only security audit event ledger (`security_audit_events`).
- Cryptographic hash chaining (`previous_event_hash`, `event_hash`).
- Strict relational bounds and foreign keys to actor `users` and scope `departments`.
- Tamper-evident evidence export logging (`evidence_exports`).
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
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.audit import AuditOutcome
from backend.app.models.base import (
    Base,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.department import Department
    from backend.app.models.incident import Incident
    from backend.app.models.user import User


class SecurityAuditEvent(UUIDPrimaryKeyMixin, Base):
    """Immutable, append-only security audit event entity (`security_audit_events` table).

    Implements Phase 58 requirements:
    - Cryptographic SHA-256 hash chaining across events.
    - Captures actor identity, UTC timestamp, action, target reference, outcome, and minimal context.
    - Omits credentials, access tokens, and sensitive secrets.
    """

    __tablename__ = "security_audit_events"
    __table_args__ = (
        CheckConstraint(
            f"outcome IN ('{AuditOutcome.SUCCESS.value}', '{AuditOutcome.FAILURE.value}', '{AuditOutcome.DENIED.value}')",
            name="ck_security_audit_events_outcome_allowed_values",
        ),
        Index("ix_security_audit_events_target_type_id", "target_type", "target_id"),
        Index("ix_security_audit_events_department_created", "department_id", "created_at"),
    )

    sequence_number: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_role: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    actor_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    actor_user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    target_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    previous_event_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )

    actor: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[actor_id],
        lazy="selectin",
    )
    department: Mapped[Department | None] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityAuditEvent id={self.id} seq={self.sequence_number} "
            f"action={self.action!r} outcome={self.outcome!r} dept_id={self.department_id}>"
        )


class EvidenceExport(UUIDPrimaryKeyMixin, Base):
    """Traceable manifest entity for authorized evidence package exports (`evidence_exports` table).

    Implements Phase 59 requirements:
    - Scoped evidence access and export operation tracking.
    - Records export scope, format, evidence item count, and cryptographic manifest digest.
    """

    __tablename__ = "evidence_exports"
    __table_args__ = (
        CheckConstraint(
            "export_scope IN ('single_evidence', 'incident_package', 'custody_bundle')",
            name="ck_evidence_exports_scope_allowed_values",
        ),
        CheckConstraint(
            "export_format IN ('zip', 'json_manifest', 'tar_gz')",
            name="ck_evidence_exports_format_allowed_values",
        ),
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
    exported_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    export_scope: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="incident_package",
    )
    export_format: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="zip",
    )
    evidence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    manifest_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="completed",
        index=True,
    )
    reason: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )

    incident: Mapped[Incident] = relationship(
        "Incident",
        foreign_keys=[incident_id],
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    exported_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[exported_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceExport id={self.id} incident_id={self.incident_id} "
            f"count={self.evidence_count} exported_by={self.exported_by_id}>"
        )
