"""Incident persistence entity and lifecycle constraints (Phases 41-42).

Enforces:
- Normalized, unique incident reference numbers (`INC-YYYY-XXXXXXXX`).
- Category validation from canonical `IncidentCategory` domain values.
- Explicit lifecycle status transitions (`IncidentStatus`).
- Strong foreign-key bindings to submitting `users` and target `departments`.
- Occurrence timestamp bounds and structured location text constraints.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.incident import (
    AssignmentStatus,
    IncidentCategory,
    IncidentRoutingType,
    IncidentSeverity,
    IncidentStatus,
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
    from backend.app.models.evidence import EvidenceAttachment, UploadSession
    from backend.app.models.user import User


_CATEGORY_VALUES = ", ".join(f"'{c.value}'" for c in IncidentCategory)
_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in IncidentStatus)
_SEVERITY_VALUES = ", ".join(f"'{s.value}'" for s in IncidentSeverity)
_ASSIGNMENT_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in AssignmentStatus)


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Incident report entity (`incidents` table)."""

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_department_id_status", "department_id", "status"),
        Index("ix_incidents_reporter_id_status", "reporter_id", "status"),
        Index("ix_incidents_assigned_reviewer_id_status", "assigned_reviewer_id", "status"),
        Index(
            "ix_incidents_department_id_assignment_status",
            "department_id",
            "assignment_status",
        ),
        CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_incidents_title_length",
        ),
        CheckConstraint(
            "length(trim(description)) >= 10 AND length(description) <= 10000",
            name="ck_incidents_description_length",
        ),
        CheckConstraint(
            "length(trim(location)) >= 2 AND length(location) <= 255",
            name="ck_incidents_location_length",
        ),
        CheckConstraint(
            f"category IN ({_CATEGORY_VALUES})",
            name="ck_incidents_category_allowed_values",
        ),
        CheckConstraint(
            f"status IN ({_STATUS_VALUES})",
            name="ck_incidents_status_allowed_values",
        ),
        CheckConstraint(
            f"severity IN ({_SEVERITY_VALUES})",
            name="ck_incidents_severity_allowed_values",
        ),
        CheckConstraint(
            f"assignment_status IN ({_ASSIGNMENT_STATUS_VALUES})",
            name="ck_incidents_assignment_status_allowed_values",
        ),
        CheckConstraint(
            "reference_number = upper(trim(reference_number)) AND length(reference_number) >= 12",
            name="ck_incidents_reference_number_normalized",
        ),
    )

    reference_number: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        unique=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        String(10000),
        nullable=False,
    )
    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=IncidentSeverity.MEDIUM.value,
        server_default=IncidentSeverity.MEDIUM.value,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=IncidentStatus.SUBMITTED.value,
        server_default=IncidentStatus.SUBMITTED.value,
        index=True,
    )
    location: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )
    reporter_id: Mapped[UUID] = mapped_column(
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
    assigned_reviewer_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    assignment_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AssignmentStatus.UNASSIGNED.value,
        server_default=AssignmentStatus.UNASSIGNED.value,
        index=True,
    )
    assigned_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )

    # Relational associations
    reporter: Mapped[User] = relationship(
        "User",
        foreign_keys=[reporter_id],
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    assigned_reviewer: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[assigned_reviewer_id],
        lazy="selectin",
    )
    attachments: Mapped[list[EvidenceAttachment]] = relationship(
        "EvidenceAttachment",
        back_populates="incident",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    upload_sessions: Mapped[list[UploadSession]] = relationship(
        "UploadSession",
        back_populates="incident",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    routing_decisions: Mapped[list[IncidentRoutingDecision]] = relationship(
        "IncidentRoutingDecision",
        back_populates="incident",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="IncidentRoutingDecision.created_at",
    )
    assignments: Mapped[list[IncidentAssignment]] = relationship(
        "IncidentAssignment",
        back_populates="incident",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="IncidentAssignment.created_at",
    )

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.id} ref={self.reference_number!r} "
            f"status={self.status!r} severity={self.severity!r} dept_id={self.department_id}>"
        )


class IncidentRoutingDecision(UUIDPrimaryKeyMixin, Base):
    """Traceable incident department routing decision entity (`incident_routing_decisions` table).

    Implements requirements for deterministic configurable routing and authorized overrides (Phase 55).
    """

    __tablename__ = "incident_routing_decisions"
    __table_args__ = (
        CheckConstraint(
            f"routing_type IN ('{IncidentRoutingType.SYSTEM_RULE.value}', '{IncidentRoutingType.AUTHORIZED_OVERRIDE.value}')",
            name="ck_incident_routing_decisions_type",
        ),
    )

    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    target_department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    assigned_by_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    routing_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=IncidentRoutingType.SYSTEM_RULE.value,
        server_default=IncidentRoutingType.SYSTEM_RULE.value,
        index=True,
    )
    rule_applied: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(
        String(1000),
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
        back_populates="routing_decisions",
        lazy="selectin",
    )
    target_department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[target_department_id],
        lazy="selectin",
    )
    assigned_by: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[assigned_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentRoutingDecision id={self.id} incident_id={self.incident_id} "
            f"target_dept={self.target_department_id} type={self.routing_type!r}>"
        )


class IncidentAssignment(UUIDPrimaryKeyMixin, Base):
    """Traceable reviewer assignment record for incidents (Phase 57).

    Enforces:
    - Chronological history of reviewer assignments, reassignments, and acknowledgements.
    - Captures assigned reviewer, assigner, state, and justification reasons.
    """

    __tablename__ = "incident_assignments"
    __table_args__ = (
        CheckConstraint(
            f"status IN ('{AssignmentStatus.ASSIGNED.value}', '{AssignmentStatus.ACKNOWLEDGED.value}', '{AssignmentStatus.REASSIGNED.value}', '{AssignmentStatus.UNASSIGNED.value}')",
            name="ck_incident_assignments_status_allowed_values",
        ),
    )

    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reviewer_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    assigned_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AssignmentStatus.ASSIGNED.value,
        server_default=AssignmentStatus.ASSIGNED.value,
        index=True,
    )
    reason: Mapped[str | None] = mapped_column(
        String(1000),
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
        back_populates="assignments",
        lazy="selectin",
    )
    reviewer: Mapped[User] = relationship(
        "User",
        foreign_keys=[reviewer_id],
        lazy="selectin",
    )
    assigned_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[assigned_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentAssignment id={self.id} incident_id={self.incident_id} "
            f"reviewer_id={self.reviewer_id} status={self.status!r}>"
        )
