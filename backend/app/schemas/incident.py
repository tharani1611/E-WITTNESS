"""Pydantic v2 validation schemas for Incident reporting (Phases 41-42).

Enforces:
- Strict input validation bounds on title, description, category, and location.
- Future occurrence timestamp rejection.
- Zero leakage of internal security fields or notes in output models.
- Explicit OpenAPI documentation examples.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.exceptions import BusinessRuleError
from backend.app.core.incident import (
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    parse_incident_category,
    parse_incident_severity,
)


class IncidentCreate(BaseModel):
    """Payload for submitting a new incident report."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "title": "Academic misconduct observed in examination hall",
                "description": "Student was observed using unauthorized notes during the midterm exam in Hall 3B.",
                "category": "academic_misconduct",
                "location": "Sciences Complex Hall 3B",
                "occurred_at": "2026-10-14T02:00:00Z",
                "department_id": "a0000000-0000-0000-0000-000000000001",
            }
        },
    )

    title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Concise summary title of the incident (5-200 chars).",
    )
    description: str = Field(
        ...,
        min_length=10,
        max_length=10000,
        description="Detailed narrative statement of the incident (10-10000 chars).",
    )
    category: IncidentCategory = Field(
        ...,
        description="Canonical classification category of the incident.",
    )
    severity: IncidentSeverity = Field(
        default=IncidentSeverity.MEDIUM,
        description="Triage severity level of the incident (low, medium, high, critical).",
    )
    location: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Structured descriptive physical location of the occurrence.",
    )
    occurred_at: datetime = Field(
        ...,
        description="UTC timestamp when the incident occurred (must not be in the future).",
    )
    department_id: UUID | None = Field(
        default=None,
        description="Target department ID. Defaults to caller's assigned department if omitted.",
    )

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> IncidentCategory:
        if isinstance(value, IncidentCategory):
            return value
        if isinstance(value, str):
            try:
                return parse_incident_category(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError("Invalid incident category format.")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: Any) -> IncidentSeverity:
        if isinstance(value, IncidentSeverity):
            return value
        if isinstance(value, str):
            try:
                return parse_incident_severity(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError("Invalid incident severity format.")

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_not_future(cls, value: datetime) -> datetime:
        now = datetime.now(UTC)
        # Ensure value is timezone-aware
        val_utc = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        if val_utc > now:
            raise ValueError("Incident occurred_at timestamp cannot be in the future.")
        return val_utc


class IncidentUpdate(BaseModel):
    """Payload for updating permitted incident fields while in SUBMITTED status."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "title": "Updated incident title",
                "description": "Amended narrative with additional factual details.",
                "location": "Sciences Complex Hall 3B Room 202",
            }
        },
    )

    title: str | None = Field(
        default=None,
        min_length=5,
        max_length=200,
        description="Updated summary title of the incident.",
    )
    description: str | None = Field(
        default=None,
        min_length=10,
        max_length=10000,
        description="Updated narrative statement.",
    )
    category: IncidentCategory | None = Field(
        default=None,
        description="Updated incident category.",
    )
    severity: IncidentSeverity | None = Field(
        default=None,
        description="Updated incident severity level.",
    )
    location: str | None = Field(
        default=None,
        min_length=2,
        max_length=255,
        description="Updated descriptive location.",
    )
    occurred_at: datetime | None = Field(
        default=None,
        description="Updated occurrence timestamp.",
    )

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> IncidentCategory | None:
        if value is None or isinstance(value, IncidentCategory):
            return value
        if isinstance(value, str):
            try:
                return parse_incident_category(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError("Invalid incident category format.")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: Any) -> IncidentSeverity | None:
        if value is None or isinstance(value, IncidentSeverity):
            return value
        if isinstance(value, str):
            try:
                return parse_incident_severity(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError("Invalid incident severity format.")

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_not_future(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        now = datetime.now(UTC)
        val_utc = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        if val_utc > now:
            raise ValueError("Incident occurred_at timestamp cannot be in the future.")
        return val_utc


class IncidentStatusTransitionRequest(BaseModel):
    """Payload for administrative workflow status transitions."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "status": "triaged",
                "reason": "Department intake completed; routed for formal investigation.",
            }
        },
    )

    status: IncidentStatus = Field(
        ...,
        description="Target lifecycle state to transition the incident into.",
    )
    reason: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional administrative justification for the transition.",
    )


class IncidentRead(BaseModel):
    """Public safe representation of an incident record."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "b1111111-1111-1111-1111-111111111111",
                "reference_number": "INC-2026-A1B2C3D4",
                "title": "Academic misconduct observed in examination hall",
                "description": "Student was observed using unauthorized notes during the midterm exam.",
                "category": "academic_misconduct",
                "severity": "medium",
                "status": "submitted",
                "location": "Sciences Complex Hall 3B",
                "occurred_at": "2026-10-14T02:00:00Z",
                "reporter_id": "c2222222-2222-2222-2222-222222222222",
                "department_id": "a0000000-0000-0000-0000-000000000001",
                "created_at": "2026-10-14T02:30:00Z",
                "updated_at": "2026-10-14T02:30:00Z",
            }
        },
    )

    id: UUID = Field(..., description="Unique persistent incident identifier.")
    reference_number: str = Field(..., description="Unique opaque incident reference code.")
    title: str = Field(..., description="Incident title.")
    description: str = Field(..., description="Incident narrative statement.")
    category: str = Field(..., description="Incident category.")
    severity: str = Field(default="medium", description="Triage severity level.")
    status: str = Field(..., description="Current lifecycle state.")
    location: str = Field(..., description="Structured descriptive location.")
    occurred_at: datetime = Field(..., description="Occurrence timestamp.")
    reporter_id: UUID = Field(..., description="Submitting user identifier.")
    department_id: UUID = Field(..., description="Assigned department identifier.")
    assigned_reviewer_id: UUID | None = Field(
        default=None, description="Assigned reviewer user identifier."
    )
    assignment_status: str = Field(
        default="unassigned", description="Current assignment lifecycle status."
    )
    assigned_at: datetime | None = Field(
        default=None, description="Timestamp when reviewer was assigned."
    )
    acknowledged_at: datetime | None = Field(
        default=None, description="Timestamp when reviewer acknowledged assignment."
    )
    created_at: datetime = Field(..., description="Creation UTC timestamp.")
    updated_at: datetime = Field(..., description="Last update UTC timestamp.")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: Any) -> str:
        if not value:
            return "medium"
        if hasattr(value, "value"):
            return str(value.value)
        return str(value)

    @field_validator("assignment_status", mode="before")
    @classmethod
    def validate_assignment_status(cls, value: Any) -> str:
        if not value:
            return "unassigned"
        if hasattr(value, "value"):
            return str(value.value)
        return str(value)


class ReviewQueueWorkloadSummary(BaseModel):
    """Workload summary counts for review queue (Phase 56)."""

    model_config = ConfigDict(from_attributes=True)

    pending: int = Field(0, description="Total pending review/triage incidents.")
    assigned: int = Field(0, description="Total assigned incidents.")
    unassigned: int = Field(0, description="Total unassigned incidents.")
    overdue: int = Field(0, description="Total overdue review items.")
    completed: int = Field(0, description="Total resolved/closed incidents.")
    total: int = Field(0, description="Total incidents in scope.")


class ReviewerAssignRequest(BaseModel):
    """Payload for assigning a reviewer to an incident (Phase 57)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reviewer_id: UUID = Field(..., description="Target reviewer user ID.")
    reason: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional administrative notes or justification for assignment.",
    )


class ReviewerReassignRequest(BaseModel):
    """Payload for reassigning an incident to another reviewer (Phase 57)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reviewer_id: UUID = Field(..., description="New reviewer user ID.")
    reason: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="Mandatory administrative justification for reassignment.",
    )


class IncidentAssignmentRead(BaseModel):
    """Audit record of a reviewer assignment transition (Phase 57)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Unique assignment record identifier.")
    incident_id: UUID = Field(..., description="Target incident identifier.")
    reviewer_id: UUID = Field(..., description="Assigned reviewer user identifier.")
    assigned_by_id: UUID = Field(..., description="User who performed the assignment.")
    status: str = Field(..., description="Assignment state at record creation.")
    reason: str | None = Field(None, description="Administrative justification text.")
    created_at: datetime = Field(..., description="UTC timestamp of the assignment record.")


class IncidentRouteOverrideRequest(BaseModel):
    """Payload for authorized administrative department re-routing of an incident (Phase 55)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_department_id: UUID = Field(
        ..., description="Target department ID to re-route the incident to."
    )
    reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Mandatory administrative justification for routing override.",
    )


class IncidentRoutingDecisionRead(BaseModel):
    """Public representation of a traceable routing decision record (Phase 55)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Unique routing record identifier.")
    incident_id: UUID = Field(..., description="Target incident identifier.")
    source_department_id: UUID | None = Field(None, description="Originating department ID.")
    target_department_id: UUID = Field(..., description="Assigned destination department ID.")
    assigned_by_id: UUID | None = Field(
        None, description="User who executed override (null if system rule)."
    )
    routing_type: str = Field(
        ..., description="Origin of routing (system_rule or authorized_override)."
    )
    rule_applied: str = Field(
        ..., description="Description of deterministic rule applied or override action."
    )
    reason: str | None = Field(None, description="Administrative justification text if overridden.")
    created_at: datetime = Field(..., description="UTC timestamp of the routing decision.")
