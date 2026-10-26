"""Pydantic v2 schemas for Security Audit and Evidence Export (Phases 58-59).

Covers:
- Tamper-evident audit event serialization and verification reporting.
- Search filters with strict bounded pagination (max 100).
- Evidence export requests and manifest metadata responses.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.audit import AUDIT_DISCLAIMER, AuditAction, AuditOutcome, AuditTargetType


class SecurityAuditEventRead(BaseModel):
    """Public safe representation of a tamper-evident security audit event."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Unique event identifier.")
    sequence_number: int = Field(..., description="Monotonically increasing sequence number.")
    action: str = Field(..., description="Action classification name.")
    actor_id: UUID | None = Field(
        None, description="User who initiated the action (or null for system)."
    )
    actor_role: str | None = Field(None, description="Role of the actor at time of event.")
    actor_ip: str | None = Field(None, description="IP address of the caller.")
    actor_user_agent: str | None = Field(None, description="User agent string of the caller.")
    department_id: UUID | None = Field(None, description="Department scope ID.")
    target_type: str = Field(..., description="Classification of target object.")
    target_id: str = Field(..., description="Target object identifier.")
    outcome: str = Field(..., description="Result outcome: success, failure, denied.")
    details: dict[str, Any] | None = Field(None, description="Structured action context.")
    previous_event_hash: str | None = Field(
        None, description="Hash of the preceding event in the chain."
    )
    event_hash: str = Field(..., description="SHA-256 integrity hash of this record.")
    created_at: datetime = Field(..., description="UTC timestamp of the audit entry.")

    @field_validator("details", mode="before")
    @classmethod
    def parse_details_json(cls, value: Any) -> dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {"raw": parsed}
            except Exception:
                return {"raw": value}
        return {"raw": str(value)}


class AuditSearchFilterParams(BaseModel):
    """Query parameters for searching security audit events (Phase 59)."""

    model_config = ConfigDict(extra="forbid")

    actor_id: UUID | None = Field(None, description="Filter by initiating actor ID.")
    action: AuditAction | str | None = Field(None, description="Filter by audit action.")
    target_type: AuditTargetType | str | None = Field(None, description="Filter by target type.")
    target_id: str | None = Field(None, max_length=128, description="Filter by exact target ID.")
    department_id: UUID | None = Field(None, description="Filter by department ID.")
    outcome: AuditOutcome | str | None = Field(None, description="Filter by outcome.")
    start_time: datetime | None = Field(None, description="Earliest UTC created_at timestamp.")
    end_time: datetime | None = Field(None, description="Latest UTC created_at timestamp.")
    page: int = Field(default=1, ge=1, description="Page number (1-based).")
    page_size: int = Field(default=50, ge=1, le=100, description="Items per page (max 100).")


class AuditVerificationReport(BaseModel):
    """Cryptographic chain verification result report (Phase 58)."""

    model_config = ConfigDict(from_attributes=True)

    status: str = Field(..., description="Audit chain status: verified, compromised, or empty.")
    chain_valid: bool = Field(..., description="True if all hashes and links match consecutively.")
    total_events_verified: int = Field(..., description="Count of evaluated ledger entries.")
    first_sequence_number: int | None = Field(
        None, description="Starting sequence number in verified range."
    )
    last_sequence_number: int | None = Field(
        None, description="Ending sequence number in verified range."
    )
    tampered_event_ids: list[UUID] = Field(
        default_factory=list, description="IDs of records failing verification."
    )
    tampered_sequence_numbers: list[int] = Field(
        default_factory=list, description="Sequence numbers of broken chain nodes."
    )
    errors: list[str] = Field(
        default_factory=list, description="Descriptive diagnostic mismatch explanations."
    )
    disclaimer: str = Field(
        default=AUDIT_DISCLAIMER,
        description="Mandatory legal and integrity verification scope limitation disclosure.",
    )
    verified_at: datetime = Field(
        ..., description="UTC timestamp when verification check was executed."
    )


class EvidenceExportRequest(BaseModel):
    """Payload for requesting an evidence export archive or manifest (Phase 59)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    export_scope: str = Field(
        default="incident_package",
        description="Scope of export: incident_package, single_evidence, or custody_bundle.",
    )
    export_format: str = Field(
        default="zip",
        description="Archive format: zip, json_manifest, or tar_gz.",
    )
    reason: str | None = Field(
        default=None,
        max_length=500,
        description="Optional justification statement for legal or supervisory records.",
    )

    @field_validator("export_scope")
    @classmethod
    def validate_export_scope(cls, value: str) -> str:
        allowed = {"incident_package", "single_evidence", "custody_bundle"}
        if value not in allowed:
            raise ValueError(f"Invalid export scope: {value}. Allowed: {sorted(allowed)}")
        return value

    @field_validator("export_format")
    @classmethod
    def validate_export_format(cls, value: str) -> str:
        allowed = {"zip", "json_manifest", "tar_gz"}
        if value not in allowed:
            raise ValueError(f"Invalid export format: {value}. Allowed: {sorted(allowed)}")
        return value


class EvidenceExportResponse(BaseModel):
    """Result metadata for an authorized evidence export package."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Unique export record identifier.")
    incident_id: UUID = Field(..., description="Target incident identifier.")
    department_id: UUID = Field(..., description="Department scope of exported incident.")
    exported_by_id: UUID = Field(..., description="User who generated the export.")
    export_scope: str = Field(..., description="Export scope applied.")
    export_format: str = Field(..., description="Archive format created.")
    evidence_count: int = Field(..., description="Total evidence objects included in export.")
    manifest_sha256: str = Field(..., description="SHA-256 digest of export manifest.")
    status: str = Field(..., description="Status of the export package.")
    reason: str | None = Field(None, description="Justification provided by exporter.")
    created_at: datetime = Field(..., description="UTC creation timestamp.")
