"""Pydantic v2 DTO schemas for Department, Role, User, and Session entities (Phases 14-15).

Enforces strict model-to-schema boundaries (`from_attributes=True`, `extra="forbid"`)
and applies deterministic identity normalization (`email`, `institutional_id`,
`code`) at the schema validation boundary.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.core.identity import (
    AccountStatus,
    RoleCode,
    SessionStatus,
    normalize_department_code,
    normalize_email,
    normalize_institutional_id,
)


class DepartmentCreate(BaseModel):
    """Input schema for creating a new institutional department."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "code": "FORENSICS",
                "name": "Digital Forensics Department",
                "description": "Specialized investigations into digital evidence and network anomalies.",
            }
        },
    )

    code: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("code")
    @classmethod
    def _validate_code(cls, value: str) -> str:
        return normalize_department_code(value)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Department name must be at least 2 non-whitespace characters.")
        return cleaned


class DepartmentRead(BaseModel):
    """Output DTO representing a persisted Department."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        json_schema_extra={
            "example": {
                "id": "11111111-1111-4111-8111-111111111111",
                "code": "FORENSICS",
                "name": "Digital Forensics Department",
                "description": "Specialized investigations into digital evidence and network anomalies.",
                "is_active": True,
                "deactivated_at": None,
                "created_at": "2026-10-14T00:00:00Z",
                "updated_at": "2026-10-14T00:00:00Z",
            }
        },
    )

    id: UUID
    code: str
    name: str
    description: str | None
    is_active: bool
    deactivated_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DepartmentUpdate(BaseModel):
    """Input schema for updating an institutional department."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "name": "Updated Digital Forensics Department",
                "description": "Updated scope for institutional evidence handling.",
                "is_active": True,
            }
        },
    )

    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    is_active: bool | None = Field(default=None)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Department name must be at least 2 non-whitespace characters.")
        return cleaned


class RoleCreate(BaseModel):
    """Input schema for registering a stakeholder role."""

    model_config = ConfigDict(extra="forbid")

    code: RoleCode
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(..., min_length=5, max_length=2000)
    requires_department_scope: bool = Field(default=True)
    is_system_role: bool = Field(default=True)


class RoleRead(BaseModel):
    """Output DTO representing a persisted Role."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        json_schema_extra={
            "example": {
                "id": "22222222-2222-4222-8222-222222222222",
                "code": "investigator",
                "name": "Investigator",
                "description": "Assigned case reviewer who examines evidence and manages investigations.",
                "requires_department_scope": True,
                "is_system_role": True,
                "created_at": "2026-10-14T00:00:00Z",
                "updated_at": "2026-10-14T00:00:00Z",
            }
        },
    )

    id: UUID
    code: RoleCode
    name: str
    description: str
    requires_department_scope: bool
    is_system_role: bool
    created_at: datetime
    updated_at: datetime


class UserCreate(BaseModel):
    """Input schema for creating a user identity record (no password/token fields in Phase 15)."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=5, max_length=254)
    institutional_id: str | None = Field(default=None, max_length=64)
    full_name: str = Field(..., min_length=2, max_length=160)
    role_id: UUID
    department_id: UUID | None = Field(default=None)
    account_status: AccountStatus = Field(default=AccountStatus.PENDING_VERIFICATION)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("institutional_id")
    @classmethod
    def _validate_institutional_id(cls, value: str | None) -> str | None:
        return normalize_institutional_id(value)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 non-whitespace characters.")
        return cleaned


class UserRead(BaseModel):
    """Output DTO representing a persisted User identity."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        json_schema_extra={
            "example": {
                "id": "33333333-3333-4333-8333-333333333333",
                "email": "investigator.lead@ewitness.edu",
                "institutional_id": "INST-INV-001",
                "full_name": "Detective Sarah Connor",
                "account_status": "active",
                "is_active": True,
                "department_id": "11111111-1111-4111-8111-111111111111",
                "role_id": "22222222-2222-4222-8222-222222222222",
                "verified_at": "2026-10-14T00:00:00Z",
                "deactivated_at": None,
                "deactivation_reason": None,
                "created_at": "2026-10-14T00:00:00Z",
                "updated_at": "2026-10-14T00:00:00Z",
            }
        },
    )

    id: UUID
    email: str
    institutional_id: str | None
    full_name: str
    account_status: AccountStatus
    is_active: bool
    department_id: UUID | None
    role_id: UUID
    verified_at: datetime | None
    deactivated_at: datetime | None
    deactivation_reason: str | None
    created_at: datetime
    updated_at: datetime


class UserAdminCreate(BaseModel):
    """Input schema for administrative user provisioning."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "email": "investigator.lead@ewitness.edu",
                "full_name": "Detective Sarah Connor",
                "role_id": "22222222-2222-4222-8222-222222222222",
                "department_id": "11111111-1111-4111-8111-111111111111",
                "institutional_id": "INST-INV-001",
                "password": "ExampleSecurePassword123!",
                "account_status": "active",
            }
        },
    )

    email: str = Field(..., min_length=5, max_length=254)
    full_name: str = Field(..., min_length=2, max_length=160)
    role_id: UUID
    department_id: UUID | None = Field(default=None)
    institutional_id: str | None = Field(default=None, max_length=64)
    password: str = Field(..., min_length=12, max_length=128)
    account_status: AccountStatus = Field(default=AccountStatus.ACTIVE)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("institutional_id")
    @classmethod
    def _validate_institutional_id(cls, value: str | None) -> str | None:
        return normalize_institutional_id(value)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 non-whitespace characters.")
        return cleaned


class UserUpdate(BaseModel):
    """Input schema for administrative user modification."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "full_name": "Detective Sarah Connor-Reese",
                "role_id": "22222222-2222-4222-8222-222222222222",
                "department_id": "11111111-1111-4111-8111-111111111111",
                "account_status": "active",
                "is_active": True,
            }
        },
    )

    full_name: str | None = Field(default=None, min_length=2, max_length=160)
    role_id: UUID | None = Field(default=None)
    department_id: UUID | None = Field(default=None)
    account_status: AccountStatus | None = Field(default=None)
    is_active: bool | None = Field(default=None)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 non-whitespace characters.")
        return cleaned


class UserProfileUpdate(BaseModel):
    """Input schema for self-service profile modification."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "full_name": "Detective Sarah Connor",
            }
        },
    )

    full_name: str = Field(..., min_length=2, max_length=160)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 non-whitespace characters.")
        return cleaned


class SessionCreate(BaseModel):
    """Input schema for creating a user session metadata record."""

    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    department_id: UUID | None = Field(default=None)
    client_ip: str | None = Field(default=None, max_length=45)
    user_agent: str | None = Field(default=None, max_length=512)
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def _validate_expiry_window(self) -> SessionCreate:
        if self.expires_at <= self.issued_at:
            raise ValueError("Session expires_at must be strictly greater than issued_at.")
        return self


class SessionRead(BaseModel):
    """Output DTO representing a persisted User Session."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    user_id: UUID
    department_id: UUID | None
    status: SessionStatus
    client_ip: str | None
    user_agent: str | None
    issued_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    created_at: datetime
    updated_at: datetime


class UserDeactivateRequest(BaseModel):
    """Input schema for administrative deactivation of an account."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "reason": "Administrative transition or investigation leave.",
            }
        },
    )

    reason: str | None = Field(default=None, max_length=255)


class UserDepartmentAssignRequest(BaseModel):
    """Input schema for assigning or reassigning a user's department."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "department_id": "11111111-1111-4111-8111-111111111111",
            }
        },
    )

    department_id: UUID


class InvestigatorAssignRequest(BaseModel):
    """Input schema for assigning an investigator to an institutional department (Phase 36)."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "investigator_id": "33333333-3333-4333-8333-333333333333",
            }
        },
    )

    investigator_id: UUID = Field(
        ...,
        alias="user_id",
        description="Unique identifier of the active investigator user to assign.",
    )


class StaffInviteRequest(BaseModel):
    """Input schema for inviting a staff or investigator account (Phase 32)."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "email": "investigator.invited@ewitness.edu",
                "full_name": "Detective Marcus Wright",
                "role_id": "22222222-2222-4222-8222-222222222222",
                "department_id": "11111111-1111-4111-8111-111111111111",
                "institutional_id": "INST-INV-042",
            }
        },
    )

    email: str = Field(..., min_length=5, max_length=254)
    full_name: str = Field(..., min_length=2, max_length=160)
    role_id: UUID
    department_id: UUID | None = Field(default=None)
    institutional_id: str | None = Field(default=None, max_length=64)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("institutional_id")
    @classmethod
    def _validate_institutional_id(cls, value: str | None) -> str | None:
        return normalize_institutional_id(value)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 non-whitespace characters.")
        return cleaned


class StaffInviteResponse(BaseModel):
    """Output DTO for staff invitation creation."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "user": {
                    "id": "33333333-3333-4333-8333-333333333333",
                    "email": "investigator.invited@ewitness.edu",
                    "institutional_id": "INST-INV-042",
                    "full_name": "Detective Marcus Wright",
                    "account_status": "pending_verification",
                    "is_active": False,
                    "department_id": "11111111-1111-4111-8111-111111111111",
                    "role_id": "22222222-2222-4222-8222-222222222222",
                    "verified_at": None,
                    "deactivated_at": None,
                    "deactivation_reason": None,
                    "created_at": "2026-10-14T00:00:00Z",
                    "updated_at": "2026-10-14T00:00:00Z",
                },
                "message": "Staff invitation successfully dispatched.",
                "invitation_token": None,
            }
        },
    )

    user: UserRead
    message: str
    invitation_token: str | None = None
