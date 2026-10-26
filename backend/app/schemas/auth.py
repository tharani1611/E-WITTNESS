"""Pydantic validation schemas for authentication and verification workflows (Phases 16-18).

Provides strict request and response schemas for:
- Login and credential exchange
- Access token issuance and refresh rotation
- Self-service password recovery and reset
- Email verification request and confirmation
- Session revocation and current principal introspection

Security invariants:
- Password values and raw token digests are strictly excluded from output DTOs.
- String boundaries and formats are rigorously validated.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.identity import (
    RoleCode,
    normalize_email,
    normalize_institutional_id,
)
from backend.app.schemas.identity import DepartmentRead, RoleRead, UserRead


class LoginRequest(BaseModel):
    """User credential login request payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: str = Field(
        ..., min_length=5, max_length=254, description="Normalized institutional email address."
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Plaintext password credential.",
    )

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return normalize_email(value)


class TokenResponse(BaseModel):
    """Authenticated token response payload."""

    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(..., description="Signed JWT bearer access token.")
    refresh_token: str = Field(..., description="Opaque refresh token for session rotation.")
    token_type: str = Field(default="bearer", description="Token scheme identifier.")
    expires_in: int = Field(
        ...,
        description="Access token lifespan in seconds.",
    )


class RefreshTokenRequest(BaseModel):
    """Refresh token rotation request payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    refresh_token: str = Field(
        ...,
        min_length=16,
        max_length=256,
        description="Opaque refresh token credential.",
    )


class ForgotPasswordRequest(BaseModel):
    """Self-service password recovery initiation payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: str = Field(
        ..., min_length=5, max_length=254, description="Target account email address."
    )

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return normalize_email(value)


class ResetPasswordRequest(BaseModel):
    """Password reset completion payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    token: str = Field(
        ...,
        min_length=16,
        max_length=256,
        description="One-time password reset token.",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New replacement password conforming to policy.",
    )


class ChangePasswordRequest(BaseModel):
    """Authenticated password change request payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    current_password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Current plaintext password credential.",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New replacement password conforming to policy.",
    )


class VerifyEmailRequestRequest(BaseModel):
    """Email verification dispatch payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: str = Field(
        ..., min_length=5, max_length=254, description="Target account email address."
    )

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return normalize_email(value)


class VerifyEmailConfirmRequest(BaseModel):
    """Email verification confirmation payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    token: str = Field(
        ...,
        min_length=16,
        max_length=256,
        description="One-time email verification token.",
    )


class GenericActionResponse(BaseModel):
    """Generic status response for privacy-preserving authentication actions."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="success", description="Status code string.")
    message: str = Field(..., description="Human-readable informational message.")


class RevokeSessionRequest(BaseModel):
    """Session revocation parameters."""

    model_config = ConfigDict(extra="forbid")

    session_id: UUID | None = Field(
        default=None,
        description="Specific session ID to revoke, or None to revoke current session.",
    )
    all_other_sessions: bool = Field(
        default=False,
        description="If True, revokes all active sessions for the user except the current one.",
    )


class CurrentUserResponse(BaseModel):
    """Authenticated user profile introspection response."""

    model_config = ConfigDict(extra="forbid")

    user: UserRead
    role: RoleRead
    department: DepartmentRead | None = None
    session_id: UUID


class AuthenticatedPrincipal(BaseModel):
    """Authoritative principal resolved from valid token and database session (Phase 19)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UUID
    email: str
    full_name: str
    account_status: str
    is_active: bool
    role_code: str
    department_id: UUID | None
    session_id: UUID

    @property
    def id(self) -> UUID:
        """Alias for user_id to support standard entity ID access."""
        return self.user_id

    @property
    def role(self) -> RoleCode:
        """Return the canonical RoleCode enum for this principal."""
        return RoleCode(self.role_code)


class StudentRegisterRequest(BaseModel):
    """Input schema for self-service student registration (Phase 35)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: str = Field(
        ..., min_length=5, max_length=254, description="Student institutional email."
    )
    password: str = Field(
        ..., min_length=12, max_length=128, description="Password meeting complexity policy."
    )
    full_name: str = Field(
        ..., min_length=2, max_length=160, description="Student legal full name."
    )
    department_id: UUID = Field(..., description="Target enrolled institutional department.")
    institutional_id: str | None = Field(
        default=None, max_length=64, description="Optional student ID."
    )

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


class StudentRegisterResponse(BaseModel):
    """Response payload after student self-registration."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="success")
    message: str = Field(..., description="User-facing confirmation message.")
    user_id: UUID = Field(..., description="Assigned user identifier.")
    verification_token: str | None = Field(default=None, description="Test/dev verification token.")


class AcceptInvitationRequest(BaseModel):
    """Input schema for accepting an account invitation and setting password (Phase 32)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    token: str = Field(..., min_length=16, max_length=256, description="One-time invitation token.")
    password: str = Field(
        ..., min_length=12, max_length=128, description="Password conforming to policy."
    )
    full_name: str | None = Field(
        default=None, min_length=2, max_length=160, description="Optional updated name."
    )

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 non-whitespace characters.")
        return cleaned
