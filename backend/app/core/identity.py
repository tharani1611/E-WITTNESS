"""User identity normalization, role/session enums, and account-state rules (Phases 14-15).

Provides pure domain primitives with zero HTTP or ORM framework dependencies:
- Canonical `RoleCode`, `AccountStatus`, and `SessionStatus` enumerations
- Deterministic normalization for email addresses, institutional identifiers,
  and department codes so application validation and PostgreSQL constraints
  agree byte-for-byte
- Explicit account-state transition validation (`PENDING_VERIFICATION`,
  `ACTIVE`, `SUSPENDED`, `DISABLED`)
- Role-to-department scope validation ensuring role assignment never implies
  unrestricted cross-department access
"""

from __future__ import annotations

import re
from enum import StrEnum
from uuid import UUID

from backend.app.core.exceptions import BusinessRuleError


class RoleCode(StrEnum):
    """Canonical stakeholder role codes defined in the E-WITNESS SRS (Phase 02)."""

    STUDENT = "ROLE_STUDENT"
    STAFF = "ROLE_STAFF"
    DEPT_ADMIN = "ROLE_DEPT_ADMIN"
    INVESTIGATOR = "ROLE_INVESTIGATOR"
    SUPER_ADMIN = "ROLE_SUPER_ADMIN"


DEPARTMENT_SCOPED_ROLE_CODES: frozenset[RoleCode] = frozenset(
    {
        RoleCode.STUDENT,
        RoleCode.STAFF,
        RoleCode.DEPT_ADMIN,
        RoleCode.INVESTIGATOR,
    }
)


class AccountStatus(StrEnum):
    """Explicit user account lifecycle states enforced by application and database."""

    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class SessionStatus(StrEnum):
    """Explicit user session lifecycle states."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuthTokenPurpose(StrEnum):
    """Purpose-scoped types for one-time verification tokens (Phases 18, 32)."""

    PASSWORD_RESET = "password_reset"  # noqa: S105
    EMAIL_VERIFICATION = "email_verification"
    INVITATION = "invitation"


ALLOWED_ACCOUNT_STATUS_TRANSITIONS: dict[AccountStatus, frozenset[AccountStatus]] = {
    AccountStatus.PENDING_VERIFICATION: frozenset({AccountStatus.ACTIVE, AccountStatus.DISABLED}),
    AccountStatus.ACTIVE: frozenset({AccountStatus.SUSPENDED, AccountStatus.DISABLED}),
    AccountStatus.SUSPENDED: frozenset({AccountStatus.ACTIVE, AccountStatus.DISABLED}),
    AccountStatus.DISABLED: frozenset(),
}

_EMAIL_RE = re.compile(
    r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_INSTITUTIONAL_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")
_DEPARTMENT_CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,63}$")


def normalize_email(value: str) -> str:
    """Normalize an email address to lowercase trimmed form and validate syntax."""
    if not isinstance(value, str):
        raise ValueError("Email address must be a string.")
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("Email address cannot be empty.")
    if len(cleaned) < 5 or len(cleaned) > 254:
        raise ValueError("Email address must be between 5 and 254 characters long.")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in cleaned):
        raise ValueError("Email address contains invalid whitespace or control characters.")
    if not _EMAIL_RE.match(cleaned):
        raise ValueError(f"Invalid email address format: '{cleaned}'.")
    return cleaned


def normalize_institutional_id(value: str | None) -> str | None:
    """Normalize an optional institutional ID to uppercase trimmed form."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Institutional ID must be a string or None.")
    cleaned = value.strip().upper()
    if not cleaned:
        raise ValueError("Institutional ID cannot be an empty or whitespace-only string.")
    if not _INSTITUTIONAL_ID_RE.match(cleaned):
        raise ValueError(
            "Institutional ID must be 3-64 characters of uppercase alphanumeric, "
            "dot, underscore, or hyphen characters, starting with an alphanumeric."
        )
    return cleaned


def normalize_department_code(value: str) -> str:
    """Normalize a department code to uppercase trimmed form and validate syntax."""
    if not isinstance(value, str):
        raise ValueError("Department code must be a string.")
    cleaned = value.strip().upper()
    if not _DEPARTMENT_CODE_RE.match(cleaned):
        raise ValueError(
            "Department code must be 2-64 characters of uppercase alphanumeric, "
            "underscore, or hyphen characters, starting with an alphanumeric."
        )
    return cleaned


def parse_account_status(value: AccountStatus | str) -> AccountStatus:
    """Validate and coerce ``value`` into an ``AccountStatus`` enum member."""
    if isinstance(value, AccountStatus):
        return value
    if isinstance(value, str):
        try:
            return AccountStatus(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(s.value for s in AccountStatus)
            raise BusinessRuleError(
                f"Invalid account status '{value}'. Allowed values: {allowed}.",
                code="INVALID_ACCOUNT_STATUS",
            ) from exc
    raise BusinessRuleError(
        "Account status must be a valid string or AccountStatus value.",
        code="INVALID_ACCOUNT_STATUS",
    )


def validate_account_status_transition(
    current: AccountStatus | str,
    target: AccountStatus | str,
) -> AccountStatus:
    """Validate that transitioning an account from ``current`` to ``target`` is permitted."""
    current_status = parse_account_status(current)
    target_status = parse_account_status(target)
    if current_status == target_status:
        return target_status

    allowed_targets = ALLOWED_ACCOUNT_STATUS_TRANSITIONS.get(current_status, frozenset())
    if target_status not in allowed_targets:
        raise BusinessRuleError(
            f"Account status transition from '{current_status.value}' to "
            f"'{target_status.value}' is not permitted.",
            code="INVALID_ACCOUNT_STATE_TRANSITION",
        )
    return target_status


def validate_role_department_binding(
    role_code: RoleCode | str,
    department_id: UUID | None,
    *,
    requires_department_scope: bool | None = None,
) -> None:
    """Enforce that department-scoped roles are bound to a non-null ``department_id``."""
    try:
        resolved_code = role_code if isinstance(role_code, RoleCode) else RoleCode(str(role_code))
    except ValueError as exc:
        allowed = ", ".join(r.value for r in RoleCode)
        raise BusinessRuleError(
            f"Unsupported role code '{role_code}'. Allowed values: {allowed}.",
            code="INVALID_ROLE_CODE",
        ) from exc

    must_have_department = (
        requires_department_scope
        if requires_department_scope is not None
        else (resolved_code in DEPARTMENT_SCOPED_ROLE_CODES)
    )
    if must_have_department and department_id is None:
        raise BusinessRuleError(
            f"Role '{resolved_code.value}' requires an explicit department assignment "
            "(department_id cannot be None).",
            code="DEPARTMENT_ASSIGNMENT_REQUIRED",
        )
