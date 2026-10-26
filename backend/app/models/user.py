"""User identity persistence model and account lifecycle state constraints (Phases 14-15).

Enforces:
- Normalized, unique email and optional institutional_id identifiers at both the
  application/ORM validation layer and PostgreSQL constraint layer
- Explicit account states (`pending_verification`, `active`, `suspended`, `disabled`)
  with lifecycle consistency checks between `account_status`, `is_active`, and
  `deactivated_at`
- Explicit foreign-key bindings to `roles` and `departments` (`ondelete="RESTRICT"`)
- Zero password or authentication token fields in Phases 11-15 (scheduled for Phases 16-20)
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from backend.app.core.identity import (
    AccountStatus,
    normalize_email,
    normalize_institutional_id,
    parse_account_status,
    validate_account_status_transition,
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
    from backend.app.models.role import Role
    from backend.app.models.session import Session
    from backend.app.models.token import AuthToken


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """User identity and role/department assignment entity (`users` table)."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("id", "department_id", name="uq_users_id_department_id"),
        Index("ix_users_department_id_account_status", "department_id", "account_status"),
        Index("ix_users_department_id_role_id", "department_id", "role_id"),
        CheckConstraint(
            "email = lower(trim(email)) AND length(email) >= 5 AND email LIKE '%_@_%'",
            name="user_email_normalized",
        ),
        CheckConstraint(
            "institutional_id IS NULL OR "
            "(institutional_id = upper(trim(institutional_id)) AND length(institutional_id) >= 3)",
            name="user_institutional_id_normalized",
        ),
        CheckConstraint(
            "length(trim(full_name)) >= 2",
            name="user_full_name_non_empty",
        ),
        CheckConstraint(
            "account_status IN ('pending_verification', 'active', 'suspended', 'disabled')",
            name="user_account_status_allowed_values",
        ),
        CheckConstraint(
            "(account_status = 'active' AND is_active = true AND deactivated_at IS NULL) "
            "OR (account_status = 'pending_verification' AND is_active = false AND deactivated_at IS NULL) "
            "OR (account_status IN ('suspended', 'disabled') AND is_active = false AND deactivated_at IS NOT NULL)",
            name="user_status_lifecycle_consistency",
        ),
        CheckConstraint(
            "password_hash IS NULL OR length(password_hash) >= 20",
            name="user_password_hash_min_length",
        ),
    )

    email: Mapped[str] = mapped_column(
        String(254),
        nullable=False,
        unique=True,
        index=True,
    )
    institutional_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
        default=None,
    )
    full_name: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
    )
    account_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AccountStatus.PENDING_VERIFICATION.value,
        server_default=AccountStatus.PENDING_VERIFICATION.value,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
        index=True,
    )
    department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )
    deactivated_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )
    deactivation_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )
    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )

    department: Mapped[Department | None] = relationship(
        "Department",
        back_populates="users",
        lazy="selectin",
    )
    role: Mapped[Role] = relationship(
        "Role",
        back_populates="users",
        lazy="selectin",
    )
    sessions: Mapped[list[Session]] = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    auth_tokens: Mapped[list[AuthToken]] = relationship(
        "AuthToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    @validates("email")
    def _validate_email(self, _key: str, value: str) -> str:
        return normalize_email(value)

    @validates("institutional_id")
    def _validate_institutional_id(self, _key: str, value: str | None) -> str | None:
        return normalize_institutional_id(value)

    @validates("full_name")
    def _validate_full_name(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Full name must be a string.")
        cleaned = value.strip()
        if len(cleaned) < 2 or len(cleaned) > 160:
            raise ValueError("Full name must be between 2 and 160 characters long.")
        return cleaned

    @validates("account_status")
    def _validate_account_status(self, _key: str, value: AccountStatus | str) -> str:
        status_enum = parse_account_status(value)
        return status_enum.value

    def transition_status(
        self,
        target: AccountStatus | str,
        *,
        reason: str | None = None,
        when: datetime | None = None,
    ) -> None:
        """Validate and apply an account status lifecycle transition."""
        current_str = self.account_status or AccountStatus.PENDING_VERIFICATION.value
        target_enum = validate_account_status_transition(current_str, target)
        timestamp = when or utc_now()

        self.account_status = target_enum.value
        if target_enum == AccountStatus.ACTIVE:
            self.is_active = True
            if self.verified_at is None:
                self.verified_at = timestamp
            self.deactivated_at = None
            self.deactivation_reason = None
        elif target_enum in {AccountStatus.SUSPENDED, AccountStatus.DISABLED}:
            self.is_active = False
            self.deactivated_at = timestamp
            self.deactivation_reason = reason.strip() if reason else None
        else:
            self.is_active = False
            self.deactivated_at = None
            self.deactivation_reason = None

    def activate(self, *, when: datetime | None = None) -> None:
        """Transition user account to `active` state."""
        self.transition_status(AccountStatus.ACTIVE, when=when)

    def suspend(self, *, reason: str | None = None, when: datetime | None = None) -> None:
        """Transition user account to `suspended` state."""
        self.transition_status(AccountStatus.SUSPENDED, reason=reason, when=when)

    def disable(self, *, reason: str | None = None, when: datetime | None = None) -> None:
        """Soft-deactivate user account into terminal `disabled` state."""
        self.transition_status(AccountStatus.DISABLED, reason=reason, when=when)

    def set_password_hash(self, hash_val: str | None) -> None:
        """Store a computed password hash on the user entity."""
        if hash_val is not None and len(hash_val.strip()) < 20:
            raise ValueError("Password hash must be at least 20 characters long.")
        self.password_hash = hash_val.strip() if hash_val is not None else None

    def has_usable_password(self) -> bool:
        """Return True if user has an established password hash."""
        return bool(self.password_hash and len(self.password_hash) >= 20)

    @property
    def is_verified(self) -> bool:
        """Return True if account has verified email/credentials."""
        return self.verified_at is not None

    def __repr__(self) -> str:
        return (
            f"User(id={self.id!r}, email={self.email!r}, "
            f"account_status={self.account_status!r}, department_id={self.department_id!r}, "
            f"role_id={self.role_id!r})"
        )
