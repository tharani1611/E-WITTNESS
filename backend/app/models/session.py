"""User session ownership and lifecycle persistence model (Phase 14).

Tracks session ownership (`user_id`, `department_id`), validity window
(`issued_at`, `expires_at`, `last_activity_at`), client attribution
(`client_ip`, `user_agent`), and revocation state (`status`, `revoked_at`,
`revocation_reason`) without storing plaintext tokens or secrets.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from backend.app.core.identity import SessionStatus
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.department import Department
    from backend.app.models.user import User


class Session(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """User session lifecycle entity (`user_sessions` table)."""

    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_id_status", "user_id", "status"),
        CheckConstraint(
            "status IN ('active', 'expired', 'revoked')",
            name="session_status_allowed_values",
        ),
        CheckConstraint(
            "expires_at > issued_at",
            name="session_expiry_after_issued",
        ),
        CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL) "
            "OR (status IN ('active', 'expired') AND revoked_at IS NULL)",
            name="session_revocation_consistency",
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=SessionStatus.ACTIVE.value,
        server_default=SessionStatus.ACTIVE.value,
        index=True,
    )
    client_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        default=None,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        default=None,
    )
    issued_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )
    refresh_token_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        unique=True,
        index=True,
        default=None,
    )
    previous_refresh_token_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        default=None,
    )
    rotation_counter: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )

    user: Mapped[User] = relationship(
        "User",
        back_populates="sessions",
        lazy="selectin",
    )
    department: Mapped[Department | None] = relationship(
        "Department",
        lazy="selectin",
    )

    @validates("status")
    def _validate_status(self, _key: str, value: SessionStatus | str) -> str:
        raw = value.value if isinstance(value, SessionStatus) else str(value).strip().lower()
        try:
            return SessionStatus(raw).value
        except ValueError as exc:
            allowed = ", ".join(s.value for s in SessionStatus)
            raise ValueError(
                f"Invalid session status '{value}'. Allowed values: {allowed}."
            ) from exc

    def rotate_refresh_token(self, new_token_hash: str, *, when: datetime | None = None) -> None:
        """Rotate the session refresh token digest and update activity timestamps."""
        self.previous_refresh_token_hash = self.refresh_token_hash
        self.refresh_token_hash = new_token_hash
        self.rotation_counter += 1
        self.last_activity_at = when or utc_now()

    def revoke(self, *, reason: str | None = None, when: datetime | None = None) -> None:
        """Mark the session as revoked with an explicit UTC revocation timestamp."""
        self.status = SessionStatus.REVOKED.value
        self.revoked_at = when or utc_now()
        self.revocation_reason = reason.strip() if reason else None

    def mark_expired(self) -> None:
        """Mark an active session as expired."""
        self.status = SessionStatus.EXPIRED.value
        self.revoked_at = None
        self.revocation_reason = None

    def __repr__(self) -> str:
        return (
            f"Session(id={self.id!r}, user_id={self.user_id!r}, "
            f"status={self.status!r}, expires_at={self.expires_at!r})"
        )


UserSession = Session
