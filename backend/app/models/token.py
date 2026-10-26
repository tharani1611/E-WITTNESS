"""One-time authentication and verification token entity (Phase 18).

Represents cryptographically bound, purpose-scoped, single-use tokens for:
- Self-service password recovery (`password_reset`)
- Account email verification (`email_verification`)

Security invariants:
- Raw token values are NEVER persisted to the database. Only deterministic
  SHA-256 digests (`token_hash`) are stored.
- Tokens have explicit expiration boundaries and single-use consumption states.
- Atomic consumption prevents double-spend race conditions.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.identity import AuthTokenPurpose
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.user import User


class AuthToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One-time purpose-scoped credential token (`auth_tokens` table)."""

    __tablename__ = "auth_tokens"
    __table_args__ = (
        Index("ix_auth_tokens_user_id_purpose", "user_id", "purpose"),
        CheckConstraint(
            f"purpose IN ('{AuthTokenPurpose.PASSWORD_RESET.value}', "
            f"'{AuthTokenPurpose.EMAIL_VERIFICATION.value}', "
            f"'{AuthTokenPurpose.INVITATION.value}')",
            name="ck_auth_tokens_purpose_allowed_values",
        ),
        CheckConstraint(
            "length(token_hash) = 64",
            name="ck_auth_tokens_token_hash_sha256_length",
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
    )
    purpose: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
        index=True,
    )
    created_by_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        default=None,
    )

    user: Mapped[User] = relationship(
        "User",
        back_populates="auth_tokens",
        lazy="selectin",
    )

    def is_valid_at(self, moment: datetime | None = None) -> bool:
        """Return True if token is unconsumed and unexpired at ``moment``."""
        check_time = moment or utc_now()
        return self.consumed_at is None and self.expires_at > check_time

    def consume(self, moment: datetime | None = None) -> None:
        """Mark token as consumed at ``moment``."""
        self.consumed_at = moment or utc_now()

    def __repr__(self) -> str:
        return (
            f"<AuthToken id={self.id} user_id={self.user_id} purpose={self.purpose!r} "
            f"consumed={self.consumed_at is not None}>"
        )
