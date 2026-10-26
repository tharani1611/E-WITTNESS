"""Department (tenant) persistence model for multi-department isolation (Phases 14-15).

Implements the foundational tenant entity required by `FR-002`, `NFR-006`,
and `SEC-002`.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, String, Text, true
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from backend.app.core.identity import normalize_department_code
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.user import User


class Department(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Institutional department/tenant entity (`departments` table)."""

    __tablename__ = "departments"
    __table_args__ = (
        CheckConstraint(
            "code = upper(trim(code)) AND length(trim(code)) >= 2",
            name="department_code_normalized",
        ),
        CheckConstraint(
            "length(trim(name)) >= 2",
            name="department_name_non_empty",
        ),
        CheckConstraint(
            "(is_active = true AND deactivated_at IS NULL) "
            "OR (is_active = false AND deactivated_at IS NOT NULL)",
            name="department_deactivation_consistency",
        ),
    )

    code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
        unique=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
        index=True,
    )
    deactivated_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )

    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="department",
        lazy="selectin",
    )

    @validates("code")
    def _validate_code(self, _key: str, value: str) -> str:
        return normalize_department_code(value)

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Department name must be a string.")
        cleaned = value.strip()
        if len(cleaned) < 2 or len(cleaned) > 160:
            raise ValueError("Department name must be between 2 and 160 characters long.")
        return cleaned

    def deactivate(self, *, when: datetime | None = None) -> None:
        """Mark the department as inactive with an explicit UTC deactivation timestamp."""
        self.is_active = False
        self.deactivated_at = when or utc_now()

    def activate(self) -> None:
        """Mark the department as active and clear any deactivation timestamp."""
        self.is_active = True
        self.deactivated_at = None

    def __repr__(self) -> str:
        return (
            f"Department(id={self.id!r}, code={self.code!r}, "
            f"name={self.name!r}, is_active={self.is_active!r})"
        )
