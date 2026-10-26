"""Role persistence model enforcing least-privilege stakeholder definitions (Phases 14-15).

Defines the five approved E-WITNESS stakeholder roles (`ROLE_STUDENT`,
`ROLE_STAFF`, `ROLE_DEPT_ADMIN`, `ROLE_INVESTIGATOR`, `ROLE_SUPER_ADMIN`) and
explicitly records whether a role requires mandatory department scoping so that
role assignment alone never grants unrestricted cross-department access.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, String, Text, true
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from backend.app.core.identity import DEPARTMENT_SCOPED_ROLE_CODES, RoleCode
from backend.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from backend.app.models.user import User


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stakeholder role definition entity (`roles` table)."""

    __tablename__ = "roles"
    __table_args__ = (
        CheckConstraint(
            "code IN ('ROLE_STUDENT', 'ROLE_STAFF', 'ROLE_DEPT_ADMIN', "
            "'ROLE_INVESTIGATOR', 'ROLE_SUPER_ADMIN')",
            name="role_code_allowed_values",
        ),
        CheckConstraint(
            "length(trim(name)) >= 2",
            name="role_name_non_empty",
        ),
        CheckConstraint(
            "length(trim(description)) >= 5",
            name="role_description_non_empty",
        ),
        CheckConstraint(
            "(code = 'ROLE_SUPER_ADMIN') OR (requires_department_scope = true)",
            name="role_department_scope_enforcement",
        ),
    )

    code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    requires_department_scope: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )
    is_system_role: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )

    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="role",
        lazy="selectin",
    )

    @validates("code")
    def _validate_code(self, _key: str, value: RoleCode | str) -> str:
        raw = value.value if isinstance(value, RoleCode) else str(value).strip()
        try:
            role_enum = RoleCode(raw)
        except ValueError as exc:
            allowed = ", ".join(r.value for r in RoleCode)
            raise ValueError(f"Unsupported role code '{raw}'. Allowed values: {allowed}.") from exc
        if role_enum in DEPARTMENT_SCOPED_ROLE_CODES:
            self.requires_department_scope = True
        return role_enum.value

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or len(value.strip()) < 2:
            raise ValueError("Role name must be at least 2 characters long.")
        return value.strip()

    @validates("description")
    def _validate_description(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or len(value.strip()) < 5:
            raise ValueError("Role description must be at least 5 characters long.")
        return value.strip()

    def __repr__(self) -> str:
        return (
            f"Role(id={self.id!r}, code={self.code!r}, "
            f"requires_department_scope={self.requires_department_scope!r})"
        )
