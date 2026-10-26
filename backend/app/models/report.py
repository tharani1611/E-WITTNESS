"""Controlled report export persistence models (Phase 98).

Enforces:
- Record-level tracking of generated CSV and PDF report packages.
- Strict department scoping, ownership, and role-based download boundaries.
- Cryptographic SHA-256 integrity verification of exported artifact payloads.
- Bounded retention and expiration tracking with automated cleanup metadata.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.analytics import ExportStatus, ReportFormat, ReportType
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)

if TYPE_CHECKING:
    from backend.app.models.department import Department
    from backend.app.models.user import User


_REPORT_TYPE_VALUES = ", ".join(f"'{s.value}'" for s in ReportType)
_REPORT_FORMAT_VALUES = ", ".join(f"'{s.value}'" for s in ReportFormat)
_EXPORT_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in ExportStatus)


class ReportExport(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Persisted report export metadata for controlled disclosure and download tracking."""

    __tablename__ = "report_exports"
    __table_args__ = (
        CheckConstraint(
            f"report_type IN ({_REPORT_TYPE_VALUES})",
            name="ck_report_exports_type",
        ),
        CheckConstraint(
            f"export_format IN ({_REPORT_FORMAT_VALUES})",
            name="ck_report_exports_format",
        ),
        CheckConstraint(
            f"status IN ({_EXPORT_STATUS_VALUES})",
            name="ck_report_exports_status",
        ),
        CheckConstraint(
            "download_count >= 0",
            name="ck_report_exports_download_count_non_negative",
        ),
        Index("ix_report_exports_created_by_id", "created_by_id"),
        Index("ix_report_exports_department_id", "department_id"),
        Index("ix_report_exports_status", "status"),
        Index("ix_report_exports_expires_at", "expires_at"),
        Index("ix_report_exports_created_at", "created_at"),
    )

    report_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    export_format: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    parameters_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
        server_default="{}",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ExportStatus.COMPLETED.value,
        server_default=ExportStatus.COMPLETED.value,
    )
    file_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    file_size_bytes: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )
    content_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    storage_path: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    download_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
    )

    department: Mapped[Department | None] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    created_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[created_by_id],
        lazy="selectin",
    )

    @property
    def parameters(self) -> dict[str, Any]:
        """Safely parse serialized JSON parameters dictionary."""
        try:
            return json.loads(self.parameters_json) if self.parameters_json else {}
        except Exception:
            return {}

    def __repr__(self) -> str:
        return (
            f"<ReportExport id={self.id} type={self.report_type} "
            f"format={self.export_format} status={self.status}>"
        )
