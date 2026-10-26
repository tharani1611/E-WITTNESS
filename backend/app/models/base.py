"""Declarative SQLAlchemy 2.x base class, naming conventions, and timestamp mixins (Phases 12-14).

Provides:
- Deterministic constraint and index naming conventions for Alembic migrations
- Timezone-aware UTC datetime column type (`UTCDateTime`) ensuring consistent
  UTC timestamps across PostgreSQL (`TIMESTAMPTZ`) and SQLite unit tests
- UUIDv4 primary-key mixin (`UUIDPrimaryKeyMixin`)
- Creation and update timestamp mixin (`TimestampMixin`)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData, Uuid, func
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """SQLAlchemy type decorator enforcing timezone-aware UTC datetimes on write and read."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
                return value.replace(tzinfo=UTC)
            return value.astimezone(UTC)
        return None


class Base(DeclarativeBase):
    """Centralized SQLAlchemy 2.x declarative base with Alembic naming conventions."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """Mixin supplying a non-sequential UUIDv4 primary key column (`SEC-004`)."""

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )


class TimestampMixin:
    """Mixin supplying UTC-consistent `created_at` and `updated_at` columns."""

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )
