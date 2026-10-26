"""Programmatic Alembic migration runner and schema drift verifier (Phase 13).

Provides safe async helpers to:
- Build an Alembic `Config` without exposing secrets
- Apply migrations (`upgrade`) or revert migrations (`downgrade`) on an active
  `AsyncEngine`
- Query the current applied Alembic revision (`alembic_version`)
- Verify that the live database schema matches `Base.metadata` with zero drift
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from backend.app.core.secrets import redact_text
from backend.app.models import Base

REPO_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_INI_PATH = REPO_ROOT / "alembic.ini"
MIGRATIONS_DIR = REPO_ROOT / "backend" / "migrations"


def build_alembic_config(database_url: str | None = None) -> Config:
    """Construct an Alembic `Config` pointing to `backend/migrations`."""
    alembic_cfg = Config(str(ALEMBIC_INI_PATH))
    alembic_cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    alembic_cfg.attributes["configure_logger"] = False
    if database_url:
        alembic_cfg.set_main_option("sqlalchemy.url", database_url)
    return alembic_cfg


def get_expected_head_revision() -> str | None:
    """Return the current head revision ID defined in `backend/migrations/versions`."""
    alembic_cfg = build_alembic_config()
    script = ScriptDirectory.from_config(alembic_cfg)
    return script.get_current_head()


async def run_migrations_upgrade(
    engine: AsyncEngine,
    revision: str = "head",
) -> None:
    """Apply Alembic forward migrations up to ``revision`` using ``engine``."""

    def _upgrade(connection: Connection) -> None:
        cfg = build_alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, revision)

    try:
        async with engine.begin() as conn:
            await conn.run_sync(_upgrade)
    except Exception as exc:
        safe_msg = redact_text(str(exc))
        raise RuntimeError(f"Database migration upgrade failed: {safe_msg}") from None


async def run_migrations_downgrade(
    engine: AsyncEngine,
    revision: str = "base",
) -> None:
    """Revert Alembic migrations down to ``revision`` using ``engine``."""

    def _downgrade(connection: Connection) -> None:
        cfg = build_alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, revision)

    try:
        async with engine.begin() as conn:
            await conn.run_sync(_downgrade)
    except Exception as exc:
        safe_msg = redact_text(str(exc))
        raise RuntimeError(f"Database migration downgrade failed: {safe_msg}") from None


async def get_current_database_revision(engine: AsyncEngine) -> str | None:
    """Return the currently applied Alembic revision stored in the database."""

    def _get_rev(connection: Connection) -> str | None:
        migration_ctx = MigrationContext.configure(connection)
        return migration_ctx.get_current_revision()

    async with engine.connect() as conn:
        return await conn.run_sync(_get_rev)


async def detect_schema_drift(engine: AsyncEngine) -> list[Any]:
    """Compare live database schema against `Base.metadata` and return any diffs."""

    def _compare(connection: Connection) -> list[Any]:
        migration_ctx = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "compare_server_default": False,
            },
        )
        return list(compare_metadata(migration_ctx, Base.metadata))

    async with engine.connect() as conn:
        return await conn.run_sync(_compare)
