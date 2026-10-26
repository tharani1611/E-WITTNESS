"""Alembic migration environment for E-WITNESS (Phase 13).

Integrates with `backend.app.config.settings` and `backend.app.models.Base.metadata`
while ensuring database connection strings and credentials are never leaked in
migration exceptions or logs.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from backend.app.config.settings import get_settings
from backend.app.core.secrets import redact_text
from backend.app.infrastructure.database import validate_database_target_isolation
from backend.app.models import Base

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def resolve_migration_database_url() -> str:
    """Resolve the database URL from Alembic config overrides or validated `Settings`."""
    configured_url = (config.get_main_option("sqlalchemy.url") or "").strip()
    if configured_url:
        return configured_url
    settings = get_settings()
    validate_database_target_isolation(settings)
    return settings.DATABASE_URL


def do_run_migrations(connection: Connection) -> None:
    """Configure the Alembic migration context on an active synchronous connection."""
    is_sqlite = connection.dialect.name == "sqlite"
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=is_sqlite,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode without opening a live database connection."""
    url = resolve_migration_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations inside an async connection."""
    provided_connection = config.attributes.get("connection")
    if provided_connection is not None:
        do_run_migrations(provided_connection)
        return

    url = resolve_migration_database_url()
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    except Exception as exc:
        safe_msg = redact_text(str(exc))
        raise RuntimeError(f"Alembic migration execution failed: {safe_msg}") from None
    finally:
        await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    provided_connection = config.attributes.get("connection")
    if provided_connection is not None:
        do_run_migrations(provided_connection)
        return

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        raise RuntimeError(
            "run_migrations_online() was invoked inside an active event loop without a "
            "pre-bound synchronous connection; use `run_async_migrations()` or pass "
            "`connection` via `config.attributes['connection']`."
        )

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
