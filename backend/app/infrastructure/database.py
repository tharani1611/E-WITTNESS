"""Asynchronous SQLAlchemy 2.x engine, session management, and connectivity verification (Phases 11-12).

Security and architectural guarantees:
- Zero import-time network side effects: importing this module never creates an
  engine or opens a database connection.
- Strict test isolation: refuses to create an engine in `ENVIRONMENT=testing`
  unless `DATABASE_URL` targets an isolated `:memory:` or `*test*` database.
- Bounded connection pooling and command/connection timeouts configured from
  validated `Settings`.
- Explicit transaction ownership (`session()` vs. `transactional_session()`)
  with automatic rollback on error and guaranteed session closure.
- Safe database exception translation (`translate_database_error`) that maps
  SQLAlchemy integrity/operational errors to sanitized `AppError` subclasses
  without leaking connection strings, credentials, or raw SQL statements.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from backend.app.config.settings import Environment, Settings
from backend.app.core.exceptions import (
    AppError,
    BusinessRuleError,
    ConflictError,
    ServiceUnavailableError,
)
from backend.app.core.logging import get_logger, sanitize_log_text

logger = get_logger("infrastructure.database")

# Type alias re-exported for dependency injection without direct SQLAlchemy imports in API layer
AsyncDatabaseSession = AsyncSession


def validate_database_target_isolation(settings: Settings) -> None:
    """Ensure test environments cannot connect to production or non-test databases."""
    if settings.ENVIRONMENT == Environment.TESTING:
        lowered_url = settings.DATABASE_URL.lower()
        parts = urlsplit(lowered_url)
        hostname = parts.hostname or ""
        path = parts.path or ""
        if "prod" in hostname or "prod" in path:
            raise RuntimeError(
                "Database isolation guard triggered: Testing environment cannot target a "
                "production database host or schema."
            )
        if ":memory:" not in lowered_url and "test" not in path:
            raise RuntimeError(
                "Database isolation guard triggered: Testing DATABASE_URL must use "
                "':memory:' or a database name containing 'test'."
            )


def create_db_engine(settings: Settings) -> AsyncEngine:
    """Create a configured SQLAlchemy 2.x `AsyncEngine` from validated `Settings`.

    Does not open a network connection until a session or connection is actually
    acquired.
    """
    validate_database_target_isolation(settings)

    parts = urlsplit(settings.DATABASE_URL)
    scheme = parts.scheme.lower()

    if scheme == "sqlite+aiosqlite":
        is_in_memory = ":memory:" in settings.DATABASE_URL
        engine_kwargs: dict[str, Any] = {
            "echo": settings.DB_ECHO,
            "connect_args": {
                "check_same_thread": False,
                "timeout": float(settings.DB_CONNECT_TIMEOUT_SECONDS),
            },
        }
        if is_in_memory:
            engine_kwargs["poolclass"] = StaticPool

        engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    # PostgreSQL (`postgresql+asyncpg://`) configuration with bounded pooling & timeouts
    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DB_ECHO,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
        pool_recycle=settings.DB_POOL_RECYCLE_SECONDS,
        pool_pre_ping=settings.DB_POOL_PRE_PING,
        connect_args={
            "timeout": float(settings.DB_CONNECT_TIMEOUT_SECONDS),
            "command_timeout": float(settings.DB_COMMAND_TIMEOUT_SECONDS),
            "server_settings": {
                "application_name": settings.APP_NAME,
                "timezone": "UTC",
            },
        },
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an `async_sessionmaker` producing isolated `AsyncSession` instances."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


def translate_database_error(exc: BaseException) -> AppError:
    """Translate a low-level SQLAlchemy/driver exception into a sanitized `AppError`.

    Ensures connection strings, database credentials, table schemas, and raw SQL
    queries are never exposed to API callers.
    """
    if isinstance(exc, AppError):
        return exc

    raw_detail = sanitize_log_text(str(exc), redact=True)

    if isinstance(exc, IntegrityError):
        orig = getattr(exc, "orig", None)
        sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
        lowered = raw_detail.lower()

        logger.warning(
            "Database integrity constraint violation",
            extra={
                "error_type": type(exc).__name__,
                "sqlstate": str(sqlstate) if sqlstate else "unknown",
            },
        )

        if sqlstate == "23505" or "unique constraint" in lowered or "duplicate key" in lowered:
            return ConflictError(
                "A record with the specified unique identity or identifier already exists.",
                code="DATABASE_UNIQUE_CONFLICT",
            )

        if sqlstate == "23503" or "foreign key constraint" in lowered:
            return BusinessRuleError(
                "Referenced parent record does not exist or cannot be removed while referenced.",
                code="DATABASE_FOREIGN_KEY_VIOLATION",
            )

        return BusinessRuleError(
            "Operation violated a database data-integrity constraint.",
            code="DATABASE_CONSTRAINT_VIOLATION",
        )

    if isinstance(exc, OperationalError | TimeoutError | OSError):
        logger.error(
            "Database operational or connectivity failure",
            extra={"error_type": type(exc).__name__},
        )
        return ServiceUnavailableError(
            "Database service is temporarily unavailable.",
            code="DATABASE_UNAVAILABLE",
        )

    logger.error(
        "Unexpected database persistence error",
        extra={"error_type": type(exc).__name__},
    )
    return ServiceUnavailableError(
        "A database persistence error occurred.",
        code="DATABASE_ERROR",
    )


async def verify_database_connectivity(
    engine: AsyncEngine,
    *,
    timeout_seconds: float | None = 5.0,
) -> bool:
    """Execute a lightweight `SELECT 1` health check against ``engine``.

    Returns ``True`` when the database responds with ``1``, or ``False`` if the
    connection times out or fails, without leaking connection credentials.
    """

    async def _probe() -> bool:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            scalar = result.scalar()
            return scalar == 1

    try:
        if timeout_seconds is not None:
            return await asyncio.wait_for(_probe(), timeout=timeout_seconds)
        return await _probe()
    except Exception as exc:
        logger.warning(
            "Database connectivity check failed",
            extra={"error_type": type(exc).__name__},
        )
        return False


def create_database_readiness_probe(
    engine: AsyncEngine,
    *,
    timeout_seconds: float = 5.0,
) -> Callable[[], Awaitable[bool]]:
    """Return an async readiness probe callable for `HealthService`."""

    async def _check() -> bool:
        return await verify_database_connectivity(engine, timeout_seconds=timeout_seconds)

    return _check


class DatabaseSessionManager:
    """Manages an `AsyncEngine` and produces isolated per-request `AsyncSession` instances.

    Transaction ownership rules:
    - `session()`: Yields an isolated `AsyncSession` where callers or services
      control commits explicitly (or via `transactional_session()`). If an
      exception escapes the context block, any uncommitted work is automatically
      rolled back and database exceptions are translated into sanitized `AppError`
      instances before closing the session.
    - `transactional_session()`: Yields an isolated `AsyncSession` that commits
      automatically when the `async with` block exits cleanly, and rolls back
      automatically on any exception.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        engine: AsyncEngine | None = None,
    ) -> None:
        self._settings = settings
        self._engine: AsyncEngine = engine if engine is not None else create_db_engine(settings)
        self._session_factory: async_sessionmaker[AsyncSession] = create_session_factory(
            self._engine
        )

    @property
    def engine(self) -> AsyncEngine:
        """Return the managed `AsyncEngine`."""
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Return the configured `async_sessionmaker`."""
        return self._session_factory

    @asynccontextmanager
    async def session(self, *, translate_errors: bool = True) -> AsyncIterator[AsyncSession]:
        """Yield a new, isolated `AsyncSession` with guaranteed rollback on error and cleanup."""
        db_session: AsyncSession = self._session_factory()
        try:
            yield db_session
        except Exception as exc:
            await db_session.rollback()
            if translate_errors and isinstance(exc, SQLAlchemyError | TimeoutError | OSError):
                raise translate_database_error(exc) from None
            raise
        finally:
            await db_session.close()

    @asynccontextmanager
    async def transactional_session(
        self,
        *,
        translate_errors: bool = True,
    ) -> AsyncIterator[AsyncSession]:
        """Yield an atomic unit-of-work `AsyncSession` that commits on success and rolls back on failure."""
        async with self.session(translate_errors=translate_errors) as db_session:
            yield db_session
            try:
                await db_session.commit()
            except Exception as exc:
                await db_session.rollback()
                if translate_errors and isinstance(exc, SQLAlchemyError | TimeoutError | OSError):
                    raise translate_database_error(exc) from None
                raise

    async def verify_connectivity(self, *, timeout_seconds: float | None = None) -> bool:
        """Verify live database connectivity using `SELECT 1`."""
        effective_timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else float(self._settings.DB_CONNECT_TIMEOUT_SECONDS)
        )
        return await verify_database_connectivity(
            self._engine,
            timeout_seconds=effective_timeout,
        )

    async def dispose(self) -> None:
        """Dispose all pooled connections on the underlying `AsyncEngine`."""
        await self._engine.dispose()
