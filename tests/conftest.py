"""Shared pytest fixtures for E-WITNESS automated unit and integration tests (Phases 05-15).

Ensures all tests run deterministically with isolated dummy configuration,
clean `contextvars` correlation state, strict guards preventing test suites
from accidentally targeting production databases, Redis instances, or S3 buckets,
and an isolated PostgreSQL test cluster fixture for database integration tests.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Environment, Settings, get_settings
from backend.app.core.context import clear_request_id
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.migrations import run_migrations_upgrade
from backend.app.main import create_app
from backend.app.services.health import ReadinessProbe

# Tracked environment variable names managed by Settings
MANAGED_ENV_VARS: tuple[str, ...] = (
    "APP_NAME",
    "APP_VERSION",
    "ENVIRONMENT",
    "DEBUG",
    "API_V1_PREFIX",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "LOG_REDACT_SENSITIVE",
    "CORS_ALLOWED_ORIGINS",
    "ALLOWED_HOSTS",
    "TRUSTED_PROXIES",
    "ENFORCE_SSL",
    "SECURITY_HEADERS_ENABLED",
    "RATE_LIMIT_LOGIN_MAX_REQUESTS",
    "RATE_LIMIT_LOGIN_WINDOW_SECONDS",
    "RATE_LIMIT_AUTH_MAX_REQUESTS",
    "RATE_LIMIT_AUTH_WINDOW_SECONDS",
    "RATE_LIMIT_RESET_MAX_REQUESTS",
    "RATE_LIMIT_RESET_WINDOW_SECONDS",
    "RATE_LIMIT_VERIFY_MAX_REQUESTS",
    "RATE_LIMIT_VERIFY_WINDOW_SECONDS",
    "RATE_LIMIT_GLOBAL_MAX_REQUESTS",
    "RATE_LIMIT_GLOBAL_WINDOW_SECONDS",
    "RATE_LIMIT_BACKEND",
    "RATE_LIMIT_FAIL_OPEN",
    "DATABASE_URL",
    "DB_POOL_SIZE",
    "DB_MAX_OVERFLOW",
    "DB_POOL_TIMEOUT_SECONDS",
    "DB_CONNECT_TIMEOUT_SECONDS",
    "DB_COMMAND_TIMEOUT_SECONDS",
    "DB_POOL_RECYCLE_SECONDS",
    "DB_POOL_PRE_PING",
    "DB_ECHO",
    "REDIS_URL",
    "REDIS_MAX_CONNECTIONS",
    "REDIS_TIMEOUT_SECONDS",
    "STORAGE_ENDPOINT_URL",
    "STORAGE_BUCKET_NAME",
    "STORAGE_REGION",
    "STORAGE_ACCESS_KEY",
    "STORAGE_SECRET_KEY",
    "STORAGE_USE_SSL",
    "STORAGE_VERIFY_TLS",
    "STORAGE_TIMEOUT_SECONDS",
    "AUTH_SECRET_KEY",
    "AUTH_ALGORITHM",
    "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES",
    "AUTH_REFRESH_TOKEN_EXPIRE_DAYS",
    "AUTH_ISSUER",
    "AUTH_AUDIENCE",
    "AI_ENABLED",
    "AI_PROVIDER",
    "AI_MODEL_NAME",
    "AI_API_KEY",
    "AI_BASE_URL",
    "AI_MAX_TOKENS",
    "AI_TEMPERATURE",
    "AI_REQUEST_TIMEOUT_SECONDS",
    "AI_CONNECT_ON_STARTUP",
    "MAX_REQUEST_BODY_BYTES",
    "MAX_EVIDENCE_FILE_BYTES",
    "UPLOAD_CHUNK_SIZE_BYTES",
    "ALLOWED_EVIDENCE_MIME_TYPES",
    "HTTP_TIMEOUT_SECONDS",
)


def assert_test_resource_isolation(settings: Settings) -> None:
    """Verify a test `Settings` instance cannot target production infrastructure (Phase 09)."""
    if settings.ENVIRONMENT == Environment.PRODUCTION:
        raise RuntimeError(
            "Safety guard triggered: Refusing to run test client against ENVIRONMENT='production'."
        )
    if ":memory:" not in settings.DATABASE_URL and "test" not in settings.DATABASE_URL.lower():
        raise RuntimeError(
            "Safety guard triggered: Test DATABASE_URL must use ':memory:' or a 'test' database."
        )
    if "test" not in settings.STORAGE_BUCKET_NAME.lower():
        raise RuntimeError("Safety guard triggered: Test STORAGE_BUCKET_NAME must contain 'test'.")
    if "prod" in settings.REDIS_URL.lower():
        raise RuntimeError(
            "Safety guard triggered: Test REDIS_URL must not reference a production host."
        )


def _locate_postgres_bin_dir() -> Path | None:
    """Locate local PostgreSQL binary directory (`initdb`, `pg_ctl`, `createdb`)."""
    which_initdb = shutil.which("initdb")
    if which_initdb:
        return Path(which_initdb).resolve().parent

    windows_pg_root = Path(r"C:\Program Files\PostgreSQL")
    if windows_pg_root.exists():
        for version_dir in sorted(windows_pg_root.iterdir(), reverse=True):
            candidate = version_dir / "bin"
            if (candidate / "initdb.exe").exists() and (candidate / "pg_ctl.exe").exists():
                return candidate

    for unix_dir in (
        Path("/usr/lib/postgresql"),
        Path("/usr/local/opt/postgresql/bin"),
        Path("/opt/homebrew/opt/postgresql/bin"),
    ):
        if unix_dir.exists():
            for match in sorted(unix_dir.rglob("initdb"), reverse=True):
                return match.parent
    return None


def _pick_free_tcp_port() -> int:
    """Allocate an available ephemeral localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def postgres_test_database_url() -> Iterator[str]:
    """Provide an isolated PostgreSQL `postgresql+asyncpg://` test database URL.

    1. If `EWITNESS_TEST_POSTGRES_URL` is set in the environment (e.g., CI service
       container), validates that it targets a `test` database and yields it.
    2. Otherwise, automatically initializes and starts an ephemeral, completely
       isolated PostgreSQL cluster in a temporary directory on an unused localhost
       port, creates the `ewitness_test` database, and tears it down after the
       test session completes.
    """
    explicit_url = os.environ.get("EWITNESS_TEST_POSTGRES_URL", "").strip()
    if explicit_url:
        if "test" not in explicit_url.lower() or "prod" in explicit_url.lower():
            raise RuntimeError(
                "EWITNESS_TEST_POSTGRES_URL must target an isolated 'test' database."
            )
        yield explicit_url
        return

    pg_bin = _locate_postgres_bin_dir()
    if pg_bin is None:
        pytest.skip("PostgreSQL binaries (initdb/pg_ctl) not found for ephemeral test cluster.")

    exe_suffix = ".exe" if os.name == "nt" else ""
    initdb_bin = pg_bin / f"initdb{exe_suffix}"
    pg_ctl_bin = pg_bin / f"pg_ctl{exe_suffix}"
    createdb_bin = pg_bin / f"createdb{exe_suffix}"

    temp_root = Path(tempfile.mkdtemp(prefix="ew_pg_isolated_"))
    data_dir = temp_root / "data"
    log_file = temp_root / "postgres.log"
    port = _pick_free_tcp_port()
    db_user = "ewitness_test_user"
    db_name = "ewitness_test"

    try:
        subprocess.run(  # noqa: S603
            [
                str(initdb_bin),
                "-D",
                str(data_dir),
                "-U",
                db_user,
                "-A",
                "trust",
                "-E",
                "UTF8",
                "--no-locale",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

        pg_opts = f"-F -p {port} -h 127.0.0.1"
        subprocess.run(  # noqa: S603
            [
                str(pg_ctl_bin),
                "-D",
                str(data_dir),
                "-l",
                str(log_file),
                "-w",
                "-o",
                pg_opts,
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

        subprocess.run(  # noqa: S603
            [
                str(createdb_bin),
                "-h",
                "127.0.0.1",
                "-p",
                str(port),
                "-U",
                db_user,
                db_name,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

        yield f"postgresql+asyncpg://{db_user}@127.0.0.1:{port}/{db_name}"
    finally:
        if (data_dir / "postmaster.pid").exists():
            subprocess.run(  # noqa: S603
                [
                    str(pg_ctl_bin),
                    "-D",
                    str(data_dir),
                    "-m",
                    "immediate",
                    "-w",
                    "stop",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Scrub managed environment variables, Settings cache, and correlation context."""
    for var in MANAGED_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    get_settings.cache_clear()
    clear_request_id()
    yield
    clear_request_id()
    get_settings.cache_clear()


@pytest.fixture
def valid_testing_config_dict() -> dict[str, Any]:
    """Return a valid, isolated configuration dictionary for the testing environment."""
    return {
        "_env_file": None,
        "ENVIRONMENT": Environment.TESTING,
        "DEBUG": False,
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "REDIS_URL": "redis://localhost:6379/15",
        "STORAGE_ENDPOINT_URL": "https://s3.test.internal:9000",
        "STORAGE_BUCKET_NAME": "ewitness-test-bucket",
        "STORAGE_ACCESS_KEY": "test_access_key_isolated",
        "STORAGE_SECRET_KEY": "test_secret_key_isolated_value",
        "AUTH_SECRET_KEY": "test_only_signing_key_with_sufficient_length_32_plus",
    }


@pytest.fixture
def valid_production_config_dict() -> dict[str, Any]:
    """Return a valid, high-entropy configuration dictionary for production validation tests."""
    return {
        "_env_file": None,
        "ENVIRONMENT": Environment.PRODUCTION,
        "DEBUG": False,
        "DB_ECHO": False,
        "LOG_LEVEL": "INFO",
        "LOG_FORMAT": "json",
        "LOG_REDACT_SENSITIVE": True,
        "CORS_ALLOWED_ORIGINS": ["https://portal.ewitness.edu", "https://admin.ewitness.edu"],
        "ALLOWED_HOSTS": ["api.ewitness.edu", "portal.ewitness.edu"],
        "DATABASE_URL": "postgresql+asyncpg://ewitness_prod:K9mP2vL8nQ5!zR4~wX7*bC1_yT6@db.internal.ewitness.edu:5432/ewitness_prod",
        "REDIS_URL": "rediss://:R8kM3pL9vN2!qW6~zX4*cB7_jF5@redis.internal.ewitness.edu:6379/0",
        "STORAGE_ENDPOINT_URL": "https://s3.us-east-1.amazonaws.com",
        "STORAGE_BUCKET_NAME": "ewitness-evidence-prod-vault",
        "STORAGE_REGION": "us-east-1",
        "STORAGE_ACCESS_KEY": "AKIA9X7P4M2L8Q5N3R6W",
        "STORAGE_SECRET_KEY": "Zx8#Qp3$Lm9@Vn5!Kw2&Yr7*Bt4^Hc6%Jd1_Fg0",
        "STORAGE_USE_SSL": True,
        "STORAGE_VERIFY_TLS": True,
        "AUTH_SECRET_KEY": "vN9#mK4$pL8@qW2!zX7&cB5*rT1^yU6%hJ3_gF0-dS8+aE5",
        "AUTH_ALGORITHM": "HS256",
        "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES": 15,
        "AUTH_REFRESH_TOKEN_EXPIRE_DAYS": 7,
        "ENFORCE_SSL": True,
        "SECURITY_HEADERS_ENABLED": True,
    }


@pytest.fixture
def test_settings(valid_testing_config_dict: dict[str, Any]) -> Settings:
    """Return a validated Settings instance configured for unit and integration tests."""
    settings = Settings(**valid_testing_config_dict)
    assert_test_resource_isolation(settings)
    return settings


@pytest.fixture
def settings_factory(valid_testing_config_dict: dict[str, Any]) -> Callable[..., Settings]:
    """Return a factory creating isolated test `Settings` with custom overrides."""

    def _make_settings(**overrides: Any) -> Settings:
        merged = {**valid_testing_config_dict, **overrides}
        settings = Settings(**merged)
        if settings.ENVIRONMENT != Environment.PRODUCTION:
            assert_test_resource_isolation(settings)
        return settings

    return _make_settings


@pytest.fixture
def app_factory(
    settings_factory: Callable[..., Settings],
) -> Callable[..., FastAPI]:
    """Return a factory creating a configured FastAPI application for testing."""

    def _make_app(
        settings: Settings | None = None,
        *,
        readiness_probes: Mapping[str, ReadinessProbe] | None = None,
        db_manager: DatabaseSessionManager | None = None,
        register_db_probe: bool = False,
        **setting_overrides: Any,
    ) -> FastAPI:
        resolved = settings if settings is not None else settings_factory(**setting_overrides)
        return create_app(
            resolved,
            readiness_probes=readiness_probes,
            db_manager=db_manager,
            register_db_probe=register_db_probe,
        )

    return _make_app


@pytest.fixture
def test_app(test_settings: Settings) -> FastAPI:
    """Return a default configured FastAPI application instance for integration tests."""
    return create_app(test_settings)


@pytest.fixture
async def async_client(test_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Return an HTTPX `AsyncClient` bound to `test_app` via `ASGITransport`."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver.local",
    ) as client:
        yield client


@pytest.fixture
def postgres_settings(
    settings_factory: Callable[..., Settings],
    postgres_test_database_url: str,
) -> Settings:
    """Return a validated `Settings` instance targeting the isolated PostgreSQL test database."""
    return settings_factory(
        DATABASE_URL=postgres_test_database_url,
        DB_POOL_SIZE=5,
        DB_MAX_OVERFLOW=10,
        DB_CONNECT_TIMEOUT_SECONDS=5.0,
        DB_COMMAND_TIMEOUT_SECONDS=15.0,
    )


@pytest.fixture
async def postgres_db_manager(
    postgres_settings: Settings,
) -> AsyncIterator[DatabaseSessionManager]:
    """Return an initialized `DatabaseSessionManager` migrated to `head` on real PostgreSQL."""
    manager = DatabaseSessionManager(postgres_settings)
    try:
        await run_migrations_upgrade(manager.engine, "head")
        async with manager.engine.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE TABLE auth_tokens, user_sessions, users, roles, departments "
                    "RESTART IDENTITY CASCADE"
                )
            )
        yield manager
    finally:
        await manager.dispose()


@pytest.fixture
async def postgres_session(
    postgres_db_manager: DatabaseSessionManager,
) -> AsyncIterator[AsyncSession]:
    """Yield an isolated `AsyncSession` connected to the migrated PostgreSQL test database."""
    async with postgres_db_manager.session() as session:
        yield session
