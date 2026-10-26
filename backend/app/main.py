"""FastAPI application factory and lifecycle management for E-WITNESS (Phase 06).

Security and architectural guarantees:
- Importing this module has zero side effects: it does not read environment
  variables or open connections to PostgreSQL, Redis, S3, or AI services at
  import time.
- Interactive OpenAPI/Swagger documentation is automatically disabled when
  `ENVIRONMENT == "production"`.
- Middleware stack is ordered deliberately so `RequestTracingMiddleware` runs
  outermost, `CORSMiddleware` runs second, and `RequestBodyLimitMiddleware`
  runs innermost before route execution.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from backend.app.api.errors import register_exception_handlers
from backend.app.api.router import register_routers
from backend.app.config.settings import Environment, Settings, get_settings
from backend.app.core.logging import configure_logging, get_logger
from backend.app.infrastructure.database import (
    DatabaseSessionManager,
    create_database_readiness_probe,
)
from backend.app.middleware.body_size_limit import RequestBodyLimitMiddleware
from backend.app.middleware.request_context import RequestTracingMiddleware
from backend.app.middleware.security_headers import SecurityHeadersMiddleware
from backend.app.services.health import ReadinessProbe

logger = get_logger("main")


@asynccontextmanager
async def _app_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage FastAPI application startup and shutdown lifecycle."""
    settings: Settings = app.state.settings
    configure_logging(settings)
    app.state.is_running = True
    logger.info(
        "E-WITNESS application startup complete",
        extra={
            "app_version": settings.APP_VERSION,
            "api_prefix": settings.API_V1_PREFIX,
            "ai_enabled": settings.AI_ENABLED,
        },
    )
    try:
        yield
    finally:
        db_manager: DatabaseSessionManager | None = getattr(app.state, "db_manager", None)
        if db_manager is not None:
            await db_manager.dispose()
        app.state.is_running = False
        logger.info("E-WITNESS application shutdown complete")


def create_app(
    settings: Settings | None = None,
    *,
    readiness_probes: Mapping[str, ReadinessProbe] | None = None,
    db_manager: DatabaseSessionManager | None = None,
    register_db_probe: bool = False,
) -> FastAPI:
    """Create and configure a validated FastAPI application instance.

    Parameters
    ----------
    settings:
        Optional pre-validated ``Settings`` instance (used in tests and custom
        bootstraps). When ``None``, ``get_settings()`` is called.
    readiness_probes:
        Optional mapping of component names (e.g., ``"database"``, ``"redis"``,
        ``"object_storage"``) to async boolean callables for `/health/ready`.
    db_manager:
        Optional pre-configured ``DatabaseSessionManager`` for dependency injection.
    register_db_probe:
        When ``True``, automatically registers the live SQL `SELECT 1` readiness
        probe for ``"database"`` unless overridden in ``readiness_probes``.
    """
    resolved_settings = settings if settings is not None else get_settings()
    configure_logging(resolved_settings)

    is_production = resolved_settings.ENVIRONMENT == Environment.PRODUCTION
    openapi_url = None if is_production else f"{resolved_settings.API_V1_PREFIX}/openapi.json"
    docs_url = None if is_production else "/docs"
    redoc_url = None if is_production else "/redoc"

    app = FastAPI(
        title=resolved_settings.APP_NAME,
        version=resolved_settings.APP_VERSION,
        description=(
            "High-assurance institutional incident reporting, digital evidence "
            "custody, and investigation platform."
        ),
        debug=resolved_settings.DEBUG,
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
        lifespan=_app_lifespan,
    )

    resolved_db_manager = (
        db_manager if db_manager is not None else DatabaseSessionManager(resolved_settings)
    )
    effective_probes: dict[str, ReadinessProbe] = dict(readiness_probes) if readiness_probes else {}
    if register_db_probe and "database" not in effective_probes:
        effective_probes["database"] = create_database_readiness_probe(
            resolved_db_manager.engine,
            timeout_seconds=float(resolved_settings.DB_CONNECT_TIMEOUT_SECONDS),
        )

    # Bind validated settings, database manager, and readiness probes to application state
    app.state.settings = resolved_settings
    app.state.db_manager = resolved_db_manager
    app.state.readiness_probes = effective_probes
    app.state.is_running = False

    # 1. Register centralized exception handlers
    register_exception_handlers(app)

    # 2. Register middleware in reverse wrapping order (last added = outermost):
    #    Incoming Request -> TrustedHostMiddleware -> RequestTracingMiddleware
    #                     -> SecurityHeadersMiddleware -> CORSMiddleware
    #                     -> RequestBodyLimitMiddleware -> Route Handler
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=resolved_settings.MAX_REQUEST_BODY_BYTES,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved_settings.CORS_ALLOWED_ORIGINS),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    if resolved_settings.SECURITY_HEADERS_ENABLED:
        app.add_middleware(
            SecurityHeadersMiddleware,
            enforce_ssl=resolved_settings.ENFORCE_SSL,
        )
    app.add_middleware(RequestTracingMiddleware)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(resolved_settings.ALLOWED_HOSTS),
    )

    # 3. Register root and versioned routers
    register_routers(app, resolved_settings)

    return app
