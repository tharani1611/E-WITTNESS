"""Top-level router registration wiring root and versioned API routes (Phase 06)."""

from __future__ import annotations

from fastapi import FastAPI

from backend.app.api.v1.health import root_health_router
from backend.app.api.v1.router import build_v1_router
from backend.app.config.settings import Settings


def register_routers(app: FastAPI, settings: Settings) -> None:
    """Register root liveness and `API_V1_PREFIX` versioned routers on ``app``."""
    app.include_router(root_health_router)
    app.include_router(build_v1_router(), prefix=settings.API_V1_PREFIX)
