"""Aggregated API v1 router registration (Phase 06)."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1.ai import router as v1_ai_router
from backend.app.api.v1.analytics import router as v1_analytics_router
from backend.app.api.v1.audit import v1_audit_router
from backend.app.api.v1.auth import v1_auth_router
from backend.app.api.v1.biometrics import router as v1_biometrics_router
from backend.app.api.v1.cases import v1_cases_router
from backend.app.api.v1.dashboards import router as v1_dashboards_router
from backend.app.api.v1.departments import v1_departments_router
from backend.app.api.v1.health import v1_health_router
from backend.app.api.v1.incidents import v1_incidents_router
from backend.app.api.v1.notifications import router as v1_notifications_router
from backend.app.api.v1.reports import router as v1_reports_router
from backend.app.api.v1.users import v1_users_router


def build_v1_router() -> APIRouter:
    """Construct the versioned v1 ``APIRouter`` with all active v1 sub-routers."""
    router = APIRouter()
    router.include_router(v1_health_router)
    router.include_router(v1_auth_router)
    router.include_router(v1_departments_router)
    router.include_router(v1_users_router)
    router.include_router(v1_incidents_router)
    router.include_router(v1_audit_router)
    router.include_router(v1_ai_router)
    router.include_router(v1_biometrics_router)
    router.include_router(v1_cases_router)
    router.include_router(v1_notifications_router)
    router.include_router(v1_dashboards_router)
    router.include_router(v1_analytics_router)
    router.include_router(v1_reports_router)
    return router
