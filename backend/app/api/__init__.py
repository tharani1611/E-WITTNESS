"""API route controllers, dependency providers, and exception handlers."""

from backend.app.api.dependencies import (
    AuthServiceDep,
    CorrelationIdDep,
    CurrentUserDep,
    DbManagerDep,
    DbSessionDep,
    HealthServiceDep,
    SettingsDep,
    get_app_settings,
    get_auth_service,
    get_correlation_id,
    get_current_principal,
    get_db_manager,
    get_db_session,
    get_health_service,
)
from backend.app.api.errors import register_exception_handlers
from backend.app.api.router import register_routers

__all__ = [
    "AuthServiceDep",
    "CorrelationIdDep",
    "CurrentUserDep",
    "DbManagerDep",
    "DbSessionDep",
    "HealthServiceDep",
    "SettingsDep",
    "get_app_settings",
    "get_auth_service",
    "get_correlation_id",
    "get_current_principal",
    "get_db_manager",
    "get_db_session",
    "get_health_service",
    "register_exception_handlers",
    "register_routers",
]
