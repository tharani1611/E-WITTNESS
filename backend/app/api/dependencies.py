"""FastAPI dependency injection providers for E-WITNESS (Phases 06-12).

Provides typed dependency functions (`SettingsDep`, `CorrelationIdDep`,
`HealthServiceDep`, `DbManagerDep`, `DbSessionDep`) so API controllers never
access raw environment variables or construct domain services/sessions directly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.config.settings import Settings, get_settings
from backend.app.core.authorization import (
    Permission,
    has_all_permissions,
    has_any_permission,
    has_permission,
)
from backend.app.core.context import get_request_id
from backend.app.core.exceptions import AuthenticationError, PermissionDeniedError
from backend.app.core.proxy import resolve_client_ip
from backend.app.infrastructure.database import (
    AsyncDatabaseSession,
    DatabaseSessionManager,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.ai_dataset import AIDatasetService
from backend.app.services.ai_job import AIAnalysisJobService
from backend.app.services.ai_retention import AIRetentionService
from backend.app.services.ai_segment import AICandidateSegmentService
from backend.app.services.analytics import AnalyticsService
from backend.app.services.audit import AuditService
from backend.app.services.auth import AuthService
from backend.app.services.biometrics import (
    BiometricEvaluationService,
    BiometricGovernanceService,
    BiometricReferenceService,
    BiometricVerificationService,
    FaceDetectionService,
    FaceMatchingService,
)
from backend.app.services.case import CaseService
from backend.app.services.dashboard import DashboardService
from backend.app.services.department import DepartmentService
from backend.app.services.evidence import EvidenceService
from backend.app.services.health import HealthService, ReadinessProbe
from backend.app.services.incident import IncidentService
from backend.app.services.monitoring import OperationalMonitoringService
from backend.app.services.notification import NotificationService
from backend.app.services.report import ReportExportService
from backend.app.services.user import UserService
from backend.app.services.workload import WorkloadService


def get_app_settings(request: Request) -> Settings:
    """Return the validated ``Settings`` instance bound to the active FastAPI app."""
    app_settings = getattr(request.app.state, "settings", None)
    if isinstance(app_settings, Settings):
        return app_settings
    return get_settings()


def get_correlation_id(request: Request) -> str:
    """Return the verified correlation ID for the current HTTP request."""
    state_id = getattr(request.state, "request_id", None)
    if isinstance(state_id, str) and state_id:
        return state_id
    return get_request_id() or "-"


SettingsDep = Annotated[Settings, Depends(get_app_settings)]
CorrelationIdDep = Annotated[str, Depends(get_correlation_id)]


def get_client_ip(request: Request, settings: SettingsDep) -> str | None:
    """Extract verified client IP respecting TRUSTED_PROXIES configuration."""
    peer_ip = request.client.host if request.client else None
    x_forwarded_for = request.headers.get("x-forwarded-for")
    return resolve_client_ip(
        peer_ip,
        x_forwarded_for,
        trusted_proxies=settings.TRUSTED_PROXIES,
    )


ClientIpDep = Annotated[str | None, Depends(get_client_ip)]


def get_db_manager(request: Request, settings: SettingsDep) -> DatabaseSessionManager:
    """Return the ``DatabaseSessionManager`` bound to the active FastAPI app."""
    db_manager = getattr(request.app.state, "db_manager", None)
    if isinstance(db_manager, DatabaseSessionManager):
        return db_manager
    created = DatabaseSessionManager(settings)
    request.app.state.db_manager = created
    return created


DbManagerDep = Annotated[DatabaseSessionManager, Depends(get_db_manager)]


async def get_db_session(
    db_manager: DbManagerDep,
) -> AsyncIterator[AsyncDatabaseSession]:
    """Yield a request-scoped ``AsyncSession`` that commits on success and rolls back on error."""
    async with db_manager.transactional_session() as session:
        yield session


DbSessionDep = Annotated[AsyncDatabaseSession, Depends(get_db_session)]


def get_health_service(request: Request, settings: SettingsDep) -> HealthService:
    """Construct a ``HealthService`` wired with active settings and registered probes."""
    raw_probes = getattr(request.app.state, "readiness_probes", None)
    probes = (
        cast("Mapping[str, ReadinessProbe]", raw_probes)
        if isinstance(raw_probes, Mapping)
        else None
    )
    return HealthService(settings=settings, probes=probes)


HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]


def get_auth_service(
    request: Request,
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AuthService:
    """Construct an ``AuthService`` bound to the active request DB session and settings."""
    email_service = getattr(request.app.state, "email_service", None)
    rate_limiter = getattr(request.app.state, "rate_limiter", None)
    return AuthService.from_session(
        session=db_session,
        settings=settings,
        email_service=email_service,
        rate_limiter=rate_limiter,
    )


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]

_bearer_security = HTTPBearer(auto_error=False)


async def get_current_principal(
    auth_service: AuthServiceDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_security)],
) -> AuthenticatedPrincipal:
    """Resolve and authorize the active user principal from bearer credentials.

    Raises:
        AuthenticationError: If credentials are missing, expired, revoked, or invalid.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError(
            "Authentication credentials were not provided.",
            code="UNAUTHENTICATED",
        )
    return await auth_service.get_authenticated_principal(credentials.credentials)


CurrentUserDep = Annotated[AuthenticatedPrincipal, Depends(get_current_principal)]
RequirePermissionDep = Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]


def require_permission(
    permission: Permission | str,
) -> Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]:
    """Dependency factory enforcing an explicit granular permission check (Phase 22).

    Usage:
        `principal: AuthenticatedPrincipal = Depends(require_permission(Permission.USER_CREATE_DEPT))`
    """
    target_perm = permission if isinstance(permission, Permission) else Permission(str(permission))

    def _permission_dependency(
        current_user: CurrentUserDep,
    ) -> AuthenticatedPrincipal:
        if not has_permission(current_user.role, target_perm):
            raise PermissionDeniedError(
                f"Principal with role '{current_user.role}' lacks required permission '{target_perm.value}'.",
                code="PERMISSION_DENIED",
            )
        return current_user

    return _permission_dependency


def require_any_permission(
    *permissions: Permission | str,
) -> Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]:
    """Dependency factory requiring at least one of the specified permissions (Phase 22)."""
    resolved_perms = [p if isinstance(p, Permission) else Permission(str(p)) for p in permissions]

    def _any_permission_dependency(
        current_user: CurrentUserDep,
    ) -> AuthenticatedPrincipal:
        if not has_any_permission(current_user.role, resolved_perms):
            raise PermissionDeniedError(
                f"Principal with role '{current_user.role}' lacks any of the required permissions.",
                code="PERMISSION_DENIED",
            )
        return current_user

    return _any_permission_dependency


def require_all_permissions(
    *permissions: Permission | str,
) -> Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]:
    """Dependency factory requiring all specified permissions (Phase 22)."""
    resolved_perms = [p if isinstance(p, Permission) else Permission(str(p)) for p in permissions]

    def _all_permissions_dependency(
        current_user: CurrentUserDep,
    ) -> AuthenticatedPrincipal:
        if not has_all_permissions(current_user.role, resolved_perms):
            raise PermissionDeniedError(
                f"Principal with role '{current_user.role}' lacks all required permissions.",
                code="PERMISSION_DENIED",
            )
        return current_user

    return _all_permissions_dependency


def get_user_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> UserService:
    """Construct a ``UserService`` bound to the active request DB session and settings."""
    return UserService.from_session(session=db_session, settings=settings)


UserServiceDep = Annotated[UserService, Depends(get_user_service)]


def get_department_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> DepartmentService:
    """Construct a ``DepartmentService`` bound to the active request DB session and settings."""
    return DepartmentService.from_session(session=db_session, settings=settings)


DepartmentServiceDep = Annotated[DepartmentService, Depends(get_department_service)]


def get_incident_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> IncidentService:
    """Construct an ``IncidentService`` bound to the active request DB session and settings."""
    return IncidentService.from_session(session=db_session, settings=settings)


IncidentServiceDep = Annotated[IncidentService, Depends(get_incident_service)]


def get_evidence_service(
    request: Request,
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> EvidenceService:
    """Construct an ``EvidenceService`` bound to the active request DB session, storage, and settings."""
    storage_client = getattr(request.app.state, "storage_client", None)
    malware_scanner = getattr(request.app.state, "malware_scanner", None)
    return EvidenceService.from_session(
        session=db_session,
        settings=settings,
        storage_client=storage_client,
        scanner=malware_scanner,
    )


EvidenceServiceDep = Annotated[EvidenceService, Depends(get_evidence_service)]


def get_audit_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AuditService:
    """Construct an ``AuditService`` bound to the active request DB session and settings (Phases 58-59)."""
    return AuditService.from_session(session=db_session, settings=settings)


AuditServiceDep = Annotated[AuditService, Depends(get_audit_service)]


def get_ai_dataset_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AIDatasetService:
    """Construct an AIDatasetService bound to the active request DB session and settings."""
    return AIDatasetService.from_session(session=db_session, settings=settings)


AIDatasetServiceDep = Annotated[AIDatasetService, Depends(get_ai_dataset_service)]


def get_ai_job_service(
    request: Request,
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AIAnalysisJobService:
    """Construct an AIAnalysisJobService bound to session, storage, and classifier."""
    storage_client = getattr(request.app.state, "storage_client", None)
    classifier = getattr(request.app.state, "classifier", None)
    return AIAnalysisJobService.from_session(
        session=db_session,
        settings=settings,
        storage_client=storage_client,
        classifier=classifier,
    )


AIAnalysisJobServiceDep = Annotated[AIAnalysisJobService, Depends(get_ai_job_service)]


def get_ai_segment_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AICandidateSegmentService:
    """Construct an AICandidateSegmentService bound to the active request DB session and settings."""
    return AICandidateSegmentService.from_session(session=db_session, settings=settings)


AISegmentServiceDep = Annotated[AICandidateSegmentService, Depends(get_ai_segment_service)]


def get_ai_retention_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AIRetentionService:
    """Construct an AIRetentionService bound to the active request DB session and settings."""
    return AIRetentionService.from_session(session=db_session, settings=settings)


AIRetentionServiceDep = Annotated[AIRetentionService, Depends(get_ai_retention_service)]


def get_biometric_governance_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> BiometricGovernanceService:
    """Construct a BiometricGovernanceService bound to session and settings."""
    return BiometricGovernanceService.from_session(session=db_session, settings=settings)


BiometricGovernanceServiceDep = Annotated[
    BiometricGovernanceService, Depends(get_biometric_governance_service)
]


def get_biometric_reference_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> BiometricReferenceService:
    """Construct a BiometricReferenceService bound to session and settings."""
    return BiometricReferenceService.from_session(session=db_session, settings=settings)


BiometricReferenceServiceDep = Annotated[
    BiometricReferenceService, Depends(get_biometric_reference_service)
]


def get_face_detection_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> FaceDetectionService:
    """Construct a FaceDetectionService bound to session and settings."""
    return FaceDetectionService.from_session(session=db_session, settings=settings)


FaceDetectionServiceDep = Annotated[FaceDetectionService, Depends(get_face_detection_service)]


def get_face_matching_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> FaceMatchingService:
    """Construct a FaceMatchingService bound to session and settings."""
    return FaceMatchingService.from_session(session=db_session, settings=settings)


FaceMatchingServiceDep = Annotated[FaceMatchingService, Depends(get_face_matching_service)]


def get_biometric_verification_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> BiometricVerificationService:
    """Construct a BiometricVerificationService bound to session and settings."""
    return BiometricVerificationService.from_session(session=db_session, settings=settings)


BiometricVerificationServiceDep = Annotated[
    BiometricVerificationService, Depends(get_biometric_verification_service)
]


def get_biometric_evaluation_service(
    settings: SettingsDep,
) -> BiometricEvaluationService:
    """Construct a BiometricEvaluationService bound to settings."""
    return BiometricEvaluationService(settings=settings)


BiometricEvaluationServiceDep = Annotated[
    BiometricEvaluationService, Depends(get_biometric_evaluation_service)
]


def get_case_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> CaseService:
    """Construct a CaseService bound to the active request DB session and settings."""
    return CaseService.from_session(session=db_session, settings=settings)


CaseServiceDep = Annotated[CaseService, Depends(get_case_service)]


def get_notification_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> NotificationService:
    """Construct a NotificationService bound to the active request DB session and settings."""
    return NotificationService.from_session(session=db_session, settings=settings)


NotificationServiceDep = Annotated[NotificationService, Depends(get_notification_service)]


def get_dashboard_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> DashboardService:
    """Construct a DashboardService bound to the active request DB session and settings."""
    return DashboardService.from_session(session=db_session, settings=settings)


DashboardServiceDep = Annotated[DashboardService, Depends(get_dashboard_service)]


def get_analytics_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> AnalyticsService:
    """Construct an AnalyticsService bound to the active request DB session and settings."""
    return AnalyticsService.from_session(session=db_session, settings=settings)


AnalyticsServiceDep = Annotated[AnalyticsService, Depends(get_analytics_service)]


def get_workload_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> WorkloadService:
    """Construct a WorkloadService bound to the active request DB session and settings."""
    return WorkloadService.from_session(session=db_session, settings=settings)


WorkloadServiceDep = Annotated[WorkloadService, Depends(get_workload_service)]


def get_report_export_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
) -> ReportExportService:
    """Construct a ReportExportService bound to the active request DB session and settings."""
    return ReportExportService.from_session(session=db_session, settings=settings)


ReportExportServiceDep = Annotated[ReportExportService, Depends(get_report_export_service)]


def get_operational_monitoring_service(
    db_session: DbSessionDep,
    settings: SettingsDep,
    health_service: HealthServiceDep,
) -> OperationalMonitoringService:
    """Construct an OperationalMonitoringService bound to session, settings, and health service."""
    return OperationalMonitoringService.from_session(
        session=db_session,
        settings=settings,
        health_service=health_service,
    )


OperationalMonitoringServiceDep = Annotated[
    OperationalMonitoringService, Depends(get_operational_monitoring_service)
]
