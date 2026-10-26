"""Data-access repositories and structural protocols for E-WITNESS (Phases 07-15)."""

from __future__ import annotations

from backend.app.repositories.ai_dataset import AIDatasetRepository
from backend.app.repositories.ai_job import AIAnalysisJobRepository
from backend.app.repositories.ai_segment import AICandidateSegmentRepository
from backend.app.repositories.analytics import AnalyticsRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.base import (
    AppendOnlyLedgerRepositoryProtocol,
    TenantScopedRepositoryProtocol,
)
from backend.app.repositories.biometrics import (
    BiometricGovernanceRepository,
    BiometricReferenceRepository,
)
from backend.app.repositories.case import CaseRepository
from backend.app.repositories.dashboard import DashboardRepository
from backend.app.repositories.evidence import EvidenceRepository
from backend.app.repositories.identity import (
    DEFAULT_SYSTEM_ROLES,
    AuthTokenRepository,
    DepartmentRepository,
    RoleRepository,
    SessionRepository,
    UserRepository,
)
from backend.app.repositories.incident import IncidentRepository
from backend.app.repositories.monitoring import OperationalMonitoringRepository
from backend.app.repositories.notification import NotificationRepository
from backend.app.repositories.report import ReportRepository

__all__ = [
    "DEFAULT_SYSTEM_ROLES",
    "AIAnalysisJobRepository",
    "AICandidateSegmentRepository",
    "AIDatasetRepository",
    "AnalyticsRepository",
    "AppendOnlyLedgerRepositoryProtocol",
    "AuditRepository",
    "AuthTokenRepository",
    "BiometricGovernanceRepository",
    "BiometricReferenceRepository",
    "CaseRepository",
    "DashboardRepository",
    "DepartmentRepository",
    "EvidenceRepository",
    "IncidentRepository",
    "NotificationRepository",
    "OperationalMonitoringRepository",
    "ReportRepository",
    "RoleRepository",
    "SessionRepository",
    "TenantScopedRepositoryProtocol",
    "UserRepository",
]
