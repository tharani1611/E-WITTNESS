"""Core SQLAlchemy 2.x persistence models for E-WITNESS (Phases 12-15).

Exports the declarative `Base` and the four initial identity and tenant
foundation models (`Department`, `Role`, `User`, `Session`/`UserSession`) so
Alembic metadata inspection discovers all tables automatically.
"""

from __future__ import annotations

from backend.app.models.ai import AIAnalysisJob, AICandidateSegment, AIDataset
from backend.app.models.audit import EvidenceExport, SecurityAuditEvent
from backend.app.models.base import (
    NAMING_CONVENTION,
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)
from backend.app.models.biometrics import (
    BiometricGovernanceRecord,
    BiometricReference,
    BiometricVerificationReview,
)
from backend.app.models.case import (
    Case,
    CaseAISegment,
    CaseApproval,
    CaseAssignment,
    CaseEscalation,
    CaseEvidence,
    CaseExport,
    CaseFinding,
    CaseFindingHistory,
    CaseIncident,
    CaseNote,
    CaseNoteHistory,
    CaseReferral,
)
from backend.app.models.department import Department
from backend.app.models.evidence import (
    EvidenceAttachment,
    EvidenceCustodyEvent,
    UploadSession,
)
from backend.app.models.incident import (
    Incident,
    IncidentAssignment,
    IncidentRoutingDecision,
)
from backend.app.models.monitoring import OperationalAlert, WorkerHeartbeat
from backend.app.models.notification import (
    Notification,
    NotificationDeliveryAttempt,
    NotificationPreference,
)
from backend.app.models.report import ReportExport
from backend.app.models.role import Role
from backend.app.models.session import Session, UserSession
from backend.app.models.token import AuthToken
from backend.app.models.user import User

__all__ = [
    "NAMING_CONVENTION",
    "AIAnalysisJob",
    "AICandidateSegment",
    "AIDataset",
    "AuthToken",
    "Base",
    "BiometricGovernanceRecord",
    "BiometricReference",
    "BiometricVerificationReview",
    "Case",
    "CaseAISegment",
    "CaseApproval",
    "CaseAssignment",
    "CaseEscalation",
    "CaseEvidence",
    "CaseExport",
    "CaseFinding",
    "CaseFindingHistory",
    "CaseIncident",
    "CaseNote",
    "CaseNoteHistory",
    "CaseReferral",
    "Department",
    "EvidenceAttachment",
    "EvidenceCustodyEvent",
    "EvidenceExport",
    "Incident",
    "IncidentAssignment",
    "IncidentRoutingDecision",
    "Notification",
    "NotificationDeliveryAttempt",
    "NotificationPreference",
    "OperationalAlert",
    "ReportExport",
    "Role",
    "SecurityAuditEvent",
    "Session",
    "TimestampMixin",
    "UTCDateTime",
    "UUIDPrimaryKeyMixin",
    "UploadSession",
    "User",
    "UserSession",
    "WorkerHeartbeat",
    "utc_now",
]
