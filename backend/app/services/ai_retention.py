"""Retention policy service for AI results and candidate segments (Phase 69.4).

Enforces:
- Configurable retention periods for AI candidate segments.
- Mandatory legal-hold and active investigation protection: segments belonging to active
  or unclosed incidents (SUBMITTED, TRIAGED, UNDER_INVESTIGATION) are strictly exempt from purging.
- Non-destructive evidence preservation: original evidence objects (evidence_attachments)
  and physical storage files are permanently preserved.
- Immutable audit preservation: chain-of-custody and security audit ledgers are never deleted.
- Authorized execution restricted to administrators with AI_RESULT_RETENTION_MANAGE permission.
- Comprehensive security audit logging of all purge operations.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import PermissionDeniedError
from backend.app.core.incident import IncidentStatus
from backend.app.models.base import utc_now
from backend.app.models.incident import Incident
from backend.app.repositories.ai_segment import AICandidateSegmentRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.schemas.ai import AIRetentionPurgeResponse
from backend.app.schemas.auth import AuthenticatedPrincipal

ACTIVE_INVESTIGATION_STATUSES = frozenset(
    {
        IncidentStatus.SUBMITTED.value,
        IncidentStatus.TRIAGED.value,
        IncidentStatus.UNDER_INVESTIGATION.value,
    }
)


class AIRetentionService:
    """Service executing authorized retention lifecycle policies for AI analysis results."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        segment_repo: AICandidateSegmentRepository,
        audit_repo: AuditRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.segment_repo = segment_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> AIRetentionService:
        """Construct an AIRetentionService bound to the active session."""
        return cls(
            session=session,
            segment_repo=AICandidateSegmentRepository(session),
            audit_repo=audit_repo or AuditRepository(session),
            settings=settings,
        )

    async def purge_expired_candidate_segments(
        self,
        *,
        retention_days: int = 90,
        department_id: UUID | None = None,
        principal: AuthenticatedPrincipal,
    ) -> AIRetentionPurgeResponse:
        """Purge candidate segments older than retention_days, respecting legal holds and active cases."""
        if not has_permission(principal.role, Permission.AI_RESULT_RETENTION_MANAGE):
            raise PermissionDeniedError(
                "Caller lacks permission to manage AI result retention.",
                code="RETENTION_PERMISSION_DENIED",
            )

        # Department scoping: DEPT_ADMIN can only purge within their assigned department
        is_global = has_permission(principal.role, Permission.INCIDENT_READ_GLOBAL)
        scoped_dept: UUID | None = None
        if not is_global:
            scoped_dept = principal.department_id
        elif department_id is not None:
            scoped_dept = department_id

        cutoff_date = utc_now() - timedelta(days=retention_days)

        # Identify all active incidents under investigation (legal hold / active cases)
        active_stmt = select(Incident.id).where(Incident.status.in_(ACTIVE_INVESTIGATION_STATUSES))
        if scoped_dept is not None:
            active_stmt = active_stmt.where(Incident.department_id == scoped_dept)
        active_result = await self.session.execute(active_stmt)
        exempt_incident_ids = set(active_result.scalars().all())

        # Execute safe purge on segment repository
        purged_count = await self.segment_repo.purge_expired(
            cutoff_date=cutoff_date,
            department_id=scoped_dept,
            exempt_incident_ids=exempt_incident_ids,
        )

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_RESULTS_PURGED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=scoped_dept,
                target_type=AuditTargetType.AI_SEGMENT.value,
                target_id=str(scoped_dept or "global"),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "purged_count": purged_count,
                    "retention_days": retention_days,
                    "cutoff_date": cutoff_date.isoformat(),
                    "exempt_active_incidents_count": len(exempt_incident_ids),
                },
            )

        return AIRetentionPurgeResponse(
            purged_count=purged_count,
            retention_days=retention_days,
            cutoff_date=cutoff_date,
            department_id=scoped_dept,
        )
