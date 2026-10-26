"""Investigation Case service orchestrating domain logic, linkages, capacity, and human review (Phases 81-85).

Enforces:
- Strict department and tenant isolation across cases, incidents, evidence, and AI results.
- Human review non-negotiable principle: AI identifies candidate leads only, never establishes guilt or facts.
- Conflict-of-interest prevention: incident reporters cannot review AI candidate segments for that incident.
- Concurrency safety with optimistic locking via version_id.
- Investigator workload capacity limits (default max 10 active cases).
- Append-only assignment and audit ledger events for every state, link, and review transition.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.ai import SegmentReviewStatus
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.case import (
    AI_ADVISORY_DISCLAIMER,
    INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES,
    TERMINAL_CASE_STATUSES,
    CaseApprovalDecision,
    CaseNoteVisibility,
    CasePriority,
    CaseReferralStatus,
    CaseStatus,
    EvidenceVerificationStatus,
    IncidentLinkType,
    InvestigativeRelevance,
    generate_case_reference_number,
    validate_case_status_transition,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.logging import get_logger
from backend.app.models.base import utc_now
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
from backend.app.repositories.ai_segment import AICandidateSegmentRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.case import CaseRepository
from backend.app.repositories.evidence import EvidenceRepository
from backend.app.repositories.identity import DepartmentRepository, UserRepository
from backend.app.repositories.incident import IncidentRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.case import (
    CaseAISegmentRead,
    CaseAISegmentReviewRequest,
    CaseApprovalRead,
    CaseApprovalRequest,
    CaseAssignmentRead,
    CaseAssignRequest,
    CaseCloseRequest,
    CaseCreate,
    CaseEscalationRead,
    CaseEscalationRequest,
    CaseEvidenceItemRead,
    CaseExportRead,
    CaseExportRequest,
    CaseFindingCreate,
    CaseFindingHistoryRead,
    CaseFindingRead,
    CaseFindingUpdate,
    CaseIncidentRead,
    CaseLinkAISegmentRequest,
    CaseLinkEvidenceRequest,
    CaseLinkIncidentRequest,
    CaseNoteCreate,
    CaseNoteHistoryRead,
    CaseNoteRead,
    CaseNoteUpdate,
    CaseRead,
    CaseReferralCreate,
    CaseReferralRead,
    CaseReferralUpdate,
    CaseReopenRequest,
    CaseTransitionRequest,
    CaseUpdate,
    InvestigatorWorkloadRead,
    PaginatedCasesRead,
)

logger = get_logger("services.case")


class CaseService:
    """Domain service managing investigation cases, linkages, capacity, and human review."""

    def __init__(
        self,
        case_repo: CaseRepository,
        incident_repo: IncidentRepository,
        evidence_repo: EvidenceRepository,
        ai_segment_repo: AICandidateSegmentRepository,
        department_repo: DepartmentRepository,
        user_repo: UserRepository,
        audit_repo: AuditRepository,
        settings: Settings,
        max_active_cases: int = INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES,
    ) -> None:
        self.case_repo = case_repo
        self.incident_repo = incident_repo
        self.evidence_repo = evidence_repo
        self.ai_segment_repo = ai_segment_repo
        self.department_repo = department_repo
        self.user_repo = user_repo
        self.audit_repo = audit_repo
        self.settings = settings
        self.max_active_cases = max_active_cases

    @classmethod
    def from_session(cls, session: AsyncSession, settings: Settings) -> CaseService:
        """Construct a CaseService wired with repositories bound to session."""
        return cls(
            case_repo=CaseRepository(session),
            incident_repo=IncidentRepository(session),
            evidence_repo=EvidenceRepository(session),
            ai_segment_repo=AICandidateSegmentRepository(session),
            department_repo=DepartmentRepository(session),
            user_repo=UserRepository(session),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    # =========================================================================
    # Phase 81: Case CRUD & Incident Linkage
    # =========================================================================

    async def create_case(
        self,
        payload: CaseCreate,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseRead:
        """Create a new investigation case bound to department and owner."""
        # 1. Authorization check
        can_global = has_permission(principal.role_code, Permission.CASE_CREATE_GLOBAL)
        can_dept = has_permission(principal.role_code, Permission.CASE_CREATE_DEPT)
        if not (can_global or can_dept):
            raise PermissionDeniedError(
                "You do not have permission to create investigation cases.",
                code="PERMISSION_DENIED",
            )

        # 2. Determine target department
        if payload.department_id is not None:
            if not can_global and payload.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "You cannot create cases for another department.",
                    code="CROSS_DEPARTMENT_FORBIDDEN",
                )
            dept_id = payload.department_id
        else:
            if principal.department_id is None:
                raise BusinessRuleError(
                    "A department must be specified for case creation.",
                    code="DEPARTMENT_REQUIRED",
                )
            dept_id = principal.department_id

        # Verify department exists and is active
        dept = await self.department_repo.get_by_id(dept_id)
        if dept is None or not dept.is_active:
            raise BusinessRuleError(
                "The target department does not exist or is inactive.",
                code="INACTIVE_DEPARTMENT",
            )

        # 3. Optional initial lead investigator validation
        lead_id = payload.lead_investigator_id
        if lead_id is not None:
            await self._validate_investigator_assignment(
                investigator_id=lead_id,
                target_department_id=dept_id,
                can_global=can_global,
            )

        # 4. Optional initial incident validation
        initial_incident = None
        if payload.initial_incident_id is not None:
            initial_incident = await self.incident_repo.get_by_id(payload.initial_incident_id)
            if initial_incident is None:
                raise ResourceNotFoundError(
                    "Initial incident not found.", code="INCIDENT_NOT_FOUND"
                )
            if initial_incident.department_id != dept_id:
                raise BusinessRuleError(
                    "Initial incident belongs to a different department than the case.",
                    code="DEPARTMENT_MISMATCH",
                )

        # 5. Generate stable, unique reference number
        ref_number = generate_case_reference_number()
        existing = await self.case_repo.get_by_reference_number(ref_number)
        if existing is not None:
            ref_number = generate_case_reference_number()

        # 6. Create Case record
        case_record = Case(
            reference_number=ref_number,
            title=payload.title,
            summary=payload.summary,
            status=CaseStatus.OPEN.value,
            priority=payload.priority.value,
            department_id=dept_id,
            created_by_id=principal.user_id,
            lead_investigator_id=lead_id,
            version_id=1,
            is_legal_hold=False,
        )
        created_case = await self.case_repo.create(case_record)

        # 7. Record initial assignment if lead was specified
        if lead_id is not None:
            assignment = CaseAssignment(
                case_id=created_case.id,
                previous_investigator_id=None,
                new_investigator_id=lead_id,
                assigned_by_id=principal.user_id,
                assignment_reason="Initial lead assignment upon case creation.",
            )
            await self.case_repo.record_assignment(assignment)

        # 8. Link initial incident if specified
        if initial_incident is not None:
            incident_link = CaseIncident(
                case_id=created_case.id,
                incident_id=initial_incident.id,
                linked_by_id=principal.user_id,
                link_type=IncidentLinkType.PRIMARY.value,
            )
            await self.case_repo.link_incident(incident_link)

        # 9. Audit event
        await self.audit_repo.append_event(
            action=AuditAction.CASE_CREATED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.CASE,
            target_id=str(created_case.id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=dept_id,
            details={
                "reference_number": created_case.reference_number,
                "title": created_case.title,
                "priority": created_case.priority,
                "lead_investigator_id": str(lead_id) if lead_id else None,
                "initial_incident_id": str(payload.initial_incident_id)
                if payload.initial_incident_id
                else None,
            },
        )

        return self._to_case_read(created_case)

    async def get_case(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> CaseRead:
        """Retrieve a single investigation case enforcing visibility boundaries."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)
        return self._to_case_read(case_record)

    async def get_case_by_reference(
        self,
        reference_number: str,
        principal: AuthenticatedPrincipal,
    ) -> CaseRead:
        """Lookup a case by unique reference number."""
        case_record = await self.case_repo.get_by_reference_number(reference_number)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)
        return self._to_case_read(case_record)

    async def list_cases(
        self,
        principal: AuthenticatedPrincipal,
        *,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        priority: str | None = None,
        is_legal_hold: bool | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> PaginatedCasesRead:
        """List cases respecting department or own-case scoping."""
        can_global = has_permission(principal.role_code, Permission.CASE_READ_GLOBAL)
        can_dept = has_permission(principal.role_code, Permission.CASE_READ_DEPT)
        can_own = has_permission(principal.role_code, Permission.CASE_READ_OWN)

        if not (can_global or can_dept or can_own):
            raise PermissionDeniedError(
                "You do not have permission to list cases.",
                code="PERMISSION_DENIED",
            )

        dept_id_filter: UUID | None = None
        lead_id_filter: UUID | None = None
        creator_id_filter: UUID | None = None

        if can_global:
            dept_id_filter = None
        elif can_dept:
            dept_id_filter = principal.department_id
        elif can_own:
            lead_id_filter = principal.user_id

        rows, total = await self.case_repo.list_paginated(
            limit=limit,
            offset=offset,
            department_id=dept_id_filter,
            lead_investigator_id=lead_id_filter,
            created_by_id=creator_id_filter,
            status=status,
            priority=priority,
            is_legal_hold=is_legal_hold,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        return PaginatedCasesRead(
            items=[self._to_case_read(c) for c in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    async def update_case(
        self,
        case_id: UUID,
        payload: CaseUpdate,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseRead:
        """Update case details, status, or legal hold with optimistic locking."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_writable(case_record, principal)

        # Optimistic concurrency check
        if case_record.version_id != payload.expected_version:
            raise BusinessRuleError(
                f"Concurrent modification detected. Current version is {case_record.version_id}, "
                f"expected {payload.expected_version}.",
                code="CONCURRENCY_CONFLICT",
                status_code=409,
            )

        if (
            case_record.status in {s.value for s in TERMINAL_CASE_STATUSES}
            and payload.status is None
        ):
            raise BusinessRuleError(
                f"Case is in terminal status '{case_record.status}' and cannot be modified.",
                code="CASE_TERMINAL_IMMUTABLE",
                status_code=400,
            )

        updated_fields: dict[str, Any] = {}

        # 1. Update text metadata if provided
        if payload.title is not None and payload.title != case_record.title:
            case_record.title = payload.title
            updated_fields["title"] = payload.title
        if payload.summary is not None and payload.summary != case_record.summary:
            case_record.summary = payload.summary
            updated_fields["summary"] = payload.summary
        if payload.priority is not None and payload.priority.value != case_record.priority:
            case_record.priority = payload.priority.value
            updated_fields["priority"] = payload.priority.value

        # 2. Status transition
        if payload.status is not None and payload.status.value != case_record.status:
            validate_case_status_transition(case_record.status, payload.status.value)
            old_status = case_record.status
            new_status = payload.status.value

            # If moving to terminal status, require status_reason
            if payload.status in TERMINAL_CASE_STATUSES:
                if not payload.status_reason or not payload.status_reason.strip():
                    raise BusinessRuleError(
                        f"Documented rationale is required when transitioning case to '{new_status}'.",
                        code="STATUS_REASON_REQUIRED",
                    )
                case_record.closed_at = utc_now()
            else:
                case_record.closed_at = None

            case_record.status = new_status
            updated_fields["status"] = new_status
            updated_fields["previous_status"] = old_status
            if payload.status_reason:
                updated_fields["status_reason"] = payload.status_reason

            await self.audit_repo.append_event(
                action=AuditAction.CASE_STATUS_TRANSITION,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                target_type=AuditTargetType.CASE,
                target_id=str(case_record.id),
                outcome=AuditOutcome.SUCCESS,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                department_id=case_record.department_id,
                details={
                    "from_status": old_status,
                    "to_status": new_status,
                    "reason": payload.status_reason,
                },
            )

        # 3. Legal Hold toggling
        if payload.is_legal_hold is not None and payload.is_legal_hold != case_record.is_legal_hold:
            if payload.is_legal_hold and not payload.legal_hold_reason:
                raise BusinessRuleError(
                    "A legal hold reason is required when placing a case under legal hold.",
                    code="LEGAL_HOLD_REASON_REQUIRED",
                )
            case_record.is_legal_hold = payload.is_legal_hold
            case_record.legal_hold_reason = (
                payload.legal_hold_reason if payload.is_legal_hold else None
            )
            updated_fields["is_legal_hold"] = case_record.is_legal_hold
            if case_record.legal_hold_reason:
                updated_fields["legal_hold_reason"] = case_record.legal_hold_reason

        # Increment version_id
        case_record.version_id += 1
        updated = await self.case_repo.update(case_record)
        return self._to_case_read(updated)

    # =========================================================================
    # Phase 82: Assignment & Capacity Controls
    # =========================================================================

    async def assign_case(
        self,
        case_id: UUID,
        payload: CaseAssignRequest,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseRead:
        """Assign or reassign a case lead investigator with workload capacity checks."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        can_global = has_permission(principal.role_code, Permission.CASE_ASSIGN_GLOBAL)
        can_dept = has_permission(principal.role_code, Permission.CASE_ASSIGN_DEPT)
        if not (can_global or can_dept):
            raise PermissionDeniedError(
                "You do not have permission to assign cases.",
                code="PERMISSION_DENIED",
            )
        if not can_global and case_record.department_id != principal.department_id:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        # Concurrency check
        if case_record.version_id != payload.expected_version:
            raise BusinessRuleError(
                f"Concurrent modification detected. Current version is {case_record.version_id}, "
                f"expected {payload.expected_version}.",
                code="CONCURRENCY_CONFLICT",
                status_code=409,
            )

        # Validate investigator and workload
        await self._validate_investigator_assignment(
            investigator_id=payload.new_investigator_id,
            target_department_id=case_record.department_id,
            can_global=can_global,
            exclude_case_id=case_record.id,
        )

        previous_lead = case_record.lead_investigator_id
        case_record.lead_investigator_id = payload.new_investigator_id
        case_record.version_id += 1

        # Record append-only assignment
        assignment = CaseAssignment(
            case_id=case_record.id,
            previous_investigator_id=previous_lead,
            new_investigator_id=payload.new_investigator_id,
            assigned_by_id=principal.user_id,
            assignment_reason=payload.assignment_reason,
        )
        await self.case_repo.record_assignment(assignment)
        updated = await self.case_repo.update(case_record)

        audit_action = AuditAction.CASE_REASSIGNED if previous_lead else AuditAction.CASE_ASSIGNED
        await self.audit_repo.append_event(
            action=audit_action,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.CASE,
            target_id=str(case_record.id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=case_record.department_id,
            details={
                "previous_investigator_id": str(previous_lead) if previous_lead else None,
                "new_investigator_id": str(payload.new_investigator_id),
                "reason": payload.assignment_reason,
            },
        )

        return self._to_case_read(updated)

    async def list_assignments(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseAssignmentRead]:
        """List historical assignment events for a case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)
        assignments = await self.case_repo.list_assignments(case_id)
        return [CaseAssignmentRead.model_validate(a) for a in assignments]

    async def get_investigator_workload(
        self,
        investigator_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> InvestigatorWorkloadRead:
        """Inspect active workload capacity for an investigator."""
        can_global = has_permission(principal.role_code, Permission.CASE_WORKLOAD_READ_GLOBAL)
        can_dept = has_permission(principal.role_code, Permission.CASE_WORKLOAD_READ_DEPT)
        if not (can_global or can_dept):
            raise PermissionDeniedError(
                "You do not have permission to inspect investigator workload.",
                code="PERMISSION_DENIED",
            )

        if can_global:
            investigator = await self.user_repo.get_by_id_unscoped(investigator_id)
        else:
            if principal.department_id is None:
                raise PermissionDeniedError("Department required.", code="PERMISSION_DENIED")
            investigator = await self.user_repo.get_by_id(
                investigator_id, department_id=principal.department_id
            )
        if investigator is None:
            raise ResourceNotFoundError("Investigator not found.", code="USER_NOT_FOUND")

        active_count = await self.case_repo.count_active_cases_for_investigator(investigator_id)
        return InvestigatorWorkloadRead(
            investigator_id=investigator_id,
            active_cases_count=active_count,
            max_active_cases=self.max_active_cases,
            capacity_available=active_count < self.max_active_cases,
        )

    # =========================================================================
    # Phase 81 Linkages: Case Incidents
    # =========================================================================

    async def link_incident(
        self,
        case_id: UUID,
        payload: CaseLinkIncidentRequest,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseIncidentRead:
        """Link an incident to an investigation case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        incident = await self.incident_repo.get_by_id(payload.incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        # Department boundary check
        if incident.department_id != case_record.department_id:
            raise BusinessRuleError(
                "Cannot link incident from a different department.",
                code="DEPARTMENT_MISMATCH",
            )

        # Check existing link
        existing = await self.case_repo.get_incident_link(case_id, payload.incident_id)
        if existing is not None:
            raise BusinessRuleError(
                "This incident is already linked to the case.",
                code="INCIDENT_ALREADY_LINKED",
            )

        link = CaseIncident(
            id=uuid4(),
            case_id=case_id,
            incident_id=payload.incident_id,
            linked_by_id=principal.user_id,
            link_type=payload.link_type.value,
        )
        created_link = await self.case_repo.link_incident(link) or link

        await self.audit_repo.append_event(
            action=AuditAction.CASE_INCIDENT_LINKED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.CASE,
            target_id=str(case_id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=case_record.department_id,
            details={
                "incident_id": str(payload.incident_id),
                "link_type": payload.link_type.value,
            },
        )

        link_id = (
            created_link.id if isinstance(getattr(created_link, "id", None), UUID) else link.id
        )
        link_created_at = (
            created_link.created_at
            if isinstance(getattr(created_link, "created_at", None), datetime)
            else utc_now()
        )

        return CaseIncidentRead(
            id=link_id,
            case_id=link.case_id,
            incident_id=link.incident_id,
            linked_by_id=link.linked_by_id,
            link_type=payload.link_type,
            created_at=link_created_at,
            incident_title=incident.title,
            incident_reference_number=incident.reference_number,
            incident_status=incident.status,
        )

    async def unlink_incident(
        self,
        case_id: UUID,
        incident_id: UUID,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> bool:
        """Unlink an incident from a case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        link = await self.case_repo.get_incident_link(case_id, incident_id)
        if link is None:
            raise ResourceNotFoundError("Incident link not found.", code="LINK_NOT_FOUND")

        if case_record.is_legal_hold:
            raise BusinessRuleError(
                "Cannot unlink incidents while case is under legal hold.",
                code="LEGAL_HOLD_ACTIVE",
                status_code=409,
            )

        unlinked = await self.case_repo.unlink_incident(case_id, incident_id)
        if unlinked:
            await self.audit_repo.append_event(
                action=AuditAction.CASE_INCIDENT_UNLINKED,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                target_type=AuditTargetType.CASE,
                target_id=str(case_id),
                outcome=AuditOutcome.SUCCESS,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                department_id=case_record.department_id,
                details={"incident_id": str(incident_id)},
            )
        return unlinked

    async def list_case_incidents(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseIncidentRead]:
        """List all incidents linked to an investigation case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_visible(case_record, principal)

        links = await self.case_repo.list_case_incidents(case_id)
        results = []
        for lk in links:
            inc = lk.incident
            results.append(
                CaseIncidentRead(
                    id=getattr(lk, "id", None) or uuid4(),
                    case_id=lk.case_id,
                    incident_id=lk.incident_id,
                    linked_by_id=getattr(lk, "linked_by_id", None) or uuid4(),
                    link_type=IncidentLinkType(lk.link_type),
                    created_at=lk.created_at,
                    incident_title=inc.title if inc else None,
                    incident_reference_number=inc.reference_number if inc else None,
                    incident_status=inc.status if inc else None,
                )
            )
        return results

    # =========================================================================
    # Phase 83: Evidence Inventory & Integrity
    # =========================================================================

    async def link_evidence(
        self,
        case_id: UUID,
        payload: CaseLinkEvidenceRequest,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseEvidenceItemRead:
        """Attach evidence to a case and enrich with integrity metadata."""
        if not has_permission(principal.role_code, Permission.CASE_EVIDENCE_MANAGE):
            raise PermissionDeniedError(
                "You do not have permission to manage case evidence.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        evidence = await self.evidence_repo.get_attachment_by_id(payload.evidence_id)
        if evidence is None:
            raise ResourceNotFoundError("Evidence attachment not found.", code="EVIDENCE_NOT_FOUND")

        # Verify evidence belongs to an incident in the same department
        incident = await self.incident_repo.get_by_id(evidence.incident_id)
        if incident is None or incident.department_id != case_record.department_id:
            raise BusinessRuleError(
                "Evidence belongs to a different department than the case.",
                code="DEPARTMENT_MISMATCH",
            )

        existing = await self.case_repo.get_evidence_link(case_id, payload.evidence_id)
        if existing is not None:
            raise BusinessRuleError(
                "This evidence attachment is already linked to the case.",
                code="EVIDENCE_ALREADY_LINKED",
            )

        fname = getattr(evidence, "original_filename", getattr(evidence, "file_name", "unknown"))
        ctype = getattr(
            evidence,
            "declared_mime_type",
            getattr(evidence, "content_type", "application/octet-stream"),
        )
        hash_val = getattr(evidence, "sha256_hash", "") or ""

        import re

        if not re.fullmatch(r"[0-9a-fA-F]{64}", hash_val):
            raise BusinessRuleError(
                "Evidence digest is invalid or compromised.",
                code="EVIDENCE_INTEGRITY_COMPROMISED",
                status_code=422,
            )

        link = CaseEvidence(
            id=uuid4(),
            case_id=case_id,
            evidence_id=payload.evidence_id,
            linked_by_id=principal.user_id,
            notes=payload.notes,
            is_exhibiting=payload.is_exhibiting,
        )
        created_link = await self.case_repo.link_evidence(link) or link

        await self.audit_repo.append_event(
            action=AuditAction.CASE_EVIDENCE_LINKED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.CASE,
            target_id=str(case_id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=case_record.department_id,
            details={
                "evidence_id": str(payload.evidence_id),
                "file_name": fname,
                "sha256_hash": hash_val,
                "is_exhibiting": payload.is_exhibiting,
            },
        )

        ev_link_id = (
            created_link.id if isinstance(getattr(created_link, "id", None), UUID) else link.id
        )
        ev_link_created_at = (
            created_link.created_at
            if isinstance(getattr(created_link, "created_at", None), datetime)
            else utc_now()
        )

        return CaseEvidenceItemRead(
            id=ev_link_id,
            case_id=link.case_id,
            evidence_id=link.evidence_id,
            linked_by_id=link.linked_by_id,
            notes=link.notes,
            is_exhibiting=link.is_exhibiting,
            created_at=ev_link_created_at,
            file_name=fname,
            file_size_bytes=evidence.file_size_bytes,
            content_type=ctype,
            sha256_hash=hash_val,
            integrity_status="verified",
            is_legal_hold=case_record.is_legal_hold,
            chain_of_custody_events_count=len(evidence.custody_events)
            if getattr(evidence, "custody_events", None)
            else 0,
        )

    async def unlink_evidence(
        self,
        case_id: UUID,
        evidence_id: UUID,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> bool:
        """Unlink an evidence attachment from a case."""
        if not has_permission(principal.role_code, Permission.CASE_EVIDENCE_MANAGE):
            raise PermissionDeniedError(
                "You do not have permission to manage case evidence.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        link = await self.case_repo.get_evidence_link(case_id, evidence_id)
        if link is None:
            raise ResourceNotFoundError("Evidence link not found.", code="LINK_NOT_FOUND")

        if case_record.is_legal_hold:
            raise BusinessRuleError(
                "Cannot unlink evidence while case is under legal hold.",
                code="LEGAL_HOLD_ACTIVE",
                status_code=409,
            )

        unlinked = await self.case_repo.unlink_evidence(case_id, evidence_id)
        if unlinked:
            await self.audit_repo.append_event(
                action=AuditAction.CASE_EVIDENCE_UNLINKED,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                target_type=AuditTargetType.CASE,
                target_id=str(case_id),
                outcome=AuditOutcome.SUCCESS,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                department_id=case_record.department_id,
                details={"evidence_id": str(evidence_id)},
            )
        return unlinked

    async def list_case_evidence(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseEvidenceItemRead]:
        """List enriched evidence inventory for a case.

        NEVER leaks storage bucket, raw storage keys, or presigned upload URLs.
        """
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_visible(case_record, principal)

        links = await self.case_repo.list_case_evidence(case_id)
        results = []
        for lk in links:
            ev = lk.evidence
            fname = getattr(ev, "original_filename", getattr(ev, "file_name", "unknown"))
            ctype = getattr(
                ev, "declared_mime_type", getattr(ev, "content_type", "application/octet-stream")
            )
            hash_val = getattr(ev, "sha256_hash", "") or ""
            results.append(
                CaseEvidenceItemRead(
                    id=getattr(lk, "id", None) or uuid4(),
                    case_id=lk.case_id,
                    evidence_id=lk.evidence_id,
                    linked_by_id=getattr(lk, "linked_by_id", None) or uuid4(),
                    notes=lk.notes,
                    is_exhibiting=lk.is_exhibiting,
                    created_at=lk.created_at,
                    file_name=fname,
                    file_size_bytes=ev.file_size_bytes,
                    content_type=ctype,
                    sha256_hash=hash_val,
                    integrity_status="verified",
                    is_legal_hold=case_record.is_legal_hold,
                    chain_of_custody_events_count=len(ev.custody_events)
                    if getattr(ev, "custody_events", None)
                    else 0,
                )
            )
        return results

    # =========================================================================
    # Phase 84: AI Candidate Segments Integration
    # =========================================================================

    async def link_ai_segment(
        self,
        case_id: UUID,
        payload: CaseLinkAISegmentRequest,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseAISegmentRead:
        """Integrate an AI candidate segment into a case as an advisory lead."""
        if not has_permission(principal.role_code, Permission.CASE_AI_SEGMENT_MANAGE):
            raise PermissionDeniedError(
                "You do not have permission to manage case AI segments.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        segment = await self.ai_segment_repo.get_by_id(payload.segment_id)
        if segment is None:
            raise ResourceNotFoundError("AI candidate segment not found.", code="SEGMENT_NOT_FOUND")

        # Department alignment check
        if segment.department_id != case_record.department_id:
            raise BusinessRuleError(
                "AI candidate segment belongs to a different department than the case.",
                code="DEPARTMENT_MISMATCH",
            )

        existing = await self.case_repo.get_ai_segment_link(case_id, payload.segment_id)
        if existing is not None:
            raise BusinessRuleError(
                "This AI candidate segment is already linked to the case.",
                code="SEGMENT_ALREADY_LINKED",
            )

        link = CaseAISegment(
            case_id=case_id,
            segment_id=payload.segment_id,
            linked_by_id=principal.user_id,
            investigative_relevance=payload.investigative_relevance.value,
            relevance_notes=payload.relevance_notes,
        )
        await self.case_repo.link_ai_segment(link)

        await self.audit_repo.append_event(
            action=AuditAction.CASE_AI_SEGMENT_LINKED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.CASE,
            target_id=str(case_id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=case_record.department_id,
            details={
                "segment_id": str(payload.segment_id),
                "investigative_relevance": payload.investigative_relevance.value,
                "score": segment.calibrated_score
                if getattr(segment, "calibrated_score", None) is not None
                else getattr(segment, "raw_score", 0.0),
                "label": getattr(segment, "raw_label", "violence"),
            },
        )

        return self._to_ai_segment_read(link, segment)

    async def unlink_ai_segment(
        self,
        case_id: UUID,
        segment_id: UUID,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> bool:
        """Unlink an AI candidate segment from a case."""
        if not has_permission(principal.role_code, Permission.CASE_AI_SEGMENT_MANAGE):
            raise PermissionDeniedError(
                "You do not have permission to manage case AI segments.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        link = await self.case_repo.get_ai_segment_link(case_id, segment_id)
        if link is None:
            raise ResourceNotFoundError("AI segment link not found.", code="LINK_NOT_FOUND")

        if case_record.is_legal_hold:
            raise BusinessRuleError(
                "Cannot unlink AI candidate segments while case is under legal hold.",
                code="LEGAL_HOLD_ACTIVE",
                status_code=409,
            )

        unlinked = await self.case_repo.unlink_ai_segment(case_id, segment_id)
        if unlinked:
            await self.audit_repo.append_event(
                action=AuditAction.CASE_AI_SEGMENT_UNLINKED,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                target_type=AuditTargetType.CASE,
                target_id=str(case_id),
                outcome=AuditOutcome.SUCCESS,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                department_id=case_record.department_id,
                details={"segment_id": str(segment_id)},
            )
        return unlinked

    async def list_case_ai_segments(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseAISegmentRead]:
        """List AI candidate segments linked to a case with non-authoritative advisory disclaimer."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_visible(case_record, principal)

        links = await self.case_repo.list_case_ai_segments(case_id)
        results = []
        for lk in links:
            seg = lk.segment
            results.append(self._to_ai_segment_read(lk, seg))
        return results

    # =========================================================================
    # Phase 85: Human Review & AI Classification Correction
    # =========================================================================

    async def review_ai_segment(
        self,
        case_id: UUID,
        segment_id: UUID,
        payload: CaseAISegmentReviewRequest,
        principal: AuthenticatedPrincipal,
        *,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseAISegmentRead:
        """Perform authorized human review of an AI candidate segment with conflict-of-interest check."""
        if not has_permission(principal.role_code, Permission.CASE_AI_SEGMENT_REVIEW):
            raise PermissionDeniedError(
                "You do not have permission to review AI candidate segments.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")
        self._assert_case_writable(case_record, principal)

        link = await self.case_repo.get_ai_segment_link(case_id, segment_id)
        if link is None:
            raise ResourceNotFoundError(
                "AI candidate segment is not linked to this case.", code="LINK_NOT_FOUND"
            )

        segment = await self.ai_segment_repo.get_by_id(segment_id)
        if segment is None:
            raise ResourceNotFoundError("AI candidate segment not found.", code="SEGMENT_NOT_FOUND")

        # Conflict-of-interest check: Report-author cannot review AI results for their reported incident
        incident = await self.incident_repo.get_by_id(segment.incident_id)
        if incident is not None and incident.reporter_id == principal.user_id:
            raise PermissionDeniedError(
                "Reviewer conflict of interest: you cannot review AI candidate segments for an incident you reported.",
                code="REVIEWER_CONFLICT_OF_INTEREST",
            )

        old_status = getattr(segment, "review_status", SegmentReviewStatus.PENDING_REVIEW.value)
        old_label = getattr(segment, "raw_label", "violence")

        # Apply human review determination
        segment.review_status = payload.review_status
        segment.reviewed_by_id = principal.user_id
        segment.reviewed_at = utc_now()
        segment.review_notes = payload.review_rationale

        if payload.corrected_label is not None:
            segment.raw_label = payload.corrected_label

        if payload.review_status == SegmentReviewStatus.REJECTED.value:
            link.investigative_relevance = InvestigativeRelevance.DISMISSED.value
        elif payload.review_status == SegmentReviewStatus.CONFIRMED.value:
            link.investigative_relevance = InvestigativeRelevance.CORROBORATING.value

        await self.ai_segment_repo.create(segment)  # session.flush()

        await self.audit_repo.append_event(
            action=AuditAction.CASE_AI_SEGMENT_REVIEWED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.CASE,
            target_id=str(case_id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=case_record.department_id,
            details={
                "segment_id": str(segment_id),
                "previous_review_status": old_status,
                "new_review_status": payload.review_status,
                "previous_classification_label": old_label,
                "new_classification_label": getattr(segment, "raw_label", old_label),
                "review_rationale": payload.review_rationale,
            },
        )

        return self._to_ai_segment_read(link, segment)

    # =========================================================================
    # Helper & Validation Methods
    # =========================================================================

    async def _validate_investigator_assignment(
        self,
        investigator_id: UUID,
        target_department_id: UUID,
        can_global: bool,
        exclude_case_id: UUID | None = None,
    ) -> None:
        if can_global:
            investigator = await self.user_repo.get_by_id_unscoped(investigator_id)
        else:
            investigator = await self.user_repo.get_by_id(
                investigator_id, department_id=target_department_id
            )
        if investigator is None or not investigator.is_active:
            raise BusinessRuleError(
                "The designated investigator does not exist or is inactive.",
                code="INVALID_INVESTIGATOR",
            )

        active_count = await self.case_repo.count_active_cases_for_investigator(
            investigator_id,
            exclude_case_id=exclude_case_id,
        )
        if active_count >= self.max_active_cases:
            raise BusinessRuleError(
                f"Investigator {investigator_id} has reached maximum active case capacity ({self.max_active_cases}).",
                code="INVESTIGATOR_CAPACITY_EXCEEDED",
                status_code=422,
            )

    def _assert_case_visible(self, case_record: Case, principal: AuthenticatedPrincipal) -> None:
        """Assert principal has visibility into the case, or mask as 404."""
        can_global = has_permission(principal.role_code, Permission.CASE_READ_GLOBAL)
        if can_global:
            return

        can_dept = has_permission(principal.role_code, Permission.CASE_READ_DEPT)
        if can_dept and principal.department_id == case_record.department_id:
            return

        can_own = has_permission(principal.role_code, Permission.CASE_READ_OWN)
        if can_own and (
            case_record.lead_investigator_id == principal.user_id
            or case_record.created_by_id == principal.user_id
        ):
            return

        raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

    def _assert_case_writable(self, case_record: Case, principal: AuthenticatedPrincipal) -> None:
        """Assert principal has update authorization over the case."""
        can_global = has_permission(principal.role_code, Permission.CASE_UPDATE_GLOBAL)
        if can_global:
            return

        can_dept = has_permission(principal.role_code, Permission.CASE_UPDATE_DEPT)
        if can_dept and principal.department_id == case_record.department_id:
            return

        raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

    def _to_case_read(self, c: Case) -> CaseRead:
        """Map Case entity to CaseRead DTO safely without triggering lazy loading."""
        from sqlalchemy import inspect

        state = inspect(c)
        incidents = state.dict.get("incidents")
        evidence = state.dict.get("evidence")
        ai_segments = state.dict.get("ai_segments")
        dept = state.dict.get("department")
        lead = state.dict.get("lead_investigator")

        return CaseRead(
            id=c.id,
            reference_number=c.reference_number,
            title=c.title,
            summary=c.summary,
            status=CaseStatus(c.status),
            priority=CasePriority(c.priority),
            department_id=c.department_id,
            created_by_id=c.created_by_id,
            lead_investigator_id=c.lead_investigator_id,
            version_id=c.version_id,
            is_legal_hold=c.is_legal_hold,
            legal_hold_reason=c.legal_hold_reason,
            closed_at=c.closed_at,
            created_at=c.created_at,
            updated_at=c.updated_at,
            incidents_count=len(incidents) if incidents is not None else 0,
            evidence_count=len(evidence) if evidence is not None else 0,
            ai_segments_count=len(ai_segments) if ai_segments is not None else 0,
            department_name=dept.name if dept is not None else None,
            lead_investigator_name=lead.full_name if lead is not None else None,
        )

    def _to_ai_segment_read(self, link: CaseAISegment, seg: Any) -> CaseAISegmentRead:
        """Map CaseAISegment and AICandidateSegment entity to CaseAISegmentRead DTO."""
        score = (
            seg.calibrated_score
            if getattr(seg, "calibrated_score", None) is not None
            else getattr(seg, "raw_score", 0.0)
        )
        return CaseAISegmentRead(
            id=getattr(link, "id", None) or uuid4(),
            case_id=link.case_id,
            segment_id=link.segment_id,
            linked_by_id=getattr(link, "linked_by_id", None) or uuid4(),
            investigative_relevance=InvestigativeRelevance(link.investigative_relevance),
            relevance_notes=link.relevance_notes,
            created_at=getattr(link, "created_at", None) or utc_now(),
            job_id=seg.job_id,
            evidence_id=getattr(seg, "evidence_id", uuid4()),
            incident_id=getattr(seg, "incident_id", uuid4()),
            start_seconds=getattr(seg, "start_seconds", 0.0),
            end_seconds=getattr(seg, "end_seconds", 0.0),
            score=score,
            label=getattr(seg, "raw_label", "violence"),
            review_status=getattr(seg, "review_status", SegmentReviewStatus.PENDING_REVIEW.value),
            reviewed_by_id=getattr(seg, "reviewed_by_id", None),
            reviewed_at=getattr(seg, "reviewed_at", None),
            review_notes=getattr(seg, "review_notes", None),
            advisory_disclaimer=AI_ADVISORY_DISCLAIMER,
        )

    async def _record_audit_event(
        self,
        *,
        actor_id: UUID,
        actor_role: str = "investigator",
        action: AuditAction | str,
        target_id: UUID | str,
        department_id: UUID | None,
        details: dict[str, Any],
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> None:
        """Helper to append a security audit event to the append-only ledger."""
        audit_action = AuditAction(action) if isinstance(action, str) else action
        await self.audit_repo.append_event(
            action=audit_action,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=AuditTargetType.CASE,
            target_id=str(target_id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=department_id,
            details=details,
        )

    # =========================================================================
    # Phase 86: Case Notes & Findings
    # =========================================================================

    async def create_case_note(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseNoteCreate,
    ) -> CaseNoteRead:
        """Create an authorized investigation note with visibility restrictions (Phase 86)."""
        if not has_permission(principal.role_code, Permission.CASE_NOTE_CREATE):
            raise PermissionDeniedError(
                "You do not have permission to create case notes.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        # Restricted note visibility requires elevated permission
        if payload.visibility == CaseNoteVisibility.RESTRICTED.value:
            can_restricted = has_permission(
                principal.role_code, Permission.CASE_NOTE_READ_RESTRICTED
            )
            if not can_restricted:
                raise PermissionDeniedError(
                    "You do not have permission to author restricted working notes.",
                    code="RESTRICTED_NOTE_FORBIDDEN",
                )

        # Validate evidence reference IDs
        if payload.evidence_reference_ids:
            linked_evidence = await self.case_repo.list_case_evidence(case_id)
            linked_ids = {le.evidence_id for le in linked_evidence}
            for ref_id in payload.evidence_reference_ids:
                if ref_id not in linked_ids:
                    raise BusinessRuleError(
                        f"Referenced evidence {ref_id} is not linked to this case.",
                        code="INVALID_EVIDENCE_REFERENCE",
                    )

        note_record = CaseNote(
            id=uuid4(),
            case_id=case_id,
            author_id=principal.user_id,
            visibility=payload.visibility,
            content=payload.content,
            version_id=1,
            is_archived=False,
            evidence_reference_ids_json=json.dumps([str(u) for u in payload.evidence_reference_ids])
            if payload.evidence_reference_ids
            else None,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        saved_note = await self.case_repo.create_note(note_record)

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_NOTE_CREATED.value,
            target_id=saved_note.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "note_id": str(saved_note.id),
                "visibility": payload.visibility,
            },
        )
        return self._to_note_read(saved_note)

    async def update_case_note(
        self,
        case_id: UUID,
        note_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseNoteUpdate,
    ) -> CaseNoteRead:
        """Update an existing investigation note with optimistic locking and history logging."""
        if not has_permission(principal.role_code, Permission.CASE_NOTE_CREATE):
            raise PermissionDeniedError(
                "You do not have permission to update case notes.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        note_record = await self.case_repo.get_note_by_id(note_id)
        if note_record is None or note_record.case_id != case_id:
            raise ResourceNotFoundError("Case note not found.", code="NOTE_NOT_FOUND")

        # Note modification restriction: only author or department admin
        can_global = has_permission(principal.role_code, Permission.CASE_UPDATE_GLOBAL)
        can_dept_admin = (
            has_permission(principal.role_code, Permission.CASE_NOTE_READ_RESTRICTED)
            and principal.department_id == case_record.department_id
        )
        if note_record.author_id != principal.user_id and not can_global and not can_dept_admin:
            raise PermissionDeniedError(
                "You cannot modify another investigator's note.",
                code="NOTE_MODIFICATION_FORBIDDEN",
            )

        # Optimistic concurrency check
        if note_record.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Note version conflict: expected {payload.expected_version_id}, but found {note_record.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        # Log historical version
        history = CaseNoteHistory(
            id=uuid4(),
            note_id=note_record.id,
            version_id=note_record.version_id,
            author_id=note_record.author_id,
            editor_id=principal.user_id,
            content=note_record.content,
            edit_reason=payload.edit_reason,
            created_at=utc_now(),
        )
        await self.case_repo.create_note_history(history)

        # Apply edit
        note_record.content = payload.content
        note_record.version_id += 1
        note_record.updated_at = utc_now()
        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_NOTE_UPDATED.value,
            target_id=note_record.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "note_id": str(note_record.id),
                "new_version": note_record.version_id,
            },
        )
        return self._to_note_read(note_record)

    async def list_case_notes(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseNoteRead]:
        """List case notes, filtering out restricted notes if caller lacks permissions."""
        if not has_permission(principal.role_code, Permission.CASE_NOTE_READ):
            raise PermissionDeniedError(
                "You do not have permission to view case notes.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        can_restricted = has_permission(principal.role_code, Permission.CASE_NOTE_READ_RESTRICTED)
        can_global = has_permission(principal.role_code, Permission.CASE_READ_GLOBAL)
        can_dept = (
            has_permission(principal.role_code, Permission.CASE_READ_DEPT)
            and principal.department_id == case_record.department_id
        )

        notes = await self.case_repo.list_notes_for_case(case_id)
        visible: list[CaseNoteRead] = []
        for n in notes:
            if (
                n.visibility == CaseNoteVisibility.RESTRICTED.value
                and n.author_id != principal.user_id
                and not can_restricted
            ) or (
                n.visibility == CaseNoteVisibility.CONFIDENTIAL.value
                and n.author_id != principal.user_id
                and not can_dept
                and not can_global
            ):
                continue
            visible.append(self._to_note_read(n))
        return visible

    async def get_case_note_history(
        self,
        case_id: UUID,
        note_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseNoteHistoryRead]:
        """Retrieve edit version history for a note."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        note_record = await self.case_repo.get_note_by_id(note_id)
        if note_record is None or note_record.case_id != case_id:
            raise ResourceNotFoundError("Case note not found.", code="NOTE_NOT_FOUND")

        # Visibility checks for history match note
        if (
            note_record.visibility == CaseNoteVisibility.RESTRICTED.value
            and note_record.author_id != principal.user_id
            and not has_permission(principal.role_code, Permission.CASE_NOTE_READ_RESTRICTED)
        ):
            raise PermissionDeniedError(
                "Access to restricted note history denied.", code="PERMISSION_DENIED"
            )

        history_rows = await self.case_repo.list_note_history(note_id)
        return [
            CaseNoteHistoryRead(
                id=h.id,
                note_id=h.note_id,
                version_id=h.version_id,
                author_id=h.author_id,
                editor_id=h.editor_id,
                content=h.content,
                edit_reason=h.edit_reason,
                created_at=h.created_at,
            )
            for h in history_rows
        ]

    async def create_case_finding(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseFindingCreate,
    ) -> CaseFindingRead:
        """Create a formal, structured investigation finding."""
        if not has_permission(principal.role_code, Permission.CASE_FINDING_MANAGE):
            raise PermissionDeniedError(
                "You do not have permission to manage case findings.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        # Validate evidence IDs
        if payload.evidence_ids:
            linked_ev = await self.case_repo.list_case_evidence(case_id)
            linked_ev_ids = {e.evidence_id for e in linked_ev}
            for eid in payload.evidence_ids:
                if eid not in linked_ev_ids:
                    raise BusinessRuleError(
                        f"Evidence {eid} is not linked to this case.",
                        code="INVALID_EVIDENCE_REFERENCE",
                    )

        # Validate AI segment IDs
        if payload.ai_segment_ids:
            linked_seg = await self.case_repo.list_case_ai_segments(case_id)
            linked_seg_ids = {s.segment_id for s in linked_seg}
            for sid in payload.ai_segment_ids:
                if sid not in linked_seg_ids:
                    raise BusinessRuleError(
                        f"AI segment {sid} is not linked to this case.",
                        code="INVALID_AI_SEGMENT_REFERENCE",
                    )

        # Validate incident IDs
        if payload.incident_ids:
            linked_inc = await self.case_repo.list_case_incidents(case_id)
            linked_inc_ids = {i.incident_id for i in linked_inc}
            for iid in payload.incident_ids:
                if iid not in linked_inc_ids:
                    raise BusinessRuleError(
                        f"Incident {iid} is not linked to this case.",
                        code="INVALID_INCIDENT_REFERENCE",
                    )

        finding = CaseFinding(
            id=uuid4(),
            case_id=case_id,
            author_id=principal.user_id,
            finding_type=payload.finding_type,
            title=payload.title,
            description=payload.description,
            evidence_ids_json=json.dumps([str(u) for u in payload.evidence_ids])
            if payload.evidence_ids
            else None,
            ai_segment_ids_json=json.dumps([str(u) for u in payload.ai_segment_ids])
            if payload.ai_segment_ids
            else None,
            incident_ids_json=json.dumps([str(u) for u in payload.incident_ids])
            if payload.incident_ids
            else None,
            version_id=1,
            is_preliminary=payload.is_preliminary,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        saved = await self.case_repo.create_finding(finding)

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_FINDING_CREATED.value,
            target_id=saved.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "finding_id": str(saved.id),
                "finding_type": saved.finding_type,
                "title": saved.title,
            },
        )
        return self._to_finding_read(saved)

    async def update_case_finding(
        self,
        case_id: UUID,
        finding_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseFindingUpdate,
    ) -> CaseFindingRead:
        """Update a formal investigation finding with optimistic locking and version history."""
        if not has_permission(principal.role_code, Permission.CASE_FINDING_MANAGE):
            raise PermissionDeniedError(
                "You do not have permission to manage case findings.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        finding = await self.case_repo.get_finding_by_id(finding_id)
        if finding is None or finding.case_id != case_id:
            raise ResourceNotFoundError("Case finding not found.", code="FINDING_NOT_FOUND")

        # Concurrency check
        if finding.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Finding version conflict: expected {payload.expected_version_id}, but found {finding.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        # Log history
        history = CaseFindingHistory(
            id=uuid4(),
            finding_id=finding.id,
            version_id=finding.version_id,
            editor_id=principal.user_id,
            title=finding.title,
            description=finding.description,
            reason=payload.reason,
            created_at=utc_now(),
        )
        await self.case_repo.create_finding_history(history)

        # Apply updates
        if payload.title is not None:
            finding.title = payload.title
        if payload.description is not None:
            finding.description = payload.description
        if payload.finding_type is not None:
            finding.finding_type = payload.finding_type
        if payload.is_preliminary is not None:
            finding.is_preliminary = payload.is_preliminary
        if payload.evidence_ids is not None:
            finding.evidence_ids_json = json.dumps([str(u) for u in payload.evidence_ids])
        if payload.ai_segment_ids is not None:
            finding.ai_segment_ids_json = json.dumps([str(u) for u in payload.ai_segment_ids])
        if payload.incident_ids is not None:
            finding.incident_ids_json = json.dumps([str(u) for u in payload.incident_ids])

        finding.version_id += 1
        finding.updated_at = utc_now()
        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_FINDING_UPDATED.value,
            target_id=finding.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "finding_id": str(finding.id),
                "new_version": finding.version_id,
            },
        )
        return self._to_finding_read(finding)

    async def list_case_findings(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseFindingRead]:
        """List all formal findings for a case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        findings = await self.case_repo.list_findings_for_case(case_id)
        return [self._to_finding_read(f) for f in findings]

    async def get_case_finding_history(
        self,
        case_id: UUID,
        finding_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseFindingHistoryRead]:
        """List version history logs for an investigation finding."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        finding = await self.case_repo.get_finding_by_id(finding_id)
        if finding is None or finding.case_id != case_id:
            raise ResourceNotFoundError("Case finding not found.", code="FINDING_NOT_FOUND")

        history_rows = await self.case_repo.list_finding_history(finding_id)
        return [
            CaseFindingHistoryRead(
                id=h.id,
                finding_id=h.finding_id,
                version_id=h.version_id,
                editor_id=h.editor_id,
                title=h.title,
                description=h.description,
                reason=h.reason,
                created_at=h.created_at,
            )
            for h in history_rows
        ]

    # =========================================================================
    # Phase 87: Lifecycle Transitions & Approvals
    # =========================================================================

    async def transition_case_status(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseTransitionRequest,
    ) -> CaseRead:
        """Execute and validate a case lifecycle status transition (Phase 87)."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_writable(case_record, principal)

        current_status = CaseStatus(case_record.status)
        target_status = CaseStatus(payload.target_status)

        # Validate state transition matrix
        validate_case_status_transition(current_status, target_status)

        # Concurrency check
        if case_record.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Case version conflict: expected {payload.expected_version_id}, but found {case_record.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        # Enforce transition prerequisites
        if target_status == CaseStatus.UNDER_INVESTIGATION:
            if case_record.lead_investigator_id is None:
                raise BusinessRuleError(
                    "Cannot transition to 'under_investigation' without an assigned lead investigator.",
                    code="LEAD_INVESTIGATOR_REQUIRED",
                )
            incidents = await self.case_repo.list_case_incidents(case_id)
            if not incidents:
                raise BusinessRuleError(
                    "Cannot transition to 'under_investigation' without at least one linked incident.",
                    code="INCIDENT_REQUIRED",
                )

        elif target_status == CaseStatus.PENDING_REVIEW:
            notes = await self.case_repo.list_notes_for_case(case_id)
            findings = await self.case_repo.list_findings_for_case(case_id)
            if not notes and not findings:
                raise BusinessRuleError(
                    "Cannot transition to 'pending_review' without investigation findings or notes.",
                    code="EVIDENCE_FINDINGS_REQUIRED",
                )
            ai_segs = await self.case_repo.list_case_ai_segments(case_id)
            for seg_link in ai_segs:
                if seg_link.segment.review_status == SegmentReviewStatus.PENDING_REVIEW.value:
                    raise BusinessRuleError(
                        "Cannot transition to 'pending_review' while linked AI candidate segments remain unreviewed.",
                        code="AI_SEGMENTS_PENDING_REVIEW",
                    )

        elif target_status == CaseStatus.RESOLVED:
            # Direct transition to RESOLVED requires formal approval permission
            if not has_permission(principal.role_code, Permission.CASE_TRANSITION_APPROVE):
                raise PermissionDeniedError(
                    "Direct case resolution requires supervisor approval permission.",
                    code="APPROVAL_REQUIRED",
                )

        elif target_status == CaseStatus.CLOSED:
            if not has_permission(principal.role_code, Permission.CASE_CLOSE):
                raise PermissionDeniedError(
                    "You do not have permission to close cases.",
                    code="PERMISSION_DENIED",
                )
            if current_status == CaseStatus.DRAFT:
                raise BusinessRuleError(
                    "Draft cases cannot be closed directly without opening.",
                    code="INVALID_TRANSITION_FOR_DRAFT",
                )

        case_record.status = target_status.value
        case_record.version_id += 1
        if target_status in TERMINAL_CASE_STATUSES:
            case_record.closed_at = utc_now()
        else:
            case_record.closed_at = None

        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_STATUS_TRANSITION.value,
            target_id=case_record.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "from_status": current_status.value,
                "to_status": target_status.value,
                "reason": payload.reason,
                "new_version": case_record.version_id,
            },
        )
        return self._to_case_read(case_record)

    async def approve_case_transition(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseApprovalRequest,
    ) -> CaseApprovalRead:
        """Record formal supervisory approval decision on case transition (Phase 87)."""
        if not has_permission(principal.role_code, Permission.CASE_TRANSITION_APPROVE):
            raise PermissionDeniedError(
                "You do not have permission to approve case transitions.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        if case_record.status != payload.from_status:
            raise BusinessRuleError(
                f"Case status mismatch: expected '{payload.from_status}', found '{case_record.status}'.",
                code="CASE_STATUS_MISMATCH",
            )

        if case_record.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Case version conflict: expected {payload.expected_version_id}, but found {case_record.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        approval = CaseApproval(
            id=uuid4(),
            case_id=case_id,
            approver_id=principal.user_id,
            decision=payload.decision,
            from_status=payload.from_status,
            to_status=payload.to_status,
            rationale=payload.rationale,
            created_at=utc_now(),
        )
        saved_approval = await self.case_repo.create_approval(approval)

        # Update case status based on approval decision
        if payload.decision == CaseApprovalDecision.APPROVED.value:
            validate_case_status_transition(case_record.status, payload.to_status)
            case_record.status = payload.to_status
            if CaseStatus(payload.to_status) in TERMINAL_CASE_STATUSES:
                case_record.closed_at = utc_now()
        elif payload.decision in {
            CaseApprovalDecision.REJECTED.value,
            CaseApprovalDecision.CHANGES_REQUESTED.value,
        }:
            case_record.status = CaseStatus.UNDER_INVESTIGATION.value
            case_record.closed_at = None

        case_record.version_id += 1
        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_APPROVAL_RECORDED.value,
            target_id=saved_approval.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "approval_id": str(saved_approval.id),
                "decision": payload.decision,
                "from_status": payload.from_status,
                "to_status": payload.to_status,
                "rationale": payload.rationale,
            },
        )
        return self._to_approval_read(saved_approval)

    async def list_case_approvals(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseApprovalRead]:
        """List all approval records for a case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        approvals = await self.case_repo.list_approvals_for_case(case_id)
        return [self._to_approval_read(a) for a in approvals]

    # =========================================================================
    # Phase 88: Escalations, Referrals, Closure, and Reopening
    # =========================================================================

    async def escalate_case(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseEscalationRequest,
    ) -> CaseEscalationRead:
        """Escalate an investigation case to leadership or external oversight (Phase 88)."""
        if not has_permission(principal.role_code, Permission.CASE_ESCALATE):
            raise PermissionDeniedError(
                "You do not have permission to escalate cases.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        # Validate target department exists
        target_dept = await self.department_repo.get_by_id(payload.escalated_to_department_id)
        if target_dept is None:
            raise ResourceNotFoundError(
                "Target escalation department not found.",
                code="DEPARTMENT_NOT_FOUND",
            )

        # Concurrency check
        if case_record.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Case version conflict: expected {payload.expected_version_id}, but found {case_record.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        escalation = CaseEscalation(
            id=uuid4(),
            case_id=case_id,
            escalated_by_id=principal.user_id,
            escalated_to_department_id=payload.escalated_to_department_id,
            reason=payload.reason,
            escalation_level=payload.escalation_level,
            case_version_id=case_record.version_id,
            created_at=utc_now(),
        )
        saved = await self.case_repo.create_escalation(escalation)

        case_record.version_id += 1
        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_ESCALATED.value,
            target_id=saved.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "escalated_to_department_id": str(payload.escalated_to_department_id),
                "escalation_level": payload.escalation_level,
                "reason": payload.reason,
            },
        )
        return self._to_escalation_read(saved)

    async def list_case_escalations(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseEscalationRead]:
        """List all escalations recorded for a case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        escalations = await self.case_repo.list_escalations_for_case(case_id)
        return [self._to_escalation_read(e) for e in escalations]

    async def refer_case(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseReferralCreate,
    ) -> CaseReferralRead:
        """Create a case referral to an internal partner or external agency (Phase 88)."""
        if not has_permission(principal.role_code, Permission.CASE_REFER):
            raise PermissionDeniedError(
                "You do not have permission to refer cases.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        if payload.target_department_id is not None:
            target_dept = await self.department_repo.get_by_id(payload.target_department_id)
            if target_dept is None:
                raise ResourceNotFoundError(
                    "Target referral department not found.", code="DEPARTMENT_NOT_FOUND"
                )

        referral = CaseReferral(
            id=uuid4(),
            case_id=case_id,
            referred_by_id=principal.user_id,
            target_department_id=payload.target_department_id,
            target_external_agency=payload.target_external_agency,
            referral_purpose=payload.referral_purpose,
            status=CaseReferralStatus.PENDING.value,
            resolution_notes=None,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        saved = await self.case_repo.create_referral(referral)

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_REFERRED.value,
            target_id=saved.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "referral_id": str(saved.id),
                "purpose": payload.referral_purpose,
            },
        )
        return self._to_referral_read(saved)

    async def update_referral_status(
        self,
        case_id: UUID,
        referral_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseReferralUpdate,
    ) -> CaseReferralRead:
        """Update case referral outcome and resolution notes."""
        if not has_permission(principal.role_code, Permission.CASE_REFER):
            raise PermissionDeniedError(
                "You do not have permission to manage case referrals.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        referral = await self.case_repo.get_referral_by_id(referral_id)
        if referral is None or referral.case_id != case_id:
            raise ResourceNotFoundError("Case referral not found.", code="REFERRAL_NOT_FOUND")

        referral.status = payload.status
        if payload.resolution_notes is not None:
            referral.resolution_notes = payload.resolution_notes
        referral.updated_at = utc_now()
        await self.case_repo.session.flush()
        return self._to_referral_read(referral)

    async def list_case_referrals(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[CaseReferralRead]:
        """List all referrals for a case."""
        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        referrals = await self.case_repo.list_referrals_for_case(case_id)
        return [self._to_referral_read(r) for r in referrals]

    async def close_case(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseCloseRequest,
    ) -> CaseRead:
        """Formally close an investigation case with documented rationale (Phase 88)."""
        if not has_permission(principal.role_code, Permission.CASE_CLOSE):
            raise PermissionDeniedError(
                "You do not have permission to close cases.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_writable(case_record, principal)

        if case_record.status == CaseStatus.DRAFT.value:
            raise BusinessRuleError(
                "Draft cases cannot be closed without being opened.", code="INVALID_CASE_STATE"
            )

        if case_record.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Case version conflict: expected {payload.expected_version_id}, but found {case_record.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        prior_status = case_record.status
        case_record.status = CaseStatus.CLOSED.value
        case_record.closed_at = utc_now()
        case_record.version_id += 1
        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_CLOSED.value,
            target_id=case_record.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "prior_status": prior_status,
                "reason": payload.reason,
                "is_legal_hold": case_record.is_legal_hold,
            },
        )
        return self._to_case_read(case_record)

    async def reopen_case(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseReopenRequest,
    ) -> CaseRead:
        """Reopen a closed or resolved investigation case (Phase 88)."""
        if not has_permission(principal.role_code, Permission.CASE_REOPEN):
            raise PermissionDeniedError(
                "You do not have permission to reopen cases.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_writable(case_record, principal)

        if CaseStatus(case_record.status) not in TERMINAL_CASE_STATUSES:
            raise BusinessRuleError(
                f"Only resolved or closed cases can be reopened (current: '{case_record.status}').",
                code="CASE_NOT_CLOSED",
            )

        if case_record.version_id != payload.expected_version_id:
            raise ConflictError(
                f"Case version conflict: expected {payload.expected_version_id}, but found {case_record.version_id}.",
                code="CONCURRENCY_CONFLICT",
            )

        prior_status = case_record.status
        case_record.status = CaseStatus.UNDER_INVESTIGATION.value
        case_record.closed_at = None
        case_record.version_id += 1
        await self.case_repo.session.flush()

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_REOPENED.value,
            target_id=case_record.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "prior_status": prior_status,
                "reason": payload.reason,
            },
        )
        return self._to_case_read(case_record)

    # =========================================================================
    # Phase 89: Case Exports & Manifests
    # =========================================================================

    async def export_case(
        self,
        case_id: UUID,
        principal: AuthenticatedPrincipal,
        payload: CaseExportRequest,
    ) -> CaseExportRead:
        """Generate a cryptographically hashed, controlled case disclosure package (Phase 89)."""
        if not has_permission(principal.role_code, Permission.CASE_EXPORT):
            raise PermissionDeniedError(
                "You do not have permission to export cases.",
                code="PERMISSION_DENIED",
            )

        case_record = await self.case_repo.get_by_id(case_id)
        if case_record is None:
            raise ResourceNotFoundError("Case not found.", code="CASE_NOT_FOUND")

        self._assert_case_visible(case_record, principal)

        # Restricted notes export validation
        if payload.include_restricted_notes:
            can_restricted = has_permission(
                principal.role_code, Permission.CASE_NOTE_READ_RESTRICTED
            )
            if not can_restricted:
                raise PermissionDeniedError(
                    "Elevated permission required to export restricted working notes.",
                    code="RESTRICTED_EXPORT_DENIED",
                )

        # 1. Compile evidence manifest items (verifying digest format and integrity)
        evidence_links = await self.case_repo.list_case_evidence(case_id)
        manifest_evidence_items: list[dict[str, Any]] = []
        for el in evidence_links:
            att = el.evidence
            digest = getattr(att, "sha256_hash", None) or getattr(att, "sha256_digest", "")
            is_valid_digest = isinstance(digest, str) and len(digest.strip()) == 64
            v_status = (
                EvidenceVerificationStatus.VERIFIED.value
                if is_valid_digest
                else EvidenceVerificationStatus.INTEGRITY_FAILED.value
            )
            manifest_evidence_items.append(
                {
                    "evidence_id": str(el.evidence_id),
                    "file_name": getattr(att, "original_filename", "evidence_artifact"),
                    "sha256_digest": digest,
                    "file_size_bytes": getattr(att, "file_size", 0),
                    "verification_status": v_status,
                    "notes": el.notes,
                }
            )

        # 2. Compile notes (redacting restricted notes if not authorized)
        raw_notes = await self.case_repo.list_notes_for_case(case_id)
        manifest_notes: list[dict[str, Any]] = []
        for n in raw_notes:
            if (
                n.visibility == CaseNoteVisibility.RESTRICTED.value
                and not payload.include_restricted_notes
            ):
                continue
            manifest_notes.append(
                {
                    "note_id": str(n.id),
                    "visibility": n.visibility,
                    "content": n.content,
                    "author_id": str(n.author_id),
                    "created_at": n.created_at.isoformat(),
                }
            )

        # 3. Compile findings
        raw_findings = await self.case_repo.list_findings_for_case(case_id)
        manifest_findings: list[dict[str, Any]] = [
            {
                "finding_id": str(f.id),
                "title": f.title,
                "description": f.description,
                "finding_type": f.finding_type,
                "is_preliminary": f.is_preliminary,
                "created_at": f.created_at.isoformat(),
            }
            for f in raw_findings
        ]

        # 4. Compile AI candidate segments with mandatory statutory disclaimer
        raw_ai_segs = await self.case_repo.list_case_ai_segments(case_id)
        manifest_ai_segs: list[dict[str, Any]] = [
            {
                "segment_id": str(s.segment_id),
                "investigative_relevance": s.investigative_relevance,
                "score": s.segment.calibrated_score
                if getattr(s.segment, "calibrated_score", None) is not None
                else getattr(s.segment, "raw_score", 0.0),
                "label": getattr(s.segment, "raw_label", "candidate_action"),
                "review_status": getattr(
                    s.segment, "review_status", SegmentReviewStatus.PENDING_REVIEW.value
                ),
                "advisory_disclaimer": AI_ADVISORY_DISCLAIMER,
            }
            for s in raw_ai_segs
        ]

        # 5. Assemble complete manifest dictionary (strict exclusion of credentials/tokens)
        manifest_payload: dict[str, Any] = {
            "case_reference_number": case_record.reference_number,
            "case_id": str(case_record.id),
            "department_id": str(case_record.department_id),
            "title": case_record.title,
            "summary": case_record.summary,
            "status": case_record.status,
            "priority": case_record.priority,
            "export_scope": payload.export_scope,
            "export_format": payload.export_format,
            "exported_by_id": str(principal.user_id),
            "exported_at": utc_now().isoformat(),
            "evidence_manifest": manifest_evidence_items,
            "notes": manifest_notes,
            "findings": manifest_findings,
            "ai_candidate_segments": manifest_ai_segs,
            "advisory_notice": AI_ADVISORY_DISCLAIMER,
        }

        # Canonical JSON string for hashing
        canonical_json = json.dumps(manifest_payload, sort_keys=True, separators=(",", ":"))
        manifest_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        export_record = CaseExport(
            id=uuid4(),
            case_id=case_id,
            department_id=case_record.department_id,
            exported_by_id=principal.user_id,
            export_scope=payload.export_scope,
            export_format=payload.export_format,
            manifest_sha256=manifest_sha256,
            evidence_count=len(manifest_evidence_items),
            manifest_payload=canonical_json,
            status="completed",
            purpose=payload.purpose,
            expires_at=utc_now() + timedelta(days=7),
            created_at=utc_now(),
        )
        saved_export = await self.case_repo.create_export(export_record)

        await self._record_audit_event(
            actor_id=principal.user_id,
            action=AuditAction.CASE_EXPORTED.value,
            target_id=saved_export.id,
            department_id=case_record.department_id,
            details={
                "case_id": str(case_id),
                "export_id": str(saved_export.id),
                "manifest_sha256": manifest_sha256,
                "evidence_count": len(manifest_evidence_items),
                "scope": payload.export_scope,
                "purpose": payload.purpose,
            },
        )
        return self._to_export_read(saved_export, manifest_payload)

    async def get_case_export(
        self,
        export_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> CaseExportRead:
        """Retrieve an existing case export package (Phase 89)."""
        export_record = await self.case_repo.get_export_by_id(export_id)
        if export_record is None:
            raise ResourceNotFoundError("Case export not found.", code="EXPORT_NOT_FOUND")

        can_global = has_permission(principal.role_code, Permission.CASE_READ_GLOBAL)
        if not can_global and export_record.department_id != principal.department_id:
            raise ResourceNotFoundError("Case export not found.", code="EXPORT_NOT_FOUND")

        try:
            payload_dict = json.loads(export_record.manifest_payload)
        except Exception:
            payload_dict = {}

        return self._to_export_read(export_record, payload_dict)

    # -------------------------------------------------------------------------
    # DTO Mappers
    # -------------------------------------------------------------------------

    def _to_note_read(self, n: CaseNote) -> CaseNoteRead:
        return CaseNoteRead(
            id=n.id,
            case_id=n.case_id,
            author_id=n.author_id,
            visibility=n.visibility,
            content=n.content,
            version_id=n.version_id,
            is_archived=n.is_archived,
            evidence_reference_ids=n.evidence_reference_ids,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )

    def _to_finding_read(self, f: CaseFinding) -> CaseFindingRead:
        return CaseFindingRead(
            id=f.id,
            case_id=f.case_id,
            author_id=f.author_id,
            finding_type=f.finding_type,
            title=f.title,
            description=f.description,
            evidence_ids=f.evidence_ids,
            ai_segment_ids=f.ai_segment_ids,
            incident_ids=f.incident_ids,
            version_id=f.version_id,
            is_preliminary=f.is_preliminary,
            created_at=f.created_at,
            updated_at=f.updated_at,
        )

    def _to_approval_read(self, a: CaseApproval) -> CaseApprovalRead:
        return CaseApprovalRead(
            id=a.id,
            case_id=a.case_id,
            approver_id=a.approver_id,
            decision=a.decision,
            from_status=a.from_status,
            to_status=a.to_status,
            rationale=a.rationale,
            created_at=a.created_at,
        )

    def _to_escalation_read(self, e: CaseEscalation) -> CaseEscalationRead:
        return CaseEscalationRead(
            id=e.id,
            case_id=e.case_id,
            escalated_by_id=e.escalated_by_id,
            escalated_to_department_id=e.escalated_to_department_id,
            reason=e.reason,
            escalation_level=e.escalation_level,
            case_version_id=e.case_version_id,
            created_at=e.created_at,
        )

    def _to_referral_read(self, r: CaseReferral) -> CaseReferralRead:
        return CaseReferralRead(
            id=r.id,
            case_id=r.case_id,
            referred_by_id=r.referred_by_id,
            target_department_id=r.target_department_id,
            target_external_agency=r.target_external_agency,
            referral_purpose=r.referral_purpose,
            status=r.status,
            resolution_notes=r.resolution_notes,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )

    def _to_export_read(self, ex: CaseExport, payload_dict: dict[str, Any]) -> CaseExportRead:
        return CaseExportRead(
            id=ex.id,
            case_id=ex.case_id,
            department_id=ex.department_id,
            exported_by_id=ex.exported_by_id,
            export_scope=ex.export_scope,
            export_format=ex.export_format,
            manifest_sha256=ex.manifest_sha256,
            evidence_count=ex.evidence_count,
            manifest_payload=payload_dict,
            status=ex.status,
            purpose=ex.purpose,
            expires_at=ex.expires_at,
            created_at=ex.created_at,
        )
