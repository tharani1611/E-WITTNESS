"""Incident service business logic, ownership enforcement, and lifecycle orchestration (Phases 41-42).

Enforces:
- Submitting identity is strictly derived from server-side authenticated principal.
- Non-guessable, concurrency-safe incident reference number assignment.
- Multi-tenant department scoping and submitter record isolation.
- Tamper-proof privilege escalation and status transition rules.
- Complete masking of unauthorized incidents across departments (404 Not Found).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.core.incident import (
    AssignmentStatus,
    IncidentRoutingType,
    IncidentStatus,
    evaluate_deterministic_routing,
    generate_incident_reference_number,
    validate_incident_status_transition,
    validate_reviewer_assignment,
)
from backend.app.core.logging import get_logger
from backend.app.models.incident import Incident, IncidentAssignment, IncidentRoutingDecision
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.identity import DepartmentRepository, UserRepository
from backend.app.repositories.incident import IncidentRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.incident import (
    IncidentAssignmentRead,
    IncidentCreate,
    IncidentRead,
    IncidentRoutingDecisionRead,
    IncidentUpdate,
    ReviewerAssignRequest,
    ReviewerReassignRequest,
    ReviewQueueWorkloadSummary,
)
from backend.app.schemas.pagination import PaginatedResponse, PaginationMetadata, PaginationParams

logger = get_logger("services.incident")


class IncidentService:
    """Domain service managing incident submission, scoping, and workflow lifecycles."""

    def __init__(
        self,
        incident_repo: IncidentRepository,
        department_repo: DepartmentRepository,
        settings: Settings,
        user_repo: UserRepository | None = None,
        audit_repo: AuditRepository | None = None,
    ) -> None:
        self.incident_repo = incident_repo
        self.department_repo = department_repo
        self.user_repo = user_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
    ) -> IncidentService:
        """Construct an IncidentService wired with repositories bound to ``session``."""
        return cls(
            incident_repo=IncidentRepository(session),
            department_repo=DepartmentRepository(session),
            settings=settings,
            user_repo=UserRepository(session),
            audit_repo=AuditRepository(session),
        )

    async def create_incident(
        self,
        payload: IncidentCreate,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Create and persist a new incident report bound to caller's identity."""
        # 1. Enforce permission to create incidents
        if not has_permission(principal.role_code, Permission.INCIDENT_CREATE):
            raise PermissionDeniedError(
                "You do not have permission to submit incident reports.",
                code="PERMISSION_DENIED",
            )

        # 2. Cross-department submission check: Students and staff cannot submit for another department
        if (
            principal.role_code in {RoleCode.STUDENT.value, RoleCode.STAFF.value}
            and payload.department_id is not None
            and payload.department_id != principal.department_id
        ):
            raise BusinessRuleError(
                "Students and staff cannot submit reports for another department.",
                code="CROSS_DEPARTMENT_REPORT_FORBIDDEN",
            )

        # 3. Determine target department and routing decision
        routing_type: str
        rule_applied: str
        assigned_by_id: UUID | None
        decision_reason: str

        if payload.department_id is None and principal.department_id is None:
            raise BusinessRuleError(
                "A target department must be specified for incident submission.",
                code="DEPARTMENT_REQUIRED",
            )

        if payload.department_id is None:
            active_depts = await self.department_repo.list_active(limit=100)
            dept_pairs = [(d.id, d.code) for d in active_depts]
            reporter_dept = principal.department_id
            if reporter_dept is None:
                raise BusinessRuleError(
                    "A target department must be specified for incident submission.",
                    code="DEPARTMENT_REQUIRED",
                )
            target_dept_id, rule_applied = evaluate_deterministic_routing(
                category=payload.category,
                severity=payload.severity,
                available_departments=dept_pairs,
                reporter_department_id=reporter_dept,
            )
            routing_type = IncidentRoutingType.SYSTEM_RULE.value
            assigned_by_id = None
            decision_reason = (
                f"Deterministic intake routing evaluated for category '{payload.category.value}' "
                f"and severity '{payload.severity.value}'."
            )
        else:
            target_dept_id = payload.department_id
            routing_type = IncidentRoutingType.AUTHORIZED_OVERRIDE.value
            rule_applied = "EXPLICIT_DEPARTMENT_SPECIFIED"
            assigned_by_id = principal.user_id
            decision_reason = "Explicit department specified at submission."

        target_dept = await self.department_repo.get_by_id(target_dept_id)
        if target_dept is None or not target_dept.is_active:
            raise BusinessRuleError(
                "The target department does not exist or is inactive.",
                code="INACTIVE_DEPARTMENT_TARGET",
            )

        # 4. Generate concurrency-safe, opaque reference number
        ref_number = generate_incident_reference_number()

        # Ensure reference number uniqueness under edge-case collision
        existing = await self.incident_repo.get_by_reference_number(ref_number)
        if existing is not None:
            ref_number = generate_incident_reference_number()

        # 5. Ensure timezone awareness on occurred_at
        occurred_utc = (
            payload.occurred_at
            if payload.occurred_at.tzinfo is not None
            else payload.occurred_at.replace(tzinfo=UTC)
        )

        # 6. Instantiate and persist Incident entity
        incident = Incident(
            reference_number=ref_number,
            title=payload.title,
            description=payload.description,
            category=payload.category.value,
            severity=payload.severity.value,
            status=IncidentStatus.SUBMITTED.value,
            location=payload.location,
            occurred_at=occurred_utc,
            reporter_id=principal.user_id,
            department_id=target_dept_id,
        )

        created = await self.incident_repo.create(incident)

        # 7. Record initial traceable department routing decision
        routing_decision = IncidentRoutingDecision(
            incident_id=created.id,
            source_department_id=None,
            target_department_id=target_dept_id,
            assigned_by_id=assigned_by_id,
            routing_type=routing_type,
            rule_applied=rule_applied,
            reason=decision_reason,
        )
        await self.incident_repo.create_routing_decision(routing_decision)

        logger.info(
            "Incident submitted successfully",
            extra={
                "incident_id": str(created.id),
                "reference_number": created.reference_number,
                "reporter_id": str(principal.user_id),
                "department_id": str(target_dept_id),
                "category": created.category,
                "severity": created.severity,
                "routing_rule": rule_applied,
            },
        )

        return IncidentRead.model_validate(created)

    async def get_incident(
        self,
        incident_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Retrieve an incident enforcing strict tenant and submitter visibility boundaries."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)
        return IncidentRead.model_validate(incident)

    async def get_incident_by_reference(
        self,
        reference_number: str,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Lookup an incident by reference number enforcing identical visibility boundaries."""
        incident = await self.incident_repo.get_by_reference_number(reference_number)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)
        return IncidentRead.model_validate(incident)

    async def list_incidents(
        self,
        principal: AuthenticatedPrincipal,
        pagination: PaginationParams,
        *,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> PaginatedResponse[IncidentRead]:
        """List incidents with mandatory server-side ownership and department scoping."""
        reporter_scope: UUID | None = None
        department_scope: UUID | None = None

        if principal.role_code == RoleCode.SUPER_ADMIN.value:
            # Super admin can view all or filter by query
            pass
        elif principal.role_code in {RoleCode.DEPT_ADMIN.value, RoleCode.INVESTIGATOR.value}:
            # Scoped strictly to own department
            department_scope = principal.department_id
        elif principal.role_code in {RoleCode.STUDENT.value, RoleCode.STAFF.value}:
            # Scoped strictly to own submitted records
            reporter_scope = principal.user_id
        else:
            raise PermissionDeniedError(
                "Access to incident listings is denied.",
                code="PERMISSION_DENIED",
            )

        items, total_count = await self.incident_repo.list_paginated(
            limit=pagination.page_size,
            offset=pagination.offset,
            reporter_id=reporter_scope,
            department_id=department_scope,
            status=status,
            category=category,
            severity=severity,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        read_items = [IncidentRead.model_validate(item) for item in items]
        metadata = PaginationMetadata.from_counts(
            page=pagination.page,
            page_size=pagination.page_size,
            total_items=total_count,
        )

        return PaginatedResponse(items=read_items, pagination=metadata)

    async def update_incident(
        self,
        incident_id: UUID,
        payload: IncidentUpdate,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Update permitted incident fields while in SUBMITTED status."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        # Submitter can update their own report while it is SUBMITTED
        if principal.role_code in {RoleCode.STUDENT.value, RoleCode.STAFF.value}:
            if incident.reporter_id != principal.user_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
            if incident.status != IncidentStatus.SUBMITTED.value:
                raise BusinessRuleError(
                    "Cannot modify an incident report that has already been triaged or closed.",
                    code="INCIDENT_UPDATE_LOCKED",
                )
        elif principal.role_code == RoleCode.DEPT_ADMIN.value:
            if incident.department_id != principal.department_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        elif principal.role_code == RoleCode.SUPER_ADMIN.value:
            pass
        else:
            raise PermissionDeniedError(
                "You do not have permission to modify this incident.",
                code="PERMISSION_DENIED",
            )

        # Apply partial updates
        if payload.title is not None:
            incident.title = payload.title
        if payload.description is not None:
            incident.description = payload.description
        if payload.category is not None:
            incident.category = payload.category.value
        if payload.severity is not None:
            incident.severity = payload.severity.value
        if payload.location is not None:
            incident.location = payload.location
        if payload.occurred_at is not None:
            incident.occurred_at = (
                payload.occurred_at
                if payload.occurred_at.tzinfo is not None
                else payload.occurred_at.replace(tzinfo=UTC)
            )

        updated = await self.incident_repo.update(incident)
        return IncidentRead.model_validate(updated)

    async def transition_status(
        self,
        incident_id: UUID,
        new_status: IncidentStatus,
        principal: AuthenticatedPrincipal,
        reason: str | None = None,
    ) -> IncidentRead:
        """Administratively transition an incident's lifecycle status."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        # Only Dept Admin (in own department) or Super Admin can transition status
        if principal.role_code == RoleCode.DEPT_ADMIN.value:
            if incident.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department administrators can only transition incidents within their department.",
                    code="DEPARTMENT_MISMATCH",
                )
        elif principal.role_code != RoleCode.SUPER_ADMIN.value:
            raise PermissionDeniedError(
                "Insufficient privileges to transition incident status.",
                code="PERMISSION_DENIED",
            )

        current = IncidentStatus(incident.status)
        validate_incident_status_transition(current, new_status)

        incident.status = new_status.value
        updated = await self.incident_repo.update(incident)

        logger.info(
            "Incident status transitioned",
            extra={
                "incident_id": str(incident.id),
                "from_status": current.value,
                "to_status": new_status.value,
                "actor_id": str(principal.user_id),
                "reason": reason,
            },
        )

        return IncidentRead.model_validate(updated)

    async def override_incident_routing(
        self,
        incident_id: UUID,
        target_department_id: UUID,
        reason: str,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Administratively re-route an incident to another department with mandatory audit trail (Phase 55)."""
        if principal.role_code not in {RoleCode.DEPT_ADMIN.value, RoleCode.SUPER_ADMIN.value}:
            raise PermissionDeniedError(
                "Only administrators can re-route incidents.",
                code="PERMISSION_DENIED",
            )

        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        if (
            principal.role_code == RoleCode.DEPT_ADMIN.value
            and incident.department_id != principal.department_id
        ):
            raise PermissionDeniedError(
                "Department administrators can only re-route incidents currently assigned to their department.",
                code="DEPARTMENT_MISMATCH",
            )

        if incident.status in {IncidentStatus.CLOSED.value, IncidentStatus.DISMISSED.value}:
            raise BusinessRuleError(
                "Cannot re-route an incident that is closed or dismissed.",
                code="INCIDENT_ROUTING_LOCKED",
            )

        if incident.department_id == target_department_id:
            raise BusinessRuleError(
                "Incident is already assigned to the target department.",
                code="SAME_DEPARTMENT_ROUTING",
            )

        target_dept = await self.department_repo.get_by_id(target_department_id)
        if target_dept is None or not target_dept.is_active:
            raise BusinessRuleError(
                "The target department does not exist or is inactive.",
                code="INACTIVE_DEPARTMENT_TARGET",
            )

        old_dept_id = incident.department_id
        incident.department_id = target_department_id
        updated = await self.incident_repo.update(incident)

        decision = IncidentRoutingDecision(
            incident_id=incident.id,
            source_department_id=old_dept_id,
            target_department_id=target_department_id,
            assigned_by_id=principal.user_id,
            routing_type=IncidentRoutingType.AUTHORIZED_OVERRIDE.value,
            rule_applied="MANUAL_ADMIN_OVERRIDE",
            reason=reason.strip(),
        )
        await self.incident_repo.create_routing_decision(decision)

        logger.info(
            "Incident department routing overridden",
            extra={
                "incident_id": str(incident.id),
                "from_department_id": str(old_dept_id),
                "to_department_id": str(target_department_id),
                "actor_id": str(principal.user_id),
                "reason": reason,
            },
        )

        return IncidentRead.model_validate(updated)

    async def get_incident_routing_history(
        self,
        incident_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[IncidentRoutingDecisionRead]:
        """Retrieve chronological routing decisions for an incident within authorized visibility (Phase 55)."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)
        decisions = await self.incident_repo.get_routing_history(incident_id)
        return [IncidentRoutingDecisionRead.model_validate(d) for d in decisions]

    async def get_review_queue(
        self,
        principal: AuthenticatedPrincipal,
        pagination: PaginationParams,
        *,
        reviewer_id: UUID | None = None,
        assignment_status: str | None = None,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> PaginatedResponse[IncidentRead]:
        """List incidents for department review queue strictly scoped to caller's tenant/department (Phase 56)."""
        can_read_global = has_permission(principal.role_code, Permission.INCIDENT_QUEUE_READ_GLOBAL)
        can_read_dept = has_permission(principal.role_code, Permission.INCIDENT_QUEUE_READ_DEPT)

        if not can_read_global and not can_read_dept:
            raise PermissionDeniedError(
                "Access to review queue is restricted to authorized investigators and administrators.",
                code="PERMISSION_DENIED",
            )

        department_scope: UUID | None = None
        if not can_read_global:
            department_scope = principal.department_id

        items, total_count = await self.incident_repo.list_review_queue_paginated(
            limit=pagination.page_size,
            offset=pagination.offset,
            department_id=department_scope,
            reviewer_id=reviewer_id,
            assignment_status=assignment_status,
            status=status,
            category=category,
            severity=severity,
            search=search,
            created_after=created_after,
            created_before=created_before,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        read_items = [IncidentRead.model_validate(item) for item in items]
        metadata = PaginationMetadata.from_counts(
            page=pagination.page,
            page_size=pagination.page_size,
            total_items=total_count,
        )
        return PaginatedResponse(items=read_items, pagination=metadata)

    async def get_workload_summary(
        self,
        principal: AuthenticatedPrincipal,
        *,
        reviewer_id: UUID | None = None,
    ) -> ReviewQueueWorkloadSummary:
        """Get review queue workload metrics strictly scoped to caller's department (Phase 56)."""
        can_read_global = has_permission(principal.role_code, Permission.INCIDENT_QUEUE_READ_GLOBAL)
        can_read_dept = has_permission(principal.role_code, Permission.INCIDENT_QUEUE_READ_DEPT)

        if not can_read_global and not can_read_dept:
            raise PermissionDeniedError(
                "Access to review queue workload metrics is restricted to authorized investigators.",
                code="PERMISSION_DENIED",
            )

        department_scope: UUID | None = None
        if not can_read_global:
            department_scope = principal.department_id

        counts = await self.incident_repo.get_workload_summary(
            department_id=department_scope,
            reviewer_id=reviewer_id,
        )
        return ReviewQueueWorkloadSummary(**counts)

    async def assign_reviewer(
        self,
        incident_id: UUID,
        payload: ReviewerAssignRequest,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Assign an eligible reviewer to an incident with validation and conflict checks (Phase 57)."""
        can_assign_global = has_permission(principal.role_code, Permission.INCIDENT_ASSIGN_GLOBAL)
        can_assign_dept = has_permission(principal.role_code, Permission.INCIDENT_ASSIGN_DEPT)

        if not can_assign_global and not can_assign_dept:
            raise PermissionDeniedError(
                "You do not have permission to assign reviewers.",
                code="PERMISSION_DENIED",
            )

        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        if not can_assign_global and incident.department_id != principal.department_id:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        if incident.status in {IncidentStatus.CLOSED.value, IncidentStatus.DISMISSED.value}:
            raise BusinessRuleError(
                "Cannot assign a reviewer to a closed or dismissed incident.",
                code="INCIDENT_ASSIGNMENT_LOCKED",
            )

        if not self.user_repo:
            raise BusinessRuleError(
                "User repository not configured for assignment validation.",
                code="CONFIGURATION_ERROR",
            )

        reviewer = await self.user_repo.get_by_id_unscoped(payload.reviewer_id)
        if reviewer is None:
            raise ResourceNotFoundError("Reviewer user not found.", code="REVIEWER_NOT_FOUND")

        validate_reviewer_assignment(
            incident_reporter_id=incident.reporter_id,
            reviewer_id=reviewer.id,
            reviewer_role=reviewer.role.code,
            reviewer_dept_id=reviewer.department_id,
            incident_dept_id=incident.department_id,
            is_active=reviewer.is_active,
            account_status=reviewer.account_status,
        )

        now = datetime.now(UTC)
        incident.assigned_reviewer_id = reviewer.id
        incident.assignment_status = AssignmentStatus.ASSIGNED.value
        incident.assigned_at = now
        incident.acknowledged_at = None

        if incident.status == IncidentStatus.SUBMITTED.value:
            incident.status = IncidentStatus.TRIAGED.value

        updated = await self.incident_repo.update(incident)

        assignment_record = IncidentAssignment(
            incident_id=incident.id,
            reviewer_id=reviewer.id,
            assigned_by_id=principal.user_id,
            status=AssignmentStatus.ASSIGNED.value,
            reason=payload.reason,
            created_at=now,
        )
        await self.incident_repo.create_assignment(assignment_record)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.REVIEWER_ASSIGNED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=incident.department_id,
                target_type=AuditTargetType.INCIDENT.value,
                target_id=str(incident.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "reviewer_id": str(reviewer.id),
                    "reviewer_role": reviewer.role.code,
                    "reason": payload.reason,
                },
            )

        logger.info(
            "Reviewer assigned to incident",
            extra={
                "incident_id": str(incident.id),
                "reviewer_id": str(reviewer.id),
                "assigned_by_id": str(principal.user_id),
            },
        )
        return IncidentRead.model_validate(updated)

    async def reassign_reviewer(
        self,
        incident_id: UUID,
        payload: ReviewerReassignRequest,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Reassign an incident to a new reviewer with mandatory reason (Phase 57)."""
        can_assign_global = has_permission(principal.role_code, Permission.INCIDENT_ASSIGN_GLOBAL)
        can_assign_dept = has_permission(principal.role_code, Permission.INCIDENT_ASSIGN_DEPT)

        if not can_assign_global and not can_assign_dept:
            raise PermissionDeniedError(
                "You do not have permission to reassign reviewers.",
                code="PERMISSION_DENIED",
            )

        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        if not can_assign_global and incident.department_id != principal.department_id:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        if incident.status in {IncidentStatus.CLOSED.value, IncidentStatus.DISMISSED.value}:
            raise BusinessRuleError(
                "Cannot reassign a closed or dismissed incident.",
                code="INCIDENT_ASSIGNMENT_LOCKED",
            )

        if incident.assigned_reviewer_id == payload.reviewer_id:
            raise BusinessRuleError(
                "Incident is already assigned to this reviewer.",
                code="SAME_REVIEWER_ASSIGNMENT",
            )

        if not self.user_repo:
            raise BusinessRuleError(
                "User repository not configured for assignment validation.",
                code="CONFIGURATION_ERROR",
            )

        new_reviewer = await self.user_repo.get_by_id_unscoped(payload.reviewer_id)
        if new_reviewer is None:
            raise ResourceNotFoundError("Reviewer user not found.", code="REVIEWER_NOT_FOUND")

        validate_reviewer_assignment(
            incident_reporter_id=incident.reporter_id,
            reviewer_id=new_reviewer.id,
            reviewer_role=new_reviewer.role.code,
            reviewer_dept_id=new_reviewer.department_id,
            incident_dept_id=incident.department_id,
            is_active=new_reviewer.is_active,
            account_status=new_reviewer.account_status,
        )

        now = datetime.now(UTC)
        old_reviewer_id = incident.assigned_reviewer_id
        incident.assigned_reviewer_id = new_reviewer.id
        incident.assignment_status = AssignmentStatus.REASSIGNED.value
        incident.assigned_at = now
        incident.acknowledged_at = None

        updated = await self.incident_repo.update(incident)

        assignment_record = IncidentAssignment(
            incident_id=incident.id,
            reviewer_id=new_reviewer.id,
            assigned_by_id=principal.user_id,
            status=AssignmentStatus.REASSIGNED.value,
            reason=payload.reason,
            created_at=now,
        )
        await self.incident_repo.create_assignment(assignment_record)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.REVIEWER_REASSIGNED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=incident.department_id,
                target_type=AuditTargetType.INCIDENT.value,
                target_id=str(incident.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "previous_reviewer_id": str(old_reviewer_id) if old_reviewer_id else None,
                    "new_reviewer_id": str(new_reviewer.id),
                    "reason": payload.reason,
                },
            )

        logger.info(
            "Reviewer reassigned for incident",
            extra={
                "incident_id": str(incident.id),
                "new_reviewer_id": str(new_reviewer.id),
                "reassigned_by_id": str(principal.user_id),
            },
        )
        return IncidentRead.model_validate(updated)

    async def acknowledge_assignment(
        self,
        incident_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> IncidentRead:
        """Acknowledge case assignment by the assigned reviewer (Phase 57)."""
        if not has_permission(principal.role_code, Permission.INCIDENT_ACKNOWLEDGE):
            raise PermissionDeniedError(
                "You do not have permission to acknowledge case assignments.",
                code="PERMISSION_DENIED",
            )

        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        is_super_admin = principal.role_code == RoleCode.SUPER_ADMIN.value
        if incident.assigned_reviewer_id != principal.user_id and not is_super_admin:
            raise PermissionDeniedError(
                "Only the assigned reviewer can acknowledge this case.",
                code="NOT_ASSIGNED_REVIEWER",
            )

        now = datetime.now(UTC)
        incident.assignment_status = AssignmentStatus.ACKNOWLEDGED.value
        incident.acknowledged_at = now
        updated = await self.incident_repo.update(incident)

        assignment_record = IncidentAssignment(
            incident_id=incident.id,
            reviewer_id=incident.assigned_reviewer_id or principal.user_id,
            assigned_by_id=principal.user_id,
            status=AssignmentStatus.ACKNOWLEDGED.value,
            reason="Reviewer acknowledged receipt and review responsibility.",
            created_at=now,
        )
        await self.incident_repo.create_assignment(assignment_record)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.ASSIGNMENT_ACKNOWLEDGED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=incident.department_id,
                target_type=AuditTargetType.INCIDENT.value,
                target_id=str(incident.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={"acknowledged_at": now.isoformat()},
            )

        return IncidentRead.model_validate(updated)

    async def get_assignment_history(
        self,
        incident_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[IncidentAssignmentRead]:
        """Retrieve reviewer assignment history within authorized department visibility (Phase 57)."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)
        assignments = await self.incident_repo.get_assignment_history(incident_id)
        return [IncidentAssignmentRead.model_validate(a) for a in assignments]

    def _assert_incident_visible(
        self,
        incident: Incident,
        principal: AuthenticatedPrincipal,
    ) -> None:
        """Enforce visibility boundary: raise 404 on out-of-scope access to prevent enumeration."""
        if principal.role_code == RoleCode.SUPER_ADMIN.value:
            return

        if principal.role_code in {RoleCode.DEPT_ADMIN.value, RoleCode.INVESTIGATOR.value}:
            if incident.department_id != principal.department_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
            return

        if principal.role_code in {RoleCode.STUDENT.value, RoleCode.STAFF.value}:
            if incident.reporter_id != principal.user_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
            return

        raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
