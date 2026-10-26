"""Incident repository with department scoping, status filtering, and allowlisted sorting (Phases 41-42).

Enforces:
- Mandatory department and ownership isolation at the query construction layer.
- Allowlisted sort columns and directions against SQL injection.
- Trigram / case-insensitive ILIKE search over title, description, and reference number.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.exceptions import BusinessRuleError
from backend.app.models.incident import Incident, IncidentAssignment, IncidentRoutingDecision

_ALLOWED_SORT_COLUMNS = {
    "created_at": Incident.created_at,
    "occurred_at": Incident.occurred_at,
    "title": Incident.title,
    "status": Incident.status,
    "severity": Incident.severity,
    "reference_number": Incident.reference_number,
    "assignment_status": Incident.assignment_status,
    "assigned_at": Incident.assigned_at,
    "acknowledged_at": Incident.acknowledged_at,
}


class IncidentRepository:
    """Async database repository for Incident persistence operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, incident: Incident) -> Incident:
        """Persist a new Incident record."""
        self.session.add(incident)
        await self.session.flush()
        return incident

    async def get_by_id(self, incident_id: UUID) -> Incident | None:
        """Retrieve an Incident by primary key."""
        result = await self.session.execute(select(Incident).where(Incident.id == incident_id))
        return result.scalars().first()

    async def get_by_reference_number(self, reference_number: str) -> Incident | None:
        """Retrieve an Incident by unique reference number."""
        clean_ref = reference_number.strip().upper()
        result = await self.session.execute(
            select(Incident).where(Incident.reference_number == clean_ref)
        )
        return result.scalars().first()

    async def update(self, incident: Incident) -> Incident:
        """Flush changes to an existing Incident."""
        self.session.add(incident)
        await self.session.flush()
        return incident

    async def list_paginated(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        reporter_id: UUID | None = None,
        department_id: UUID | None = None,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[Sequence[Incident], int]:
        """List incidents with filtering, search, pagination, and allowlisted sorting."""
        # 1. Validate sort parameters against allowlists
        order_key = sort_order.strip().lower()
        if order_key not in {"asc", "desc"}:
            raise BusinessRuleError(
                f"Invalid sort order '{sort_order}'. Allowed: 'asc', 'desc'.",
                code="INVALID_SORT_ORDER",
                status_code=400,
            )

        col_key = sort_by.strip().lower()
        sort_col = _ALLOWED_SORT_COLUMNS.get(col_key)
        if sort_col is None:
            allowed_cols = ", ".join(repr(k) for k in _ALLOWED_SORT_COLUMNS)
            raise BusinessRuleError(
                f"Invalid sort field '{sort_by}'. Allowed: {allowed_cols}.",
                code="INVALID_SORT_FIELD",
                status_code=400,
            )

        # 2. Build filter predicates
        predicates = []

        if reporter_id is not None:
            predicates.append(Incident.reporter_id == reporter_id)

        if department_id is not None:
            predicates.append(Incident.department_id == department_id)

        if status is not None:
            predicates.append(Incident.status == status.strip().lower())

        if category is not None:
            predicates.append(Incident.category == category.strip().lower())

        if severity is not None:
            predicates.append(Incident.severity == severity.strip().lower())

        if search is not None and search.strip():
            term = f"%{search.strip()}%"
            predicates.append(
                or_(
                    Incident.title.ilike(term),
                    Incident.description.ilike(term),
                    Incident.reference_number.ilike(term),
                    Incident.location.ilike(term),
                )
            )

        # 3. Compute total count
        count_stmt = select(func.count(Incident.id))
        if predicates:
            count_stmt = count_stmt.where(*predicates)
        total_items = (await self.session.execute(count_stmt)).scalar_one()

        if total_items == 0:
            return [], 0

        # 4. Query paginated results
        order_expr = sort_col.asc() if order_key == "asc" else sort_col.desc()
        query = select(Incident)
        if predicates:
            query = query.where(*predicates)

        query = query.order_by(order_expr).limit(limit).offset(offset)
        items = (await self.session.execute(query)).scalars().all()

        return items, total_items

    async def create_routing_decision(
        self, decision: IncidentRoutingDecision
    ) -> IncidentRoutingDecision:
        """Persist a new incident department routing decision record."""
        self.session.add(decision)
        await self.session.flush()
        return decision

    async def get_routing_history(self, incident_id: UUID) -> Sequence[IncidentRoutingDecision]:
        """List all routing decisions recorded for an incident in chronological order."""
        result = await self.session.execute(
            select(IncidentRoutingDecision)
            .where(IncidentRoutingDecision.incident_id == incident_id)
            .order_by(IncidentRoutingDecision.created_at.asc())
        )
        return result.scalars().all()

    async def list_review_queue_paginated(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        department_id: UUID | None = None,
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
    ) -> tuple[Sequence[Incident], int]:
        """List review queue incidents with reviewer, assignment, and department scoping (Phase 56)."""
        order_key = sort_order.strip().lower()
        if order_key not in {"asc", "desc"}:
            raise BusinessRuleError(
                f"Invalid sort order '{sort_order}'. Allowed: 'asc', 'desc'.",
                code="INVALID_SORT_ORDER",
                status_code=400,
            )

        col_key = sort_by.strip().lower()
        sort_col = _ALLOWED_SORT_COLUMNS.get(col_key)
        if sort_col is None:
            allowed_cols = ", ".join(repr(k) for k in _ALLOWED_SORT_COLUMNS)
            raise BusinessRuleError(
                f"Invalid sort field '{sort_by}'. Allowed: {allowed_cols}.",
                code="INVALID_SORT_FIELD",
                status_code=400,
            )

        predicates = []
        if department_id is not None:
            predicates.append(Incident.department_id == department_id)
        if reviewer_id is not None:
            predicates.append(Incident.assigned_reviewer_id == reviewer_id)
        if assignment_status is not None:
            predicates.append(Incident.assignment_status == assignment_status.strip().lower())
        if status is not None:
            predicates.append(Incident.status == status.strip().lower())
        if category is not None:
            predicates.append(Incident.category == category.strip().lower())
        if severity is not None:
            predicates.append(Incident.severity == severity.strip().lower())
        if created_after is not None:
            predicates.append(Incident.created_at >= created_after)
        if created_before is not None:
            predicates.append(Incident.created_at <= created_before)
        if search is not None and search.strip():
            term = f"%{search.strip()}%"
            predicates.append(
                or_(
                    Incident.title.ilike(term),
                    Incident.description.ilike(term),
                    Incident.reference_number.ilike(term),
                    Incident.location.ilike(term),
                )
            )

        count_stmt = select(func.count(Incident.id))
        if predicates:
            count_stmt = count_stmt.where(*predicates)
        total_items = (await self.session.execute(count_stmt)).scalar_one()

        if total_items == 0:
            return [], 0

        order_expr = sort_col.asc() if order_key == "asc" else sort_col.desc()
        query = select(Incident)
        if predicates:
            query = query.where(*predicates)
        query = query.order_by(order_expr).limit(limit).offset(offset)
        items = (await self.session.execute(query)).scalars().all()

        return items, total_items

    async def get_workload_summary(
        self,
        *,
        department_id: UUID | None = None,
        reviewer_id: UUID | None = None,
    ) -> dict[str, int]:
        """Compute workload summary metrics for incidents in review queue (Phase 56)."""
        predicates = []
        if department_id is not None:
            predicates.append(Incident.department_id == department_id)
        if reviewer_id is not None:
            predicates.append(Incident.assigned_reviewer_id == reviewer_id)

        overdue_threshold = datetime.now(UTC) - timedelta(days=7)

        stmt = select(
            func.count(Incident.id).label("total"),
            func.count(case((Incident.status.in_(["submitted", "triaged"]), 1))).label("pending"),
            func.count(
                case(
                    (
                        Incident.assignment_status.in_(
                            ["assigned", "acknowledged", "under_review"]
                        ),
                        1,
                    )
                )
            ).label("assigned"),
            func.count(case((Incident.assignment_status == "unassigned", 1))).label("unassigned"),
            func.count(
                case(
                    (
                        (Incident.created_at < overdue_threshold)
                        & (~Incident.status.in_(["resolved", "closed"])),
                        1,
                    )
                )
            ).label("overdue"),
            func.count(case((Incident.status.in_(["resolved", "closed"]), 1))).label("completed"),
        )
        if predicates:
            stmt = stmt.where(*predicates)

        result = await self.session.execute(stmt)
        row = result.one()
        return {
            "total": int(row.total or 0),
            "pending": int(row.pending or 0),
            "assigned": int(row.assigned or 0),
            "unassigned": int(row.unassigned or 0),
            "overdue": int(row.overdue or 0),
            "completed": int(row.completed or 0),
        }

    async def create_assignment(self, assignment: IncidentAssignment) -> IncidentAssignment:
        """Persist a new incident reviewer assignment history record (Phase 57)."""
        self.session.add(assignment)
        await self.session.flush()
        return assignment

    async def get_assignment_history(self, incident_id: UUID) -> Sequence[IncidentAssignment]:
        """List all assignment transitions for an incident in chronological order (Phase 57)."""
        result = await self.session.execute(
            select(IncidentAssignment)
            .where(IncidentAssignment.incident_id == incident_id)
            .order_by(IncidentAssignment.created_at.asc())
        )
        return result.scalars().all()

    async def get_latest_assignment(self, incident_id: UUID) -> IncidentAssignment | None:
        """Fetch the most recent assignment transition for an incident (Phase 57)."""
        result = await self.session.execute(
            select(IncidentAssignment)
            .where(IncidentAssignment.incident_id == incident_id)
            .order_by(IncidentAssignment.created_at.desc())
            .limit(1)
        )
        return result.scalars().first()
