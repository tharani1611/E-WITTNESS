"""Incident reporting domain primitives, categories, statuses, and validation (Phase 41).

Enforces:
- Canonical incident category enumeration (`IncidentCategory`).
- Explicit incident lifecycle states (`IncidentStatus`) and authorized state transitions.
- Concurrency-safe, opaque incident reference number generation.
- Location and title normalization.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from backend.app.core.exceptions import BusinessRuleError


class IncidentCategory(StrEnum):
    """Canonical classification categories for student and institutional incident reports."""

    ACADEMIC_MISCONDUCT = "academic_misconduct"
    HARASSMENT_DISCRIMINATION = "harassment_discrimination"
    PROPERTY_DAMAGE_THEFT = "property_damage_theft"
    SAFETY_HAZARD = "safety_hazard"
    PHYSICAL_ASSAULT = "physical_assault"
    OTHER = "other"


class IncidentStatus(StrEnum):
    """Explicit lifecycle states for incident reports."""

    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    UNDER_INVESTIGATION = "under_investigation"
    CLOSED = "closed"
    DISMISSED = "dismissed"


# Valid lifecycle status transitions
VALID_INCIDENT_TRANSITIONS: Final[dict[IncidentStatus, frozenset[IncidentStatus]]] = {
    IncidentStatus.SUBMITTED: frozenset({IncidentStatus.TRIAGED, IncidentStatus.DISMISSED}),
    IncidentStatus.TRIAGED: frozenset(
        {IncidentStatus.UNDER_INVESTIGATION, IncidentStatus.DISMISSED, IncidentStatus.CLOSED}
    ),
    IncidentStatus.UNDER_INVESTIGATION: frozenset(
        {IncidentStatus.CLOSED, IncidentStatus.DISMISSED}
    ),
    IncidentStatus.CLOSED: frozenset(),
    IncidentStatus.DISMISSED: frozenset(),
}


def parse_incident_category(value: str) -> IncidentCategory:
    """Parse and validate incident category value."""
    normalized = value.strip().lower()
    try:
        return IncidentCategory(normalized)
    except ValueError:
        valid_values = ", ".join(repr(c.value) for c in IncidentCategory)
        raise BusinessRuleError(
            f"Invalid incident category '{value}'. Allowed categories: {valid_values}.",
            code="INVALID_INCIDENT_CATEGORY",
        ) from None


def parse_incident_status(value: str) -> IncidentStatus:
    """Parse and validate incident status value."""
    normalized = value.strip().lower()
    try:
        return IncidentStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in IncidentStatus)
        raise BusinessRuleError(
            f"Invalid incident status '{value}'. Allowed statuses: {valid_values}.",
            code="INVALID_INCIDENT_STATUS",
        ) from None


def validate_incident_status_transition(
    current: IncidentStatus,
    target: IncidentStatus,
) -> None:
    """Validate whether transitioning from ``current`` to ``target`` is allowed."""
    if current == target:
        return

    allowed = VALID_INCIDENT_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise BusinessRuleError(
            f"Cannot transition incident status from '{current.value}' to '{target.value}'.",
            code="INVALID_STATUS_TRANSITION",
        )


def generate_incident_reference_number(when: datetime | None = None) -> str:
    """Generate a non-guessable, concurrency-safe, opaque incident reference number.

    Format: `INC-<YYYY>-<8-HEX>` e.g. `INC-2026-A1B2C3D4`
    """
    timestamp = when or datetime.now(UTC)
    year = timestamp.strftime("%Y")
    entropy_hex = secrets.token_hex(4).upper()
    return f"INC-{year}-{entropy_hex}"


class IncidentSeverity(StrEnum):
    """Institutional triage severity levels for incident reports (Phase 55)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def parse_incident_severity(value: str) -> IncidentSeverity:
    """Parse and validate incident severity level."""
    normalized = value.strip().lower()
    try:
        return IncidentSeverity(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in IncidentSeverity)
        raise BusinessRuleError(
            f"Invalid incident severity '{value}'. Allowed: {valid_values}.",
            code="INVALID_INCIDENT_SEVERITY",
        ) from None


class IncidentRoutingType(StrEnum):
    """Origin type of an incident department routing decision (Phase 55)."""

    SYSTEM_RULE = "system_rule"
    AUTHORIZED_OVERRIDE = "authorized_override"


def _match_department(
    candidates: tuple[str, ...],
    dept_map: dict[str, UUID],
    available_departments: list[tuple[UUID, str]],
) -> tuple[UUID, str] | None:
    for candidate in candidates:
        if candidate in dept_map:
            return dept_map[candidate], candidate
    for candidate in candidates:
        for dept_id, code in available_departments:
            upper = code.upper()
            if (
                upper.startswith(f"{candidate}-")
                or upper.startswith(f"{candidate}_")
                or candidate in upper
            ):
                return dept_id, candidate
    return None


def evaluate_deterministic_routing(
    category: IncidentCategory,
    severity: IncidentSeverity,
    available_departments: list[tuple[UUID, str]],  # (department_id, upper_code)
    reporter_department_id: UUID,
) -> tuple[UUID, str]:
    """Deterministically determine the target department for an incident based on configurable rules.

    Returns (target_department_id, rule_name).
    """
    dept_map = {code.upper(): dept_id for dept_id, code in available_departments}

    # 1. Critical severity or violent/safety incidents route to Safety & Security
    if severity == IncidentSeverity.CRITICAL or category in (
        IncidentCategory.PHYSICAL_ASSAULT,
        IncidentCategory.SAFETY_HAZARD,
    ):
        matched = _match_department(
            ("SAFETY", "CAMPUS_SAFETY", "SECURITY", "SEC"), dept_map, available_departments
        )
        if matched:
            return matched[0], f"CRITICAL_SAFETY_ROUTING:{matched[1]}"

    # 2. Academic misconduct routes to Academic Affairs / Conduct
    if category == IncidentCategory.ACADEMIC_MISCONDUCT:
        matched = _match_department(
            ("ACADEMIC", "ACADEMIC_AFFAIRS", "STUDENT_CONDUCT", "ACAD"),
            dept_map,
            available_departments,
        )
        if matched:
            return matched[0], f"ACADEMIC_AFFAIRS_ROUTING:{matched[1]}"

    # 3. Harassment and discrimination routes to Title IX / Conduct
    if category == IncidentCategory.HARASSMENT_DISCRIMINATION:
        matched = _match_department(
            ("TITLE_IX", "CONDUCT", "HR", "STUDENT_AFFAIRS", "COND"),
            dept_map,
            available_departments,
        )
        if matched:
            return matched[0], f"CONDUCT_TITLE_IX_ROUTING:{matched[1]}"

    # 4. Property damage & theft routes to Facilities / Safety
    if category == IncidentCategory.PROPERTY_DAMAGE_THEFT:
        matched = _match_department(
            ("FACILITIES", "SAFETY", "CAMPUS_SAFETY", "SECURITY", "FAC"),
            dept_map,
            available_departments,
        )
        if matched:
            return matched[0], f"FACILITIES_SAFETY_ROUTING:{matched[1]}"

    # 5. Default fallback to reporter's home department if available, or first available
    if any(dept_id == reporter_department_id for dept_id, _ in available_departments):
        return reporter_department_id, "DEFAULT_REPORTER_HOME_DEPARTMENT"

    if available_departments:
        first_id, first_code = available_departments[0]
        return first_id, f"DEFAULT_FIRST_AVAILABLE:{first_code}"

    return reporter_department_id, "DEFAULT_FALLBACK"


class AssignmentStatus(StrEnum):
    """Institutional review and assignment states for incident reports (Phase 56-57)."""

    UNASSIGNED = "unassigned"
    ASSIGNED = "assigned"
    ACKNOWLEDGED = "acknowledged"
    UNDER_REVIEW = "under_review"
    REASSIGNED = "reassigned"


def parse_assignment_status(value: str) -> AssignmentStatus:
    """Parse and validate reviewer assignment status."""
    normalized = value.strip().lower()
    try:
        return AssignmentStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in AssignmentStatus)
        raise BusinessRuleError(
            f"Invalid assignment status '{value}'. Allowed: {valid_values}.",
            code="INVALID_ASSIGNMENT_STATUS",
        ) from None


def validate_reviewer_assignment(
    *,
    incident_reporter_id: UUID,
    reviewer_id: UUID,
    reviewer_role: str,
    reviewer_dept_id: UUID | None,
    incident_dept_id: UUID,
    is_active: bool,
    account_status: str,
) -> None:
    """Validate reviewer eligibility and conflict-of-interest checks (Phase 57).

    Rules:
    1. Account must be active and verified.
    2. Reviewer cannot be the reporting party of the incident (strict conflict of interest).
    3. Reviewer role must be investigator, dept admin, or super admin.
    4. Reviewer must belong to the incident's assigned department (unless super admin).
    """
    if not is_active or account_status != "active":
        raise BusinessRuleError(
            "Reviewer account is inactive, pending verification, or suspended.",
            code="INACTIVE_REVIEWER",
        )

    if reviewer_id == incident_reporter_id:
        raise BusinessRuleError(
            "Reviewer cannot be the reporting party of this incident (conflict of interest).",
            code="CONFLICT_OF_INTEREST",
        )

    eligible_roles = {
        "ROLE_INVESTIGATOR",
        "ROLE_DEPT_ADMIN",
        "ROLE_SUPER_ADMIN",
        "investigator",
        "dept_admin",
        "super_admin",
    }
    if reviewer_role not in eligible_roles:
        raise BusinessRuleError(
            f"Role '{reviewer_role}' is not eligible for case reviewer assignments.",
            code="INELIGIBLE_REVIEWER_ROLE",
        )

    is_super_admin = reviewer_role in {"ROLE_SUPER_ADMIN", "super_admin"}
    if not is_super_admin and reviewer_dept_id != incident_dept_id:
        raise BusinessRuleError(
            "Reviewer must belong to the department handling this incident.",
            code="DEPARTMENT_MISMATCH",
        )
