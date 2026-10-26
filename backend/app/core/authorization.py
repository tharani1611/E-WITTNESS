"""Centralized authorization policies, roles, and permissions (Phase 21).

Enforces default-deny Role-Based Access Control (RBAC) and explicit
permission mapping for E-WITNESS stakeholder roles:
- Separates authentication (identity verification) from authorization (permission evaluation).
- Separates role membership from individual permission checks.
- Denies by default any unknown role, unknown permission, or unmapped action.
- Distinguishes self-service, department-scoped, and global operations.
- Enforces privilege boundary rules preventing departmental escalation.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from backend.app.core.identity import RoleCode


class Permission(StrEnum):
    """Granular action permissions across E-WITNESS resources."""

    # 1. Self-Service Permissions (caller operating on their own record)
    USER_READ_OWN = "user:read:own"
    USER_UPDATE_OWN = "user:update:own"
    SESSION_READ_OWN = "session:read:own"
    SESSION_REVOKE_OWN = "session:revoke:own"

    # 2. Department-Scoped User & Session Administration (Dept Admin)
    USER_CREATE_DEPT = "user:create:dept"
    USER_READ_DEPT = "user:read:dept"
    USER_UPDATE_DEPT = "user:update:dept"
    USER_STATUS_UPDATE_DEPT = "user:status_update:dept"
    USER_ROLE_ASSIGN_DEPT = "user:role_assign:dept"
    SESSION_READ_DEPT = "session:read:dept"
    SESSION_REVOKE_DEPT = "session:revoke:dept"
    DEPARTMENT_READ_OWN = "department:read:own"

    # 3. Global / Cross-Department User & Session Administration (Super Admin)
    USER_CREATE_GLOBAL = "user:create:global"
    USER_READ_GLOBAL = "user:read:global"
    USER_UPDATE_GLOBAL = "user:update:global"
    USER_STATUS_UPDATE_GLOBAL = "user:status_update:global"
    USER_ROLE_ASSIGN_GLOBAL = "user:role_assign:global"
    USER_DEPT_REASSIGN_GLOBAL = "user:dept_reassign:global"
    SESSION_READ_GLOBAL = "session:read:global"
    SESSION_REVOKE_GLOBAL = "session:revoke:global"

    # 4. Global Department Administration (Super Admin)
    DEPARTMENT_CREATE_GLOBAL = "department:create:global"
    DEPARTMENT_READ_GLOBAL = "department:read:global"
    DEPARTMENT_UPDATE_GLOBAL = "department:update:global"
    DEPARTMENT_STATUS_UPDATE_GLOBAL = "department:status_update:global"

    # 5. System Administration & Role Introspection
    ROLE_READ_GLOBAL = "role:read:global"
    SYSTEM_CONFIG_MANAGE = "system:config:manage"

    # 6. Incident Reporting & Management Permissions (Phases 41-42)
    INCIDENT_CREATE = "incident:create"
    INCIDENT_READ_OWN = "incident:read:own"
    INCIDENT_READ_DEPT = "incident:read:dept"
    INCIDENT_READ_GLOBAL = "incident:read:global"
    INCIDENT_UPDATE_OWN = "incident:update:own"
    INCIDENT_UPDATE_DEPT = "incident:update:dept"
    INCIDENT_UPDATE_GLOBAL = "incident:update:global"

    # 7. Evidence Attachment & Upload Permissions (Phases 43-45)
    EVIDENCE_UPLOAD_OWN = "evidence:upload:own"
    EVIDENCE_UPLOAD_DEPT = "evidence:upload:dept"
    EVIDENCE_UPLOAD_GLOBAL = "evidence:upload:global"
    EVIDENCE_READ_OWN = "evidence:read:own"
    EVIDENCE_READ_DEPT = "evidence:read:dept"
    EVIDENCE_READ_GLOBAL = "evidence:read:global"

    # 8. Review Queues, Assignment & Workflow Permissions (Phases 56-57)
    INCIDENT_QUEUE_READ_DEPT = "incident:queue:read:dept"
    INCIDENT_QUEUE_READ_GLOBAL = "incident:queue:read:global"
    INCIDENT_ASSIGN_DEPT = "incident:assign:dept"
    INCIDENT_ASSIGN_GLOBAL = "incident:assign:global"
    INCIDENT_ACKNOWLEDGE = "incident:acknowledge"

    # 9. Tamper-Evident Security Audit & Export Permissions (Phases 58-59)
    AUDIT_EVENT_READ_DEPT = "audit:read:dept"
    AUDIT_EVENT_READ_GLOBAL = "audit:read:global"
    EVIDENCE_EXPORT_DEPT = "evidence:export:dept"
    EVIDENCE_EXPORT_GLOBAL = "evidence:export:global"

    # 10. AI-Assisted Violence Detection & Dataset Governance Permissions (Phases 61-65)
    AI_JOB_SUBMIT = "ai:job:submit"
    AI_JOB_READ_OWN = "ai:job:read:own"
    AI_JOB_READ_DEPT = "ai:job:read:dept"
    AI_JOB_READ_GLOBAL = "ai:job:read:global"
    AI_JOB_CANCEL_DEPT = "ai:job:cancel:dept"
    AI_JOB_CANCEL_GLOBAL = "ai:job:cancel:global"
    AI_DATASET_READ = "ai:dataset:read"
    AI_DATASET_MANAGE = "ai:dataset:manage"
    AI_SEGMENT_READ_DEPT = "ai:segment:read:dept"
    AI_SEGMENT_READ_GLOBAL = "ai:segment:read:global"
    AI_SEGMENT_REVIEW_DEPT = "ai:segment:review:dept"
    AI_SEGMENT_REVIEW_GLOBAL = "ai:segment:review:global"
    AI_RESULT_RETENTION_MANAGE = "ai:result:retention:manage"

    # 11. Biometric Governance, Reference Registry & Face Detection Permissions (Phases 71-75)
    BIOMETRIC_CONFIG_MANAGE = "biometric:config:manage"
    BIOMETRIC_REFERENCE_READ_OWN = "biometric:reference:read:own"
    BIOMETRIC_REFERENCE_MANAGE_OWN = "biometric:reference:manage:own"
    BIOMETRIC_REFERENCE_READ_DEPT = "biometric:reference:read:dept"
    BIOMETRIC_REFERENCE_MANAGE_DEPT = "biometric:reference:manage:dept"
    BIOMETRIC_REFERENCE_READ_GLOBAL = "biometric:reference:read:global"
    BIOMETRIC_REFERENCE_MANAGE_GLOBAL = "biometric:reference:manage:global"
    BIOMETRIC_DETECTION_EXECUTE = "biometric:detection:execute"
    BIOMETRIC_MATCHING_EXECUTE = "biometric:matching:execute"
    BIOMETRIC_VERIFICATION_REVIEW = "biometric:verification:review"
    BIOMETRIC_GOVERNANCE_REVIEW = "biometric:governance:review"
    BIOMETRIC_AUDIT_READ = "biometric:audit:read"

    # 12. Investigation Case Management, Workload & Inventory Permissions (Phases 81-85)
    CASE_CREATE_DEPT = "case:create:dept"
    CASE_CREATE_GLOBAL = "case:create:global"
    CASE_READ_OWN = "case:read:own"
    CASE_READ_DEPT = "case:read:dept"
    CASE_READ_GLOBAL = "case:read:global"
    CASE_UPDATE_DEPT = "case:update:dept"
    CASE_UPDATE_GLOBAL = "case:update:global"
    CASE_ASSIGN_DEPT = "case:assign:dept"
    CASE_ASSIGN_GLOBAL = "case:assign:global"
    CASE_WORKLOAD_READ_DEPT = "case:workload:read:dept"
    CASE_WORKLOAD_READ_GLOBAL = "case:workload:read:global"
    CASE_EVIDENCE_MANAGE = "case:evidence:manage"
    CASE_AI_SEGMENT_MANAGE = "case:ai_segment:manage"
    CASE_AI_SEGMENT_REVIEW = "case:ai_segment:review"
    CASE_NOTE_CREATE = "case:note:create"
    CASE_NOTE_READ = "case:note:read"
    CASE_NOTE_READ_RESTRICTED = "case:note:read:restricted"
    CASE_FINDING_MANAGE = "case:finding:manage"
    CASE_TRANSITION_APPROVE = "case:transition:approve"
    CASE_ESCALATE = "case:escalate"
    CASE_REFER = "case:refer"
    CASE_CLOSE = "case:close"
    CASE_REOPEN = "case:reopen"
    CASE_EXPORT = "case:export"

    # 13. Notifications, Alerts & Preferences (Phases 91-94)
    NOTIFICATION_READ_OWN = "notification:read:own"
    NOTIFICATION_UPDATE_OWN = "notification:update:own"
    NOTIFICATION_PREFERENCE_MANAGE_OWN = "notification:preference:manage:own"
    NOTIFICATION_DISPATCH_SYSTEM = "notification:dispatch:system"

    # 14. Operational Dashboards & Aggregations (Phase 95)
    DASHBOARD_VIEW_DEPT = "dashboard:view:dept"
    DASHBOARD_VIEW_GLOBAL = "dashboard:view:global"

    # 15. Analytics, Reporting & Operational Monitoring (Phases 96-99)
    ANALYTICS_VIEW_DEPT = "analytics:view:dept"
    ANALYTICS_VIEW_GLOBAL = "analytics:view:global"
    OPERATIONS_METRICS_READ_DEPT = "operations:metrics:read:dept"
    OPERATIONS_METRICS_READ_GLOBAL = "operations:metrics:read:global"
    REPORT_EXPORT_DEPT = "report:export:dept"
    REPORT_EXPORT_GLOBAL = "report:export:global"
    HEALTH_VIEW_DETAILED = "health:view:detailed"
    OPERATIONAL_ALERT_MANAGE = "operational:alert:manage"


# Canonical mapping from RoleCode to explicit set of granted Permissions
ROLE_PERMISSIONS: Final[dict[RoleCode, frozenset[Permission]]] = {
    RoleCode.STUDENT: frozenset(
        {
            Permission.USER_READ_OWN,
            Permission.USER_UPDATE_OWN,
            Permission.SESSION_READ_OWN,
            Permission.SESSION_REVOKE_OWN,
            Permission.INCIDENT_CREATE,
            Permission.INCIDENT_READ_OWN,
            Permission.INCIDENT_UPDATE_OWN,
            Permission.EVIDENCE_UPLOAD_OWN,
            Permission.EVIDENCE_READ_OWN,
            Permission.BIOMETRIC_REFERENCE_READ_OWN,
            Permission.BIOMETRIC_REFERENCE_MANAGE_OWN,
            Permission.NOTIFICATION_READ_OWN,
            Permission.NOTIFICATION_UPDATE_OWN,
            Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN,
        }
    ),
    RoleCode.STAFF: frozenset(
        {
            Permission.USER_READ_OWN,
            Permission.USER_UPDATE_OWN,
            Permission.SESSION_READ_OWN,
            Permission.SESSION_REVOKE_OWN,
            Permission.INCIDENT_CREATE,
            Permission.INCIDENT_READ_OWN,
            Permission.INCIDENT_UPDATE_OWN,
            Permission.EVIDENCE_UPLOAD_OWN,
            Permission.EVIDENCE_READ_OWN,
            Permission.BIOMETRIC_REFERENCE_READ_OWN,
            Permission.BIOMETRIC_REFERENCE_MANAGE_OWN,
            Permission.NOTIFICATION_READ_OWN,
            Permission.NOTIFICATION_UPDATE_OWN,
            Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN,
        }
    ),
    RoleCode.INVESTIGATOR: frozenset(
        {
            Permission.USER_READ_OWN,
            Permission.USER_UPDATE_OWN,
            Permission.SESSION_READ_OWN,
            Permission.SESSION_REVOKE_OWN,
            Permission.DEPARTMENT_READ_OWN,
            Permission.INCIDENT_READ_DEPT,
            Permission.EVIDENCE_UPLOAD_DEPT,
            Permission.EVIDENCE_READ_DEPT,
            Permission.INCIDENT_QUEUE_READ_DEPT,
            Permission.INCIDENT_ACKNOWLEDGE,
            Permission.AUDIT_EVENT_READ_DEPT,
            Permission.EVIDENCE_EXPORT_DEPT,
            Permission.AI_JOB_SUBMIT,
            Permission.AI_JOB_READ_OWN,
            Permission.AI_JOB_READ_DEPT,
            Permission.AI_JOB_CANCEL_DEPT,
            Permission.AI_DATASET_READ,
            Permission.AI_SEGMENT_READ_DEPT,
            Permission.AI_SEGMENT_REVIEW_DEPT,
            Permission.BIOMETRIC_REFERENCE_READ_DEPT,
            Permission.BIOMETRIC_DETECTION_EXECUTE,
            Permission.BIOMETRIC_MATCHING_EXECUTE,
            Permission.BIOMETRIC_VERIFICATION_REVIEW,
            Permission.CASE_CREATE_DEPT,
            Permission.CASE_READ_OWN,
            Permission.CASE_READ_DEPT,
            Permission.CASE_UPDATE_DEPT,
            Permission.CASE_EVIDENCE_MANAGE,
            Permission.CASE_AI_SEGMENT_MANAGE,
            Permission.CASE_AI_SEGMENT_REVIEW,
            Permission.CASE_NOTE_CREATE,
            Permission.CASE_NOTE_READ,
            Permission.CASE_FINDING_MANAGE,
            Permission.CASE_ESCALATE,
            Permission.CASE_REFER,
            Permission.CASE_EXPORT,
            Permission.NOTIFICATION_READ_OWN,
            Permission.NOTIFICATION_UPDATE_OWN,
            Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN,
            Permission.ANALYTICS_VIEW_DEPT,
            Permission.REPORT_EXPORT_DEPT,
        }
    ),
    RoleCode.DEPT_ADMIN: frozenset(
        {
            Permission.USER_READ_OWN,
            Permission.USER_UPDATE_OWN,
            Permission.SESSION_READ_OWN,
            Permission.SESSION_REVOKE_OWN,
            Permission.USER_CREATE_DEPT,
            Permission.USER_READ_DEPT,
            Permission.USER_UPDATE_DEPT,
            Permission.USER_STATUS_UPDATE_DEPT,
            Permission.USER_ROLE_ASSIGN_DEPT,
            Permission.DEPARTMENT_READ_OWN,
            Permission.SESSION_READ_DEPT,
            Permission.SESSION_REVOKE_DEPT,
            Permission.INCIDENT_CREATE,
            Permission.INCIDENT_READ_DEPT,
            Permission.INCIDENT_UPDATE_DEPT,
            Permission.EVIDENCE_UPLOAD_DEPT,
            Permission.EVIDENCE_READ_DEPT,
            Permission.INCIDENT_QUEUE_READ_DEPT,
            Permission.INCIDENT_ASSIGN_DEPT,
            Permission.INCIDENT_ACKNOWLEDGE,
            Permission.AUDIT_EVENT_READ_DEPT,
            Permission.EVIDENCE_EXPORT_DEPT,
            Permission.AI_JOB_SUBMIT,
            Permission.AI_JOB_READ_OWN,
            Permission.AI_JOB_READ_DEPT,
            Permission.AI_JOB_CANCEL_DEPT,
            Permission.AI_DATASET_READ,
            Permission.AI_SEGMENT_READ_DEPT,
            Permission.AI_SEGMENT_REVIEW_DEPT,
            Permission.AI_RESULT_RETENTION_MANAGE,
            Permission.BIOMETRIC_REFERENCE_READ_DEPT,
            Permission.BIOMETRIC_REFERENCE_MANAGE_DEPT,
            Permission.BIOMETRIC_DETECTION_EXECUTE,
            Permission.BIOMETRIC_MATCHING_EXECUTE,
            Permission.BIOMETRIC_VERIFICATION_REVIEW,
            Permission.BIOMETRIC_GOVERNANCE_REVIEW,
            Permission.BIOMETRIC_AUDIT_READ,
            Permission.CASE_CREATE_DEPT,
            Permission.CASE_READ_DEPT,
            Permission.CASE_UPDATE_DEPT,
            Permission.CASE_ASSIGN_DEPT,
            Permission.CASE_WORKLOAD_READ_DEPT,
            Permission.CASE_EVIDENCE_MANAGE,
            Permission.CASE_AI_SEGMENT_MANAGE,
            Permission.CASE_AI_SEGMENT_REVIEW,
            Permission.CASE_NOTE_CREATE,
            Permission.CASE_NOTE_READ,
            Permission.CASE_NOTE_READ_RESTRICTED,
            Permission.CASE_FINDING_MANAGE,
            Permission.CASE_TRANSITION_APPROVE,
            Permission.CASE_ESCALATE,
            Permission.CASE_REFER,
            Permission.CASE_CLOSE,
            Permission.CASE_REOPEN,
            Permission.CASE_EXPORT,
            Permission.NOTIFICATION_READ_OWN,
            Permission.NOTIFICATION_UPDATE_OWN,
            Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN,
            Permission.NOTIFICATION_DISPATCH_SYSTEM,
            Permission.DASHBOARD_VIEW_DEPT,
            Permission.ANALYTICS_VIEW_DEPT,
            Permission.OPERATIONS_METRICS_READ_DEPT,
            Permission.REPORT_EXPORT_DEPT,
            Permission.HEALTH_VIEW_DETAILED,
            Permission.OPERATIONAL_ALERT_MANAGE,
        }
    ),
    RoleCode.SUPER_ADMIN: frozenset(
        {
            Permission.USER_READ_OWN,
            Permission.USER_UPDATE_OWN,
            Permission.SESSION_READ_OWN,
            Permission.SESSION_REVOKE_OWN,
            Permission.USER_CREATE_GLOBAL,
            Permission.USER_READ_GLOBAL,
            Permission.USER_UPDATE_GLOBAL,
            Permission.USER_STATUS_UPDATE_GLOBAL,
            Permission.USER_ROLE_ASSIGN_GLOBAL,
            Permission.USER_DEPT_REASSIGN_GLOBAL,
            Permission.DEPARTMENT_CREATE_GLOBAL,
            Permission.DEPARTMENT_READ_GLOBAL,
            Permission.DEPARTMENT_UPDATE_GLOBAL,
            Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL,
            Permission.ROLE_READ_GLOBAL,
            Permission.SESSION_READ_GLOBAL,
            Permission.SESSION_REVOKE_GLOBAL,
            Permission.SYSTEM_CONFIG_MANAGE,
            Permission.INCIDENT_CREATE,
            Permission.INCIDENT_READ_GLOBAL,
            Permission.INCIDENT_UPDATE_GLOBAL,
            Permission.EVIDENCE_UPLOAD_GLOBAL,
            Permission.EVIDENCE_READ_GLOBAL,
            Permission.INCIDENT_QUEUE_READ_DEPT,
            Permission.INCIDENT_QUEUE_READ_GLOBAL,
            Permission.INCIDENT_ASSIGN_DEPT,
            Permission.INCIDENT_ASSIGN_GLOBAL,
            Permission.INCIDENT_ACKNOWLEDGE,
            Permission.AUDIT_EVENT_READ_DEPT,
            Permission.AUDIT_EVENT_READ_GLOBAL,
            Permission.EVIDENCE_EXPORT_DEPT,
            Permission.EVIDENCE_EXPORT_GLOBAL,
            Permission.AI_JOB_SUBMIT,
            Permission.AI_JOB_READ_OWN,
            Permission.AI_JOB_READ_DEPT,
            Permission.AI_JOB_READ_GLOBAL,
            Permission.AI_JOB_CANCEL_DEPT,
            Permission.AI_JOB_CANCEL_GLOBAL,
            Permission.AI_DATASET_READ,
            Permission.AI_DATASET_MANAGE,
            Permission.AI_SEGMENT_READ_DEPT,
            Permission.AI_SEGMENT_READ_GLOBAL,
            Permission.AI_SEGMENT_REVIEW_DEPT,
            Permission.AI_SEGMENT_REVIEW_GLOBAL,
            Permission.AI_RESULT_RETENTION_MANAGE,
            Permission.BIOMETRIC_CONFIG_MANAGE,
            Permission.BIOMETRIC_REFERENCE_READ_DEPT,
            Permission.BIOMETRIC_REFERENCE_READ_GLOBAL,
            Permission.BIOMETRIC_REFERENCE_MANAGE_DEPT,
            Permission.BIOMETRIC_REFERENCE_MANAGE_GLOBAL,
            Permission.BIOMETRIC_DETECTION_EXECUTE,
            Permission.BIOMETRIC_MATCHING_EXECUTE,
            Permission.BIOMETRIC_VERIFICATION_REVIEW,
            Permission.BIOMETRIC_GOVERNANCE_REVIEW,
            Permission.BIOMETRIC_AUDIT_READ,
            Permission.CASE_CREATE_DEPT,
            Permission.CASE_CREATE_GLOBAL,
            Permission.CASE_READ_OWN,
            Permission.CASE_READ_DEPT,
            Permission.CASE_READ_GLOBAL,
            Permission.CASE_UPDATE_DEPT,
            Permission.CASE_UPDATE_GLOBAL,
            Permission.CASE_ASSIGN_DEPT,
            Permission.CASE_ASSIGN_GLOBAL,
            Permission.CASE_WORKLOAD_READ_DEPT,
            Permission.CASE_WORKLOAD_READ_GLOBAL,
            Permission.CASE_EVIDENCE_MANAGE,
            Permission.CASE_AI_SEGMENT_MANAGE,
            Permission.CASE_AI_SEGMENT_REVIEW,
            Permission.CASE_NOTE_CREATE,
            Permission.CASE_NOTE_READ,
            Permission.CASE_NOTE_READ_RESTRICTED,
            Permission.CASE_FINDING_MANAGE,
            Permission.CASE_TRANSITION_APPROVE,
            Permission.CASE_ESCALATE,
            Permission.CASE_REFER,
            Permission.CASE_CLOSE,
            Permission.CASE_REOPEN,
            Permission.CASE_EXPORT,
            Permission.NOTIFICATION_READ_OWN,
            Permission.NOTIFICATION_UPDATE_OWN,
            Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN,
            Permission.NOTIFICATION_DISPATCH_SYSTEM,
            Permission.DASHBOARD_VIEW_DEPT,
            Permission.DASHBOARD_VIEW_GLOBAL,
            Permission.ANALYTICS_VIEW_DEPT,
            Permission.ANALYTICS_VIEW_GLOBAL,
            Permission.OPERATIONS_METRICS_READ_DEPT,
            Permission.OPERATIONS_METRICS_READ_GLOBAL,
            Permission.REPORT_EXPORT_DEPT,
            Permission.REPORT_EXPORT_GLOBAL,
            Permission.HEALTH_VIEW_DETAILED,
            Permission.OPERATIONAL_ALERT_MANAGE,
        }
    ),
}

# Roles that a Department Administrator is permitted to assign.
# Escalation guard: DEPT_ADMIN cannot grant DEPT_ADMIN or SUPER_ADMIN.
DEPT_ADMIN_ASSIGNABLE_ROLES: Final[frozenset[RoleCode]] = frozenset(
    {
        RoleCode.STUDENT,
        RoleCode.STAFF,
        RoleCode.INVESTIGATOR,
    }
)


def get_role_permissions(role: RoleCode | str) -> frozenset[Permission]:
    """Return granted permissions for ``role``.

    Denies by default: returns an empty frozenset for any unknown or malformed role.
    """
    try:
        role_enum = role if isinstance(role, RoleCode) else RoleCode(str(role))
        return ROLE_PERMISSIONS.get(role_enum, frozenset())
    except (ValueError, KeyError):
        return frozenset()


def has_permission(role: RoleCode | str, permission: Permission | str) -> bool:
    """Return True if ``role`` possesses ``permission``. Denies by default."""
    try:
        perm_enum = (
            permission if isinstance(permission, Permission) else Permission(str(permission))
        )
    except ValueError:
        return False
    return perm_enum in get_role_permissions(role)


def has_any_permission(role: RoleCode | str, permissions: Iterable[Permission | str]) -> bool:
    """Return True if ``role`` possesses at least one of the specified permissions."""
    granted = get_role_permissions(role)
    for p in permissions:
        try:
            perm_enum = p if isinstance(p, Permission) else Permission(str(p))
            if perm_enum in granted:
                return True
        except ValueError:
            continue
    return False


def has_all_permissions(role: RoleCode | str, permissions: Iterable[Permission | str]) -> bool:
    """Return True if ``role`` possesses all specified permissions."""
    granted = get_role_permissions(role)
    for p in permissions:
        try:
            perm_enum = p if isinstance(p, Permission) else Permission(str(p))
            if perm_enum not in granted:
                return False
        except ValueError:
            return False
    return True
