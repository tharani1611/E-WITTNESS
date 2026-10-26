"""Domain primitives, actions, and cryptographic hash chaining for security audit events (Phases 58-59).

Enforces:
- Canonical JSON serialization of security-critical actions and metadata.
- Monotonically sequence-checked, tamper-evident SHA-256 hash chaining.
- Strict isolation of sensitive data (no credentials, session tokens, or raw secrets).
- Statutory legal disclaimers distinguishing audit log immutability from host-level anchoring.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

AUDIT_DISCLAIMER: str = (
    "Cryptographic hash chaining detects historical alteration of security audit records; "
    "it does not prevent an attacker with full database administration privileges from "
    "re-signing an entire log unless checkpoints are externally and immutably anchored."
)


class AuditAction(StrEnum):
    """Canonical classification for security-relevant operational audit events (Phase 58)."""

    # Authentication & Access Control
    AUTH_LOGIN_SUCCESS = "auth:login:success"
    AUTH_LOGIN_FAILED = "auth:login:failed"
    AUTH_SESSION_REVOKED = "auth:session:revoked"
    SECURITY_ACCESS_DENIED = "security:access:denied"
    PRIVILEGED_ROLE_ASSIGNED = "privileged:role:assigned"

    # Incident Workflow & Routing
    INCIDENT_SUBMITTED = "incident:submitted"
    INCIDENT_STATUS_TRANSITION = "incident:status:transition"
    INCIDENT_ROUTING_OVERRIDE = "incident:routing:override"
    INCIDENT_ASSIGNED = "incident:reviewer:assigned"
    INCIDENT_REASSIGNED = "incident:reviewer:reassigned"
    INCIDENT_ACKNOWLEDGED = "incident:reviewer:acknowledged"
    REVIEWER_ASSIGNED = "incident:reviewer:assigned"
    REVIEWER_REASSIGNED = "incident:reviewer:reassigned"
    ASSIGNMENT_ACKNOWLEDGED = "incident:reviewer:acknowledged"

    # Evidence, Custody & Exports
    EVIDENCE_INGESTED = "evidence:ingested"
    EVIDENCE_INTEGRITY_VERIFIED = "evidence:integrity:verified"
    EVIDENCE_TAMPER_DETECTED = "evidence:tamper:detected"
    CUSTODY_COMPENSATING_CORRECTION = "custody:compensating:correction"
    EVIDENCE_ACCESS = "evidence:access"
    EVIDENCE_EXPORT = "evidence:export"
    EVIDENCE_EXPORTED = "evidence:export"

    # AI Violence Detection & Dataset Governance (Phases 61-65)
    AI_JOB_SUBMITTED = "ai:job:submitted"
    AI_JOB_STARTED = "ai:job:started"
    AI_JOB_COMPLETED = "ai:job:completed"
    AI_JOB_FAILED = "ai:job:failed"
    AI_JOB_CANCELLED = "ai:job:cancelled"
    AI_DATASET_REGISTERED = "ai:dataset:registered"
    AI_DATASET_REVIEWED = "ai:dataset:reviewed"
    AI_SEGMENT_REVIEWED = "ai:segment:reviewed"
    AI_RESULTS_PURGED = "ai:results:purged"

    # Biometric Privacy, Governance & Reference Registry (Phases 71-75)
    BIOMETRIC_POLICY_EVALUATED = "biometric:policy:evaluated"
    BIOMETRIC_NOTICE_ACKNOWLEDGED = "biometric:notice:acknowledged"
    BIOMETRIC_CONSENT_GRANTED = "biometric:consent:granted"
    BIOMETRIC_CONSENT_REVOKED = "biometric:consent:revoked"
    BIOMETRIC_REFERENCE_ENROLLED = "biometric:reference:enrolled"
    BIOMETRIC_REFERENCE_REVOKED = "biometric:reference:revoked"
    BIOMETRIC_REFERENCE_PURGED = "biometric:reference:purged"
    BIOMETRIC_DETECTION_EXECUTED = "biometric:detection:executed"
    BIOMETRIC_MATCHING_EXECUTED = "biometric:matching:executed"
    BIOMETRIC_QUALITY_FAILED = "biometric:quality:failed"
    BIOMETRIC_VERIFICATION_RECORDED = "biometric:verification:recorded"
    BIOMETRIC_KEY_ACCESSED = "biometric:key:accessed"
    BIOMETRIC_KEY_ROTATED = "biometric:key:rotated"

    # Investigation Case Management & Inventory (Phases 81-85)
    CASE_CREATED = "case:created"
    CASE_STATUS_TRANSITION = "case:status:transition"
    CASE_ASSIGNED = "case:assigned"
    CASE_REASSIGNED = "case:reassigned"
    CASE_INCIDENT_LINKED = "case:incident:linked"
    CASE_INCIDENT_UNLINKED = "case:incident:unlinked"
    CASE_EVIDENCE_LINKED = "case:evidence:linked"
    CASE_EVIDENCE_UNLINKED = "case:evidence:unlinked"
    CASE_AI_SEGMENT_LINKED = "case:ai_segment:linked"
    CASE_AI_SEGMENT_UNLINKED = "case:ai_segment:unlinked"
    CASE_AI_SEGMENT_REVIEWED = "case:ai_segment:reviewed"

    # Case Workflow, Collaborative Notes and Reporting (Phases 86-90)
    CASE_NOTE_CREATED = "case:note:created"
    CASE_NOTE_UPDATED = "case:note:updated"
    CASE_FINDING_CREATED = "case:finding:created"
    CASE_FINDING_UPDATED = "case:finding:updated"
    CASE_APPROVAL_RECORDED = "case:approval:recorded"
    CASE_ESCALATED = "case:escalated"
    CASE_REFERRED = "case:referred"
    CASE_CLOSED = "case:closed"
    CASE_REOPENED = "case:reopened"
    CASE_EXPORTED = "case:exported"

    # Notifications and Dashboards (Phases 91-95)
    NOTIFICATION_DISPATCHED = "notification:dispatched"
    NOTIFICATION_READ = "notification:read"
    NOTIFICATION_PREFERENCE_UPDATED = "notification:preference:updated"
    NOTIFICATION_DELIVERY_ATTEMPTED = "notification:delivery:attempted"
    NOTIFICATION_DELIVERY_FAILED = "notification:delivery:failed"
    DASHBOARD_ACCESSED = "dashboard:accessed"

    # Analytics, Reporting & Operational Monitoring (Phases 96-99)
    ANALYTICS_ACCESSED = "analytics:accessed"
    WORKLOAD_ACCESSED = "workload:accessed"
    REPORT_EXPORTED = "report:exported"
    REPORT_DOWNLOADED = "report:downloaded"
    HEALTH_DETAILED_ACCESSED = "health:detailed:accessed"
    OPERATIONAL_ALERT_TRIGGERED = "operational:alert:triggered"
    OPERATIONAL_ALERT_RESOLVED = "operational:alert:resolved"


class AuditTargetType(StrEnum):
    """Resource classification targets for security audit events."""

    INCIDENT = "incident"
    EVIDENCE = "evidence"
    USER = "user"
    DEPARTMENT = "department"
    SESSION = "session"
    SYSTEM = "system"
    AI_JOB = "ai_job"
    AI_DATASET = "ai_dataset"
    AI_SEGMENT = "ai_segment"
    BIOMETRIC_GOVERNANCE = "biometric_governance"
    BIOMETRIC_REFERENCE = "biometric_reference"
    BIOMETRIC_VERIFICATION = "biometric_verification"
    CASE = "case"
    NOTIFICATION = "notification"
    NOTIFICATION_PREFERENCE = "notification_preference"
    DASHBOARD = "dashboard"
    ANALYTICS = "analytics"
    WORKLOAD = "workload"
    REPORT = "report"
    HEALTH = "health"
    WORKER = "worker"
    OPERATIONAL_ALERT = "operational_alert"


class AuditOutcome(StrEnum):
    """Outcome verdict of an audited operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditFailClosedPolicy(StrEnum):
    """Policy governing system behavior upon security audit ledger failures."""

    FAIL_CLOSED = "fail_closed"
    FAIL_SAFE = "fail_safe"


def compute_security_audit_event_hash(
    *,
    sequence_number: int,
    action: str,
    actor_id: UUID | str | None,
    department_id: UUID | str | None,
    target_type: str,
    target_id: str,
    outcome: str,
    details: dict[str, Any] | str | None,
    previous_event_hash: str | None,
    created_at: datetime | str,
) -> str:
    """Calculate the deterministic SHA-256 digest of a security audit record.

    Ensures canonical key ordering and compact JSON formatting to prevent
    serialization discrepancies across environments and runtimes.
    """
    ts_str = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)

    details_obj: Any
    if isinstance(details, str):
        try:
            details_obj = json.loads(details)
        except Exception:
            details_obj = {"text": details}
    elif isinstance(details, dict):
        details_obj = details
    else:
        details_obj = {}

    canonical_payload = {
        "sequence_number": int(sequence_number),
        "action": str(action).strip().lower(),
        "actor_id": str(actor_id) if actor_id else None,
        "department_id": str(department_id) if department_id else None,
        "target_type": str(target_type).strip().lower(),
        "target_id": str(target_id).strip(),
        "outcome": str(outcome).strip().lower(),
        "details": details_obj,
        "previous_event_hash": str(previous_event_hash).strip().lower()
        if previous_event_hash
        else None,
        "created_at": ts_str,
    }

    serialized = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
