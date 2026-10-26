"""Dashboard repository for operational metric aggregations (Phase 95).

Enforces:
- Strict department and tenant scoping.
- Bounded time queries with UTC normalization.
- Aggregation via SQL group-by queries to avoid high memory allocations.
- Read-only data access.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.case import TERMINAL_CASE_STATUSES
from backend.app.core.notification import DeliveryStatus
from backend.app.models.ai import AIAnalysisJob
from backend.app.models.case import Case, CaseEscalation
from backend.app.models.department import Department
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.incident import Incident
from backend.app.models.notification import Notification, NotificationDeliveryAttempt


class DashboardRepository:
    """Async database repository for aggregated dashboard queries."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_incident_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate incident metrics across status, severity, and departments."""
        # 1. Total incidents
        stmt_total = select(func.count(Incident.id)).where(
            Incident.created_at >= start_date,
            Incident.created_at <= end_date,
        )
        if department_id is not None:
            stmt_total = stmt_total.where(Incident.department_id == department_id)
        total_res = await self.session.execute(stmt_total)
        total_incidents = int(total_res.scalar_one_or_none() or 0)

        # 2. Incidents by status
        stmt_status = (
            select(Incident.status, func.count(Incident.id))
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
            .group_by(Incident.status)
        )
        if department_id is not None:
            stmt_status = stmt_status.where(Incident.department_id == department_id)
        res_status = await self.session.execute(stmt_status)
        incidents_by_status = {str(row[0]): int(row[1]) for row in res_status.all()}

        # 3. Incidents by severity
        stmt_sev = (
            select(Incident.severity, func.count(Incident.id))
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
            .group_by(Incident.severity)
        )
        if department_id is not None:
            stmt_sev = stmt_sev.where(Incident.department_id == department_id)
        res_sev = await self.session.execute(stmt_sev)
        incidents_by_severity = {str(row[0]): int(row[1]) for row in res_sev.all()}

        # 4. Incidents by department
        stmt_dept = (
            select(Department.name, func.count(Incident.id))
            .join(Department, Incident.department_id == Department.id)
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
            .group_by(Department.name)
        )
        if department_id is not None:
            stmt_dept = stmt_dept.where(Incident.department_id == department_id)
        res_dept = await self.session.execute(stmt_dept)
        incidents_by_department = {str(row[0]): int(row[1]) for row in res_dept.all()}

        # 5. Evidence attachments total
        stmt_ev = (
            select(func.count(EvidenceAttachment.id))
            .join(Incident, EvidenceAttachment.incident_id == Incident.id)
            .where(
                EvidenceAttachment.created_at >= start_date,
                EvidenceAttachment.created_at <= end_date,
            )
        )
        if department_id is not None:
            stmt_ev = stmt_ev.where(Incident.department_id == department_id)
        res_ev = await self.session.execute(stmt_ev)
        total_evidence_items = int(res_ev.scalar_one_or_none() or 0)

        return {
            "total_incidents": total_incidents,
            "incidents_by_status": incidents_by_status,
            "incidents_by_severity": incidents_by_severity,
            "incidents_by_department": incidents_by_department,
            "total_evidence_items": total_evidence_items,
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }

    async def get_case_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate case metrics across status, priority, and escalations."""
        # 1. Total cases
        stmt_total = select(func.count(Case.id)).where(
            Case.created_at >= start_date,
            Case.created_at <= end_date,
        )
        if department_id is not None:
            stmt_total = stmt_total.where(Case.department_id == department_id)
        res_total = await self.session.execute(stmt_total)
        total_cases = int(res_total.scalar_one_or_none() or 0)

        # 2. Cases by status
        stmt_status = (
            select(Case.status, func.count(Case.id))
            .where(
                Case.created_at >= start_date,
                Case.created_at <= end_date,
            )
            .group_by(Case.status)
        )
        if department_id is not None:
            stmt_status = stmt_status.where(Case.department_id == department_id)
        res_status = await self.session.execute(stmt_status)
        cases_by_status = {str(row[0]): int(row[1]) for row in res_status.all()}

        # 3. Cases by priority
        stmt_prio = (
            select(Case.priority, func.count(Case.id))
            .where(
                Case.created_at >= start_date,
                Case.created_at <= end_date,
            )
            .group_by(Case.priority)
        )
        if department_id is not None:
            stmt_prio = stmt_prio.where(Case.department_id == department_id)
        res_prio = await self.session.execute(stmt_prio)
        cases_by_priority = {str(row[0]): int(row[1]) for row in res_prio.all()}

        # 4. Cases by escalation
        stmt_esc = (
            select(CaseEscalation.escalation_level, func.count(CaseEscalation.id))
            .join(Case, CaseEscalation.case_id == Case.id)
            .where(
                CaseEscalation.created_at >= start_date,
                CaseEscalation.created_at <= end_date,
            )
            .group_by(CaseEscalation.escalation_level)
        )
        if department_id is not None:
            stmt_esc = stmt_esc.where(Case.department_id == department_id)
        res_esc = await self.session.execute(stmt_esc)
        cases_by_escalation = {str(row[0]): int(row[1]) for row in res_esc.all()}

        # 5. Active investigations
        terminal_status_vals = [s.value for s in TERMINAL_CASE_STATUSES]
        stmt_active = select(func.count(Case.id)).where(
            Case.created_at >= start_date,
            Case.created_at <= end_date,
            Case.status.notin_(terminal_status_vals),
        )
        if department_id is not None:
            stmt_active = stmt_active.where(Case.department_id == department_id)
        res_active = await self.session.execute(stmt_active)
        active_investigations_count = int(res_active.scalar_one_or_none() or 0)

        # 6. Legal hold cases
        stmt_lh = select(func.count(Case.id)).where(
            Case.created_at >= start_date,
            Case.created_at <= end_date,
            Case.is_legal_hold.is_(True),
        )
        if department_id is not None:
            stmt_lh = stmt_lh.where(Case.department_id == department_id)
        res_lh = await self.session.execute(stmt_lh)
        legal_hold_cases_count = int(res_lh.scalar_one_or_none() or 0)

        return {
            "total_cases": total_cases,
            "cases_by_status": cases_by_status,
            "cases_by_priority": cases_by_priority,
            "cases_by_escalation": cases_by_escalation,
            "active_investigations_count": active_investigations_count,
            "legal_hold_cases_count": legal_hold_cases_count,
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }

    async def get_operations_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate operational metrics for AI jobs and notification delivery."""
        # 1. AI Jobs
        stmt_ai_total = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.created_at >= start_date,
            AIAnalysisJob.created_at <= end_date,
        )
        if department_id is not None:
            stmt_ai_total = stmt_ai_total.where(AIAnalysisJob.department_id == department_id)
        res_ai_total = await self.session.execute(stmt_ai_total)
        ai_jobs_total = int(res_ai_total.scalar_one_or_none() or 0)

        stmt_ai_status = (
            select(AIAnalysisJob.status, func.count(AIAnalysisJob.id))
            .where(
                AIAnalysisJob.created_at >= start_date,
                AIAnalysisJob.created_at <= end_date,
            )
            .group_by(AIAnalysisJob.status)
        )
        if department_id is not None:
            stmt_ai_status = stmt_ai_status.where(AIAnalysisJob.department_id == department_id)
        res_ai_status = await self.session.execute(stmt_ai_status)
        ai_jobs_by_status = {str(row[0]): int(row[1]) for row in res_ai_status.all()}

        stmt_ai_step = (
            select(AIAnalysisJob.current_step, func.count(AIAnalysisJob.id))
            .where(
                AIAnalysisJob.created_at >= start_date,
                AIAnalysisJob.created_at <= end_date,
            )
            .group_by(AIAnalysisJob.current_step)
        )
        if department_id is not None:
            stmt_ai_step = stmt_ai_step.where(AIAnalysisJob.department_id == department_id)
        res_ai_step = await self.session.execute(stmt_ai_step)
        ai_jobs_by_task_type = {str(row[0]): int(row[1]) for row in res_ai_step.all()}

        # 2. Notifications
        stmt_notif_total = select(func.count(Notification.id)).where(
            Notification.created_at >= start_date,
            Notification.created_at <= end_date,
        )
        if department_id is not None:
            stmt_notif_total = stmt_notif_total.where(Notification.department_id == department_id)
        res_notif_total = await self.session.execute(stmt_notif_total)
        notifications_total = int(res_notif_total.scalar_one_or_none() or 0)

        stmt_notif_chan = (
            select(Notification.channel, func.count(Notification.id))
            .where(
                Notification.created_at >= start_date,
                Notification.created_at <= end_date,
            )
            .group_by(Notification.channel)
        )
        if department_id is not None:
            stmt_notif_chan = stmt_notif_chan.where(Notification.department_id == department_id)
        res_notif_chan = await self.session.execute(stmt_notif_chan)
        notifications_by_channel = {str(row[0]): int(row[1]) for row in res_notif_chan.all()}

        stmt_notif_status = (
            select(Notification.delivery_status, func.count(Notification.id))
            .where(
                Notification.created_at >= start_date,
                Notification.created_at <= end_date,
            )
            .group_by(Notification.delivery_status)
        )
        if department_id is not None:
            stmt_notif_status = stmt_notif_status.where(Notification.department_id == department_id)
        res_notif_status = await self.session.execute(stmt_notif_status)
        notifications_by_status = {str(row[0]): int(row[1]) for row in res_notif_status.all()}

        # 3. Delivery attempts
        stmt_att_total = (
            select(func.count(NotificationDeliveryAttempt.id))
            .join(
                Notification,
                NotificationDeliveryAttempt.notification_id == Notification.id,
            )
            .where(
                NotificationDeliveryAttempt.attempted_at >= start_date,
                NotificationDeliveryAttempt.attempted_at <= end_date,
            )
        )
        if department_id is not None:
            stmt_att_total = stmt_att_total.where(Notification.department_id == department_id)
        res_att_total = await self.session.execute(stmt_att_total)
        delivery_attempts_total = int(res_att_total.scalar_one_or_none() or 0)

        stmt_att_fail = (
            select(func.count(NotificationDeliveryAttempt.id))
            .join(
                Notification,
                NotificationDeliveryAttempt.notification_id == Notification.id,
            )
            .where(
                NotificationDeliveryAttempt.attempted_at >= start_date,
                NotificationDeliveryAttempt.attempted_at <= end_date,
                NotificationDeliveryAttempt.status == DeliveryStatus.FAILED.value,
            )
        )
        if department_id is not None:
            stmt_att_fail = stmt_att_fail.where(Notification.department_id == department_id)
        res_att_fail = await self.session.execute(stmt_att_fail)
        delivery_failures_total = int(res_att_fail.scalar_one_or_none() or 0)

        return {
            "ai_jobs_total": ai_jobs_total,
            "ai_jobs_by_status": ai_jobs_by_status,
            "ai_jobs_by_task_type": ai_jobs_by_task_type,
            "notifications_total": notifications_total,
            "notifications_by_channel": notifications_by_channel,
            "notifications_by_status": notifications_by_status,
            "delivery_attempts_total": delivery_attempts_total,
            "delivery_failures_total": delivery_failures_total,
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }
