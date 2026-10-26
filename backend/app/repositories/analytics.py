"""Analytics and aggregate statistics repository (Phases 96 & 97).

Enforces:
- Strict department and tenant scoping on every aggregation query.
- SQL-side aggregations using `func.count` and `func.date_trunc` to avoid loading raw datasets into memory.
- Pure dictionary return values ensuring complete layer isolation (no imports from `schemas`).
- Consistent UTC time-series intervals and handling of empty result sets.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.ai import AIJobStatus, SegmentReviewStatus
from backend.app.core.analytics import TimeBucket
from backend.app.core.case import TERMINAL_CASE_STATUSES
from backend.app.core.identity import RoleCode
from backend.app.core.notification import DeliveryStatus
from backend.app.models.ai import AIAnalysisJob, AICandidateSegment
from backend.app.models.case import Case, CaseEscalation
from backend.app.models.department import Department
from backend.app.models.incident import Incident
from backend.app.models.notification import Notification, NotificationDeliveryAttempt
from backend.app.models.role import Role
from backend.app.models.user import User


class AnalyticsRepository:
    """Async database repository for analytical metric aggregations and time-series trends."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # =========================================================================
    # Phase 96: Incident Analytics
    # =========================================================================

    async def get_incident_analytics(
        self,
        start_date: datetime,
        end_date: datetime,
        bucket: TimeBucket,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate incident statistics across categories, severities, statuses, and time buckets."""
        # 1. Total incidents
        stmt_total = select(func.count(Incident.id)).where(
            Incident.created_at >= start_date,
            Incident.created_at <= end_date,
        )
        if department_id is not None:
            stmt_total = stmt_total.where(Incident.department_id == department_id)
        res_total = await self.session.execute(stmt_total)
        total_incidents = int(res_total.scalar_one_or_none() or 0)

        # 2. By Category
        stmt_cat = (
            select(Incident.category, func.count(Incident.id))
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
            .group_by(Incident.category)
        )
        if department_id is not None:
            stmt_cat = stmt_cat.where(Incident.department_id == department_id)
        res_cat = await self.session.execute(stmt_cat)
        incidents_by_category = {str(row[0]): int(row[1]) for row in res_cat.all()}

        # 3. By Severity
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

        # 4. By Status
        stmt_stat = (
            select(Incident.status, func.count(Incident.id))
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
            .group_by(Incident.status)
        )
        if department_id is not None:
            stmt_stat = stmt_stat.where(Incident.department_id == department_id)
        res_stat = await self.session.execute(stmt_stat)
        incidents_by_status = {str(row[0]): int(row[1]) for row in res_stat.all()}

        # 5. By Department
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

        # 6. Time Series Histogram
        trunc_unit = bucket.value  # 'day', 'week', 'month'
        time_col = func.date_trunc(trunc_unit, Incident.created_at)
        stmt_ts = (
            select(time_col, func.count(Incident.id))
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
            .group_by(time_col)
            .order_by(time_col.asc())
        )
        if department_id is not None:
            stmt_ts = stmt_ts.where(Incident.department_id == department_id)
        res_ts = await self.session.execute(stmt_ts)

        bucket_duration = (
            timedelta(days=1)
            if bucket == TimeBucket.DAY
            else timedelta(days=7)
            if bucket == TimeBucket.WEEK
            else timedelta(days=30)
        )
        time_series: list[dict[str, Any]] = []
        for row in res_ts.all():
            b_start = row[0]
            if b_start.tzinfo is None:
                b_start = b_start.replace(tzinfo=UTC)
            b_end = b_start + bucket_duration
            time_series.append(
                {
                    "bucket_start": b_start,
                    "bucket_end": b_end,
                    "count": int(row[1]),
                }
            )

        return {
            "total_incidents": total_incidents,
            "incidents_by_category": incidents_by_category,
            "incidents_by_severity": incidents_by_severity,
            "incidents_by_status": incidents_by_status,
            "incidents_by_department": incidents_by_department,
            "time_series": time_series,
            "avg_resolution_hours": None,
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }

    # =========================================================================
    # Phase 96: Case Analytics
    # =========================================================================

    async def get_case_analytics(
        self,
        start_date: datetime,
        end_date: datetime,
        bucket: TimeBucket,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate investigation case analytics and status trends."""
        # 1. Total cases
        stmt_total = select(func.count(Case.id)).where(
            Case.created_at >= start_date,
            Case.created_at <= end_date,
        )
        if department_id is not None:
            stmt_total = stmt_total.where(Case.department_id == department_id)
        res_total = await self.session.execute(stmt_total)
        total_cases = int(res_total.scalar_one_or_none() or 0)

        # 2. By Status
        stmt_stat = (
            select(Case.status, func.count(Case.id))
            .where(
                Case.created_at >= start_date,
                Case.created_at <= end_date,
            )
            .group_by(Case.status)
        )
        if department_id is not None:
            stmt_stat = stmt_stat.where(Case.department_id == department_id)
        res_stat = await self.session.execute(stmt_stat)
        cases_by_status = {str(row[0]): int(row[1]) for row in res_stat.all()}

        # 3. By Priority
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

        # 4. By Escalation
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

        # 5. Active & Closed counts
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

        closed_cases_count = cases_by_status.get("closed", 0)

        # 6. Time Series
        trunc_unit = bucket.value
        time_col = func.date_trunc(trunc_unit, Case.created_at)
        stmt_ts = (
            select(time_col, func.count(Case.id))
            .where(
                Case.created_at >= start_date,
                Case.created_at <= end_date,
            )
            .group_by(time_col)
            .order_by(time_col.asc())
        )
        if department_id is not None:
            stmt_ts = stmt_ts.where(Case.department_id == department_id)
        res_ts = await self.session.execute(stmt_ts)

        bucket_duration = (
            timedelta(days=1)
            if bucket == TimeBucket.DAY
            else timedelta(days=7)
            if bucket == TimeBucket.WEEK
            else timedelta(days=30)
        )
        time_series: list[dict[str, Any]] = []
        for row in res_ts.all():
            b_start = row[0]
            if b_start.tzinfo is None:
                b_start = b_start.replace(tzinfo=UTC)
            b_end = b_start + bucket_duration
            time_series.append(
                {
                    "bucket_start": b_start,
                    "bucket_end": b_end,
                    "count": int(row[1]),
                }
            )

        return {
            "total_cases": total_cases,
            "cases_by_status": cases_by_status,
            "cases_by_priority": cases_by_priority,
            "cases_by_escalation": cases_by_escalation,
            "active_investigations_count": active_investigations_count,
            "closed_cases_count": closed_cases_count,
            "time_series": time_series,
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }

    # =========================================================================
    # Phase 96: Human Review Outcome Analytics
    # =========================================================================

    async def get_review_outcome_analytics(
        self,
        start_date: datetime,
        end_date: datetime,
        bucket: TimeBucket,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate human review outcomes, acceptance rates, and false-positive reasons."""
        stmt_base = select(
            AICandidateSegment.review_status,
            func.count(AICandidateSegment.id),
        ).where(
            AICandidateSegment.created_at >= start_date,
            AICandidateSegment.created_at <= end_date,
        )
        if department_id is not None:
            stmt_base = stmt_base.where(AICandidateSegment.department_id == department_id)
        stmt_base = stmt_base.group_by(AICandidateSegment.review_status)
        res_status = await self.session.execute(stmt_base)

        reviews_by_status = {str(row[0]): int(row[1]) for row in res_status.all()}
        total_reviews = sum(reviews_by_status.values())

        accepted = reviews_by_status.get(SegmentReviewStatus.CONFIRMED.value, 0)
        rejected = reviews_by_status.get(SegmentReviewStatus.REJECTED.value, 0)
        completed_reviews = accepted + rejected

        acceptance_rate = round(accepted / completed_reviews, 4) if completed_reviews > 0 else 0.0
        rejection_rate = round(rejected / completed_reviews, 4) if completed_reviews > 0 else 0.0

        # False positive reasons
        stmt_fp = (
            select(
                AICandidateSegment.false_positive_reason,
                func.count(AICandidateSegment.id),
            )
            .where(
                AICandidateSegment.created_at >= start_date,
                AICandidateSegment.created_at <= end_date,
                AICandidateSegment.false_positive_reason.isnot(None),
            )
            .group_by(AICandidateSegment.false_positive_reason)
        )
        if department_id is not None:
            stmt_fp = stmt_fp.where(AICandidateSegment.department_id == department_id)
        res_fp = await self.session.execute(stmt_fp)
        false_positive_reasons = {str(row[0]): int(row[1]) for row in res_fp.all()}

        # Time series of completed reviews
        trunc_unit = bucket.value
        time_col = func.date_trunc(trunc_unit, AICandidateSegment.reviewed_at)
        stmt_ts = (
            select(time_col, func.count(AICandidateSegment.id))
            .where(
                AICandidateSegment.reviewed_at.isnot(None),
                AICandidateSegment.reviewed_at >= start_date,
                AICandidateSegment.reviewed_at <= end_date,
            )
            .group_by(time_col)
            .order_by(time_col.asc())
        )
        if department_id is not None:
            stmt_ts = stmt_ts.where(AICandidateSegment.department_id == department_id)
        res_ts = await self.session.execute(stmt_ts)

        bucket_duration = (
            timedelta(days=1)
            if bucket == TimeBucket.DAY
            else timedelta(days=7)
            if bucket == TimeBucket.WEEK
            else timedelta(days=30)
        )
        time_series: list[dict[str, Any]] = []
        for row in res_ts.all():
            b_start = row[0]
            if b_start.tzinfo is None:
                b_start = b_start.replace(tzinfo=UTC)
            b_end = b_start + bucket_duration
            time_series.append(
                {
                    "bucket_start": b_start,
                    "bucket_end": b_end,
                    "count": int(row[1]),
                }
            )

        return {
            "total_reviews": total_reviews,
            "reviews_by_status": reviews_by_status,
            "acceptance_rate": acceptance_rate,
            "rejection_rate": rejection_rate,
            "false_positive_reasons": false_positive_reasons,
            "time_series": time_series,
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }

    # =========================================================================
    # Phase 97: Reviewer Workload Metrics
    # =========================================================================

    async def get_reviewer_workload(
        self,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate active case assignments and review workloads across authorized reviewers."""
        # 1. Fetch relevant reviewers (Investigators and Dept Admins)
        stmt_users = (
            select(User)
            .join(Role, User.role_id == Role.id)
            .where(
                Role.code.in_([RoleCode.INVESTIGATOR.value, RoleCode.DEPT_ADMIN.value]),
                User.is_active.is_(True),
            )
        )
        if department_id is not None:
            stmt_users = stmt_users.where(User.department_id == department_id)
        res_users = await self.session.execute(stmt_users)
        reviewers_list = list(res_users.scalars().all())

        terminal_case_vals = [s.value for s in TERMINAL_CASE_STATUSES]

        reviewers_metrics: list[dict[str, Any]] = []
        for user in reviewers_list:
            # Active cases where user is lead investigator
            stmt_cases = select(func.count(Case.id)).where(
                Case.lead_investigator_id == user.id,
                Case.status.notin_(terminal_case_vals),
            )
            res_c = await self.session.execute(stmt_cases)
            active_cases_count = int(res_c.scalar_one_or_none() or 0)

            # Assigned open incidents
            stmt_inc = select(func.count(Incident.id)).where(
                Incident.assigned_reviewer_id == user.id,
                Incident.status.notin_(["closed", "rejected"]),
            )
            res_i = await self.session.execute(stmt_inc)
            assigned_incidents_count = int(res_i.scalar_one_or_none() or 0)

            # Completed AI segment reviews
            stmt_segs_done = select(func.count(AICandidateSegment.id)).where(
                AICandidateSegment.reviewed_by_id == user.id,
            )
            res_sd = await self.session.execute(stmt_segs_done)
            completed_ai_segment_reviews_count = int(res_sd.scalar_one_or_none() or 0)

            # Pending reviews in user's department
            stmt_segs_pend = select(func.count(AICandidateSegment.id)).where(
                AICandidateSegment.department_id == user.department_id,
                AICandidateSegment.review_status == SegmentReviewStatus.PENDING_REVIEW.value,
            )
            res_sp = await self.session.execute(stmt_segs_pend)
            pending_ai_segment_reviews_count = int(res_sp.scalar_one_or_none() or 0)

            reviewers_metrics.append(
                {
                    "reviewer_id": user.id,
                    "reviewer_name": user.full_name,
                    "reviewer_email": user.email,
                    "department_id": user.department_id,
                    "active_cases_count": active_cases_count,
                    "assigned_incidents_count": assigned_incidents_count,
                    "completed_case_reviews_count": active_cases_count,
                    "completed_ai_segment_reviews_count": completed_ai_segment_reviews_count,
                    "pending_ai_segment_reviews_count": pending_ai_segment_reviews_count,
                }
            )

        # Unassigned counts
        stmt_unassigned_inc = select(func.count(Incident.id)).where(
            Incident.assigned_reviewer_id.is_(None),
            Incident.status.notin_(["closed", "rejected"]),
        )
        if department_id is not None:
            stmt_unassigned_inc = stmt_unassigned_inc.where(Incident.department_id == department_id)
        res_u_inc = await self.session.execute(stmt_unassigned_inc)
        unassigned_incidents_count = int(res_u_inc.scalar_one_or_none() or 0)

        stmt_unassigned_case = select(func.count(Case.id)).where(
            Case.lead_investigator_id.is_(None),
            Case.status.notin_(terminal_case_vals),
        )
        if department_id is not None:
            stmt_unassigned_case = stmt_unassigned_case.where(Case.department_id == department_id)
        res_u_case = await self.session.execute(stmt_unassigned_case)
        unassigned_cases_count = int(res_u_case.scalar_one_or_none() or 0)

        return {
            "reviewers": reviewers_metrics,
            "total_reviewers": len(reviewers_metrics),
            "unassigned_incidents_count": unassigned_incidents_count,
            "unassigned_cases_count": unassigned_cases_count,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }

    # =========================================================================
    # Phase 97: Background Processing Metrics
    # =========================================================================

    async def get_background_processing_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Aggregate background worker throughput, processing durations, and failure tallies."""
        # 1. AI Jobs metrics
        stmt_ai = select(
            AIAnalysisJob.status,
            func.count(AIAnalysisJob.id),
        ).where(
            AIAnalysisJob.created_at >= start_date,
            AIAnalysisJob.created_at <= end_date,
        )
        if department_id is not None:
            stmt_ai = stmt_ai.where(AIAnalysisJob.department_id == department_id)
        stmt_ai = stmt_ai.group_by(AIAnalysisJob.status)
        res_ai = await self.session.execute(stmt_ai)

        ai_status_counts = {str(row[0]): int(row[1]) for row in res_ai.all()}
        total_logical_jobs = sum(ai_status_counts.values())

        pending_count = ai_status_counts.get(AIJobStatus.QUEUED.value, 0)
        running_count = ai_status_counts.get(AIJobStatus.RUNNING.value, 0)
        completed_count = ai_status_counts.get(AIJobStatus.SUCCEEDED.value, 0)
        failed_count = ai_status_counts.get(AIJobStatus.FAILED.value, 0)
        cancelled_count = ai_status_counts.get(AIJobStatus.CANCELLED.value, 0)

        terminal_jobs = completed_count + failed_count
        completion_rate = round(completed_count / terminal_jobs, 4) if terminal_jobs > 0 else 0.0
        failure_rate = round(failed_count / terminal_jobs, 4) if terminal_jobs > 0 else 0.0

        # Retry attempts count
        stmt_retries = select(func.sum(AIAnalysisJob.retry_count)).where(
            AIAnalysisJob.created_at >= start_date,
            AIAnalysisJob.created_at <= end_date,
        )
        if department_id is not None:
            stmt_retries = stmt_retries.where(AIAnalysisJob.department_id == department_id)
        res_retries = await self.session.execute(stmt_retries)
        retry_attempts_count = int(res_retries.scalar_one_or_none() or 0)

        # Stale running count (running for > 3600 seconds)
        stale_cutoff = datetime.now(UTC) - timedelta(seconds=3600)
        stmt_stale = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.status == AIJobStatus.RUNNING.value,
            AIAnalysisJob.started_at.isnot(None),
            AIAnalysisJob.started_at <= stale_cutoff,
        )
        if department_id is not None:
            stmt_stale = stmt_stale.where(AIAnalysisJob.department_id == department_id)
        res_stale = await self.session.execute(stmt_stale)
        stale_running_count = int(res_stale.scalar_one_or_none() or 0)

        # Processing durations for completed jobs
        # Calculate in Python from fetched completed records in time window
        stmt_completed = (
            select(AIAnalysisJob.started_at, AIAnalysisJob.completed_at, AIAnalysisJob.created_at)
            .where(
                AIAnalysisJob.created_at >= start_date,
                AIAnalysisJob.created_at <= end_date,
                AIAnalysisJob.status == AIJobStatus.SUCCEEDED.value,
                AIAnalysisJob.started_at.isnot(None),
                AIAnalysisJob.completed_at.isnot(None),
            )
            .limit(1000)
        )
        if department_id is not None:
            stmt_completed = stmt_completed.where(AIAnalysisJob.department_id == department_id)
        res_comp = await self.session.execute(stmt_completed)

        durations: list[float] = []
        queue_waits: list[float] = []
        for s_at, c_at, cr_at in res_comp.all():
            if c_at and s_at:
                dur = (c_at - s_at).total_seconds()
                if dur >= 0:
                    durations.append(dur)
            if s_at and cr_at:
                wait = (s_at - cr_at).total_seconds()
                if wait >= 0:
                    queue_waits.append(wait)

        durations.sort()
        avg_processing_duration_seconds = (
            round(sum(durations) / len(durations), 2) if durations else None
        )
        p95_processing_duration_seconds = (
            round(durations[int(len(durations) * 0.95)], 2) if durations else None
        )
        avg_queue_wait_seconds = (
            round(sum(queue_waits) / len(queue_waits), 2) if queue_waits else None
        )

        ai_jobs_metrics = {
            "total_logical_jobs": total_logical_jobs,
            "pending_count": pending_count,
            "running_count": running_count,
            "completed_count": completed_count,
            "failed_count": failed_count,
            "cancelled_count": cancelled_count,
            "retry_attempts_count": retry_attempts_count,
            "completion_rate": completion_rate,
            "failure_rate": failure_rate,
            "avg_processing_duration_seconds": avg_processing_duration_seconds,
            "p95_processing_duration_seconds": p95_processing_duration_seconds,
            "avg_queue_wait_seconds": avg_queue_wait_seconds,
            "stale_running_count": stale_running_count,
        }

        # 2. Notification metrics
        stmt_notif_total = select(func.count(Notification.id)).where(
            Notification.created_at >= start_date,
            Notification.created_at <= end_date,
        )
        if department_id is not None:
            stmt_notif_total = stmt_notif_total.where(Notification.department_id == department_id)
        res_n_tot = await self.session.execute(stmt_notif_total)
        total_logical_notifications = int(res_n_tot.scalar_one_or_none() or 0)

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
        res_n_stat = await self.session.execute(stmt_notif_status)
        n_status_counts = {str(row[0]): int(row[1]) for row in res_n_stat.all()}

        delivered_count = n_status_counts.get(DeliveryStatus.DELIVERED.value, 0)
        notif_failed_count = n_status_counts.get(DeliveryStatus.FAILED.value, 0)
        notif_pending_count = n_status_counts.get(DeliveryStatus.PENDING.value, 0)
        retry_exhausted_count = n_status_counts.get("permanent_failure", 0)

        # Delivery attempts
        stmt_att = (
            select(func.count(NotificationDeliveryAttempt.id))
            .join(Notification, NotificationDeliveryAttempt.notification_id == Notification.id)
            .where(
                NotificationDeliveryAttempt.attempted_at >= start_date,
                NotificationDeliveryAttempt.attempted_at <= end_date,
            )
        )
        if department_id is not None:
            stmt_att = stmt_att.where(Notification.department_id == department_id)
        res_att = await self.session.execute(stmt_att)
        total_delivery_attempts = int(res_att.scalar_one_or_none() or 0)

        terminal_deliveries = delivered_count + notif_failed_count + retry_exhausted_count
        delivery_success_rate = (
            round(delivered_count / terminal_deliveries, 4) if terminal_deliveries > 0 else 0.0
        )

        notification_metrics = {
            "total_logical_notifications": total_logical_notifications,
            "total_delivery_attempts": total_delivery_attempts,
            "delivered_count": delivered_count,
            "failed_count": notif_failed_count,
            "pending_count": notif_pending_count,
            "retry_exhausted_count": retry_exhausted_count,
            "delivery_success_rate": delivery_success_rate,
        }

        return {
            "ai_jobs": ai_jobs_metrics,
            "notifications": notification_metrics,
            "observation_window_start": start_date,
            "observation_window_end": end_date,
            "department_id": department_id,
            "generated_at": datetime.now(UTC),
        }
