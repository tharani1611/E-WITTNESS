"""Controlled report export repository (Phase 98).

Enforces:
- Scoped data extraction for tabular report packages (incidents, cases, reviews, operational summary).
- Result size bounding (clamped to max 5000 records) to protect worker and database memory.
- Tracking and updating of persisted `ReportExport` records and download counts.
- Layer boundary compliance (no schema imports).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.analytics import MAX_EXPORT_ROWS
from backend.app.models.ai import AIAnalysisJob, AICandidateSegment
from backend.app.models.case import Case
from backend.app.models.department import Department
from backend.app.models.incident import Incident
from backend.app.models.notification import Notification
from backend.app.models.report import ReportExport


class ReportRepository:
    """Async database repository for report metadata and bounded data extraction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # =========================================================================
    # Report Export Metadata CRUD
    # =========================================================================

    async def create_report_export(self, export: ReportExport) -> ReportExport:
        """Persist a new ReportExport record."""
        self.session.add(export)
        await self.session.flush()
        return export

    async def get_report_export_by_id(self, export_id: UUID) -> ReportExport | None:
        """Fetch report export metadata by ID."""
        stmt = select(ReportExport).where(ReportExport.id == export_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def increment_download_count(self, export_id: UUID) -> None:
        """Atomically increment the download count for an export artifact."""
        stmt = (
            update(ReportExport)
            .where(ReportExport.id == export_id)
            .values(
                download_count=ReportExport.download_count + 1,
                updated_at=datetime.now(UTC),
            )
        )
        await self.session.execute(stmt)
        await self.session.flush()

    # =========================================================================
    # Data Extraction for Reports
    # =========================================================================

    async def fetch_incidents_for_export(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict[str, Any]]:
        """Fetch tabular incident rows scoped by date range and department."""
        stmt = (
            select(
                Incident.reference_number,
                Incident.title,
                Incident.category,
                Incident.severity,
                Incident.status,
                Incident.location,
                Incident.occurred_at,
                Incident.created_at,
                Department.name,
            )
            .join(Department, Incident.department_id == Department.id)
            .where(
                Incident.created_at >= start_date,
                Incident.created_at <= end_date,
            )
        )
        if department_id is not None:
            stmt = stmt.where(Incident.department_id == department_id)
        stmt = stmt.order_by(Incident.created_at.desc()).limit(min(limit, MAX_EXPORT_ROWS))
        result = await self.session.execute(stmt)

        rows: list[dict[str, Any]] = []
        for row in result.all():
            rows.append(
                {
                    "reference_number": row[0],
                    "title": row[1],
                    "category": row[2],
                    "severity": row[3],
                    "status": row[4],
                    "location": row[5],
                    "occurred_at": row[6].isoformat() if row[6] else "",
                    "created_at": row[7].isoformat() if row[7] else "",
                    "department": row[8],
                }
            )
        return rows

    async def fetch_cases_for_export(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict[str, Any]]:
        """Fetch tabular case rows scoped by date range and department."""
        stmt = (
            select(
                Case.reference_number,
                Case.title,
                Case.status,
                Case.priority,
                Case.is_legal_hold,
                Case.created_at,
                Case.updated_at,
                Department.name,
            )
            .join(Department, Case.department_id == Department.id)
            .where(
                Case.created_at >= start_date,
                Case.created_at <= end_date,
            )
        )
        if department_id is not None:
            stmt = stmt.where(Case.department_id == department_id)
        stmt = stmt.order_by(Case.created_at.desc()).limit(min(limit, MAX_EXPORT_ROWS))
        result = await self.session.execute(stmt)

        rows: list[dict[str, Any]] = []
        for row in result.all():
            rows.append(
                {
                    "reference_number": row[0],
                    "title": row[1],
                    "status": row[2],
                    "priority": row[3],
                    "is_legal_hold": str(row[4]),
                    "created_at": row[5].isoformat() if row[5] else "",
                    "updated_at": row[6].isoformat() if row[6] else "",
                    "department": row[7],
                }
            )
        return rows

    async def fetch_reviews_for_export(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict[str, Any]]:
        """Fetch human review records for AI candidate segments."""
        stmt = (
            select(
                AICandidateSegment.id,
                AICandidateSegment.job_id,
                AICandidateSegment.incident_id,
                AICandidateSegment.model_name,
                AICandidateSegment.raw_label,
                AICandidateSegment.raw_score,
                AICandidateSegment.calibrated_score,
                AICandidateSegment.review_status,
                AICandidateSegment.false_positive_reason,
                AICandidateSegment.reviewed_at,
                Department.name,
            )
            .join(Department, AICandidateSegment.department_id == Department.id)
            .where(
                AICandidateSegment.created_at >= start_date,
                AICandidateSegment.created_at <= end_date,
            )
        )
        if department_id is not None:
            stmt = stmt.where(AICandidateSegment.department_id == department_id)
        stmt = stmt.order_by(AICandidateSegment.created_at.desc()).limit(
            min(limit, MAX_EXPORT_ROWS)
        )
        result = await self.session.execute(stmt)

        rows: list[dict[str, Any]] = []
        for row in result.all():
            rows.append(
                {
                    "segment_id": str(row[0]),
                    "job_id": str(row[1]),
                    "incident_id": str(row[2]),
                    "model_name": row[3],
                    "raw_label": row[4],
                    "raw_score": f"{row[5]:.4f}" if row[5] is not None else "",
                    "calibrated_score": f"{row[6]:.4f}" if row[6] is not None else "",
                    "review_status": row[7],
                    "false_positive_reason": row[8] or "",
                    "reviewed_at": row[9].isoformat() if row[9] else "",
                    "department": row[10],
                }
            )
        return rows

    async def fetch_operational_summary_for_export(
        self,
        start_date: datetime,
        end_date: datetime,
        department_id: UUID | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch key operational metrics summary as exportable key-value rows."""
        # 1. Total incidents in range
        stmt_inc = select(func.count(Incident.id)).where(
            Incident.created_at >= start_date,
            Incident.created_at <= end_date,
        )
        if department_id is not None:
            stmt_inc = stmt_inc.where(Incident.department_id == department_id)
        r_inc = await self.session.execute(stmt_inc)
        total_inc = int(r_inc.scalar_one_or_none() or 0)

        # 2. Total cases
        stmt_case = select(func.count(Case.id)).where(
            Case.created_at >= start_date,
            Case.created_at <= end_date,
        )
        if department_id is not None:
            stmt_case = stmt_case.where(Case.department_id == department_id)
        r_case = await self.session.execute(stmt_case)
        total_cases = int(r_case.scalar_one_or_none() or 0)

        # 3. Total AI Jobs
        stmt_ai = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.created_at >= start_date,
            AIAnalysisJob.created_at <= end_date,
        )
        if department_id is not None:
            stmt_ai = stmt_ai.where(AIAnalysisJob.department_id == department_id)
        r_ai = await self.session.execute(stmt_ai)
        total_ai_jobs = int(r_ai.scalar_one_or_none() or 0)

        # 4. Total Notifications
        stmt_n = select(func.count(Notification.id)).where(
            Notification.created_at >= start_date,
            Notification.created_at <= end_date,
        )
        if department_id is not None:
            stmt_n = stmt_n.where(Notification.department_id == department_id)
        r_n = await self.session.execute(stmt_n)
        total_notifs = int(r_n.scalar_one_or_none() or 0)

        return [
            {"metric": "Report Start Date", "value": start_date.isoformat()},
            {"metric": "Report End Date", "value": end_date.isoformat()},
            {"metric": "Total Incidents Reported", "value": str(total_inc)},
            {"metric": "Total Investigation Cases", "value": str(total_cases)},
            {"metric": "Total AI Jobs Submitted", "value": str(total_ai_jobs)},
            {"metric": "Total System Notifications", "value": str(total_notifs)},
            {"metric": "Export Generated At", "value": datetime.now(UTC).isoformat()},
        ]
