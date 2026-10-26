"""Controlled report export domain service (Phase 98).

Enforces:
- Department scoping on report extraction (`REPORT_EXPORT_GLOBAL` vs `REPORT_EXPORT_DEPT`).
- CSV formula injection sanitization (prevention of spreadsheet formula execution).
- Pure-Python secure PDF generation without external HTTP requests or HTML/JS execution.
- Bounded row limits (clamped to max 5000 rows).
- SHA-256 cryptographic attestation on exported payloads.
- Re-authorization upon download and expiration enforcement.
- Append-only security audit logging for all exports and downloads.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.analytics import (
    MAX_EXPORT_ROWS,
    ReportFormat,
    ReportType,
    generate_pdf_report,
    sanitize_csv_cell,
)
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.models.report import ReportExport
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.report import ReportRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.report import ReportExportRead, ReportExportRequest


class ReportExportService:
    """Domain service for generating and securely downloading controlled CSV and PDF reports."""

    def __init__(
        self,
        report_repo: ReportRepository,
        audit_repo: AuditRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.report_repo = report_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(cls, session: AsyncSession, settings: Settings) -> ReportExportService:
        """Construct a ReportExportService wired with session repositories."""
        return cls(
            report_repo=ReportRepository(session),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    def _resolve_department_scope(
        self,
        principal: AuthenticatedPrincipal,
        requested_dept_id: UUID | None,
    ) -> UUID | None:
        """Enforce department scoping on report exports."""
        has_global = has_permission(principal.role, Permission.REPORT_EXPORT_GLOBAL)
        has_dept = has_permission(principal.role, Permission.REPORT_EXPORT_DEPT)

        if not has_global and not has_dept:
            raise PermissionDeniedError(
                "You do not possess permission to export system reports.",
                code="PERMISSION_DENIED",
            )

        if has_global:
            return requested_dept_id

        user_dept_id = principal.department_id
        if user_dept_id is None:
            raise PermissionDeniedError(
                "User has no assigned department for department-scoped export.",
                code="DEPARTMENT_REQUIRED",
            )

        if requested_dept_id is not None and requested_dept_id != user_dept_id:
            raise PermissionDeniedError(
                "Cross-department report export is strictly forbidden.",
                code="CROSS_DEPARTMENT_ACCESS_FORBIDDEN",
            )

        return user_dept_id

    async def _audit(
        self,
        principal: AuthenticatedPrincipal,
        action: AuditAction,
        target_id: str,
        details: dict[str, Any],
        department_id: UUID | None = None,
    ) -> None:
        """Record immutable append-only audit log entry."""
        if self.audit_repo is None:
            return
        await self.audit_repo.append_event(
            action=action.value,
            actor_id=principal.id,
            actor_role=principal.role,
            target_type=AuditTargetType.REPORT.value,
            target_id=target_id,
            outcome=AuditOutcome.SUCCESS.value,
            department_id=department_id or principal.department_id,
            details=details,
        )

    async def generate_report(
        self,
        principal: AuthenticatedPrincipal,
        request: ReportExportRequest,
    ) -> tuple[ReportExportRead, bytes, str, str]:
        """Generate a controlled report export, returning metadata, bytes, filename, and MIME type."""
        resolved_dept_id = self._resolve_department_scope(principal, request.department_id)
        if request.start_date is None or request.end_date is None:
            raise BusinessRuleError(
                "Report export date range must be specified.", code="INVALID_DATE_RANGE"
            )
        start_date = request.start_date
        end_date = request.end_date

        # 1. Fetch raw data based on report type
        headers: list[str] = []
        raw_rows: list[dict[str, Any]] = []
        title = ""

        if request.report_type == ReportType.INCIDENTS:
            title = "Incident Registry Report"
            headers = [
                "Reference Number",
                "Title",
                "Category",
                "Severity",
                "Status",
                "Location",
                "Occurred At",
                "Created At",
                "Department",
            ]
            raw_rows = await self.report_repo.fetch_incidents_for_export(
                start_date=start_date,
                end_date=end_date,
                department_id=resolved_dept_id,
                limit=MAX_EXPORT_ROWS,
            )
        elif request.report_type == ReportType.CASES:
            title = "Investigation Case Registry Report"
            headers = [
                "Reference Number",
                "Title",
                "Status",
                "Priority",
                "Legal Hold",
                "Created At",
                "Updated At",
                "Department",
            ]
            raw_rows = await self.report_repo.fetch_cases_for_export(
                start_date=start_date,
                end_date=end_date,
                department_id=resolved_dept_id,
                limit=MAX_EXPORT_ROWS,
            )
        elif request.report_type == ReportType.HUMAN_REVIEWS:
            title = "AI Segment Human Review Report"
            headers = [
                "Segment ID",
                "Job ID",
                "Incident ID",
                "Model Name",
                "Raw Label",
                "Raw Score",
                "Calibrated Score",
                "Review Status",
                "False Positive Reason",
                "Reviewed At",
                "Department",
            ]
            raw_rows = await self.report_repo.fetch_reviews_for_export(
                start_date=start_date,
                end_date=end_date,
                department_id=resolved_dept_id,
                limit=MAX_EXPORT_ROWS,
            )
        else:  # OPERATIONAL_SUMMARY
            title = "Operational Summary Report"
            headers = ["Metric", "Value"]
            raw_rows = await self.report_repo.fetch_operational_summary_for_export(
                start_date=start_date,
                end_date=end_date,
                department_id=resolved_dept_id,
            )

        # Convert dictionary rows to list of strings
        row_lists: list[list[str]] = []
        for r in raw_rows:
            row_lists.append([str(r.get(col, "")) for col in r])

        # 2. Render artifact by format
        timestamp_slug = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        safe_type = request.report_type.value

        file_bytes: bytes = b""
        filename = ""
        media_type = ""

        if request.export_format == ReportFormat.CSV:
            buf = io.StringIO()
            # UTF-8 with BOM for Excel compatibility
            writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
            # Write sanitized headers
            writer.writerow([sanitize_csv_cell(h) for h in headers])
            # Write sanitized rows
            for row in row_lists:
                writer.writerow([sanitize_csv_cell(cell) for cell in row])

            file_bytes = b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")
            filename = f"{safe_type}_report_{timestamp_slug}.csv"
            media_type = "text/csv; charset=utf-8"
        else:
            filename = f"{safe_type}_report_{timestamp_slug}.pdf"
            media_type = "application/pdf"
            file_bytes = generate_pdf_report(
                title=title,
                headers=headers,
                rows=row_lists,
                metadata={
                    "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "department": f"Department ID: {resolved_dept_id}"
                    if resolved_dept_id
                    else "Global / All",
                },
            )

        content_sha256 = hashlib.sha256(file_bytes).hexdigest()
        file_size = len(file_bytes)
        expires_at = datetime.now(UTC) + timedelta(days=7)

        # 3. Persist ReportExport record
        record = ReportExport(
            id=uuid4(),
            created_at=datetime.now(UTC),
            report_type=request.report_type.value,
            export_format=request.export_format.value,
            department_id=resolved_dept_id,
            created_by_id=principal.id,
            parameters_json=json.dumps(
                {
                    "start_date": request.start_date.isoformat(),
                    "end_date": request.end_date.isoformat(),
                    "record_count": len(row_lists),
                }
            ),
            status="completed",
            file_name=filename,
            file_size_bytes=file_size,
            content_sha256=content_sha256,
            download_count=1,  # First immediate delivery counts as 1 download
            expires_at=expires_at,
        )
        saved = await self.report_repo.create_report_export(record)

        # 4. Audit
        await self._audit(
            principal=principal,
            action=AuditAction.REPORT_EXPORTED,
            target_id=str(saved.id),
            details={
                "report_type": request.report_type.value,
                "format": request.export_format.value,
                "rows_exported": len(row_lists),
                "sha256": content_sha256,
                "file_size": file_size,
            },
            department_id=resolved_dept_id,
        )

        return ReportExportRead.model_validate(saved), file_bytes, filename, media_type

    async def download_report(
        self,
        principal: AuthenticatedPrincipal,
        export_id: UUID,
    ) -> ReportExportRead:
        """Verify download authorization, check expiration, and increment download tally."""
        export = await self.report_repo.get_report_export_by_id(export_id)
        if export is None:
            raise ResourceNotFoundError(
                f"Report export record '{export_id}' not found.",
                code="REPORT_NOT_FOUND",
            )

        # Re-check authorization
        has_global = has_permission(principal.role, Permission.REPORT_EXPORT_GLOBAL)
        if (
            not has_global
            and export.department_id is not None
            and export.department_id != principal.department_id
            and export.created_by_id != principal.id
        ):
            raise PermissionDeniedError(
                "You are not authorized to download this departmental report.",
                code="CROSS_DEPARTMENT_ACCESS_FORBIDDEN",
            )

        # Check expiration
        now = datetime.now(UTC)
        exp = export.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)

        if now > exp:
            raise BusinessRuleError(
                "This report export has expired and is no longer available for download.",
                code="REPORT_EXPIRED",
            )

        # Increment download count
        await self.report_repo.increment_download_count(export_id)

        # Audit
        await self._audit(
            principal=principal,
            action=AuditAction.REPORT_DOWNLOADED,
            target_id=str(export_id),
            details={
                "report_type": export.report_type,
                "format": export.export_format,
                "new_download_count": export.download_count + 1,
            },
            department_id=export.department_id,
        )

        return ReportExportRead.model_validate(export)

    get_report_for_download = download_report
