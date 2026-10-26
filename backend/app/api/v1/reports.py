"""Controlled report generation and export API endpoints (Phase 98).

Provides:
- Immediate on-demand CSV and PDF report generation and download.
- Re-authorized download verification and expiration enforcement.
- Injection-sanitized CSV exports (prevention of spreadsheet macro execution).
- Secure PDF generation with embedded statutory AI advisory disclaimers.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request, Response, status

from backend.app.api.dependencies import (
    ClientIpDep,
    ReportExportServiceDep,
    require_any_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.report import ReportExportRead, ReportExportRequest

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post(
    "/export",
    status_code=status.HTTP_200_OK,
    summary="Generate and download a controlled CSV or PDF report",
    response_description="Binary file stream of the generated report with Content-Disposition header.",
)
async def export_report(
    service: ReportExportServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.REPORT_EXPORT_DEPT,
                Permission.REPORT_EXPORT_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
    payload: ReportExportRequest,
) -> Response:
    """Generate and stream a controlled report package."""
    export_meta, file_bytes, filename, media_type = await service.generate_report(
        principal=principal,
        request=payload,
    )

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": media_type,
        "X-Report-Id": str(export_meta.id),
        "X-Export-Id": str(export_meta.id),
        "X-Content-SHA256": export_meta.content_sha256 or "",
        "X-Export-SHA256": export_meta.content_sha256 or "",
    }

    return Response(
        content=file_bytes,
        media_type=media_type,
        headers=headers,
    )


@router.get(
    "/{id}/download",
    response_model=ReportExportRead,
    status_code=status.HTTP_200_OK,
    summary="Verify authorization and record download of an existing report export",
)
async def download_report_metadata(
    service: ReportExportServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.REPORT_EXPORT_DEPT,
                Permission.REPORT_EXPORT_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
    id: Annotated[UUID, Path(description="Report export ID.")],
) -> ReportExportRead:
    """Re-verify download permissions, check expiration, and increment download tally."""
    return await service.download_report(
        principal=principal,
        export_id=id,
    )
