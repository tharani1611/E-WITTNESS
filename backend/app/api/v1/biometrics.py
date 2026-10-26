"""Biometric Privacy, Governance, Reference Registry, and Face Detection API routes (Phases 71-75).

Enforces:
- Tenant and department boundary isolation on every operation.
- Purpose-binding and affirmative legal governance prerequisites.
- Automatic cascading reference revocation upon subject consent withdrawal.
- Zero raw biometric template or embedding disclosure in API responses.
- Fail-closed execution for face detection without persistent image storage.
"""

from __future__ import annotations

import base64
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.dependencies import (
    BiometricEvaluationServiceDep,
    BiometricGovernanceServiceDep,
    BiometricReferenceServiceDep,
    BiometricVerificationServiceDep,
    CurrentUserDep,
    FaceDetectionServiceDep,
    FaceMatchingServiceDep,
    require_permission,
)
from backend.app.core.authorization import Permission
from backend.app.core.exceptions import BusinessRuleError
from backend.app.schemas.biometrics import (
    BiometricConsentWithdrawRequest,
    BiometricEvaluationSummaryRead,
    BiometricGovernanceCreate,
    BiometricGovernanceRead,
    BiometricGovernanceReviewRequest,
    BiometricReferenceCreate,
    BiometricReferenceRead,
    BiometricReferenceRevokeRequest,
    BiometricVerificationReviewCreate,
    BiometricVerificationReviewRead,
    FaceDetectionRequest,
    FaceDetectionResponse,
    FaceMatchRequest,
    FaceMatchResponse,
    PaginatedBiometricGovernanceRead,
    PaginatedBiometricReferenceRead,
    PaginatedBiometricVerificationReviewRead,
)

router = APIRouter(prefix="/biometrics", tags=["Biometrics & Face Detection"])


# ---------------------------------------------------------------------------
# Biometric Governance & Feasibility Endpoints (Phases 71 & 73)
# ---------------------------------------------------------------------------


@router.post(
    "/governance",
    response_model=BiometricGovernanceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new biometric processing governance assessment or consent record",
)
async def create_governance_record(
    payload: BiometricGovernanceCreate,
    principal: CurrentUserDep,
    service: BiometricGovernanceServiceDep,
) -> BiometricGovernanceRead:
    """Create a new biometric governance and consent record."""
    return await service.create_governance_record(payload, principal)


@router.get(
    "/governance",
    response_model=PaginatedBiometricGovernanceRead,
    status_code=status.HTTP_200_OK,
    summary="List biometric governance records for authenticated department",
)
async def list_governance_records(
    principal: CurrentUserDep,
    service: BiometricGovernanceServiceDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedBiometricGovernanceRead:
    """List biometric governance records with optional status filtering."""
    return await service.list_governance_records(
        principal,
        status=status_filter,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/governance/{record_id}",
    response_model=BiometricGovernanceRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single biometric governance record",
)
async def get_governance_record(
    record_id: UUID,
    principal: CurrentUserDep,
    service: BiometricGovernanceServiceDep,
) -> BiometricGovernanceRead:
    """Retrieve details for a specific biometric governance record."""
    return await service.get_governance_record(record_id, principal)


@router.post(
    "/governance/{record_id}/review",
    response_model=BiometricGovernanceRead,
    status_code=status.HTTP_200_OK,
    summary="Submit formal review decision for biometric governance record",
    dependencies=[Depends(require_permission(Permission.BIOMETRIC_GOVERNANCE_REVIEW))],
)
async def review_governance_record(
    record_id: UUID,
    payload: BiometricGovernanceReviewRequest,
    principal: CurrentUserDep,
    service: BiometricGovernanceServiceDep,
) -> BiometricGovernanceRead:
    """Record legal or operational approval, rejection, or NO-GO decision."""
    return await service.review_governance_record(record_id, payload, principal)


@router.post(
    "/governance/{record_id}/withdraw",
    response_model=BiometricGovernanceRead,
    status_code=status.HTTP_200_OK,
    summary="Withdraw biometric consent and trigger cascading revocation",
)
async def withdraw_consent(
    record_id: UUID,
    payload: BiometricConsentWithdrawRequest,
    principal: CurrentUserDep,
    service: BiometricGovernanceServiceDep,
) -> BiometricGovernanceRead:
    """Withdraw consent, halting future processing and revoking active references."""
    return await service.withdraw_consent(record_id, payload, principal)


# ---------------------------------------------------------------------------
# Restricted Biometric Reference Registry Endpoints (Phase 74)
# ---------------------------------------------------------------------------


@router.post(
    "/references",
    response_model=BiometricReferenceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll approved biometric reference into restricted registry",
)
async def enroll_reference(
    payload: BiometricReferenceCreate,
    principal: CurrentUserDep,
    service: BiometricReferenceServiceDep,
) -> BiometricReferenceRead:
    """Enroll a biometric reference under an approved governance record."""
    return await service.enroll_reference(payload, principal)


@router.get(
    "/references",
    response_model=PaginatedBiometricReferenceRead,
    status_code=status.HTTP_200_OK,
    summary="List biometric references scoped to department",
)
async def list_references(
    principal: CurrentUserDep,
    service: BiometricReferenceServiceDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedBiometricReferenceRead:
    """List biometric references metadata without exposing template payloads."""
    return await service.list_references(
        principal,
        status=status_filter,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/references/{reference_id}",
    response_model=BiometricReferenceRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve biometric reference metadata",
)
async def get_reference(
    reference_id: UUID,
    principal: CurrentUserDep,
    service: BiometricReferenceServiceDep,
) -> BiometricReferenceRead:
    """Retrieve metadata for a single biometric reference without template payload."""
    return await service.get_reference(reference_id, principal)


@router.post(
    "/references/{reference_id}/revoke",
    response_model=BiometricReferenceRead,
    status_code=status.HTTP_200_OK,
    summary="Revoke an active biometric reference",
)
async def revoke_reference(
    reference_id: UUID,
    payload: BiometricReferenceRevokeRequest,
    principal: CurrentUserDep,
    service: BiometricReferenceServiceDep,
) -> BiometricReferenceRead:
    """Revoke a biometric reference and permanently wipe its stored template."""
    return await service.revoke_reference(reference_id, payload, principal)


# ---------------------------------------------------------------------------
# Approved Face Detection Endpoint (Phase 75)
# ---------------------------------------------------------------------------


@router.post(
    "/detect",
    response_model=FaceDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute approved face detection (bounding box localization only)",
    dependencies=[Depends(require_permission(Permission.BIOMETRIC_DETECTION_EXECUTE))],
)
async def detect_faces(
    request: Request,
    principal: CurrentUserDep,
    service: FaceDetectionServiceDep,
    payload: FaceDetectionRequest | None = None,
    governance_record_id: Annotated[UUID | None, Query()] = None,
) -> FaceDetectionResponse:
    """Detect face bounding boxes under an approved governance record."""
    content_type = request.headers.get("content-type", "")
    if payload is not None:
        rec_id = payload.governance_record_id
        try:
            image_bytes = base64.b64decode(payload.image_base64)
        except Exception as exc:
            raise BusinessRuleError("Invalid base64 encoding for image") from exc
    elif "application/json" in content_type:
        body_json = await request.json()
        req = FaceDetectionRequest(**body_json)
        rec_id = req.governance_record_id
        try:
            image_bytes = base64.b64decode(req.image_base64)
        except Exception as exc:
            raise BusinessRuleError("Invalid base64 encoding for image") from exc
    else:
        if governance_record_id is None:
            raise BusinessRuleError(
                "governance_record_id query parameter is required when posting raw image bytes"
            )
        rec_id = governance_record_id
        image_bytes = await request.body()

    return await service.detect_faces(image_bytes, rec_id, principal)


# ---------------------------------------------------------------------------
# Biometric Face Matching Endpoint (Phase 76)
# ---------------------------------------------------------------------------


@router.post(
    "/match",
    response_model=FaceMatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute advisory biometric face matching (prohibited in production)",
    dependencies=[Depends(require_permission(Permission.BIOMETRIC_MATCHING_EXECUTE))],
)
async def match_faces(
    payload: FaceMatchRequest,
    principal: CurrentUserDep,
    service: FaceMatchingServiceDep,
) -> FaceMatchResponse:
    """Execute advisory biometric matching between probe and reference.

    Fails closed when matching is disabled in configuration (default).
    """
    return await service.match_faces(payload, principal)


# ---------------------------------------------------------------------------
# Biometric Human Verification & Oversight Endpoints (Phase 77)
# ---------------------------------------------------------------------------


@router.post(
    "/verifications/{review_id}/review",
    response_model=BiometricVerificationReviewRead,
    status_code=status.HTTP_200_OK,
    summary="Record authorized human review determination for a match candidate",
    dependencies=[Depends(require_permission(Permission.BIOMETRIC_VERIFICATION_REVIEW))],
)
async def record_human_verdict(
    review_id: UUID,
    payload: BiometricVerificationReviewCreate,
    principal: CurrentUserDep,
    service: BiometricVerificationServiceDep,
) -> BiometricVerificationReviewRead:
    """Record qualified human reviewer verdict with mandatory override justification if applicable."""
    return await service.record_human_verdict(review_id, payload, principal)


@router.get(
    "/verifications/{review_id}",
    response_model=BiometricVerificationReviewRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single biometric verification review record",
    dependencies=[Depends(require_permission(Permission.BIOMETRIC_VERIFICATION_REVIEW))],
)
async def get_verification_review(
    review_id: UUID,
    principal: CurrentUserDep,
    service: BiometricVerificationServiceDep,
) -> BiometricVerificationReviewRead:
    """Retrieve details for a specific biometric verification review."""
    return await service.get_review(review_id, principal)


@router.get(
    "/verifications",
    response_model=PaginatedBiometricVerificationReviewRead,
    status_code=status.HTTP_200_OK,
    summary="List biometric verification review records for authenticated department",
    dependencies=[Depends(require_permission(Permission.BIOMETRIC_VERIFICATION_REVIEW))],
)
async def list_verification_reviews(
    principal: CurrentUserDep,
    service: BiometricVerificationServiceDep,
    incident_id: Annotated[UUID | None, Query()] = None,
    is_override: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedBiometricVerificationReviewRead:
    """List biometric verification review records with optional filtering."""
    return await service.list_reviews(
        principal,
        incident_id=incident_id,
        is_override=is_override,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# Biometric Accuracy, Fairness & PAD Evaluation Endpoint (Phase 79)
# ---------------------------------------------------------------------------


@router.get(
    "/evaluation-report",
    response_model=BiometricEvaluationSummaryRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve biometric accuracy, fairness, and presentation-attack benchmark report",
)
async def get_evaluation_report(
    principal: CurrentUserDep,
    service: BiometricEvaluationServiceDep,
) -> BiometricEvaluationSummaryRead:
    """Retrieve benchmark performance metrics with explicit synthetic limitation warnings."""
    return await service.get_evaluation_report(principal)
