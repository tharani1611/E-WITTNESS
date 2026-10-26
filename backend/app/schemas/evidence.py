"""Pydantic v2 validation schemas for Evidence attachments and upload sessions (Phases 43-44).

Enforces:
- Input metadata validation bounds for evidence uploads.
- Explicit schema definitions for pre-signed upload session responses.
- Safe serialization of evidence attachment records without exposing storage credentials.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class UploadSessionCreateRequest(BaseModel):
    """Payload to authorize and initialize a short-lived evidence upload session."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "filename": "examination_notes_photo.png",
                "content_type": "image/png",
                "file_size_bytes": 2457600,
            }
        },
    )

    filename: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Original name of the evidence file to be uploaded.",
    )
    content_type: str = Field(
        ...,
        min_length=3,
        max_length=128,
        description="Declared MIME content type of the file (e.g. 'image/png', 'application/pdf').",
    )
    file_size_bytes: int = Field(
        ...,
        gt=0,
        description="Exact file size in bytes (must be greater than 0 and within configured limit).",
    )
    client_reported_at: datetime | None = Field(
        default=None,
        description="Optional client-reported creation/capture timestamp.",
    )


class UploadSessionResponse(BaseModel):
    """Authorized upload session credentials and short-lived upload endpoint."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "session_id": "d3333333-3333-3333-3333-333333333333",
                "incident_id": "b1111111-1111-1111-1111-111111111111",
                "storage_key": "incidents/b1111111-1111-1111-1111-111111111111/abc123def456.png",
                "upload_url": "https://s3.us-east-1.amazonaws.com/ewitness-evidence-prod-vault/incidents/...?",
                "upload_method": "PUT",
                "upload_headers": {
                    "Content-Type": "image/png",
                },
                "expires_at": "2026-10-14T03:15:00Z",
                "session_status": "active",
            }
        },
    )

    session_id: UUID = Field(..., description="Unique upload session identifier.")
    incident_id: UUID = Field(..., description="Target incident identifier.")
    storage_key: str = Field(..., description="Server-assigned opaque object key.")
    original_filename: str = Field(default="", description="Original filename of the evidence.")
    expected_size_bytes: int = Field(default=0, description="Expected size of the upload in bytes.")
    upload_url: str = Field(..., description="Short-lived, pre-signed upload URL.")
    upload_method: str = Field(default="PUT", description="HTTP verb required for the upload.")
    upload_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Mandatory HTTP headers to include with the upload request.",
    )
    expires_at: datetime = Field(..., description="UTC expiration timestamp of the upload session.")
    session_status: str = Field(..., description="Status of the upload session.")


class EvidenceAttachmentRead(BaseModel):
    """Public safe metadata view of a persisted evidence attachment."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "e4444444-4444-4444-4444-444444444444",
                "incident_id": "b1111111-1111-1111-1111-111111111111",
                "uploader_id": "c2222222-2222-2222-2222-222222222222",
                "department_id": "a0000000-0000-0000-0000-000000000001",
                "original_filename": "examination_notes_photo.png",
                "declared_mime_type": "image/png",
                "detected_mime_type": "image/png",
                "file_size_bytes": 2457600,
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "upload_status": "completed",
                "evidence_status": "attached",
                "created_at": "2026-10-14T02:35:00Z",
                "updated_at": "2026-10-14T02:35:00Z",
            }
        },
    )

    id: UUID = Field(..., description="Unique evidence attachment identifier.")
    incident_id: UUID = Field(..., description="Parent incident identifier.")
    uploader_id: UUID = Field(..., description="Uploading user identifier.")
    department_id: UUID = Field(..., description="Department scope identifier.")
    original_filename: str = Field(..., description="Sanitized original filename.")
    declared_mime_type: str = Field(..., description="Declared MIME type.")
    detected_mime_type: str | None = Field(None, description="Binary detected MIME type.")
    file_size_bytes: int = Field(..., description="File size in bytes.")
    sha256_hash: str | None = Field(None, description="SHA-256 cryptographic digest.")
    upload_status: str = Field(..., description="Upload lifecycle status.")
    evidence_status: str = Field(..., description="Evidence custody status.")
    scan_status: str = Field(default="pending", description="Malware scanning verification state.")
    scanned_at: datetime | None = Field(
        None, description="UTC timestamp when malware scan completed."
    )
    scan_details: str | None = Field(
        None, description="Non-sensitive malware scanning verdict details."
    )
    ingested_at: datetime | None = Field(
        None, description="UTC timestamp when evidence bytes were ingested and verified."
    )
    client_reported_at: datetime | None = Field(
        None, description="Client-reported creation/capture timestamp."
    )
    uploader_ip: str | None = Field(
        None, description="Network provenance IP address of the uploader."
    )
    user_agent: str | None = Field(None, description="User-Agent string of the uploader client.")
    created_at: datetime = Field(..., description="Creation UTC timestamp.")
    updated_at: datetime = Field(..., description="Last update UTC timestamp.")

    @field_validator("scan_status", mode="before")
    @classmethod
    def _coalesce_scan_status(cls, v: Any) -> str:
        return v or "pending"

    @property
    def hash_sha256(self) -> str | None:
        """Alias for sha256_hash for backwards and forwards compatibility."""
        return self.sha256_hash


class MultipartUploadInitRequest(BaseModel):
    """Payload to initialize a multipart/chunked evidence upload session."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "filename": "cctv_hallway_footage.mp4",
                "content_type": "video/mp4",
                "file_size_bytes": 52428800,
                "part_size_bytes": 5242880,
            }
        },
    )

    filename: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Original name of the evidence file to be uploaded.",
    )
    content_type: str = Field(
        ...,
        min_length=3,
        max_length=128,
        description="Declared MIME content type of the file (e.g. 'video/mp4').",
    )
    file_size_bytes: int = Field(
        ...,
        gt=0,
        description="Exact total file size in bytes.",
    )
    part_size_bytes: int = Field(
        default=5_242_880,
        ge=5_242_880,
        le=52_428_800,
        description="Size of each chunk in bytes (5 MB minimum for S3 multipart).",
    )
    client_reported_at: datetime | None = Field(
        default=None,
        description="Optional client-reported creation/capture timestamp.",
    )


class MultipartPartUrl(BaseModel):
    """Pre-signed upload endpoint for an individual chunk in a multipart upload."""

    model_config = ConfigDict(extra="forbid")

    part_number: int = Field(..., ge=1, le=10000, description="1-indexed part sequence number.")
    upload_url: str = Field(..., description="Pre-signed upload URL for this specific chunk.")
    headers: dict[str, str] = Field(default_factory=dict, description="Required HTTP headers.")


class MultipartUploadInitResponse(BaseModel):
    """Authorized multipart upload session credentials with pre-signed chunk URLs."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "session_id": "d3333333-3333-3333-3333-333333333333",
                "incident_id": "b1111111-1111-1111-1111-111111111111",
                "storage_key": "incidents/b1111111-1111-1111-1111-111111111111/xyz.mp4",
                "upload_id": "mp_abc123uploadid",
                "original_filename": "cctv_hallway_footage.mp4",
                "expected_size_bytes": 52428800,
                "part_size_bytes": 5242880,
                "total_parts": 10,
                "part_urls": [
                    {
                        "part_number": 1,
                        "upload_url": "https://s3.amazonaws.com/bucket/key?partNumber=1&uploadId=...",
                        "headers": {},
                    }
                ],
                "expires_at": "2026-10-14T03:15:00Z",
                "session_status": "active",
            }
        },
    )

    session_id: UUID = Field(..., description="Unique upload session identifier.")
    incident_id: UUID = Field(..., description="Target incident identifier.")
    storage_key: str = Field(..., description="Server-assigned opaque object key.")
    upload_id: str = Field(..., description="Storage provider multipart upload identifier.")
    original_filename: str = Field(..., description="Original filename of the evidence.")
    expected_size_bytes: int = Field(..., description="Total size of the upload in bytes.")
    part_size_bytes: int = Field(..., description="Size of each chunk in bytes.")
    total_parts: int = Field(..., description="Total number of parts required.")
    part_urls: list[MultipartPartUrl] = Field(..., description="Pre-signed URLs for each part.")
    expires_at: datetime = Field(..., description="UTC expiration timestamp of the session.")
    session_status: str = Field(..., description="Status of the upload session.")


class MultipartPartCompleteItem(BaseModel):
    """Uploaded part verification token."""

    model_config = ConfigDict(extra="forbid")

    part_number: int = Field(..., ge=1, le=10000, description="1-indexed part sequence number.")
    etag: str = Field(
        ..., min_length=1, description="Entity tag returned by storage provider for this part."
    )


class MultipartUploadCompleteRequest(BaseModel):
    """Payload to finalize and assemble a multipart upload session."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "parts": [
                    {"part_number": 1, "etag": "etag1"},
                    {"part_number": 2, "etag": "etag2"},
                ]
            }
        },
    )

    parts: list[MultipartPartCompleteItem] = Field(
        ..., min_length=1, description="Complete list of uploaded parts in order."
    )


class EvidenceDownloadResponse(BaseModel):
    """Authorized short-lived evidence download link and safe delivery metadata."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "download_url": "https://s3.amazonaws.com/bucket/key?X-Amz-Signature=...",
                "filename": "examination_notes_photo.png",
                "content_type": "image/png",
                "file_size_bytes": 2457600,
                "expires_at": "2026-10-14T03:10:00Z",
            }
        },
    )

    download_url: str = Field(..., description="Short-lived, pre-signed download URL.")
    filename: str = Field(..., description="Safe filename for content-disposition header.")
    content_type: str = Field(..., description="MIME content type of the evidence object.")
    file_size_bytes: int = Field(..., description="Size of the evidence file in bytes.")
    expires_at: datetime = Field(..., description="UTC expiration timestamp of the download link.")


class EvidenceProvenanceRead(BaseModel):
    """Detailed provenance metadata distinguishing server-observed facts from user declarations (Phase 52)."""

    model_config = ConfigDict(extra="forbid")

    attachment_id: UUID = Field(..., description="Unique evidence attachment identifier.")
    incident_id: UUID = Field(..., description="Parent incident identifier.")
    observed_facts: dict[str, Any] = Field(
        ...,
        description="Immutable server-verified facts (exact bytes, magic bytes, SHA-256, ingestion time, uploader IP).",
    )
    user_declarations: dict[str, Any] = Field(
        ...,
        description="Client-declared metadata (original filename, declared MIME, capture time claims).",
    )


class EvidenceCustodyEventRead(BaseModel):
    """Public safe representation of a chain-of-custody ledger event (Phase 53)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Unique custody event record identifier.")
    evidence_id: UUID = Field(..., description="Associated evidence attachment identifier.")
    incident_id: UUID = Field(..., description="Associated incident identifier.")
    department_id: UUID = Field(..., description="Department scope identifier.")
    sequence_number: int = Field(..., description="Monotonically increasing sequence number.")
    action_type: str = Field(..., description="Custody action type.")
    actor_id: UUID = Field(..., description="Actor user identifier.")
    actor_role: str = Field(..., description="Role of the actor at the time of the action.")
    actor_department_id: UUID | None = Field(None, description="Department of the actor.")
    timestamp: datetime = Field(..., description="UTC timestamp of the custody event.")
    evidence_sha256: str | None = Field(None, description="Evidence SHA-256 snapshot.")
    previous_event_hash: str | None = Field(
        None, description="SHA-256 hash of previous ledger event."
    )
    event_hash: str = Field(..., description="Cryptographic SHA-256 digest of this event record.")
    details: str | None = Field(None, description="Event action details.")
    compensates_event_id: UUID | None = Field(
        None, description="Compensated event ID if this is a correction."
    )
    compensation_reason: str | None = Field(None, description="Justification for compensation.")


class CompensatingEventCreateRequest(BaseModel):
    """Request payload to record an append-only compensating correction to a custody event (Phase 53)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_event_id: UUID = Field(
        ...,
        description="Identifier of the historical custody event being compensated/corrected.",
    )
    justification_reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Mandatory administrative justification for recording this correction.",
    )
    details: str | None = Field(
        None,
        max_length=2000,
        description="Optional detailed explanation or corrective findings.",
    )


class EvidenceIntegrityReportResponse(BaseModel):
    """Structured report returned upon cryptographic evidence integrity verification (Phase 54)."""

    model_config = ConfigDict(extra="forbid")

    attachment_id: UUID = Field(..., description="Target evidence attachment identifier.")
    incident_id: UUID = Field(..., description="Associated incident identifier.")
    status: str = Field(
        ..., description="Integrity check outcome (verified_match, tamper_detected, etc.)."
    )
    is_tampered: bool = Field(
        ..., description="True if evidence payload exhibits cryptographic discrepancy."
    )
    stored_sha256: str | None = Field(None, description="Trusted SHA-256 recorded at ingestion.")
    computed_sha256: str | None = Field(
        None, description="SHA-256 computed from live stored bytes."
    )
    stored_size_bytes: int | None = Field(
        None, description="Trusted byte size recorded at ingestion."
    )
    computed_size_bytes: int | None = Field(
        None, description="Live byte size retrieved from storage."
    )
    verified_at: datetime = Field(..., description="UTC timestamp when verification was executed.")
    disclaimer: str = Field(
        ..., description="Explicit evidentiary disclaimer on cryptographic hash match."
    )
    details: str | None = Field(None, description="Diagnostic notes or failure context.")
