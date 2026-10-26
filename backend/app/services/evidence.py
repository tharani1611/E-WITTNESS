"""Evidence attachment, upload authorization, malware scanning, and retrieval service (Phases 43-49).

Enforces:
- Verification of incident attachment eligibility and caller ownership.
- File metadata validation (extension, MIME allowlist, size limits).
- Cumulative storage quota enforcement (per-incident, per-user, per-department).
- Server-side opaque object key generation.
- Short-lived, scoped presigned upload and download authorizations.
- Resumable/multipart upload session lifecycle.
- Malware scanning verification hook with fail-closed quarantine policies.
- Zero leakage of storage credentials or internal infrastructure paths.
"""

from __future__ import annotations

import hashlib
import inspect
import math
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.evidence import (
    DEFAULT_MAX_DEPARTMENT_EVIDENCE_BYTES,
    DEFAULT_MAX_INCIDENT_EVIDENCE_BYTES,
    DEFAULT_MAX_USER_EVIDENCE_BYTES,
    INTEGRITY_DISCLAIMER,
    CustodyActionType,
    EvidenceStatus,
    IntegrityVerificationStatus,
    ScanStatus,
    UploadSessionStatus,
    UploadStatus,
    compute_custody_event_hash,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.core.incident import IncidentStatus
from backend.app.core.logging import get_logger
from backend.app.core.upload import (
    sanitize_filename,
    validate_file_magic_bytes,
    validate_upload_metadata,
)
from backend.app.infrastructure.scanner import (
    ClamAVScanner,
    MalwareScanner,
    MockMalwareScanner,
)
from backend.app.infrastructure.storage import (
    InMemoryStorageClient,
    ObjectStorageClient,
    S3StorageClient,
)
from backend.app.models.evidence import EvidenceAttachment, EvidenceCustodyEvent, UploadSession
from backend.app.models.incident import Incident
from backend.app.repositories.evidence import EvidenceRepository
from backend.app.repositories.incident import IncidentRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.evidence import (
    CompensatingEventCreateRequest,
    EvidenceAttachmentRead,
    EvidenceCustodyEventRead,
    EvidenceDownloadResponse,
    EvidenceIntegrityReportResponse,
    EvidenceProvenanceRead,
    MultipartPartUrl,
    MultipartUploadCompleteRequest,
    MultipartUploadInitRequest,
    MultipartUploadInitResponse,
    UploadSessionCreateRequest,
    UploadSessionResponse,
)

logger = get_logger("services.evidence")


class EvidenceService:
    """Domain service managing evidence metadata, upload authorizations, and storage custody."""

    def __init__(
        self,
        evidence_repo: EvidenceRepository,
        incident_repo: IncidentRepository,
        storage_client: ObjectStorageClient,
        settings: Settings,
        scanner: MalwareScanner | None = None,
    ) -> None:
        self.evidence_repo = evidence_repo
        self.incident_repo = incident_repo
        self.storage_client = storage_client
        self.settings = settings
        self.scanner = scanner or MockMalwareScanner()

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        storage_client: ObjectStorageClient | None = None,
        scanner: MalwareScanner | None = None,
    ) -> EvidenceService:
        """Construct an EvidenceService wired with repositories bound to ``session``."""
        client = storage_client or (
            InMemoryStorageClient(settings.STORAGE_ENDPOINT_URL)
            if settings.ENVIRONMENT == "testing" and "test" in settings.STORAGE_ENDPOINT_URL
            else S3StorageClient(settings)
        )
        malware_scanner = scanner or (
            MockMalwareScanner() if settings.ENVIRONMENT == "testing" else ClamAVScanner()
        )
        return cls(
            evidence_repo=EvidenceRepository(session),
            incident_repo=IncidentRepository(session),
            storage_client=client,
            settings=settings,
            scanner=malware_scanner,
        )

    async def _record_custody_event(
        self,
        *,
        evidence_id: UUID,
        incident_id: UUID,
        department_id: UUID,
        action_type: str,
        actor_id: UUID,
        actor_role: str,
        actor_department_id: UUID | None,
        evidence_sha256: str | None = None,
        details: str | None = None,
        compensates_event_id: UUID | None = None,
        compensation_reason: str | None = None,
    ) -> EvidenceCustodyEvent:
        """Append an immutable, cryptographically chained custody event to the ledger (Phase 53)."""
        latest: EvidenceCustodyEvent | None = None
        get_latest = getattr(self.evidence_repo, "get_latest_custody_event", None)
        if get_latest is not None:
            res_latest = get_latest(evidence_id)
            if inspect.isawaitable(res_latest):
                awaited_latest = await res_latest
                if isinstance(awaited_latest, EvidenceCustodyEvent):
                    latest = awaited_latest
            elif isinstance(res_latest, EvidenceCustodyEvent):
                latest = res_latest

        sequence_number = 1 if latest is None else latest.sequence_number + 1
        previous_event_hash = None if latest is None else latest.event_hash
        ts = datetime.now(UTC)

        event_hash = compute_custody_event_hash(
            evidence_id=evidence_id,
            sequence_number=sequence_number,
            action_type=action_type,
            timestamp_iso=ts.isoformat(),
            actor_id=actor_id,
            evidence_sha256=evidence_sha256,
            previous_event_hash=previous_event_hash,
            details=details,
        )

        event = EvidenceCustodyEvent(
            evidence_id=evidence_id,
            incident_id=incident_id,
            department_id=department_id,
            sequence_number=sequence_number,
            action_type=action_type,
            actor_id=actor_id,
            actor_role=actor_role,
            actor_department_id=actor_department_id,
            timestamp=ts,
            evidence_sha256=evidence_sha256,
            previous_event_hash=previous_event_hash,
            event_hash=event_hash,
            details=details,
            compensates_event_id=compensates_event_id,
            compensation_reason=compensation_reason,
        )
        create_fn = getattr(self.evidence_repo, "create_custody_event", None)
        if create_fn is not None:
            res_create = create_fn(event)
            if inspect.isawaitable(res_create):
                awaited_event = await res_create
                if isinstance(awaited_event, EvidenceCustodyEvent):
                    return awaited_event
        return event

    async def _assert_within_quotas(
        self,
        incident_id: UUID,
        uploader_id: UUID,
        department_id: UUID,
        additional_bytes: int,
    ) -> None:
        """Enforce per-incident, per-user, and per-department cumulative storage limits."""
        # 1. Incident quota
        incident_res = await self.evidence_repo.get_cumulative_size_by_incident(incident_id)
        incident_total = incident_res if isinstance(incident_res, (int, float)) else 0
        if incident_total + additional_bytes > DEFAULT_MAX_INCIDENT_EVIDENCE_BYTES:
            raise BusinessRuleError(
                f"Incident storage quota ({DEFAULT_MAX_INCIDENT_EVIDENCE_BYTES} bytes) exceeded.",
                code="INCIDENT_QUOTA_EXCEEDED",
            )

        # 2. User quota
        user_res = await self.evidence_repo.get_cumulative_size_by_user(uploader_id)
        user_total = user_res if isinstance(user_res, (int, float)) else 0
        if user_total + additional_bytes > DEFAULT_MAX_USER_EVIDENCE_BYTES:
            raise BusinessRuleError(
                f"User storage quota ({DEFAULT_MAX_USER_EVIDENCE_BYTES} bytes) exceeded.",
                code="USER_QUOTA_EXCEEDED",
            )

        # 3. Department quota
        dept_res = await self.evidence_repo.get_cumulative_size_by_department(department_id)
        dept_total = dept_res if isinstance(dept_res, (int, float)) else 0
        if dept_total + additional_bytes > DEFAULT_MAX_DEPARTMENT_EVIDENCE_BYTES:
            raise BusinessRuleError(
                f"Department storage quota ({DEFAULT_MAX_DEPARTMENT_EVIDENCE_BYTES} bytes) exceeded.",
                code="DEPARTMENT_QUOTA_EXCEEDED",
            )

    async def create_upload_session(
        self,
        incident_id: UUID,
        payload: UploadSessionCreateRequest,
        principal: AuthenticatedPrincipal,
        *,
        uploader_ip: str | None = None,
        user_agent: str | None = None,
    ) -> UploadSessionResponse:
        """Authorize and provision an evidence upload session with a pre-signed endpoint."""
        # 1. Fetch target incident
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        # 2. Enforce caller eligibility to attach evidence to target incident
        self._assert_can_attach_evidence(incident, principal)

        # 3. Validate metadata against policy and sanitize filename
        clean_filename = validate_upload_metadata(
            filename=payload.filename,
            content_type=payload.content_type,
            file_size=payload.file_size_bytes,
            max_file_size=self.settings.MAX_EVIDENCE_FILE_BYTES,
        )

        # 4. Enforce storage quotas
        await self._assert_within_quotas(
            incident.id,
            principal.user_id,
            incident.department_id,
            payload.file_size_bytes,
        )

        # 5. Generate opaque, server-side storage object key
        suffix = PurePosixPath(clean_filename).suffix.lower()
        unique_token = uuid4().hex
        storage_key = f"incidents/{incident.id}/{unique_token}{suffix}"

        # 6. Calculate session expiration (15 minutes)
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=15)

        # 7. Persist upload session record
        session = UploadSession(
            incident_id=incident.id,
            uploader_id=principal.user_id,
            department_id=incident.department_id,
            storage_key=storage_key,
            original_filename=clean_filename,
            declared_mime_type=payload.content_type,
            expected_size_bytes=payload.file_size_bytes,
            expires_at=expires_at,
            session_status=UploadSessionStatus.ACTIVE.value,
        )
        persisted_session = await self.evidence_repo.create_upload_session(session)

        # 8. Persist placeholder attachment record in PENDING status
        attachment = EvidenceAttachment(
            incident_id=incident.id,
            uploader_id=principal.user_id,
            department_id=incident.department_id,
            upload_session_id=persisted_session.id,
            original_filename=clean_filename,
            storage_key=storage_key,
            declared_mime_type=payload.content_type,
            detected_mime_type=None,
            file_size_bytes=payload.file_size_bytes,
            sha256_hash=None,
            upload_status=UploadStatus.PENDING.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.PENDING.value,
            client_reported_at=payload.client_reported_at,
            uploader_ip=uploader_ip,
            user_agent=user_agent,
        )
        await self.evidence_repo.create_attachment(attachment)

        # 9. Generate short-lived, pre-signed upload URL
        presigned = self.storage_client.generate_presigned_upload_url(
            storage_key=storage_key,
            content_type=payload.content_type,
            expires_in_seconds=900,
        )

        logger.info(
            "Evidence upload session authorized",
            extra={
                "session_id": str(persisted_session.id),
                "incident_id": str(incident.id),
                "uploader_id": str(principal.user_id),
                "storage_key": storage_key,
                "file_size_bytes": payload.file_size_bytes,
            },
        )

        return UploadSessionResponse(
            session_id=persisted_session.id,
            incident_id=incident.id,
            storage_key=storage_key,
            original_filename=persisted_session.original_filename,
            expected_size_bytes=persisted_session.expected_size_bytes,
            upload_url=presigned.upload_url,
            upload_method=presigned.upload_method,
            upload_headers=presigned.headers,
            expires_at=persisted_session.expires_at,
            session_status=persisted_session.session_status,
        )

    async def complete_upload_session(
        self,
        session_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
        *,
        uploader_ip: str | None = None,
        user_agent: str | None = None,
    ) -> EvidenceAttachmentRead:
        """Finalize an upload session, validate binary payload & magic bytes, and run malware scan."""
        # 1. Fetch upload session
        session = await self.evidence_repo.get_upload_session(session_id)
        if session is None or (incident_id is not None and session.incident_id != incident_id):
            raise ResourceNotFoundError(
                "Upload session not found.", code="UPLOAD_SESSION_NOT_FOUND"
            )

        # 2. Fetch incident and verify attachment permission
        resolved_incident_id = incident_id or session.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_can_attach_evidence(incident, principal)

        # 3. Check session status: idempotent return if already completed
        if session.session_status == UploadSessionStatus.COMPLETED.value:
            attachment = await self.evidence_repo.get_attachment_by_session_id(session.id)
            if attachment is not None:
                return EvidenceAttachmentRead.model_validate(attachment)

        if session.session_status != UploadSessionStatus.ACTIVE.value:
            raise BusinessRuleError(
                f"Upload session is not active (current status: '{session.session_status}').",
                code="UPLOAD_SESSION_INACTIVE",
            )

        now = datetime.now(UTC)
        if not session.is_valid_at(now):
            session.session_status = UploadSessionStatus.EXPIRED.value
            await self.evidence_repo.update_upload_session(session)
            raise BusinessRuleError("Upload session has expired.", code="UPLOAD_SESSION_EXPIRED")

        # 4. Verify object presence in storage
        exists = await self.storage_client.verify_object_exists(session.storage_key)
        if not exists:
            raise ResourceNotFoundError(
                "Evidence payload was not uploaded to storage.", code="OBJECT_NOT_FOUND"
            )

        # 5. Fetch binary payload from storage
        payload = await self.storage_client.get_object_bytes(session.storage_key)
        if not payload:
            raise BusinessRuleError("Uploaded file payload is empty.", code="EMPTY_PAYLOAD")

        # 6. Validate actual size matches expected size
        if len(payload) != session.expected_size_bytes:
            raise BusinessRuleError(
                f"Payload size mismatch: expected {session.expected_size_bytes} bytes but received {len(payload)} bytes.",
                code="PAYLOAD_SIZE_MISMATCH",
            )

        # 7. Validate magic bytes and MIME parity
        detected_mime = validate_file_magic_bytes(
            payload,
            expected_content_type=session.declared_mime_type,
        )

        # 8. Compute SHA-256 digest
        sha256_hash = hashlib.sha256(payload).hexdigest()

        # 9. Execute malware scan
        scan_result = await self.scanner.scan_payload(session.storage_key, payload)

        # 10. Update attachment record
        attachment = await self.evidence_repo.get_attachment_by_session_id(session.id)
        if attachment is None:
            attachment = await self.evidence_repo.get_attachment_by_storage_key(session.storage_key)

        if attachment is None:
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        attachment.detected_mime_type = detected_mime
        attachment.file_size_bytes = len(payload)
        attachment.sha256_hash = sha256_hash
        attachment.scanned_at = scan_result.scanned_at
        attachment.ingested_at = datetime.now(UTC)
        if uploader_ip and not attachment.uploader_ip:
            attachment.uploader_ip = uploader_ip
        if user_agent and not attachment.user_agent:
            attachment.user_agent = user_agent

        if scan_result.status == ScanStatus.CLEAN:
            attachment.upload_status = UploadStatus.COMPLETED.value
            attachment.evidence_status = EvidenceStatus.ATTACHED.value
            attachment.scan_status = ScanStatus.CLEAN.value
            attachment.scan_details = "Scan completed cleanly."
        elif scan_result.status == ScanStatus.INFECTED:
            attachment.upload_status = UploadStatus.COMPLETED.value
            attachment.evidence_status = EvidenceStatus.QUARANTINED.value
            attachment.scan_status = ScanStatus.INFECTED.value
            attachment.scan_details = scan_result.threat_name or "Malware detected."
            logger.warning(
                "Evidence quarantined due to malware detection",
                extra={
                    "attachment_id": str(attachment.id),
                    "storage_key": session.storage_key,
                    "threat": attachment.scan_details,
                },
            )
        else:
            # FAILED or timeout: fail closed
            attachment.upload_status = UploadStatus.COMPLETED.value
            attachment.evidence_status = EvidenceStatus.QUARANTINED.value
            attachment.scan_status = ScanStatus.FAILED.value
            attachment.scan_details = scan_result.error_message or "Scan failed or timed out."
            logger.error(
                "Evidence quarantined due to scanner failure",
                extra={
                    "attachment_id": str(attachment.id),
                    "storage_key": session.storage_key,
                    "error": attachment.scan_details,
                },
            )

        # 11. Mark session COMPLETED
        session.session_status = UploadSessionStatus.COMPLETED.value
        await self.evidence_repo.update_upload_session(session)
        updated_attachment = await self.evidence_repo.update_attachment(attachment)

        # 12. Record append-only chain-of-custody ledger events (Phase 53)
        await self._record_custody_event(
            evidence_id=attachment.id,
            incident_id=incident.id,
            department_id=incident.department_id,
            action_type=CustodyActionType.INGESTED.value,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            actor_department_id=principal.department_id,
            evidence_sha256=sha256_hash,
            details=f"Evidence binary payload ingested and SHA-256 verified ({sha256_hash}).",
        )

        if scan_result.status == ScanStatus.CLEAN:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.SEALED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=sha256_hash,
                details="Malware scanning completed clean; evidence sealed for intake.",
            )
        elif scan_result.status == ScanStatus.INFECTED:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.QUARANTINED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=sha256_hash,
                details=f"Evidence quarantined due to malware: {attachment.scan_details}.",
            )
        else:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.SCAN_FAILED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=sha256_hash,
                details=f"Evidence quarantined due to scanner failure: {attachment.scan_details}.",
            )

        return EvidenceAttachmentRead.model_validate(updated_attachment)

    async def initiate_multipart_upload(
        self,
        incident_id: UUID,
        payload: MultipartUploadInitRequest,
        principal: AuthenticatedPrincipal,
        *,
        uploader_ip: str | None = None,
        user_agent: str | None = None,
    ) -> MultipartUploadInitResponse:
        """Initialize an authorized multipart upload session with pre-signed chunk endpoints."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_can_attach_evidence(incident, principal)

        clean_filename = validate_upload_metadata(
            filename=payload.filename,
            content_type=payload.content_type,
            file_size=payload.file_size_bytes,
            max_file_size=self.settings.MAX_EVIDENCE_FILE_BYTES,
        )

        await self._assert_within_quotas(
            incident.id,
            principal.user_id,
            incident.department_id,
            payload.file_size_bytes,
        )

        suffix = PurePosixPath(clean_filename).suffix.lower()
        unique_token = uuid4().hex
        storage_key = f"incidents/{incident.id}/{unique_token}{suffix}"

        upload_id = await self.storage_client.initiate_multipart_upload(
            storage_key, payload.content_type
        )

        total_parts = math.ceil(payload.file_size_bytes / payload.part_size_bytes)
        part_urls: list[MultipartPartUrl] = []
        for part_num in range(1, total_parts + 1):
            url = self.storage_client.generate_presigned_part_upload_url(
                storage_key=storage_key,
                upload_id=upload_id,
                part_number=part_num,
                expires_in_seconds=900,
            )
            part_urls.append(MultipartPartUrl(part_number=part_num, upload_url=url, headers={}))

        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=15)

        session = UploadSession(
            incident_id=incident.id,
            uploader_id=principal.user_id,
            department_id=incident.department_id,
            storage_key=storage_key,
            original_filename=clean_filename,
            declared_mime_type=payload.content_type,
            expected_size_bytes=payload.file_size_bytes,
            expires_at=expires_at,
            session_status=UploadSessionStatus.ACTIVE.value,
            upload_id=upload_id,
            total_parts=total_parts,
            part_size_bytes=payload.part_size_bytes,
        )
        persisted_session = await self.evidence_repo.create_upload_session(session)

        attachment = EvidenceAttachment(
            incident_id=incident.id,
            uploader_id=principal.user_id,
            department_id=incident.department_id,
            upload_session_id=persisted_session.id,
            original_filename=clean_filename,
            storage_key=storage_key,
            declared_mime_type=payload.content_type,
            detected_mime_type=None,
            file_size_bytes=payload.file_size_bytes,
            sha256_hash=None,
            upload_status=UploadStatus.PENDING.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.PENDING.value,
            client_reported_at=payload.client_reported_at,
            uploader_ip=uploader_ip,
            user_agent=user_agent,
        )
        await self.evidence_repo.create_attachment(attachment)

        return MultipartUploadInitResponse(
            session_id=persisted_session.id,
            incident_id=incident.id,
            storage_key=storage_key,
            upload_id=upload_id,
            original_filename=clean_filename,
            expected_size_bytes=payload.file_size_bytes,
            part_size_bytes=payload.part_size_bytes,
            total_parts=total_parts,
            part_urls=part_urls,
            expires_at=expires_at,
            session_status=persisted_session.session_status,
        )

    async def complete_multipart_upload(
        self,
        session_id: UUID,
        payload: MultipartUploadCompleteRequest,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
        *,
        uploader_ip: str | None = None,
        user_agent: str | None = None,
    ) -> EvidenceAttachmentRead:
        """Finalize, validate, and scan a multipart evidence upload session."""
        session = await self.evidence_repo.get_upload_session(session_id)
        if session is None or (incident_id is not None and session.incident_id != incident_id):
            raise ResourceNotFoundError(
                "Upload session not found.", code="UPLOAD_SESSION_NOT_FOUND"
            )

        resolved_incident_id = incident_id or session.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_can_attach_evidence(incident, principal)

        if session.session_status == UploadSessionStatus.COMPLETED.value:
            attachment = await self.evidence_repo.get_attachment_by_session_id(session.id)
            if attachment is not None:
                return EvidenceAttachmentRead.model_validate(attachment)

        if not session.upload_id or session.total_parts is None:
            raise BusinessRuleError(
                "Session is not a multipart upload session.", code="NOT_MULTIPART_SESSION"
            )

        if session.session_status != UploadSessionStatus.ACTIVE.value:
            raise BusinessRuleError(
                f"Upload session is not active (current status: '{session.session_status}').",
                code="UPLOAD_SESSION_INACTIVE",
            )

        now = datetime.now(UTC)
        if not session.is_valid_at(now):
            session.session_status = UploadSessionStatus.EXPIRED.value
            await self.evidence_repo.update_upload_session(session)
            raise BusinessRuleError("Upload session has expired.", code="UPLOAD_SESSION_EXPIRED")

        # Validate part numbers: must match total_parts, strictly sequential 1..N
        parts_list = payload.parts
        if len(parts_list) != session.total_parts:
            raise BusinessRuleError(
                f"Expected {session.total_parts} parts, but received {len(parts_list)}.",
                code="INCOMPLETE_PARTS",
            )

        seen_numbers: set[int] = set()
        for p in parts_list:
            if p.part_number in seen_numbers:
                raise BusinessRuleError(
                    f"Duplicate part number {p.part_number}.", code="DUPLICATE_PART"
                )
            seen_numbers.add(p.part_number)

        expected_numbers = set(range(1, session.total_parts + 1))
        if seen_numbers != expected_numbers:
            raise BusinessRuleError(
                "Part numbers are not sequential or have missing parts.",
                code="INVALID_PART_SEQUENCE",
            )

        # Complete multipart upload in storage
        parts_dict = [{"part_number": p.part_number, "etag": p.etag} for p in parts_list]
        await self.storage_client.complete_multipart_upload(
            session.storage_key, session.upload_id, parts_dict
        )

        # Retrieve assembled payload, validate, and scan
        obj_bytes = await self.storage_client.get_object_bytes(session.storage_key)
        if len(obj_bytes) != session.expected_size_bytes:
            raise BusinessRuleError(
                f"Payload size mismatch: expected {session.expected_size_bytes} but received {len(obj_bytes)}.",
                code="PAYLOAD_SIZE_MISMATCH",
            )

        detected_mime = validate_file_magic_bytes(
            obj_bytes, expected_content_type=session.declared_mime_type
        )
        sha256_hash = hashlib.sha256(obj_bytes).hexdigest()
        scan_result = await self.scanner.scan_payload(session.storage_key, obj_bytes)

        attachment = await self.evidence_repo.get_attachment_by_session_id(session.id)
        if attachment is None:
            attachment = await self.evidence_repo.get_attachment_by_storage_key(session.storage_key)
        if attachment is None:
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        attachment.detected_mime_type = detected_mime
        attachment.file_size_bytes = len(obj_bytes)
        attachment.sha256_hash = sha256_hash
        attachment.scanned_at = scan_result.scanned_at
        attachment.ingested_at = datetime.now(UTC)
        if uploader_ip and not attachment.uploader_ip:
            attachment.uploader_ip = uploader_ip
        if user_agent and not attachment.user_agent:
            attachment.user_agent = user_agent

        if scan_result.status == ScanStatus.CLEAN:
            attachment.upload_status = UploadStatus.COMPLETED.value
            attachment.evidence_status = EvidenceStatus.ATTACHED.value
            attachment.scan_status = ScanStatus.CLEAN.value
            attachment.scan_details = "Clean"
        elif scan_result.status == ScanStatus.INFECTED:
            attachment.upload_status = UploadStatus.COMPLETED.value
            attachment.evidence_status = EvidenceStatus.QUARANTINED.value
            attachment.scan_status = ScanStatus.INFECTED.value
            attachment.scan_details = scan_result.threat_name or "Malware detected"
        else:
            attachment.upload_status = UploadStatus.COMPLETED.value
            attachment.evidence_status = EvidenceStatus.QUARANTINED.value
            attachment.scan_status = ScanStatus.FAILED.value
            attachment.scan_details = scan_result.error_message or "Scan failed"

        session.session_status = UploadSessionStatus.COMPLETED.value
        await self.evidence_repo.update_upload_session(session)
        updated = await self.evidence_repo.update_attachment(attachment)

        # Record append-only chain-of-custody ledger events (Phase 53)
        await self._record_custody_event(
            evidence_id=attachment.id,
            incident_id=incident.id,
            department_id=incident.department_id,
            action_type=CustodyActionType.INGESTED.value,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            actor_department_id=principal.department_id,
            evidence_sha256=sha256_hash,
            details=f"Multipart evidence binary payload assembled, ingested, and SHA-256 verified ({sha256_hash}).",
        )

        if scan_result.status == ScanStatus.CLEAN:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.SEALED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=sha256_hash,
                details="Multipart upload malware scan clean; evidence sealed for intake.",
            )
        elif scan_result.status == ScanStatus.INFECTED:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.QUARANTINED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=sha256_hash,
                details=f"Multipart evidence quarantined due to malware: {attachment.scan_details}.",
            )
        else:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.SCAN_FAILED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=sha256_hash,
                details=f"Multipart evidence quarantined due to scanner failure: {attachment.scan_details}.",
            )

        return EvidenceAttachmentRead.model_validate(updated)

    async def abort_multipart_upload(
        self,
        session_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
    ) -> None:
        """Abort a multipart session and mark attachment as cancelled."""
        session = await self.evidence_repo.get_upload_session(session_id)
        if session is None or (incident_id is not None and session.incident_id != incident_id):
            raise ResourceNotFoundError(
                "Upload session not found.", code="UPLOAD_SESSION_NOT_FOUND"
            )

        resolved_incident_id = incident_id or session.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_can_attach_evidence(incident, principal)

        if session.upload_id and session.session_status == UploadSessionStatus.ACTIVE.value:
            await self.storage_client.abort_multipart_upload(session.storage_key, session.upload_id)

        session.session_status = UploadSessionStatus.CANCELLED.value
        await self.evidence_repo.update_upload_session(session)

        attachment = await self.evidence_repo.get_attachment_by_session_id(session.id)
        if attachment:
            attachment.upload_status = UploadStatus.CANCELLED.value
            await self.evidence_repo.update_attachment(attachment)

    async def retry_scan(
        self,
        attachment_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
    ) -> EvidenceAttachmentRead:
        """Allow administrative or investigative staff to re-trigger a failed malware scan."""
        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None or (
            incident_id is not None and attachment.incident_id != incident_id
        ):
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        resolved_incident_id = incident_id or attachment.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_incident_visible(incident, principal)

        if principal.role_code not in {
            RoleCode.SUPER_ADMIN.value,
            RoleCode.DEPT_ADMIN.value,
            RoleCode.INVESTIGATOR.value,
        }:
            raise PermissionDeniedError(
                "You do not have permission to retry evidence malware scans.",
                code="PERMISSION_DENIED",
            )

        # Reject retry on already clean attachments
        if attachment.scan_status == ScanStatus.CLEAN.value:
            raise BusinessRuleError(
                "Attachment is already marked clean and does not require re-scanning.",
                code="INVALID_SCAN_RETRY",
            )

        # Fetch payload from storage and re-scan
        payload = await self.storage_client.get_object_bytes(attachment.storage_key)
        scan_result = await self.scanner.scan_payload(attachment.storage_key, payload)

        attachment.scanned_at = scan_result.scanned_at
        if scan_result.status == ScanStatus.CLEAN:
            attachment.scan_status = ScanStatus.CLEAN.value
            attachment.evidence_status = EvidenceStatus.ATTACHED.value
            attachment.scan_details = "Clean upon scan retry."
        elif scan_result.status == ScanStatus.INFECTED:
            attachment.scan_status = ScanStatus.INFECTED.value
            attachment.evidence_status = EvidenceStatus.QUARANTINED.value
            attachment.scan_details = scan_result.threat_name or "Malware detected on retry."
        else:
            attachment.scan_status = ScanStatus.FAILED.value
            attachment.evidence_status = EvidenceStatus.QUARANTINED.value
            attachment.scan_details = scan_result.error_message or "Scan retry failed."

        updated = await self.evidence_repo.update_attachment(attachment)

        # Record scan retry custody events (Phase 53)
        await self._record_custody_event(
            evidence_id=attachment.id,
            incident_id=incident.id,
            department_id=incident.department_id,
            action_type=CustodyActionType.SCAN_RETRY.value,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            actor_department_id=principal.department_id,
            evidence_sha256=attachment.sha256_hash,
            details=f"Malware re-scan triggered by {principal.role_code} (User {principal.user_id}).",
        )

        if scan_result.status == ScanStatus.CLEAN:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.SEALED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=attachment.sha256_hash,
                details="Re-scan clean; evidence un-quarantined and sealed.",
            )
        elif scan_result.status == ScanStatus.INFECTED:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.QUARANTINED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=attachment.sha256_hash,
                details=f"Re-scan detected malware: {attachment.scan_details}.",
            )

        return EvidenceAttachmentRead.model_validate(updated)

    async def generate_download_url(
        self,
        attachment_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
        expires_in_seconds: int = 300,
    ) -> EvidenceDownloadResponse:
        """Generate a short-lived, pre-signed download URL for clean, verified evidence."""
        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None or (
            incident_id is not None and attachment.incident_id != incident_id
        ):
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        resolved_incident_id = incident_id or attachment.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_incident_visible(incident, principal)

        # Check upload completion
        if attachment.upload_status != UploadStatus.COMPLETED.value:
            raise BusinessRuleError(
                "Evidence upload is not completed.",
                code="EVIDENCE_UPLOAD_INCOMPLETE",
            )

        # Fail closed: quarantined and unverified scans cannot be retrieved
        if (
            attachment.evidence_status == EvidenceStatus.QUARANTINED.value
            or attachment.scan_status != ScanStatus.CLEAN.value
        ):
            raise BusinessRuleError(
                "Evidence is quarantined or pending malware clearance and cannot be downloaded.",
                code="EVIDENCE_NOT_RELEASED",
                status_code=403,
            )

        # Verify object still exists in storage
        exists = await self.storage_client.verify_object_exists(attachment.storage_key)
        if not exists:
            raise ResourceNotFoundError(
                "Evidence object is missing from storage.", code="OBJECT_NOT_FOUND"
            )

        # Generate safe filename and presigned download URL (300 seconds TTL)
        safe_filename = sanitize_filename(attachment.original_filename)
        download_url = self.storage_client.generate_presigned_download_url(
            storage_key=attachment.storage_key,
            expires_in_seconds=300,
        )

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=300)

        # Record custody event for download authorization (Phase 53)
        await self._record_custody_event(
            evidence_id=attachment.id,
            incident_id=incident.id,
            department_id=incident.department_id,
            action_type=CustodyActionType.DOWNLOADED.value,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            actor_department_id=principal.department_id,
            evidence_sha256=attachment.sha256_hash,
            details=f"Authorized download URL generated for {principal.role_code} (User {principal.user_id}).",
        )

        logger.info(
            "Evidence download authorized",
            extra={
                "incident_id": str(incident.id),
                "attachment_id": str(attachment.id),
                "caller_id": str(principal.user_id),
                "expires_at": expires_at.isoformat(),
            },
        )

        return EvidenceDownloadResponse(
            download_url=download_url,
            filename=safe_filename,
            content_type=attachment.declared_mime_type,
            file_size_bytes=attachment.file_size_bytes,
            expires_at=expires_at,
        )

    async def get_upload_session(
        self,
        session_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> UploadSessionResponse:
        """Inspect status of an authorized upload session."""
        session = await self.evidence_repo.get_upload_session(session_id)
        if session is None:
            raise ResourceNotFoundError(
                "Upload session not found.", code="UPLOAD_SESSION_NOT_FOUND"
            )

        incident = await self.incident_repo.get_by_id(session.incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)

        now = datetime.now(UTC)
        if not session.is_valid_at(now):
            if session.session_status == UploadSessionStatus.ACTIVE.value:
                session.session_status = UploadSessionStatus.EXPIRED.value
                await self.evidence_repo.update_upload_session(session)

            return UploadSessionResponse(
                session_id=session.id,
                incident_id=session.incident_id,
                storage_key=session.storage_key,
                original_filename=session.original_filename,
                expected_size_bytes=session.expected_size_bytes,
                upload_url="",
                upload_method="PUT",
                upload_headers={},
                expires_at=session.expires_at,
                session_status=session.session_status,
            )

        # Active session: re-sign fresh short-lived upload URL
        remaining_seconds = max(1, int((session.expires_at - now).total_seconds()))
        presigned = self.storage_client.generate_presigned_upload_url(
            storage_key=session.storage_key,
            content_type=session.declared_mime_type,
            expires_in_seconds=min(900, remaining_seconds),
        )

        return UploadSessionResponse(
            session_id=session.id,
            incident_id=session.incident_id,
            storage_key=session.storage_key,
            original_filename=session.original_filename,
            expected_size_bytes=session.expected_size_bytes,
            upload_url=presigned.upload_url,
            upload_method=presigned.upload_method,
            upload_headers=presigned.headers,
            expires_at=session.expires_at,
            session_status=session.session_status,
        )

    async def list_attachments(
        self,
        incident_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[EvidenceAttachmentRead]:
        """List all evidence attachments for an authorized incident."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)

        attachments = await self.evidence_repo.list_attachments_by_incident(incident_id)
        return [EvidenceAttachmentRead.model_validate(a) for a in attachments]

    async def get_attachment(
        self,
        attachment_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> EvidenceAttachmentRead:
        """Retrieve metadata for a specific evidence attachment."""
        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None:
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        incident = await self.incident_repo.get_by_id(attachment.incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

        self._assert_incident_visible(incident, principal)
        return EvidenceAttachmentRead.model_validate(attachment)

    async def verify_evidence_integrity(
        self,
        attachment_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
    ) -> EvidenceIntegrityReportResponse:
        """Authorized integrity verification and tamper report (Phase 54).

        Distinguishes:
        - verified_match: bit-level equality confirmed.
        - tamper_detected: cryptographic hash mismatch.
        - storage_missing: object not found in storage.
        - storage_unavailable: storage backend connection or operational failure.
        - unverified: upload incomplete / pending.

        Explicitly includes mandatory evidentiary disclaimer.
        """
        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None or (
            incident_id is not None and attachment.incident_id != incident_id
        ):
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        resolved_incident_id = incident_id or attachment.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_incident_visible(incident, principal)

        now = datetime.now(UTC)

        # Distinguish unverified / incomplete upload
        if (
            attachment.upload_status != UploadStatus.COMPLETED.value
            or attachment.sha256_hash is None
        ):
            return EvidenceIntegrityReportResponse(
                attachment_id=attachment.id,
                incident_id=incident.id,
                status=IntegrityVerificationStatus.UNVERIFIED.value,
                is_tampered=False,
                stored_sha256=attachment.sha256_hash,
                computed_sha256=None,
                stored_size_bytes=attachment.file_size_bytes,
                computed_size_bytes=None,
                verified_at=now,
                disclaimer=INTEGRITY_DISCLAIMER,
                details="Evidence upload is incomplete or pending; hash has not been finalized.",
            )

        # Check storage existence
        try:
            exists = await self.storage_client.verify_object_exists(attachment.storage_key)
        except Exception as exc:
            logger.error("Storage backend error during integrity check", exc_info=exc)
            return EvidenceIntegrityReportResponse(
                attachment_id=attachment.id,
                incident_id=incident.id,
                status=IntegrityVerificationStatus.STORAGE_UNAVAILABLE.value,
                is_tampered=False,
                stored_sha256=attachment.sha256_hash,
                computed_sha256=None,
                stored_size_bytes=attachment.file_size_bytes,
                computed_size_bytes=None,
                verified_at=now,
                disclaimer=INTEGRITY_DISCLAIMER,
                details=f"Storage backend service is unavailable: {exc}",
            )

        if not exists:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.TAMPER_DETECTED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=attachment.sha256_hash,
                details=f"Integrity check failed: storage object '{attachment.storage_key}' is missing.",
            )
            return EvidenceIntegrityReportResponse(
                attachment_id=attachment.id,
                incident_id=incident.id,
                status=IntegrityVerificationStatus.STORAGE_MISSING.value,
                is_tampered=True,
                stored_sha256=attachment.sha256_hash,
                computed_sha256=None,
                stored_size_bytes=attachment.file_size_bytes,
                computed_size_bytes=None,
                verified_at=now,
                disclaimer=INTEGRITY_DISCLAIMER,
                details=f"Evidence payload object was not found in storage key '{attachment.storage_key}'.",
            )

        # Retrieve bytes and recompute hash
        try:
            payload = await self.storage_client.get_object_bytes(attachment.storage_key)
        except Exception as exc:
            logger.error("Storage error retrieving object bytes", exc_info=exc)
            return EvidenceIntegrityReportResponse(
                attachment_id=attachment.id,
                incident_id=incident.id,
                status=IntegrityVerificationStatus.STORAGE_UNAVAILABLE.value,
                is_tampered=False,
                stored_sha256=attachment.sha256_hash,
                computed_sha256=None,
                stored_size_bytes=attachment.file_size_bytes,
                computed_size_bytes=None,
                verified_at=now,
                disclaimer=INTEGRITY_DISCLAIMER,
                details=f"Storage error reading payload: {exc}",
            )

        computed_sha256 = hashlib.sha256(payload).hexdigest()
        computed_size = len(payload)

        if (
            computed_sha256 == attachment.sha256_hash
            and computed_size == attachment.file_size_bytes
        ):
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.HASH_VERIFIED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=computed_sha256,
                details="Live cryptographic verification confirmed byte-level match against ingestion digest.",
            )
            return EvidenceIntegrityReportResponse(
                attachment_id=attachment.id,
                incident_id=incident.id,
                status=IntegrityVerificationStatus.VERIFIED_MATCH.value,
                is_tampered=False,
                stored_sha256=attachment.sha256_hash,
                computed_sha256=computed_sha256,
                stored_size_bytes=attachment.file_size_bytes,
                computed_size_bytes=computed_size,
                verified_at=now,
                disclaimer=INTEGRITY_DISCLAIMER,
                details="Bit-level integrity verified against trusted ingestion hash.",
            )
        else:
            await self._record_custody_event(
                evidence_id=attachment.id,
                incident_id=incident.id,
                department_id=incident.department_id,
                action_type=CustodyActionType.TAMPER_DETECTED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                actor_department_id=principal.department_id,
                evidence_sha256=computed_sha256,
                details=(
                    f"TAMPER DETECTED: Computed SHA-256 '{computed_sha256}' does not match "
                    f"trusted ingestion SHA-256 '{attachment.sha256_hash}'."
                ),
            )
            return EvidenceIntegrityReportResponse(
                attachment_id=attachment.id,
                incident_id=incident.id,
                status=IntegrityVerificationStatus.TAMPER_DETECTED.value,
                is_tampered=True,
                stored_sha256=attachment.sha256_hash,
                computed_sha256=computed_sha256,
                stored_size_bytes=attachment.file_size_bytes,
                computed_size_bytes=computed_size,
                verified_at=now,
                disclaimer=INTEGRITY_DISCLAIMER,
                details=(
                    f"Cryptographic digest mismatch: live payload SHA-256 '{computed_sha256}' "
                    f"does not match stored '{attachment.sha256_hash}'."
                ),
            )

    async def get_custody_ledger(
        self,
        attachment_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
    ) -> list[EvidenceCustodyEventRead]:
        """Retrieve the immutable, cryptographically chained custody events for an attachment (Phase 53)."""
        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None or (
            incident_id is not None and attachment.incident_id != incident_id
        ):
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        resolved_incident_id = incident_id or attachment.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_incident_visible(incident, principal)

        events = await self.evidence_repo.get_custody_events_for_attachment(attachment.id)
        return [EvidenceCustodyEventRead.model_validate(e) for e in events]

    async def create_compensating_custody_event(
        self,
        attachment_id: UUID,
        payload: CompensatingEventCreateRequest,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
    ) -> EvidenceCustodyEventRead:
        """Append an authorized compensating correction to the chain-of-custody ledger (Phase 53)."""
        if principal.role_code not in {RoleCode.DEPT_ADMIN.value, RoleCode.SUPER_ADMIN.value}:
            raise PermissionDeniedError(
                "Only administrators can record compensating custody events.",
                code="PERMISSION_DENIED",
            )

        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None or (
            incident_id is not None and attachment.incident_id != incident_id
        ):
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        resolved_incident_id = incident_id or attachment.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_incident_visible(incident, principal)

        if (
            principal.role_code == RoleCode.DEPT_ADMIN.value
            and incident.department_id != principal.department_id
        ):
            raise PermissionDeniedError(
                "Department administrators can only record compensating events for evidence in their department.",
                code="DEPARTMENT_MISMATCH",
            )

        target_event = await self.evidence_repo.get_custody_event_by_id(payload.target_event_id)
        if target_event is None or target_event.evidence_id != attachment.id:
            raise ResourceNotFoundError(
                "Target custody event not found for this evidence.",
                code="CUSTODY_EVENT_NOT_FOUND",
            )

        comp_event = await self._record_custody_event(
            evidence_id=attachment.id,
            incident_id=incident.id,
            department_id=incident.department_id,
            action_type=CustodyActionType.COMPENSATING_CORRECTION.value,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            actor_department_id=principal.department_id,
            evidence_sha256=attachment.sha256_hash,
            details=payload.details
            or f"Compensating correction for custody event #{target_event.sequence_number}.",
            compensates_event_id=target_event.id,
            compensation_reason=payload.justification_reason.strip(),
        )

        logger.info(
            "Compensating custody event recorded",
            extra={
                "attachment_id": str(attachment.id),
                "compensated_event_id": str(target_event.id),
                "sequence_number": comp_event.sequence_number,
                "actor_id": str(principal.user_id),
            },
        )

        return EvidenceCustodyEventRead.model_validate(comp_event)

    async def get_evidence_provenance(
        self,
        attachment_id: UUID,
        principal: AuthenticatedPrincipal,
        incident_id: UUID | None = None,
    ) -> EvidenceProvenanceRead:
        """Inspect evidence provenance distinguishing server-observed facts from user declarations (Phase 52)."""
        attachment = await self.evidence_repo.get_attachment_by_id(attachment_id)
        if attachment is None or (
            incident_id is not None and attachment.incident_id != incident_id
        ):
            raise ResourceNotFoundError(
                "Evidence attachment not found.", code="ATTACHMENT_NOT_FOUND"
            )

        resolved_incident_id = incident_id or attachment.incident_id
        incident = await self.incident_repo.get_by_id(resolved_incident_id)
        if incident is None:
            raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
        self._assert_incident_visible(incident, principal)

        observed_facts = {
            "attachment_id": str(attachment.id),
            "uploader_id": str(attachment.uploader_id),
            "department_id": str(attachment.department_id),
            "storage_key": attachment.storage_key,
            "file_size_bytes": attachment.file_size_bytes,
            "sha256_hash": attachment.sha256_hash,
            "detected_mime_type": attachment.detected_mime_type,
            "ingested_at": attachment.ingested_at.isoformat() if attachment.ingested_at else None,
            "scanned_at": attachment.scanned_at.isoformat() if attachment.scanned_at else None,
            "scan_status": attachment.scan_status,
            "scan_details": attachment.scan_details,
            "uploader_ip": attachment.uploader_ip,
            "user_agent": attachment.user_agent,
            "server_created_at": attachment.created_at.isoformat()
            if attachment.created_at
            else None,
        }
        user_declarations = {
            "original_filename": attachment.original_filename,
            "declared_mime_type": attachment.declared_mime_type,
            "client_reported_at": attachment.client_reported_at.isoformat()
            if attachment.client_reported_at
            else None,
        }

        return EvidenceProvenanceRead(
            attachment_id=attachment.id,
            incident_id=incident.id,
            observed_facts=observed_facts,
            user_declarations=user_declarations,
        )

    def _assert_can_attach_evidence(
        self,
        incident: Incident,
        principal: AuthenticatedPrincipal,
    ) -> None:
        """Validate whether caller has legal standing and active status to attach evidence."""
        # 1. Super Admin has global attachment permission
        if principal.role_code == RoleCode.SUPER_ADMIN.value:
            return

        # 2. Dept Admin & Investigator must belong to the incident's department
        if principal.role_code in {RoleCode.DEPT_ADMIN.value, RoleCode.INVESTIGATOR.value}:
            if incident.department_id != principal.department_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
            return

        # 3. Student & Staff must be the original submitter
        if principal.role_code in {RoleCode.STUDENT.value, RoleCode.STAFF.value}:
            if incident.reporter_id != principal.user_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")

            # Cannot attach evidence to closed or dismissed reports
            if incident.status in {IncidentStatus.CLOSED.value, IncidentStatus.DISMISSED.value}:
                raise BusinessRuleError(
                    f"Cannot attach evidence to an incident with status '{incident.status}'.",
                    code="INCIDENT_CLOSED_ATTACHMENT",
                )
            return

        raise PermissionDeniedError(
            "You do not have permission to attach evidence.", code="PERMISSION_DENIED"
        )

    def _assert_incident_visible(
        self,
        incident: Incident,
        principal: AuthenticatedPrincipal,
    ) -> None:
        """Enforce visibility boundary: raise 404 on out-of-scope access to prevent enumeration."""
        if principal.role_code == RoleCode.SUPER_ADMIN.value:
            return

        if principal.role_code in {RoleCode.DEPT_ADMIN.value, RoleCode.INVESTIGATOR.value}:
            if incident.department_id != principal.department_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
            return

        if principal.role_code in {RoleCode.STUDENT.value, RoleCode.STAFF.value}:
            if incident.reporter_id != principal.user_id:
                raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
            return

        raise ResourceNotFoundError("Incident not found.", code="INCIDENT_NOT_FOUND")
