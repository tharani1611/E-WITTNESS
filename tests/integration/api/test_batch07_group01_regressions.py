"""Live PostgreSQL Integration Tests for Batch 07 Group 01 (Phases 61-65).

Verifies against real PostgreSQL:
- Phase 61: Violence detection requirements, intended use, and statutory human-in-the-loop disclaimers.
- Phase 62: Dataset ingestion, manifest hashing, approved license allowlist, review workflow, and evidence separation.
- Phase 63: Pure-Python safe MP4 metadata extraction and deterministic frame sampling.
- Phase 64: Configurable classifier provider, graceful failure without score fabrication, and uncalibrated output contract.
- Phase 65: Asynchronous analysis jobs, lifecycle progression, department isolation, cancellation, and tamper-evident audit logging.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from ai_services.violence_detection.classifier import MockVideoClassifier
from backend.app.config.settings import Settings
from backend.app.core.ai import (
    AIErrorCategory,
    AIJobStatus,
    compute_manifest_sha256,
)
from backend.app.core.audit import AuditAction, AuditOutcome
from backend.app.core.evidence import EvidenceStatus
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.ai import AIAnalysisJob
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.department import Department
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.schemas.ai import DatasetManifestItem
from backend.app.services.password import PasswordService


def _build_test_mp4_bytes(
    duration_seconds: float = 8.0,
    timescale: int = 1000,
    width: int = 1280,
    height: int = 720,
    codec: str = "avc1",
) -> bytes:
    """Synthesize valid minimal ISO-BMFF MP4 bytes with ftyp, mvhd, and trak boxes."""
    ftyp_payload = b"isom" + struct.pack(">I", 512) + b"isom" + b"iso2" + b"mp41"
    ftyp_box = struct.pack(">I4s", len(ftyp_payload) + 8, b"ftyp") + ftyp_payload

    duration_ticks = int(duration_seconds * timescale)
    mvhd_payload = (
        b"\x00\x00\x00\x00"
        + struct.pack(">II", 0, 0)
        + struct.pack(">II", timescale, duration_ticks)
        + b"\x00" * 80
    )
    mvhd_box = struct.pack(">I4s", len(mvhd_payload) + 8, b"mvhd") + mvhd_payload

    tkhd_payload = (
        b"\x00\x00\x00\x07" + b"\x00" * 76 + struct.pack(">II", width << 16, height << 16)
    )
    tkhd_box = struct.pack(">I4s", len(tkhd_payload) + 8, b"tkhd") + tkhd_payload

    sample_entry_payload = (
        b"\x00" * 6
        + struct.pack(">H", 1)
        + b"\x00" * 16
        + struct.pack(">HH", width, height)
        + b"\x00" * 46
    )
    sample_entry_box = (
        struct.pack(">I4s", len(sample_entry_payload) + 8, codec.encode("ascii")[:4])
        + sample_entry_payload
    )

    stsd_payload = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + sample_entry_box
    stsd_box = struct.pack(">I4s", len(stsd_payload) + 8, b"stsd") + stsd_payload
    stbl_box = struct.pack(">I4s", len(stsd_box) + 8, b"stbl") + stsd_box
    minf_box = struct.pack(">I4s", len(stbl_box) + 8, b"minf") + stbl_box
    mdia_box = struct.pack(">I4s", len(minf_box) + 8, b"mdia") + minf_box
    trak_box = struct.pack(">I4s", len(tkhd_box + mdia_box) + 8, b"trak") + tkhd_box + mdia_box
    moov_payload = mvhd_box + trak_box
    moov_box = struct.pack(">I4s", len(moov_payload) + 8, b"moov") + moov_payload

    return ftyp_box + moov_box


async def _setup_batch07_group01_test_env(
    postgres_db_manager: DatabaseSessionManager,
) -> dict[str, Any]:
    """Seed test departments, roles, users, and video evidence in PostgreSQL."""
    pw_service = PasswordService()
    default_pw = "ValidPass123456!"
    hashed_pw = pw_service.hash_password(default_pw)

    async with postgres_db_manager.transactional_session() as session:
        dept_repo = DepartmentRepository(session)
        role_repo = RoleRepository(session)
        user_repo = UserRepository(session)

        roles = await role_repo.ensure_default_roles()
        suffix = uuid4().hex[:6].upper()

        dept_security = await dept_repo.create(
            Department(code=f"SEC-{suffix}", name=f"Campus Safety {suffix}", is_active=True)
        )
        dept_academic = await dept_repo.create(
            Department(code=f"ACAD-{suffix}", name=f"Academic Affairs {suffix}", is_active=True)
        )

        super_admin = await user_repo.create(
            User(
                email=f"superadmin_ai_{suffix.lower()}@ewitness.edu",
                full_name="AI Super Admin",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_sec = await user_repo.create(
            User(
                email=f"investigator_sec_ai_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator AI",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_acad = await user_repo.create(
            User(
                email=f"investigator_acad_ai_{suffix.lower()}@ewitness.edu",
                full_name="Academic Investigator AI",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_reporter = await user_repo.create(
            User(
                email=f"student_ai_{suffix.lower()}@ewitness.edu",
                full_name="Student AI Reporter",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        now = datetime.now(UTC)
        incident_sec = Incident(
            reference_number=f"SEC-AI-01-{suffix}",
            title="Altercation outside campus hall",
            description="Reported physical altercation between two unidentified subjects.",
            category="physical_assault",
            severity="high",
            status="submitted",
            location="North Quad",
            occurred_at=now - timedelta(hours=2),
            reporter_id=student_reporter.id,
            department_id=dept_security.id,
            assignment_status="unassigned",
            created_at=now - timedelta(hours=2),
            updated_at=now - timedelta(hours=2),
        )
        session.add(incident_sec)
        await session.flush()

        # Seed valid video evidence attachment for incident_sec
        storage_key_video = f"evidence/{incident_sec.id}/security_feed_{suffix.lower()}.mp4"
        evidence_video = EvidenceAttachment(
            incident_id=incident_sec.id,
            uploader_id=student_reporter.id,
            department_id=dept_security.id,
            storage_key=storage_key_video,
            original_filename="security_feed.mp4",
            file_size_bytes=4096,
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            sha256_hash="a" * 64,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status="clean",
            upload_status="completed",
            created_at=now - timedelta(hours=1),
        )
        session.add(evidence_video)

        # Seed non-video evidence attachment
        evidence_doc = EvidenceAttachment(
            incident_id=incident_sec.id,
            uploader_id=student_reporter.id,
            department_id=dept_security.id,
            storage_key=f"evidence/{incident_sec.id}/witness_report_{suffix.lower()}.pdf",
            original_filename="witness_report.pdf",
            file_size_bytes=1024,
            declared_mime_type="application/pdf",
            detected_mime_type="application/pdf",
            sha256_hash="b" * 64,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status="clean",
            upload_status="completed",
            created_at=now - timedelta(hours=1),
        )
        session.add(evidence_doc)
        await session.flush()

        return {
            "suffix": suffix,
            "dept_security": dept_security,
            "dept_academic": dept_academic,
            "super_admin": super_admin,
            "investigator_sec": investigator_sec,
            "investigator_acad": investigator_acad,
            "student_reporter": student_reporter,
            "incident_sec_id": incident_sec.id,
            "evidence_video_id": evidence_video.id,
            "evidence_doc_id": evidence_doc.id,
            "storage_key_video": storage_key_video,
            "default_pw": default_pw,
        }


async def _login(client: httpx.AsyncClient, email: str, password: str) -> str:
    """Helper to authenticate and retrieve a bearer token."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return str(resp.json()["access_token"])


@pytest.mark.asyncio
class TestBatch07Group01LivePostgres:
    """End-to-end integration tests for Phases 61-65 on real PostgreSQL."""

    async def test_phase61_and_62_dataset_governance_lifecycle(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify dataset registration, manifest validation, licensing checks, and review lifecycle."""
        data = await _setup_batch07_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["super_admin"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_student = await _login(client, data["student_reporter"].email, data["default_pw"])

            # 1. Student attempts to register dataset -> 403 Forbidden
            manifest = [
                {"path": "clip_001.mp4", "sha256_hash": "1" * 64, "label": "normal"},
                {"path": "clip_002.mp4", "sha256_hash": "2" * 64, "label": "violence"},
            ]
            expected_digest = compute_manifest_sha256(
                [DatasetManifestItem(**item).model_dump() for item in manifest]
            )

            resp_student = await client.post(
                "/api/v1/ai/datasets",
                headers={"Authorization": f"Bearer {token_student}"},
                json={
                    "name": f"unauthorized-dataset-{data['suffix']}",
                    "version": "1.0.0",
                    "dataset_type": "benchmark",
                    "source_uri": "https://datasets.ewitness.org/benchmark.tar.gz",
                    "license_id": "CC-BY-4.0",
                    "consent_status": "consented",
                    "manifest_items": manifest,
                },
            )
            assert resp_student.status_code == 403

            # 2. Reject unapproved license -> 422 Unprocessable Entity
            resp_bad_license = await client.post(
                "/api/v1/ai/datasets",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "name": f"bad-license-{data['suffix']}",
                    "version": "1.0.0",
                    "dataset_type": "benchmark",
                    "source_uri": "https://datasets.ewitness.org/proprietary.tar.gz",
                    "license_id": "Custom-Proprietary-Unapproved",
                    "manifest_items": manifest,
                },
            )
            assert resp_bad_license.status_code == 422

            # 3. Reject dataset importing operational incident evidence -> 422 BusinessRuleError
            resp_evidence_leak = await client.post(
                "/api/v1/ai/datasets",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "name": f"leak-test-{data['suffix']}",
                    "version": "1.0.0",
                    "dataset_type": "benchmark",
                    "source_uri": "https://research.ewitness.org/test.tar.gz",
                    "license_id": "Apache-2.0",
                    "manifest_items": [
                        {
                            "path": f"evidence/{data['incident_sec_id']}/video.mp4",
                            "sha256_hash": "3" * 64,
                        }
                    ],
                },
            )
            assert resp_evidence_leak.status_code == 422
            assert "operational evidence" in resp_evidence_leak.json()["error"]["message"].lower()

            # 4. Super Admin registers valid benchmark dataset -> 201 Created
            dataset_name = f"violence-benchmark-{data['suffix']}"
            resp_create = await client.post(
                "/api/v1/ai/datasets",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "name": dataset_name,
                    "version": "1.0.0",
                    "dataset_type": "benchmark",
                    "source_uri": "https://research.ewitness.org/ucf_violence_v1.tar.gz",
                    "license_id": "CC-BY-4.0",
                    "consent_status": "consented",
                    "provenance_details": {
                        "collection_date": "2026-01-15",
                        "curator": "E-Witness Safety Lab",
                    },
                    "manifest_items": manifest,
                },
            )
            assert resp_create.status_code == 201
            created_dataset = resp_create.json()
            assert created_dataset["name"] == dataset_name
            assert created_dataset["status"] == "pending_review"
            assert created_dataset["manifest_sha256"] == expected_digest
            assert created_dataset["manifest_item_count"] == 2
            dataset_id = created_dataset["id"]

            # 5. Investigator lists datasets -> 200 OK
            resp_list = await client.get(
                "/api/v1/ai/datasets",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_list.status_code == 200
            items = resp_list.json()["items"]
            matching = [d for d in items if d["id"] == dataset_id]
            assert len(matching) == 1

            # 6. Investigator cannot approve dataset -> 403 Forbidden
            resp_unauth_review = await client.post(
                f"/api/v1/ai/datasets/{dataset_id}/review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"decision": "approved", "review_notes": "Looks good"},
            )
            assert resp_unauth_review.status_code == 403

            # 7. Super Admin approves dataset -> 200 OK
            resp_review = await client.post(
                f"/api/v1/ai/datasets/{dataset_id}/review",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "decision": "approved",
                    "review_notes": "Ethics & license compliance verified",
                },
            )
            assert resp_review.status_code == 200
            approved_dataset = resp_review.json()
            assert approved_dataset["status"] == "approved"
            assert approved_dataset["review_notes"] == "Ethics & license compliance verified"

            # 8. Verify audit events in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                stmt = select(SecurityAuditEvent).where(SecurityAuditEvent.target_id == dataset_id)
                audit_records = (await session.execute(stmt)).scalars().all()
                actions = {r.action for r in audit_records}
                assert AuditAction.AI_DATASET_REGISTERED.value in actions
                assert AuditAction.AI_DATASET_REVIEWED.value in actions

    async def test_phase63_and_65_ai_analysis_job_submission_and_execution(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify video analysis job submission, execution, progress tracking, and audit logging."""
        data = await _setup_batch07_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        # Seed valid MP4 video bytes into storage client
        valid_video_bytes = _build_test_mp4_bytes(
            duration_seconds=6.0,
            width=1280,
            height=720,
            codec="avc1",
        )
        await storage.put_object(
            data["storage_key_video"],
            valid_video_bytes,
            content_type="video/mp4",
        )

        # Set mock classifier on app state
        app.state.classifier = MockVideoClassifier(
            is_violence_detected=True,
            violence_score=0.88,
            model_name="mock_violence_vit",
            model_version="v2.1.0",
        )

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )
            token_student = await _login(client, data["student_reporter"].email, data["default_pw"])

            # 1. Student cannot submit AI job -> 403 Forbidden
            resp_student = await client.post(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_student}"},
                json={"evidence_id": str(data["evidence_video_id"])},
            )
            assert resp_student.status_code == 403

            # 2. Academic investigator cannot submit job on Campus Safety evidence -> 403 Forbidden
            resp_cross_dept = await client.post(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
                json={"evidence_id": str(data["evidence_video_id"])},
            )
            assert resp_cross_dept.status_code == 403

            # 3. Reject non-video attachment -> 415 Unsupported Media Type
            resp_non_video = await client.post(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"evidence_id": str(data["evidence_doc_id"])},
            )
            assert resp_non_video.status_code == 415

            # 4. Security investigator submits AI job for valid video evidence -> 202 Accepted
            resp_submit = await client.post(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"evidence_id": str(data["evidence_video_id"])},
            )
            assert resp_submit.status_code == 202
            job_dto = resp_submit.json()
            job_id = job_dto["id"]
            assert job_dto["evidence_id"] == str(data["evidence_video_id"])
            assert job_dto["department_id"] == str(data["dept_security"].id)

            # 5. Fetch job status (via HTTP endpoint)
            resp_get = await client.get(
                f"/api/v1/ai/jobs/{job_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_get.status_code == 200
            current_job = resp_get.json()
            # Because BackgroundTasks executed during request completion, job reached SUCCEEDED
            assert current_job["status"] == AIJobStatus.SUCCEEDED.value
            assert current_job["progress_percent"] == 100
            assert current_job["result_summary"] is not None
            summary = current_job["result_summary"]
            assert summary["is_violence_detected"] is True
            assert summary["violence_score"] == 0.88
            assert "human review" in summary["disclaimer"].lower()

            # 6. Verify audit records in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                stmt = select(SecurityAuditEvent).where(SecurityAuditEvent.target_id == job_id)
                audit_records = (await session.execute(stmt)).scalars().all()
                actions = {r.action for r in audit_records}
                assert AuditAction.AI_JOB_SUBMITTED.value in actions
                assert AuditAction.AI_JOB_STARTED.value in actions
                assert AuditAction.AI_JOB_COMPLETED.value in actions

    async def test_phase64_classifier_failure_safe_handling(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify that when AI model is unavailable, job fails safe without score fabrication."""
        data = await _setup_batch07_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        # Valid MP4 video in storage
        valid_video_bytes = _build_test_mp4_bytes(duration_seconds=5.0)
        await storage.put_object(
            data["storage_key_video"],
            valid_video_bytes,
            content_type="video/mp4",
        )

        # Classifier explicitly configured to be NOT ready (simulates missing weights or torch)
        app.state.classifier = MockVideoClassifier(is_ready_override=False)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])

            resp_submit = await client.post(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"evidence_id": str(data["evidence_video_id"])},
            )
            assert resp_submit.status_code == 202
            job_id = resp_submit.json()["id"]

            resp_get = await client.get(
                f"/api/v1/ai/jobs/{job_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_get.status_code == 200
            failed_job = resp_get.json()
            assert failed_job["status"] == AIJobStatus.FAILED.value
            assert failed_job["error_category"] == AIErrorCategory.MODEL_UNAVAILABLE.value
            assert failed_job["result_summary"] is None  # Never fabricate scores!

            # Verify failure audit event recorded
            async with postgres_db_manager.transactional_session() as session:
                stmt = select(SecurityAuditEvent).where(
                    SecurityAuditEvent.target_id == job_id,
                    SecurityAuditEvent.action == AuditAction.AI_JOB_FAILED.value,
                )
                failure_event = (await session.execute(stmt)).scalar_one_or_none()
                assert failure_event is not None
                assert failure_event.outcome == AuditOutcome.FAILURE.value

    async def test_phase65_department_isolation_and_cancellation(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify cross-department isolation on job status/cancel and cancellation state transitions."""
        data = await _setup_batch07_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )

            # 1. Directly insert a QUEUED job for SEC department in DB to avoid background execution
            async with postgres_db_manager.transactional_session() as session:
                queued_job = AIAnalysisJob(
                    id=uuid4(),
                    evidence_id=data["evidence_video_id"],
                    incident_id=data["incident_sec_id"],
                    department_id=data["dept_security"].id,
                    submitted_by_id=data["investigator_sec"].id,
                    status=AIJobStatus.QUEUED.value,
                    model_name="mock_violence_vit",
                    model_version="v2.1.0",
                )
                session.add(queued_job)
                await session.flush()
                sec_job_id = queued_job.id

            # 2. Academic investigator attempts to retrieve SEC job -> 404 Not Found (scoped query)
            resp_cross_get = await client.get(
                f"/api/v1/ai/jobs/{sec_job_id}",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_cross_get.status_code == 404

            # 3. Academic investigator lists jobs -> does not see SEC job
            resp_acad_list = await client.get(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_acad_list.status_code == 200
            acad_items = resp_acad_list.json()["items"]
            assert str(sec_job_id) not in {item["id"] for item in acad_items}

            # 4. Academic investigator attempts to cancel SEC job -> 404 Not Found (scoped query)
            resp_cross_cancel = await client.post(
                f"/api/v1/ai/jobs/{sec_job_id}/cancel",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_cross_cancel.status_code == 404

            # 5. Security investigator cancels their queued job -> 200 OK
            resp_cancel = await client.post(
                f"/api/v1/ai/jobs/{sec_job_id}/cancel",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_cancel.status_code == 200
            cancelled_job = resp_cancel.json()
            assert cancelled_job["status"] == AIJobStatus.CANCELLED.value

            # 6. Attempting to cancel an already terminal job -> 409 Conflict
            resp_re_cancel = await client.post(
                f"/api/v1/ai/jobs/{sec_job_id}/cancel",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_re_cancel.status_code == 409
            assert "terminal" in resp_re_cancel.json()["error"]["message"].lower()

            # 7. Verify cancellation audit record in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                stmt = select(SecurityAuditEvent).where(
                    SecurityAuditEvent.target_id == str(sec_job_id),
                    SecurityAuditEvent.action == AuditAction.AI_JOB_CANCELLED.value,
                )
                cancel_event = (await session.execute(stmt)).scalar_one_or_none()
                assert cancel_event is not None
                assert cancel_event.actor_id == data["investigator_sec"].id
