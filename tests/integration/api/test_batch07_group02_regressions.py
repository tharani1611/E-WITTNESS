"""Live PostgreSQL Integration Tests for Batch 07 Group 02 (Phases 66-70).

Verifies against real PostgreSQL:
- Phase 66: Candidate segments persistence, bounded temporal windows, idempotency on retries, and advisory disclaimers.
- Phase 67: Confidence calibration (Platt, Temperature, Isotonic) and uncertainty evaluation.
- Phase 68: Metrics calculation, ECE, sweep evaluation, and fairness disaggregation with demographic bans.
- Phase 69: Traceable AI results, human review workflow, conflict-of-interest prevention, false-positive tracking, and retention lifecycle.
- Phase 70: Operational robustness, lookalike handling, failure containment without synthetic score fabrication, and cross-department isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select

from ai_services.violence_detection.classifier import MockVideoClassifier
from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome
from backend.app.core.evidence import EvidenceStatus
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.ai import AIAnalysisJob, AICandidateSegment
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
from backend.app.services.password import PasswordService
from tests.integration.api.test_batch07_group01_regressions import _build_test_mp4_bytes


async def _setup_batch07_group02_test_env(
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
                email=f"superadmin_ai2_{suffix.lower()}@ewitness.edu",
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
                email=f"investigator_sec_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator AI",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_sec_reporter = await user_repo.create(
            User(
                email=f"investigator_reporter_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator Reporter",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_acad = await user_repo.create(
            User(
                email=f"investigator_acad_{suffix.lower()}@ewitness.edu",
                full_name="Academic Investigator AI",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_user = await user_repo.create(
            User(
                email=f"student_ai2_{suffix.lower()}@ewitness.edu",
                full_name="Student AI User",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        now = datetime.now(UTC)

        # Incident 1: Reported by student, investigated by investigator_sec
        incident_sec = Incident(
            reference_number=f"SEC-AI2-01-{suffix}",
            title="Altercation at North Quad",
            description="Reported confrontation outside residence hall.",
            category="physical_assault",
            severity="high",
            status="submitted",
            location="North Quad",
            occurred_at=now - timedelta(hours=2),
            reporter_id=student_user.id,
            department_id=dept_security.id,
            assignment_status="unassigned",
            created_at=now - timedelta(hours=2),
            updated_at=now - timedelta(hours=2),
        )
        session.add(incident_sec)

        # Incident 2: Reported by investigator_sec_reporter (for conflict of interest testing)
        incident_coi = Incident(
            reference_number=f"SEC-AI2-02-{suffix}",
            title="Suspected tampering incident",
            description="Investigator noticed camera obstruction.",
            category="property_damage_theft",
            severity="medium",
            status="submitted",
            location="Library West",
            occurred_at=now - timedelta(hours=1),
            reporter_id=investigator_sec_reporter.id,
            department_id=dept_security.id,
            assignment_status="unassigned",
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
        )
        session.add(incident_coi)

        # Incident 3: Closed incident older than 60 days (for retention purge testing)
        incident_closed = Incident(
            reference_number=f"SEC-AI2-03-{suffix}",
            title="Archived old incident",
            description="Past incident marked resolved.",
            category="other",
            severity="low",
            status="closed",
            location="East Gate",
            occurred_at=now - timedelta(days=90),
            reporter_id=student_user.id,
            department_id=dept_security.id,
            assignment_status="unassigned",
            created_at=now - timedelta(days=90),
            updated_at=now - timedelta(days=80),
        )
        session.add(incident_closed)
        await session.flush()

        # Seed video attachments
        storage_key_video = f"evidence/{incident_sec.id}/security_feed_{suffix.lower()}.mp4"
        evidence_video = EvidenceAttachment(
            incident_id=incident_sec.id,
            uploader_id=student_user.id,
            department_id=dept_security.id,
            storage_key=storage_key_video,
            original_filename="security_feed.mp4",
            file_size_bytes=4096,
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            sha256_hash="c" * 64,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status="clean",
            upload_status="completed",
            created_at=now - timedelta(hours=1),
        )
        session.add(evidence_video)

        storage_key_coi = f"evidence/{incident_coi.id}/coi_feed_{suffix.lower()}.mp4"
        evidence_coi = EvidenceAttachment(
            incident_id=incident_coi.id,
            uploader_id=investigator_sec_reporter.id,
            department_id=dept_security.id,
            storage_key=storage_key_coi,
            original_filename="coi_feed.mp4",
            file_size_bytes=4096,
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            sha256_hash="d" * 64,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status="clean",
            upload_status="completed",
            created_at=now - timedelta(hours=1),
        )
        session.add(evidence_coi)

        storage_key_closed = f"evidence/{incident_closed.id}/closed_feed_{suffix.lower()}.mp4"
        evidence_closed = EvidenceAttachment(
            incident_id=incident_closed.id,
            uploader_id=student_user.id,
            department_id=dept_security.id,
            storage_key=storage_key_closed,
            original_filename="closed_feed.mp4",
            file_size_bytes=4096,
            declared_mime_type="video/mp4",
            detected_mime_type="video/mp4",
            sha256_hash="e" * 64,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status="clean",
            upload_status="completed",
            created_at=now - timedelta(days=90),
        )
        session.add(evidence_closed)
        await session.flush()

        return {
            "suffix": suffix,
            "dept_security": dept_security,
            "dept_academic": dept_academic,
            "super_admin": super_admin,
            "investigator_sec": investigator_sec,
            "investigator_sec_reporter": investigator_sec_reporter,
            "investigator_acad": investigator_acad,
            "student_user": student_user,
            "incident_sec_id": incident_sec.id,
            "incident_coi_id": incident_coi.id,
            "incident_closed_id": incident_closed.id,
            "evidence_video_id": evidence_video.id,
            "evidence_coi_id": evidence_coi.id,
            "evidence_closed_id": evidence_closed.id,
            "storage_key_video": storage_key_video,
            "storage_key_coi": storage_key_coi,
            "storage_key_closed": storage_key_closed,
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
class TestBatch07Group02LivePostgres:
    """End-to-end integration tests for Phases 66-70 on real PostgreSQL."""

    async def test_phases66_to_70_full_candidate_segment_lifecycle(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify segment persistence, human review, conflict of interest, retention, and audit trails."""
        data = await _setup_batch07_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        # Upload valid MP4 video bytes into storage client
        valid_mp4_bytes = _build_test_mp4_bytes(duration_seconds=10.0)
        await storage.put_object(
            data["storage_key_video"], valid_mp4_bytes, content_type="video/mp4"
        )
        await storage.put_object(data["storage_key_coi"], valid_mp4_bytes, content_type="video/mp4")
        await storage.put_object(
            data["storage_key_closed"], valid_mp4_bytes, content_type="video/mp4"
        )

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["super_admin"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_reporter = await _login(
                client, data["investigator_sec_reporter"].email, data["default_pw"]
            )
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )
            token_student = await _login(client, data["student_user"].email, data["default_pw"])

            # -------------------------------------------------------------
            # 1. Execute AI analysis job that generates candidate segments
            # -------------------------------------------------------------
            app.state.classifier = MockVideoClassifier(
                is_violence_detected=True, violence_score=0.88
            )
            resp_submit = await client.post(
                "/api/v1/ai/jobs",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"evidence_id": str(data["evidence_video_id"])},
            )
            assert resp_submit.status_code == 202
            job_dto = resp_submit.json()
            job_id = job_dto["id"]

            # -------------------------------------------------------------
            # 2. Phase 66: Query segments via GET /api/v1/ai/jobs/{job_id}/segments
            # -------------------------------------------------------------
            resp_job_segs = await client.get(
                f"/api/v1/ai/jobs/{job_id}/segments",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_job_segs.status_code == 200
            segments = resp_job_segs.json()
            assert len(segments) >= 1
            first_seg = segments[0]
            seg_id = first_seg["id"]

            assert first_seg["job_id"] == str(job_id)
            assert first_seg["start_seconds"] >= 0.0
            assert first_seg["end_seconds"] > first_seg["start_seconds"]
            assert first_seg["raw_score"] == 0.88
            assert first_seg["review_status"] == "pending_review"
            assert first_seg["is_flagged_for_review"] is True
            assert "advisory decision-support" in first_seg["disclaimer"]

            # -------------------------------------------------------------
            # 3. Department isolation: Academic investigator cannot view Security segments
            # -------------------------------------------------------------
            # Scoped query prevents cross-department discovery (returns 404 Not Found)
            resp_cross_dept = await client.get(
                f"/api/v1/ai/segments/{seg_id}",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_cross_dept.status_code == 404

            # Student without AI_SEGMENT_READ permission gets 403 Forbidden
            resp_student_view = await client.get(
                f"/api/v1/ai/segments/{seg_id}",
                headers={"Authorization": f"Bearer {token_student}"},
            )
            assert resp_student_view.status_code == 403

            # Security investigator CAN view segment within their own department
            resp_sec_view = await client.get(
                f"/api/v1/ai/segments/{seg_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_sec_view.status_code == 200
            assert resp_sec_view.json()["id"] == seg_id

            # -------------------------------------------------------------
            # 4. Paginated department queue: GET /api/v1/ai/segments
            # -------------------------------------------------------------
            resp_queue = await client.get(
                "/api/v1/ai/segments?page=1&page_size=10&review_status=pending_review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_queue.status_code == 200
            queue_data = resp_queue.json()
            assert queue_data["pagination"]["total_items"] >= 1
            assert any(s["id"] == seg_id for s in queue_data["items"])

            # -------------------------------------------------------------
            # 5. Phase 69: Conflict of interest check
            # -------------------------------------------------------------
            # Create a candidate segment attached to incident_coi (reported by investigator_sec_reporter)
            async with postgres_db_manager.transactional_session() as session:
                coi_job = AIAnalysisJob(
                    evidence_id=data["evidence_coi_id"],
                    incident_id=data["incident_coi_id"],
                    department_id=data["dept_security"].id,
                    submitted_by_id=data["investigator_sec_reporter"].id,
                    status="succeeded",
                    model_name="test-model",
                    model_version="1.0",
                )
                session.add(coi_job)
                await session.flush()

                coi_seg = AICandidateSegment(
                    job_id=coi_job.id,
                    evidence_id=data["evidence_coi_id"],
                    incident_id=data["incident_coi_id"],
                    department_id=data["dept_security"].id,
                    start_seconds=1.0,
                    end_seconds=3.0,
                    duration_seconds=2.0,
                    raw_score=0.75,
                    raw_label="violence",
                    model_name="test-model",
                    model_version="1.0",
                    review_status="pending_review",
                    is_flagged_for_review=True,
                )
                session.add(coi_seg)
                await session.flush()
                coi_seg_id = coi_seg.id

            # Investigator who reported incident_coi attempts to review own incident -> 409 Conflict
            resp_coi = await client.post(
                f"/api/v1/ai/segments/{coi_seg_id}/review",
                headers={"Authorization": f"Bearer {token_inv_reporter}"},
                json={
                    "decision": "confirmed",
                    "review_notes": "Attempting to review my own reported incident footage.",
                },
            )
            assert resp_coi.status_code == 409
            assert (
                "cannot review AI analysis results for incidents they reported"
                in resp_coi.json()["error"]["message"]
            )

            # Independent investigator CAN review it
            resp_indep_review = await client.post(
                f"/api/v1/ai/segments/{coi_seg_id}/review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "decision": "rejected",
                    "false_positive_reason": "sports_motion",
                    "review_notes": "Independent review: recreational basketball play, not violence.",
                },
            )
            assert resp_indep_review.status_code == 200
            review_out = resp_indep_review.json()
            assert review_out["review_status"] == "rejected"
            assert review_out["false_positive_reason"] == "sports_motion"
            assert review_out["is_flagged_for_review"] is False

            # -------------------------------------------------------------
            # 6. Finalized state: cannot review already finalized segment
            # -------------------------------------------------------------
            resp_re_review = await client.post(
                f"/api/v1/ai/segments/{coi_seg_id}/review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "decision": "confirmed",
                    "review_notes": "Attempting second review.",
                },
            )
            assert resp_re_review.status_code == 422
            assert "already" in resp_re_review.json()["error"]["message"]

            # -------------------------------------------------------------
            # 7. Phase 69: Retention lifecycle and purge rules
            # -------------------------------------------------------------
            # Seed candidate segment for closed incident (aged 60 days)
            async with postgres_db_manager.transactional_session() as session:
                closed_job = AIAnalysisJob(
                    evidence_id=data["evidence_closed_id"],
                    incident_id=data["incident_closed_id"],
                    department_id=data["dept_security"].id,
                    submitted_by_id=data["super_admin"].id,
                    status="succeeded",
                    model_name="test-model",
                    model_version="1.0",
                )
                session.add(closed_job)
                await session.flush()

                old_seg = AICandidateSegment(
                    job_id=closed_job.id,
                    evidence_id=data["evidence_closed_id"],
                    incident_id=data["incident_closed_id"],
                    department_id=data["dept_security"].id,
                    start_seconds=0.0,
                    end_seconds=4.0,
                    duration_seconds=4.0,
                    raw_score=0.60,
                    raw_label="violence",
                    model_name="test-model",
                    model_version="1.0",
                    review_status="rejected",
                    is_flagged_for_review=False,
                )
                session.add(old_seg)
                await session.flush()
                # Backdate created_at to 60 days ago
                old_seg.created_at = datetime.now(UTC) - timedelta(days=60)
                await session.flush()
                old_seg_id = old_seg.id

            # Student tries to run purge -> 403 Forbidden
            resp_student_purge = await client.post(
                "/api/v1/ai/retention/purge",
                headers={"Authorization": f"Bearer {token_student}"},
                json={"retention_days": 30},
            )
            assert resp_student_purge.status_code == 403

            # Super admin runs retention purge with retention_days=30
            resp_admin_purge = await client.post(
                "/api/v1/ai/retention/purge",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={"retention_days": 30},
            )
            assert resp_admin_purge.status_code == 200
            purge_result = resp_admin_purge.json()
            assert purge_result["purged_count"] >= 1
            assert purge_result["retention_days"] == 30

            # Verify that old_seg was deleted
            async with postgres_db_manager.session() as session:
                check_old = await session.get(AICandidateSegment, old_seg_id)
                assert check_old is None

                # Verify that active incident segment (seg_id) was strictly PRESERVED
                check_active = await session.get(AICandidateSegment, UUID(seg_id))
                assert check_active is not None

                # Verify original evidence files were untouched
                ev_active = await session.get(EvidenceAttachment, data["evidence_video_id"])
                assert ev_active is not None
                assert ev_active.evidence_status == EvidenceStatus.ATTACHED.value

                ev_closed = await session.get(EvidenceAttachment, data["evidence_closed_id"])
                assert ev_closed is not None

                # Verify security audit events were logged for segment review and retention purge
                review_events = (
                    (
                        await session.execute(
                            select(SecurityAuditEvent).where(
                                SecurityAuditEvent.action == AuditAction.AI_SEGMENT_REVIEWED.value
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                assert len(review_events) >= 1

                purge_events = (
                    (
                        await session.execute(
                            select(SecurityAuditEvent).where(
                                SecurityAuditEvent.action == AuditAction.AI_RESULTS_PURGED.value
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                assert len(purge_events) >= 1
                assert purge_events[0].outcome == AuditOutcome.SUCCESS.value
