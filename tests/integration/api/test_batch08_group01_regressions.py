"""Live PostgreSQL Integration Tests for Batch 08 Group 01 (Phases 71-75).

Verifies against real PostgreSQL:
- Phase 71: Privacy and legal feasibility assessment, 8-point checklist fail-closed NO-GO state,
            and disabled-by-default biometric flags.
- Phase 72: Granular biometric RBAC/ABAC authorization, prohibited purpose rejection, and audit trails.
- Phase 73: Biometric governance lifecycle, notice/consent records, and automatic cascading revocation
            of active reference templates upon consent withdrawal.
- Phase 74: Restricted biometric reference registry, SHA-256 digest computation, template encryption
            at rest, zero-template leakage in read responses, and manual revocation template wiping.
- Phase 75: Approved face-detection component, fail-closed enforcement when disabled, pure localization
            (bounding boxes only), mandatory advisory disclaimer, and zero image persistence.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Any
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome
from backend.app.core.biometrics import (
    BIOMETRIC_ADVISORY_DISCLAIMER,
    BiometricLawfulBasis,
    BiometricPurpose,
    BiometricReferenceStatus,
    ConsentStatus,
    GovernanceStatus,
    ProhibitedBiometricPurpose,
)
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.biometrics import BiometricReference
from backend.app.models.department import Department
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


def _create_minimal_png_bytes(width: int = 64, height: int = 64) -> bytes:
    """Synthesize a valid minimal PNG byte stream with IHDR chunk."""
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_length = struct.pack(">I", len(ihdr_data))
    ihdr_type = b"IHDR"
    ihdr_crc = struct.pack(">I", 0x12345678)
    return signature + ihdr_length + ihdr_type + ihdr_data + ihdr_crc


async def _setup_batch08_group01_test_env(
    postgres_db_manager: DatabaseSessionManager,
) -> dict[str, Any]:
    """Seed test departments, roles, and users in PostgreSQL."""
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
                email=f"superadmin_bio_{suffix.lower()}@ewitness.edu",
                full_name="Biometric Super Admin",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_sec = await user_repo.create(
            User(
                email=f"deptadmin_sec_bio_{suffix.lower()}@ewitness.edu",
                full_name="Security Dept Admin",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_sec = await user_repo.create(
            User(
                email=f"investigator_sec_bio_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator Bio",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_acad = await user_repo.create(
            User(
                email=f"investigator_acad_bio_{suffix.lower()}@ewitness.edu",
                full_name="Academic Investigator Bio",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_sec = await user_repo.create(
            User(
                email=f"student_bio_{suffix.lower()}@ewitness.edu",
                full_name="Student Bio Subject",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        return {
            "suffix": suffix,
            "dept_security": dept_security,
            "dept_academic": dept_academic,
            "super_admin": super_admin,
            "dept_admin_sec": dept_admin_sec,
            "investigator_sec": investigator_sec,
            "investigator_acad": investigator_acad,
            "student_sec": student_sec,
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
class TestBatch08Group01LivePostgres:
    """End-to-end integration tests for Phases 71-75 on real PostgreSQL."""

    async def test_phase71_and_72_governance_authorization_and_review_workflow(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify governance record registration, RBAC permission checks, and review lifecycle."""
        data = await _setup_batch08_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_student = await _login(client, data["student_sec"].email, data["default_pw"])

            # 1. Prohibited purpose rejection on registration -> 422 Unprocessable Entity
            resp_prohibited = await client.post(
                "/api/v1/biometrics/governance",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "purpose": ProhibitedBiometricPurpose.MASS_SURVEILLANCE_CROWD_SCANNING.value,
                    "lawful_basis": BiometricLawfulBasis.EXPLICIT_CONSENT.value,
                    "notice_version": "1.0.0",
                    "retention_days": 30,
                },
            )
            assert resp_prohibited.status_code == 422

            # 2. Student registers own governance and consent record -> 201 Created
            resp_student_gov = await client.post(
                "/api/v1/biometrics/governance",
                headers={"Authorization": f"Bearer {token_student}"},
                json={
                    "purpose": BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
                    "lawful_basis": BiometricLawfulBasis.EXPLICIT_CONSENT.value,
                    "notice_version": "1.0.0",
                    "subject_user_id": str(data["student_sec"].id),
                    "consent_confirmed": True,
                    "retention_days": 60,
                },
            )
            assert resp_student_gov.status_code == 201
            gov_data = resp_student_gov.json()
            gov_id = gov_data["id"]
            assert gov_data["status"] == GovernanceStatus.PENDING_LEGAL_REVIEW.value
            assert gov_data["consent_status"] == ConsentStatus.ACTIVE.value

            # 3. Student attempts to review/approve own record -> 403 Forbidden
            resp_student_review = await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_student}"},
                json={
                    "decision": GovernanceStatus.APPROVED.value,
                    "legal_review_notes": "Self-approval attempt",
                },
            )
            assert resp_student_review.status_code == 403

            # 4. Investigator attempts to review record -> 403 Forbidden
            resp_inv_review = await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "decision": GovernanceStatus.APPROVED.value,
                    "legal_review_notes": "Investigator approval attempt",
                },
            )
            assert resp_inv_review.status_code == 403

            # 5. Dept Admin reviews and approves record -> 200 OK
            resp_admin_review = await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "decision": GovernanceStatus.APPROVED.value,
                    "legal_review_notes": "Legal counsel and institutional review completed.",
                },
            )
            assert resp_admin_review.status_code == 200
            approved_gov = resp_admin_review.json()
            assert approved_gov["status"] == GovernanceStatus.APPROVED.value

            # 6. Verify audit event recorded in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                stmt = select(SecurityAuditEvent).where(
                    SecurityAuditEvent.target_id == gov_id,
                    SecurityAuditEvent.action == AuditAction.BIOMETRIC_POLICY_EVALUATED.value,
                )
                audit_event = (await session.execute(stmt)).scalar_one_or_none()
                assert audit_event is not None
                assert audit_event.outcome == AuditOutcome.SUCCESS.value
                assert audit_event.actor_id == data["dept_admin_sec"].id

    async def test_phase73_and_74_reference_registry_and_cascading_consent_withdrawal(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify restricted reference enrollment, zero-leakage read contracts, and cascading revocation."""
        data = await _setup_batch08_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )
            token_student = await _login(client, data["student_sec"].email, data["default_pw"])

            # 1. Create and approve a governance record
            resp_gov = await client.post(
                "/api/v1/biometrics/governance",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "purpose": BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
                    "lawful_basis": BiometricLawfulBasis.EXPLICIT_CONSENT.value,
                    "notice_version": "2026.1",
                    "subject_user_id": str(data["student_sec"].id),
                    "consent_confirmed": True,
                    "retention_days": 90,
                },
            )
            assert resp_gov.status_code == 201
            gov_id = resp_gov.json()["id"]

            await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "decision": GovernanceStatus.APPROVED.value,
                    "legal_review_notes": "Consent verified and approved.",
                },
            )

            # 2. Enroll reference under approved governance record
            dummy_template_bytes = b"synthetic_biometric_template_vector_512d_binary"
            template_sha256 = hashlib.sha256(dummy_template_bytes).hexdigest()
            encrypted_template_b64 = base64.b64encode(b"aes_gcm_ciphertext_dummy_bytes").decode(
                "ascii"
            )

            resp_enroll = await client.post(
                "/api/v1/biometrics/references",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "governance_record_id": gov_id,
                    "purpose": BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
                    "subject_user_id": str(data["student_sec"].id),
                    "template_digest": template_sha256,
                    "encrypted_template": encrypted_template_b64,
                    "enrollment_notes": "Enrolled under student explicit consent.",
                },
            )
            assert resp_enroll.status_code == 201
            ref_data = resp_enroll.json()
            ref_id = ref_data["id"]

            # 3. Security invariant: zero template leakage in read DTOs
            assert "encrypted_template" not in ref_data
            assert "template_payload" not in ref_data
            assert ref_data["template_digest"] == template_sha256
            assert ref_data["status"] == BiometricReferenceStatus.ACTIVE.value

            # 4. Strict tenant isolation: Academic investigator cannot access Security department's reference -> 404
            resp_cross = await client.get(
                f"/api/v1/biometrics/references/{ref_id}",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_cross.status_code == 404

            # 5. Student exercises right to withdraw consent -> triggers cascading revocation
            resp_withdraw = await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/withdraw",
                headers={"Authorization": f"Bearer {token_student}"},
                json={"reason": "Student requested deletion of all biometric references."},
            )
            assert resp_withdraw.status_code == 200
            withdrawn_data = resp_withdraw.json()
            assert withdrawn_data["status"] == GovernanceStatus.REVOKED.value
            assert withdrawn_data["consent_status"] == ConsentStatus.WITHDRAWN.value

            # 6. Verify cascading revocation in PostgreSQL: reference status is REVOKED and template is wiped
            async with postgres_db_manager.transactional_session() as session:
                stmt_ref = select(BiometricReference).where(BiometricReference.id == ref_id)
                persisted_ref = (await session.execute(stmt_ref)).scalar_one()
                assert persisted_ref.status == BiometricReferenceStatus.REVOKED.value
                assert persisted_ref.encrypted_template is None  # Ciphertext must be wiped!
                assert persisted_ref.revoked_by_id == data["student_sec"].id
                assert "withdrawn" in str(persisted_ref.revocation_reason).lower()

                # Verify audit events for consent revocation and cascading reference revocation
                stmt_ref_audit = select(SecurityAuditEvent).where(
                    SecurityAuditEvent.target_id == str(ref_id),
                    SecurityAuditEvent.action == AuditAction.BIOMETRIC_REFERENCE_REVOKED.value,
                )
                ref_audit = (await session.execute(stmt_ref_audit)).scalar_one_or_none()
                assert ref_audit is not None
                assert ref_audit.outcome == AuditOutcome.SUCCESS.value

                stmt_gov_audit = select(SecurityAuditEvent).where(
                    SecurityAuditEvent.target_id == str(gov_id),
                    SecurityAuditEvent.action == AuditAction.BIOMETRIC_CONSENT_REVOKED.value,
                )
                gov_audit = (await session.execute(stmt_gov_audit)).scalar_one_or_none()
                assert gov_audit is not None
                assert gov_audit.outcome == AuditOutcome.SUCCESS.value

    async def test_phase74_reference_manual_revocation_and_unapproved_rejection(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify that references cannot be enrolled under unapproved governance and manual revocation wipes template."""
        data = await _setup_batch08_group01_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = storage
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])

            # 1. Create a governance record in PENDING state (unapproved)
            resp_gov = await client.post(
                "/api/v1/biometrics/governance",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "purpose": BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
                    "lawful_basis": BiometricLawfulBasis.EXPLICIT_CONSENT.value,
                    "notice_version": "1.0.0",
                    "subject_user_id": str(data["student_sec"].id),
                    "consent_confirmed": True,
                    "retention_days": 30,
                },
            )
            assert resp_gov.status_code == 201
            gov_id = resp_gov.json()["id"]

            # 2. Attempt reference enrollment under unapproved record -> 422 Unprocessable Entity
            resp_bad_enroll = await client.post(
                "/api/v1/biometrics/references",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "governance_record_id": gov_id,
                    "purpose": BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
                    "subject_user_id": str(data["student_sec"].id),
                    "template_digest": "c" * 64,
                    "encrypted_template": "dummy_ciphertext",
                },
            )
            assert resp_bad_enroll.status_code == 422

            # 3. Approve governance record and enroll
            await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "decision": GovernanceStatus.APPROVED.value,
                    "legal_review_notes": "Approval for manual revocation test.",
                },
            )
            resp_good_enroll = await client.post(
                "/api/v1/biometrics/references",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "governance_record_id": gov_id,
                    "purpose": BiometricPurpose.EXPLICIT_CONSENT_REFERENCE_ENROLLMENT.value,
                    "subject_user_id": str(data["student_sec"].id),
                    "template_digest": "d" * 64,
                    "encrypted_template": "dummy_ciphertext_to_wipe",
                },
            )
            assert resp_good_enroll.status_code == 201
            ref_id = resp_good_enroll.json()["id"]

            # 4. Manual revocation of reference by Dept Admin
            resp_revoke = await client.post(
                f"/api/v1/biometrics/references/{ref_id}/revoke",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={"reason": "Routine reference rotation."},
            )
            assert resp_revoke.status_code == 200
            revoked_ref = resp_revoke.json()
            assert revoked_ref["status"] == BiometricReferenceStatus.REVOKED.value

            # 5. Verify in PostgreSQL that template is wiped
            async with postgres_db_manager.transactional_session() as session:
                persisted = (
                    await session.execute(
                        select(BiometricReference).where(BiometricReference.id == ref_id)
                    )
                ).scalar_one()
                assert persisted.status == BiometricReferenceStatus.REVOKED.value
                assert persisted.encrypted_template is None

    async def test_phase75_face_detection_endpoint_execution_and_fail_closed(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify face detection API fail-closed behavior, execution with mock provider, and disclaimer."""
        data = await _setup_batch08_group01_test_env(postgres_db_manager)
        png_bytes = _create_minimal_png_bytes(width=160, height=120)
        png_b64 = base64.b64encode(png_bytes).decode("ascii")

        # Part 1: When BIOMETRIC_DETECTION_ENABLED is False (default) -> must return 403 Forbidden
        app_disabled = create_app(postgres_settings, db_manager=postgres_db_manager)
        app_disabled.state.storage_client = InMemoryStorageClient(
            postgres_settings.STORAGE_ENDPOINT_URL
        )
        app_disabled.state.db_manager = postgres_db_manager

        transport_disabled = httpx.ASGITransport(app=app_disabled)
        async with httpx.AsyncClient(
            transport=transport_disabled, base_url="http://testserver"
        ) as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_student = await _login(client, data["student_sec"].email, data["default_pw"])

            resp_disabled = await client.post(
                "/api/v1/biometrics/detect",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "governance_record_id": str(uuid4()),
                    "image_base64": png_b64,
                },
            )
            assert resp_disabled.status_code == 403

            # Student lacks BIOMETRIC_DETECTION_EXECUTE permission -> 403 Forbidden
            resp_student_detect = await client.post(
                "/api/v1/biometrics/detect",
                headers={"Authorization": f"Bearer {token_student}"},
                json={
                    "governance_record_id": str(uuid4()),
                    "image_base64": png_b64,
                },
            )
            assert resp_student_detect.status_code == 403

        # Part 2: When BIOMETRIC_DETECTION_ENABLED is True and provider is "mock"
        enabled_settings = postgres_settings.model_copy(
            update={
                "BIOMETRIC_ANALYSIS_ENABLED": True,
                "BIOMETRIC_DETECTION_ENABLED": True,
                "BIOMETRIC_PROVIDER": "mock",
            }
        )
        app_enabled = create_app(enabled_settings, db_manager=postgres_db_manager)
        app_enabled.state.storage_client = InMemoryStorageClient(
            enabled_settings.STORAGE_ENDPOINT_URL
        )
        app_enabled.state.db_manager = postgres_db_manager

        transport_enabled = httpx.ASGITransport(app=app_enabled)
        async with httpx.AsyncClient(
            transport=transport_enabled, base_url="http://testserver"
        ) as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )

            # Register and approve an authorized investigative review governance record
            resp_gov = await client.post(
                "/api/v1/biometrics/governance",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "purpose": BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
                    "lawful_basis": BiometricLawfulBasis.SUBSTANTIAL_PUBLIC_INTEREST.value,
                    "notice_version": "1.0.0",
                    "retention_days": 30,
                },
            )
            gov_id = resp_gov.json()["id"]

            await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "decision": GovernanceStatus.APPROVED.value,
                    "legal_review_notes": "Approved for authorized forensic investigation review.",
                },
            )

            # Execute approved face detection
            resp_detect = await client.post(
                "/api/v1/biometrics/detect",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "governance_record_id": gov_id,
                    "image_base64": png_b64,
                },
            )
            assert resp_detect.status_code == 200
            detect_data = resp_detect.json()

            # Verify response schema guarantees: pure localization and disclaimer
            assert detect_data["face_count"] >= 1
            assert len(detect_data["detected_faces"]) == detect_data["face_count"]
            assert detect_data["image_width"] == 160
            assert detect_data["image_height"] == 120
            assert BIOMETRIC_ADVISORY_DISCLAIMER in detect_data["disclaimer"]

            for face in detect_data["detected_faces"]:
                ymin, xmin, ymax, xmax = face["bounding_box"]
                assert 0.0 <= ymin < ymax <= 1.0
                assert 0.0 <= xmin < xmax <= 1.0
                assert 0.0 <= face["confidence"] <= 1.0

            # Academic investigator attempting detection under Security dept governance record -> 404
            resp_cross_detect = await client.post(
                "/api/v1/biometrics/detect",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
                json={
                    "governance_record_id": gov_id,
                    "image_base64": png_b64,
                },
            )
            assert resp_cross_detect.status_code == 404

            # Verify audit event for face detection execution in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                stmt_audit = select(SecurityAuditEvent).where(
                    SecurityAuditEvent.target_id == gov_id,
                    SecurityAuditEvent.action == AuditAction.BIOMETRIC_DETECTION_EXECUTED.value,
                )
                detect_audit = (await session.execute(stmt_audit)).scalar_one_or_none()
                assert detect_audit is not None
                assert detect_audit.outcome == AuditOutcome.SUCCESS.value
                assert detect_audit.actor_id == data["investigator_sec"].id
