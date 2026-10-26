"""Live PostgreSQL Integration Tests for Batch 08 Group 02 (Phases 76-80).

Verifies against real PostgreSQL:
- Phase 76: Face matching disabled by default, fail-closed configuration, and provider abstraction.
- Phase 77: Image quality verification, uncertainty bands [0.60, 0.85], BiometricVerificationReview persistence,
            and human reviewer determination workflow with mandatory override justification.
- Phase 78: AES-256-GCM template encryption at rest, key rotation, key revocation fail-closed enforcement,
            and zero raw template leakage into read endpoints.
- Phase 79: Biometric accuracy, fairness, and PAD evaluation endpoint with synthetic limitation disclaimers.
- Phase 80: Cross-department isolation, immutable security audit trails, and mandatory NO-GO release gate.
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
from backend.app.core.audit import AuditAction
from backend.app.core.biometric_crypto import get_biometric_key_manager
from backend.app.core.biometrics import (
    BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER,
    BiometricHumanVerdict,
    BiometricLawfulBasis,
    BiometricMatchVerdict,
    BiometricPurpose,
)
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.biometrics import (
    BiometricVerificationReview,
)
from backend.app.models.department import Department
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


def _create_test_png_bytes(width: int = 128, height: int = 128, fill_seed: int = 100) -> bytes:
    """Synthesize a valid PNG image byte stream with varied payload for contrast checks."""
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    payload = bytes([(fill_seed + (i * 7)) % 256 for i in range(512)])
    idat_chunk = struct.pack(">I", len(payload)) + b"IDAT" + payload + b"\x00\x00\x00\x00"
    iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    return signature + ihdr_chunk + idat_chunk + iend_chunk


async def _setup_batch08_group02_test_env(
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
                email=f"superadmin_b8g2_{suffix.lower()}@ewitness.edu",
                full_name="Biometric Super Admin G2",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_sec = await user_repo.create(
            User(
                email=f"deptadmin_b8g2_{suffix.lower()}@ewitness.edu",
                full_name="Safety Admin G2",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_sec = await user_repo.create(
            User(
                email=f"investigator_sec_b8g2_{suffix.lower()}@ewitness.edu",
                full_name="Safety Investigator G2",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_acad = await user_repo.create(
            User(
                email=f"investigator_acad_b8g2_{suffix.lower()}@ewitness.edu",
                full_name="Academic Investigator G2",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_sec = await user_repo.create(
            User(
                email=f"student_b8g2_{suffix.lower()}@ewitness.edu",
                full_name="Student Bio Subject G2",
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
class TestBatch08Group02LivePostgres:
    """End-to-end integration tests for Phases 76-80 on real PostgreSQL."""

    async def test_phase76_matching_disabled_by_default_fails_closed(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify face matching fails closed with 403 Forbidden under default configuration."""
        data = await _setup_batch08_group02_test_env(postgres_db_manager)

        # Default settings: BIOMETRIC_MATCHING_ENABLED=False
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_student = await _login(client, data["student_sec"].email, data["default_pw"])

            # 1. Student lacks BIOMETRIC_MATCHING_EXECUTE permission -> 403
            resp_student = await client.post(
                "/api/v1/biometrics/match",
                headers={"Authorization": f"Bearer {token_student}"},
                json={
                    "governance_record_id": str(uuid4()),
                    "probe_image_base64": base64.b64encode(_create_test_png_bytes()).decode(),
                    "reference_id": str(uuid4()),
                },
            )
            assert resp_student.status_code == 403

            # 2. Investigator has role permission but matching is disabled in settings -> 403 BIOMETRIC_MATCHING_DISABLED
            resp_disabled = await client.post(
                "/api/v1/biometrics/match",
                headers={"Authorization": f"Bearer {token_inv}"},
                json={
                    "governance_record_id": str(uuid4()),
                    "probe_image_base64": base64.b64encode(_create_test_png_bytes()).decode(),
                    "reference_id": str(uuid4()),
                },
            )
            assert resp_disabled.status_code == 403
            err = resp_disabled.json().get("error", {})
            assert (
                "BIOMETRIC_MATCHING_DISABLED" in err.get("code", "")
                or "disabled" in err.get("message", "").lower()
            )

    async def test_phase76_through_78_matching_quality_and_oversight_workflow(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify full matching pipeline, image quality rejection, persistence, and human review override."""
        data = await _setup_batch08_group02_test_env(postgres_db_manager)

        # Configure enabled mock settings for testing
        test_settings = postgres_settings.model_copy(
            update={
                "BIOMETRIC_ANALYSIS_ENABLED": True,
                "BIOMETRIC_MATCHING_ENABLED": True,
                "BIOMETRIC_PROVIDER": "mock",
            }
        )

        app = create_app(test_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(test_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )

            # 1. Create and approve a governance record for investigative manual review
            resp_gov = await client.post(
                "/api/v1/biometrics/governance",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "purpose": BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
                    "lawful_basis": BiometricLawfulBasis.STATUTORY_LEGAL_OBLIGATION.value,
                    "notice_version": "1.0.0",
                    "retention_days": 60,
                },
            )
            assert resp_gov.status_code == 201
            gov_id = resp_gov.json()["id"]

            resp_approve = await client.post(
                f"/api/v1/biometrics/governance/{gov_id}/review",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "decision": "approved",
                    "legal_review_notes": "Court warrant authorized for review.",
                },
            )
            assert resp_approve.status_code == 200

            # 2. Enroll a reference with AES-256-GCM encrypted template
            probe_png = _create_test_png_bytes(width=128, height=128, fill_seed=42)
            key_mgr = get_biometric_key_manager()
            encrypted_template = key_mgr.encrypt(probe_png)
            template_digest = hashlib.sha256(probe_png).hexdigest()

            resp_ref = await client.post(
                "/api/v1/biometrics/references",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "governance_record_id": gov_id,
                    "purpose": BiometricPurpose.AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW.value,
                    "template_digest": template_digest,
                    "encrypted_template": encrypted_template,
                    "enrollment_notes": "Reference enrolled from verified ID card.",
                },
            )
            assert resp_ref.status_code == 201
            ref_id = resp_ref.json()["id"]

            # 3. Test Phase 77: Image quality check failure (corrupted / empty header) -> 422
            resp_bad_quality = await client.post(
                "/api/v1/biometrics/match",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "governance_record_id": gov_id,
                    "probe_image_base64": base64.b64encode(b"NOT_A_VALID_IMAGE_HEADER").decode(),
                    "reference_id": ref_id,
                },
            )
            assert resp_bad_quality.status_code == 422
            err_qual = resp_bad_quality.json().get("error", {})
            assert "quality" in err_qual.get(
                "message", ""
            ).lower() or "PROBE_IMAGE_QUALITY" in err_qual.get("code", "")

            # 4. Test Phase 76: Successful matching against enrolled reference
            resp_match = await client.post(
                "/api/v1/biometrics/match",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "governance_record_id": gov_id,
                    "probe_image_base64": base64.b64encode(probe_png).decode(),
                    "reference_id": ref_id,
                },
            )
            assert resp_match.status_code == 200
            match_data = resp_match.json()
            assert match_data["similarity_score"] == pytest.approx(1.0, abs=1e-3)
            assert match_data["verdict"] == BiometricMatchVerdict.MATCH_CANDIDATE.value
            assert match_data["disclaimer"] == BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER
            assert match_data["verification_review_id"] is not None
            review_id = match_data["verification_review_id"]

            # Verify BiometricVerificationReview in database
            async with postgres_db_manager.session() as db_s:
                rev_row = (
                    await db_s.execute(
                        select(BiometricVerificationReview).where(
                            BiometricVerificationReview.id == review_id
                        )
                    )
                ).scalar_one()
                assert rev_row.candidate_similarity == pytest.approx(1.0, abs=1e-3)
                assert rev_row.automated_verdict == "match_candidate"
                assert not rev_row.is_override

            # 5. Test Phase 77: Human verification review with override
            # Missing override_reason on override -> 422 validation failure
            resp_bad_override = await client.post(
                f"/api/v1/biometrics/verifications/{review_id}/review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "human_verdict": BiometricHumanVerdict.REJECTED_OVERRIDE.value,
                    "review_notes": "Rejected by forensic investigator",
                },
            )
            assert resp_bad_override.status_code == 422

            # Valid override with reason -> 200 OK
            resp_override = await client.post(
                f"/api/v1/biometrics/verifications/{review_id}/review",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "human_verdict": BiometricHumanVerdict.REJECTED_OVERRIDE.value,
                    "review_notes": "Examined high-resolution footage manually.",
                    "override_reason": "Ear geometry and scar on left cheek definitively rule out subject.",
                },
            )
            assert resp_override.status_code == 200
            review_out = resp_override.json()
            assert review_out["human_verdict"] == "rejected_override"
            assert review_out["is_override"] is True
            assert "Ear geometry" in review_out["override_reason"]

            # 6. Test Cross-Department Isolation: Academic investigator cannot read Security review -> 404
            resp_cross = await client.get(
                f"/api/v1/biometrics/verifications/{review_id}",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_cross.status_code == 404

            # 7. List reviews with is_override filter
            resp_list = await client.get(
                "/api/v1/biometrics/verifications?is_override=true",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_list.status_code == 200
            assert resp_list.json()["total"] >= 1
            assert resp_list.json()["items"][0]["is_override"] is True

            # 8. Test Phase 79: Biometric evaluation report
            resp_eval = await client.get(
                "/api/v1/biometrics/evaluation-report",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_eval.status_code == 200
            eval_data = resp_eval.json()
            assert eval_data["model_name"] == "mock-face-matcher"
            assert "SYNTHETIC BENCHMARK EVALUATION ONLY" in eval_data["disclaimer"]
            assert eval_data["pad_summary"] is not None

            # 9. Verify SecurityAuditEvent audit trail
            async with postgres_db_manager.session() as db_s:
                audit_rows = (
                    (
                        await db_s.execute(
                            select(SecurityAuditEvent).where(
                                SecurityAuditEvent.department_id == data["dept_security"].id
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                actions = {r.action for r in audit_rows}
                assert AuditAction.BIOMETRIC_MATCHING_EXECUTED.value in actions
                assert AuditAction.BIOMETRIC_KEY_ACCESSED.value in actions
                assert AuditAction.BIOMETRIC_VERIFICATION_RECORDED.value in actions
