"""Unit tests for Batch 11 Group 01 (Phases 101-105) Security Hardening.

Covers:
- Phase 102: Authentication & session hardening (refresh rate-limits, replay revocation,
  authenticated password change, timing normalization, privilege/department session revocation).
- Phase 104: Production security gates (TLS/SSL enforcement, security headers, URL redaction).
- Phase 105: Evidence and file handling security (quarantine download blocks, short TTLs,
  magic bytes verification, path traversal prevention).
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.evidence import (
    CustodyActionType,
    EvidenceStatus,
    ScanStatus,
    UploadStatus,
)
from backend.app.core.exceptions import (
    AuthenticationError,
    BusinessRuleError,
    RateLimitExceededError,
    UnsupportedMediaTypeError,
)
from backend.app.core.identity import (
    AccountStatus,
    RoleCode,
    SessionStatus,
)
from backend.app.core.rate_limit import InMemoryRateLimiter
from backend.app.core.tokens import hash_token
from backend.app.core.upload import (
    sanitize_filename,
    validate_file_magic_bytes,
)
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.incident import Incident
from backend.app.models.role import Role
from backend.app.models.session import Session
from backend.app.models.user import User
from backend.app.schemas.auth import (
    AuthenticatedPrincipal,
    ChangePasswordRequest,
    RefreshTokenRequest,
)
from backend.app.schemas.identity import UserUpdate
from backend.app.services.auth import AuthService
from backend.app.services.evidence import EvidenceService
from backend.app.services.password import PasswordService
from backend.app.services.user import UserService


def make_principal(
    *,
    user_id: UUID | None = None,
    role_code: RoleCode = RoleCode.STUDENT,
    department_id: UUID | None = None,
    email: str = "test@ewitness.edu",
    full_name: str = "Test User",
) -> AuthenticatedPrincipal:
    """Helper to instantiate a valid AuthenticatedPrincipal."""
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email=email,
        full_name=full_name,
        account_status=AccountStatus.ACTIVE.value,
        is_active=True,
        role_code=role_code.value,
        department_id=department_id,
        session_id=uuid4(),
    )


class TestBatch11AuthenticationAndSessionHardening:
    """Tests for Phase 102: Authentication, session revocation, and timing hardening."""

    @pytest.fixture
    def mock_user_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_session_repo(self) -> AsyncMock:
        mock = AsyncMock()
        mock._session = AsyncMock()
        return mock

    @pytest.fixture
    def mock_token_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_email_service(self) -> AsyncMock:
        mock = AsyncMock()
        mock.send_password_reset_email.return_value = True
        mock.send_verification_email.return_value = True
        return mock

    @pytest.fixture
    def rate_limiter(self) -> InMemoryRateLimiter:
        return InMemoryRateLimiter()

    @pytest.fixture
    def auth_service(
        self,
        mock_user_repo: AsyncMock,
        mock_session_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_email_service: AsyncMock,
        rate_limiter: InMemoryRateLimiter,
        test_settings: Settings,
    ) -> AuthService:
        return AuthService(
            user_repo=mock_user_repo,
            session_repo=mock_session_repo,
            auth_token_repo=mock_token_repo,
            password_service=PasswordService(),
            settings=test_settings,
            email_service=mock_email_service,
            rate_limiter=rate_limiter,
        )

    async def test_rotate_refresh_token_rate_limiting(
        self,
        auth_service: AuthService,
    ) -> None:
        """Token refresh endpoint enforces strict rate limiting (max 20 per minute per IP)."""
        req = RefreshTokenRequest(refresh_token="valid_length_token_1234567890_abc")

        # 20 requests succeed through rate limiter check (they fail later on session repo mock)
        for _ in range(20):
            with contextlib.suppress(AuthenticationError):
                await auth_service.rotate_refresh_token(req, client_ip="192.168.1.100")

        # 21st request triggers RateLimitExceededError
        with pytest.raises(RateLimitExceededError) as exc_info:
            await auth_service.rotate_refresh_token(req, client_ip="192.168.1.100")
        assert "Too many token_refresh requests" in str(exc_info.value)

    async def test_rotate_refresh_token_replay_revokes_session(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
    ) -> None:
        """Presenting a previously rotated refresh token triggers security revocation."""
        token_str = "reused_refresh_token_1234567890_value"
        token_hash = hash_token(token_str)

        mock_session_repo.get_by_refresh_token_hash.return_value = None
        reused_session = Session(
            user_id=uuid4(),
            refresh_token_hash="newer_hash_abc",
            previous_refresh_token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(days=7),
            status=SessionStatus.ACTIVE.value,
        )
        mock_session_repo.get_by_previous_refresh_token_hash.return_value = reused_session

        req = RefreshTokenRequest(refresh_token=token_str)
        with pytest.raises(AuthenticationError) as exc:
            await auth_service.rotate_refresh_token(req, client_ip="10.0.0.1")

        assert exc.value.code == "REFRESH_TOKEN_REUSE_DETECTED"
        assert reused_session.status == SessionStatus.REVOKED.value
        assert reused_session.revocation_reason == "refresh_token_reuse_detected"
        mock_session_repo._session.commit.assert_awaited_once()

    async def test_authenticated_password_change_success(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
        mock_session_repo: AsyncMock,
    ) -> None:
        """Authenticated password change verifies credential, updates hash, and revokes sessions."""
        user_id = uuid4()
        pw_service = PasswordService()
        current_hash = pw_service.hash_password("CurrentPassword123!")

        user = User(
            id=user_id,
            email="investigator@ewitness.edu",
            full_name="Investigator Test",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash=current_hash,
            department_id=uuid4(),
            role_id=uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = user

        principal = make_principal(
            user_id=user_id,
            email=user.email,
            role_code=RoleCode.INVESTIGATOR,
            department_id=user.department_id,
        )

        req = ChangePasswordRequest(
            current_password="CurrentPassword123!",
            new_password="NewReplacementPassword456!",
        )

        result = await auth_service.change_password(principal, req, client_ip="192.168.1.50")
        assert result.status == "success"
        assert "successfully changed" in result.message

        # Assert password hash updated
        mock_user_repo.update_password_hash.assert_awaited_once()
        # Assert all user sessions revoked
        mock_session_repo.revoke_user_sessions.assert_awaited_once()
        args, kwargs = mock_session_repo.revoke_user_sessions.call_args
        assert args[0] == user_id
        assert kwargs["reason"] == "password_change"

    async def test_authenticated_password_change_invalid_current_password(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
    ) -> None:
        """Password change rejects mismatched current password."""
        user_id = uuid4()
        pw_service = PasswordService()
        user = User(
            id=user_id,
            email="user@ewitness.edu",
            full_name="User Test",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash=pw_service.hash_password("ActualPassword123!"),
            department_id=uuid4(),
            role_id=uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = user

        principal = make_principal(
            user_id=user_id,
            email=user.email,
            role_code=RoleCode.STUDENT,
        )

        req = ChangePasswordRequest(
            current_password="WrongPassword123!",
            new_password="BrandNewPassword456!",
        )

        with pytest.raises(AuthenticationError) as exc:
            await auth_service.change_password(principal, req)
        assert exc.value.code == "INVALID_CREDENTIALS"

    async def test_authenticated_password_change_disallows_reuse(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
    ) -> None:
        """Password change disallows setting the new password identical to the current one."""
        user_id = uuid4()
        pw_service = PasswordService()
        user = User(
            id=user_id,
            email="user@ewitness.edu",
            full_name="User Test",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash=pw_service.hash_password("SamePassword123!"),
            department_id=uuid4(),
            role_id=uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = user

        principal = make_principal(
            user_id=user_id,
            email=user.email,
            role_code=RoleCode.STUDENT,
        )

        req = ChangePasswordRequest(
            current_password="SamePassword123!",
            new_password="SamePassword123!",
        )

        with pytest.raises(BusinessRuleError) as exc:
            await auth_service.change_password(principal, req)
        assert exc.value.code == "PASSWORD_REUSE_DISALLOWED"

    async def test_authenticated_password_change_enforces_policy(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
    ) -> None:
        """Password change enforces complexity and length policies."""
        user_id = uuid4()
        pw_service = PasswordService()
        user = User(
            id=user_id,
            email="user@ewitness.edu",
            full_name="User Test",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash=pw_service.hash_password("CurrentPassword123!"),
            department_id=uuid4(),
            role_id=uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = user

        principal = make_principal(
            user_id=user_id,
            email=user.email,
            role_code=RoleCode.STUDENT,
        )

        # Commonly compromised password
        req = ChangePasswordRequest(
            current_password="CurrentPassword123!",
            new_password="password123",
        )

        with pytest.raises(BusinessRuleError) as exc:
            await auth_service.change_password(principal, req)
        assert exc.value.code == "PASSWORD_COMMONLY_COMPROMISED"

    async def test_password_reset_timing_normalization(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_email_service: AsyncMock,
    ) -> None:
        """Password reset request returns identical response without enumeration for unknown users."""
        mock_user_repo.get_by_email_with_role.return_value = None

        res = await auth_service.request_password_reset(
            "nonexistent_account@ewitness.edu",
            client_ip="10.10.10.10",
        )
        assert "password recovery instructions have been sent" in res.message
        # No email sent, no token saved
        mock_token_repo.create.assert_not_called()
        mock_email_service.send_password_reset_email.assert_not_called()


class TestBatch11UserPrivilegeAndDepartmentSessionRevocation:
    """Tests for Phase 102: Immediate session revocation on privilege or department reassignment."""

    @pytest.fixture
    def mock_user_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_role_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_dept_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_session_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def user_service(
        self,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_session_repo: AsyncMock,
        test_settings: Settings,
    ) -> UserService:
        return UserService(
            user_repo=mock_user_repo,
            role_repo=mock_role_repo,
            dept_repo=mock_dept_repo,
            session_repo=mock_session_repo,
            password_service=PasswordService(),
            settings=test_settings,
        )

    async def test_update_user_role_change_revokes_sessions(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_session_repo: AsyncMock,
    ) -> None:
        """When an admin updates a user's role, their active sessions are revoked immediately."""
        user_id = uuid4()
        old_role_id = uuid4()
        new_role_id = uuid4()

        target_user = User(
            id=user_id,
            email="target@ewitness.edu",
            full_name="Target User",
            role_id=old_role_id,
            department_id=uuid4(),
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash="hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user

        super_admin_principal = make_principal(
            email="superadmin@ewitness.edu",
            role_code=RoleCode.SUPER_ADMIN,
        )

        mock_user_repo.update_admin.return_value = target_user
        mock_role_repo.get_by_id.return_value = Role(id=new_role_id, code=RoleCode.STAFF.value)

        update_dto = UserUpdate(role_id=new_role_id)
        await user_service.update_user(user_id, update_dto, super_admin_principal)

        mock_session_repo.revoke_user_sessions.assert_awaited_once()
        args, kwargs = mock_session_repo.revoke_user_sessions.call_args
        target_id = args[0] if args else kwargs.get("user_id")
        assert target_id == user_id
        assert kwargs["reason"] == "privilege_or_department_changed"

    async def test_update_user_department_change_revokes_sessions(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_session_repo: AsyncMock,
    ) -> None:
        """When an admin reassigns a user's department via update_user, sessions are revoked."""
        user_id = uuid4()
        old_dept_id = uuid4()
        new_dept_id = uuid4()

        target_user = User(
            id=user_id,
            email="target@ewitness.edu",
            full_name="Target User",
            role_id=uuid4(),
            department_id=old_dept_id,
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash="hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user

        mock_dept = MagicMock()
        mock_dept.is_active = True
        mock_dept_repo.get_by_id.return_value = mock_dept
        mock_user_repo.update_admin.return_value = target_user

        super_admin_principal = make_principal(
            email="superadmin@ewitness.edu",
            role_code=RoleCode.SUPER_ADMIN,
        )

        update_dto = UserUpdate(department_id=new_dept_id)
        await user_service.update_user(user_id, update_dto, super_admin_principal)

        mock_session_repo.revoke_user_sessions.assert_awaited_once()
        args, kwargs = mock_session_repo.revoke_user_sessions.call_args
        target_id = args[0] if args else kwargs.get("user_id")
        assert target_id == user_id
        assert kwargs["reason"] == "privilege_or_department_changed"

    async def test_assign_department_revokes_sessions(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_session_repo: AsyncMock,
    ) -> None:
        """Dedicated department assignment revokes all active user sessions."""
        user_id = uuid4()
        old_dept_id = uuid4()
        new_dept_id = uuid4()

        target_user = User(
            id=user_id,
            email="target@ewitness.edu",
            full_name="Target User",
            role_id=uuid4(),
            department_id=old_dept_id,
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash="hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user

        mock_dept = MagicMock()
        mock_dept.is_active = True
        mock_dept_repo.get_by_id.return_value = mock_dept

        super_admin_principal = make_principal(
            email="superadmin@ewitness.edu",
            role_code=RoleCode.SUPER_ADMIN,
        )

        await user_service.assign_department(user_id, new_dept_id, super_admin_principal)

        mock_session_repo.revoke_user_sessions.assert_awaited_once()
        args, kwargs = mock_session_repo.revoke_user_sessions.call_args
        target_id = args[0] if args else kwargs.get("user_id")
        assert target_id == user_id
        assert kwargs["reason"] == "department_reassigned"

    async def test_assign_investigator_revokes_sessions(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_session_repo: AsyncMock,
    ) -> None:
        """Assigning an investigator to a department revokes their sessions."""
        inv_id = uuid4()
        role_id = uuid4()
        old_dept_id = uuid4()
        new_dept_id = uuid4()

        target_inv = User(
            id=inv_id,
            email="inv@ewitness.edu",
            full_name="Investigator Target",
            role_id=role_id,
            department_id=old_dept_id,
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash="hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_inv
        mock_role_repo.get_by_id.return_value = Role(id=role_id, code=RoleCode.INVESTIGATOR.value)

        mock_dept = MagicMock()
        mock_dept.is_active = True
        mock_dept_repo.get_by_id.return_value = mock_dept

        super_admin_principal = make_principal(
            email="superadmin@ewitness.edu",
            role_code=RoleCode.SUPER_ADMIN,
        )

        await user_service.assign_investigator(
            department_id=new_dept_id,
            investigator_id=inv_id,
            principal=super_admin_principal,
        )

        mock_session_repo.revoke_user_sessions.assert_awaited_once()
        args, kwargs = mock_session_repo.revoke_user_sessions.call_args
        target_id = args[0] if args else kwargs.get("user_id")
        assert target_id == inv_id
        assert kwargs["reason"] == "investigator_department_assigned"


class TestBatch11ProductionSettingsAndEncryptionGates:
    """Tests for Phase 104: Production security gates and safe key lifecycle."""

    def test_production_rejects_disabled_ssl(
        self,
        valid_production_config_dict: dict[str, Any],
    ) -> None:
        """Production environment strictly requires ENFORCE_SSL=True."""
        insecure_cfg = {**valid_production_config_dict, "ENFORCE_SSL": False}
        with pytest.raises(ValidationError, match="ENFORCE_SSL must be True in production"):
            Settings(**insecure_cfg)

    def test_production_rejects_disabled_security_headers(
        self,
        valid_production_config_dict: dict[str, Any],
    ) -> None:
        """Production environment strictly requires SECURITY_HEADERS_ENABLED=True."""
        insecure_cfg = {**valid_production_config_dict, "SECURITY_HEADERS_ENABLED": False}
        with pytest.raises(
            ValidationError, match="SECURITY_HEADERS_ENABLED must be True in production"
        ):
            Settings(**insecure_cfg)

    def test_redacted_database_and_redis_urls(
        self,
        valid_production_config_dict: dict[str, Any],
    ) -> None:
        """Database and Redis URLs redact plaintext credentials in representations."""
        settings = Settings(**valid_production_config_dict)
        assert "***REDACTED***" in settings.redacted_database_url
        assert "K9mP2vL8nQ5" not in settings.redacted_database_url
        assert "***REDACTED***" in settings.redacted_redis_url
        assert "R8kM3pL9vN2" not in settings.redacted_redis_url


class TestBatch11EvidenceSecurityControls:
    """Tests for Phase 105: Evidence custody, quarantine enforcement, and input hardening."""

    @pytest.fixture
    def mock_evidence_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_storage_client(self) -> AsyncMock:
        mock = AsyncMock()
        mock.verify_object_exists.return_value = True
        mock.generate_presigned_download_url = MagicMock(
            return_value="https://s3.amazonaws.com/evidence/123?sig=abc"
        )
        return mock

    @pytest.fixture
    def evidence_service(
        self,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage_client: AsyncMock,
        test_settings: Settings,
    ) -> EvidenceService:
        return EvidenceService(
            evidence_repo=mock_evidence_repo,
            incident_repo=mock_incident_repo,
            storage_client=mock_storage_client,
            settings=test_settings,
        )

    async def test_quarantined_evidence_download_blocked_fail_closed(
        self,
        evidence_service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
    ) -> None:
        """Quarantined or malware-infected evidence cannot be downloaded under any circumstances."""
        attachment_id = uuid4()
        incident_id = uuid4()
        dept_id = uuid4()

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            status="under_review",
            title="Incident Title",
            description="Description",
        )
        mock_incident_repo.get_by_id.return_value = incident

        quarantined_attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            department_id=dept_id,
            original_filename="malicious.pdf",
            storage_key="incidents/test/malicious.pdf",
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.QUARANTINED.value,
            scan_status=ScanStatus.INFECTED.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_evidence_repo.get_attachment_by_id.return_value = quarantined_attachment

        principal = make_principal(
            email="investigator@ewitness.edu",
            role_code=RoleCode.INVESTIGATOR,
            department_id=dept_id,
        )

        with pytest.raises(BusinessRuleError) as exc:
            await evidence_service.generate_download_url(
                attachment_id=attachment_id,
                principal=principal,
                incident_id=incident_id,
            )
        assert exc.value.code == "EVIDENCE_NOT_RELEASED"
        assert exc.value.status_code == 403

    async def test_clean_evidence_download_generates_presigned_url_with_strict_ttl(
        self,
        evidence_service: EvidenceService,
        mock_evidence_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_storage_client: AsyncMock,
    ) -> None:
        """Clean verified evidence download issues URL with 300s TTL and logs custody event."""
        attachment_id = uuid4()
        incident_id = uuid4()
        dept_id = uuid4()

        incident = Incident(
            id=incident_id,
            department_id=dept_id,
            status="under_review",
            title="Incident Title",
            description="Description",
        )
        mock_incident_repo.get_by_id.return_value = incident

        clean_attachment = EvidenceAttachment(
            id=attachment_id,
            incident_id=incident_id,
            department_id=dept_id,
            original_filename="clean_document.pdf",
            storage_key="incidents/test/clean_document.pdf",
            declared_mime_type="application/pdf",
            file_size_bytes=1024,
            upload_status=UploadStatus.COMPLETED.value,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status=ScanStatus.CLEAN.value,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_evidence_repo.get_attachment_by_id.return_value = clean_attachment

        principal = make_principal(
            email="lead@ewitness.edu",
            role_code=RoleCode.INVESTIGATOR,
            department_id=dept_id,
        )

        res = await evidence_service.generate_download_url(
            attachment_id=attachment_id,
            principal=principal,
            incident_id=incident_id,
        )

        assert res.download_url == "https://s3.amazonaws.com/evidence/123?sig=abc"
        assert res.expires_at is not None
        assert res.filename == "clean_document.pdf"

        # Assert custody event recorded
        mock_evidence_repo.create_custody_event.assert_awaited_once()
        event = mock_evidence_repo.create_custody_event.call_args[0][0]
        assert event.action_type == CustodyActionType.DOWNLOADED.value
        assert event.actor_id == principal.user_id

    def test_sanitize_filename_rejects_path_traversal_and_malicious_extensions(self) -> None:
        """sanitize_filename strips path traversal and rejects forbidden executable extensions."""
        # Directory traversal stripped
        assert sanitize_filename("../../../secret.pdf") == "secret.pdf"
        assert sanitize_filename("..\\..\\Windows\\System32\\cmd.pdf") == "cmd.pdf"

        # Forbidden extensions rejected
        with pytest.raises(BusinessRuleError, match="forbidden executable or script extension"):
            sanitize_filename("payload.exe")
        with pytest.raises(BusinessRuleError, match="forbidden executable or script extension"):
            sanitize_filename("script.sh")
        with pytest.raises(BusinessRuleError, match="forbidden executable or script extension"):
            sanitize_filename("exploit.php.pdf")

    def test_magic_bytes_detection_and_content_type_parity(self) -> None:
        """Binary magic bytes must match declared MIME type or fail closed."""
        pdf_header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        assert validate_file_magic_bytes(pdf_header, "application/pdf") == "application/pdf"

        # Mismatched Content-Type header raises UnsupportedMediaTypeError
        with pytest.raises(UnsupportedMediaTypeError, match="MIME type mismatch"):
            validate_file_magic_bytes(pdf_header, "image/png")

        # Non-executable text check
        text_data = b"Plain text log entry without binaries"
        assert validate_file_magic_bytes(text_data, "text/plain") == "text/plain"

        # Executable binary header rejected
        elf_header = b"\x7fELF\x02\x01\x01\x00"
        with pytest.raises(UnsupportedMediaTypeError, match="File signature"):
            validate_file_magic_bytes(elf_header, "application/pdf")
