"""Unit tests for AuthService, EmailDeliveryService, and AuthToken model helpers (Phases 16-20)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    AuthenticationError,
    BusinessRuleError,
)
from backend.app.core.identity import (
    AccountStatus,
    RoleCode,
    SessionStatus,
)
from backend.app.core.rate_limit import InMemoryRateLimiter
from backend.app.core.tokens import (
    create_access_token,
    generate_opaque_token,
    hash_token,
    verify_and_decode_access_token,
)
from backend.app.models.session import Session
from backend.app.models.token import AuthToken
from backend.app.models.user import User
from backend.app.schemas.auth import (
    AuthenticatedPrincipal,
    LoginRequest,
    RefreshTokenRequest,
    ResetPasswordRequest,
)
from backend.app.services.auth import AuthService
from backend.app.services.email import (
    FakeEmailDeliveryService,
    LoggingEmailDeliveryService,
)
from backend.app.services.password import PasswordService


class TestAuthTokenModelUnit:
    """Unit tests for AuthToken model domain methods and representation."""

    def test_token_is_valid_at_and_consume(self) -> None:
        now = datetime.now(UTC)
        user_id = uuid4()
        token = AuthToken(
            user_id=user_id,
            token_hash="a" * 64,
            purpose="password_reset",
            expires_at=now + timedelta(minutes=10),
        )

        assert token.is_valid_at(now) is True
        assert token.is_valid_at(now + timedelta(minutes=15)) is False
        assert "password_reset" in repr(token)
        assert "consumed=False" in repr(token)

        token.consume(now)
        assert token.consumed_at == now
        assert token.is_valid_at(now) is False
        assert "consumed=True" in repr(token)


class TestEmailDeliveryServicesUnit:
    """Unit tests for FakeEmailDeliveryService and LoggingEmailDeliveryService."""

    async def test_fake_email_delivery_helpers(self) -> None:
        service = FakeEmailDeliveryService()
        assert await service.send_password_reset_email("user@test.edu", "reset123") is True
        assert await service.send_verification_email("user@test.edu", "verify456") is True

        assert service.get_last_token_for("user@test.edu", "password_reset") == "reset123"
        assert service.get_last_token_for("user@test.edu", "email_verification") == "verify456"
        assert service.get_last_token_for("nobody@test.edu") is None

        service.clear()
        assert len(service.sent_messages) == 0

    async def test_logging_email_delivery_service(self) -> None:
        service = LoggingEmailDeliveryService()
        assert await service.send_password_reset_email("dev@test.edu", "raw_token_xyz") is True
        assert await service.send_verification_email("dev@test.edu", "raw_token_abc") is True


class TestRateLimiterRemainingMethods:
    """Unit tests for auxiliary methods on InMemoryRateLimiter."""

    def test_reset_and_clear(self) -> None:
        limiter = InMemoryRateLimiter()
        limiter.check_rate_limit("ip-1", "action", max_requests=2, window_seconds=60)
        limiter.reset("ip-1", "action")
        limiter.check_rate_limit("ip-1", "action", max_requests=1, window_seconds=60)
        limiter.clear()


class TestTokensAuxiliaryValidation:
    """Unit tests for token error cases and algorithm validation."""

    def test_verify_token_invalid_issuer_or_audience(self, test_settings: Settings) -> None:
        token, _ = create_access_token(
            user_id=uuid4(),
            session_id=uuid4(),
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            settings=test_settings,
        )
        bad_issuer_settings = Settings(
            **{**test_settings.model_dump(), "AUTH_ISSUER": "different-issuer"}
        )
        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(token, bad_issuer_settings)
        assert exc_info.value.code == "TOKEN_INVALID"

    def test_verify_token_invalid_audience(self, test_settings: Settings) -> None:
        token, _ = create_access_token(
            user_id=uuid4(),
            session_id=uuid4(),
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            settings=test_settings,
        )
        bad_aud_settings = Settings(
            **{**test_settings.model_dump(), "AUTH_AUDIENCE": "different-aud"}
        )
        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(token, bad_aud_settings)
        assert exc_info.value.code == "TOKEN_INVALID"


class TestAuthServiceUnitBranches:
    """Unit tests for AuthService branches using repository mocks."""

    @pytest.fixture
    def mock_user_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_session_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_token_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_email_service(self) -> AsyncMock:
        mock = AsyncMock(spec=FakeEmailDeliveryService)
        mock.send_password_reset_email.return_value = True
        mock.send_verification_email.return_value = True
        return mock

    @pytest.fixture
    def auth_service(
        self,
        mock_user_repo: AsyncMock,
        mock_session_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_email_service: AsyncMock,
        test_settings: Settings,
    ) -> AuthService:
        return AuthService(
            user_repo=mock_user_repo,
            session_repo=mock_session_repo,
            auth_token_repo=mock_token_repo,
            password_service=PasswordService(),
            settings=test_settings,
            email_service=mock_email_service,
            rate_limiter=InMemoryRateLimiter(),
        )

    async def test_from_session_factory(self, test_settings: Settings) -> None:
        mock_db_session = MagicMock()
        service = AuthService.from_session(mock_db_session, test_settings)
        assert isinstance(service.email_service, LoggingEmailDeliveryService)
        assert isinstance(service.password_service, PasswordService)

    async def test_authenticate_user_inactive_branches(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
    ) -> None:
        pw_service = PasswordService()
        valid_hash = pw_service.hash_password("ValidPassword123")

        # Inactive user with is_active = False but status active
        user = User(
            id=uuid4(),
            email="inactive@test.edu",
            full_name="Inactive User",
            account_status=AccountStatus.ACTIVE.value,
            is_active=False,
            password_hash=valid_hash,
            department_id=uuid4(),
            role_id=uuid4(),
        )
        mock_user_repo.get_by_email_with_role.return_value = user

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.authenticate(
                LoginRequest(email="inactive@test.edu", password="ValidPassword123")
            )
        assert exc_info.value.code == "ACCOUNT_INACTIVE"

    async def test_rotate_refresh_token_session_expired(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
    ) -> None:
        now = datetime.now(UTC)
        raw_token = generate_opaque_token(48)
        token_hash = hash_token(raw_token)
        sess = Session(
            id=uuid4(),
            user_id=uuid4(),
            status=SessionStatus.ACTIVE.value,
            issued_at=now - timedelta(days=10),
            expires_at=now - timedelta(hours=1),
            refresh_token_hash=token_hash,
        )
        mock_session_repo.get_by_refresh_token_hash.return_value = sess
        mock_session_repo.get_by_id_with_lock.return_value = sess

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.rotate_refresh_token(RefreshTokenRequest(refresh_token=raw_token))
        assert exc_info.value.code == "SESSION_EXPIRED"

    async def test_rotate_refresh_token_session_already_revoked(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
    ) -> None:
        now = datetime.now(UTC)
        raw_token = generate_opaque_token(48)
        token_hash = hash_token(raw_token)
        sess = Session(
            id=uuid4(),
            user_id=uuid4(),
            status=SessionStatus.REVOKED.value,
            issued_at=now,
            expires_at=now + timedelta(days=7),
            refresh_token_hash=token_hash,
        )
        mock_session_repo.get_by_refresh_token_hash.return_value = sess
        mock_session_repo.get_by_id_with_lock.return_value = sess

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.rotate_refresh_token(RefreshTokenRequest(refresh_token=raw_token))
        assert exc_info.value.code == "SESSION_INVALID"

    async def test_rotate_refresh_token_concurrent_rotation_detected(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
    ) -> None:
        raw_token = generate_opaque_token(48)
        hash_token(raw_token)
        sess = MagicMock()
        sess.id = uuid4()
        sess.refresh_token_hash = "different_rotated_hash"
        mock_session_repo.get_by_refresh_token_hash.return_value = sess
        mock_session_repo.get_by_id_with_lock.return_value = sess

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.rotate_refresh_token(RefreshTokenRequest(refresh_token=raw_token))
        assert exc_info.value.code == "REFRESH_TOKEN_INVALIDATED"

    async def test_rotate_refresh_token_not_found(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
    ) -> None:
        mock_session_repo.get_by_refresh_token_hash.return_value = None
        mock_session_repo.get_by_previous_refresh_token_hash.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.rotate_refresh_token(
                RefreshTokenRequest(refresh_token=generate_opaque_token(48))
            )
        assert exc_info.value.code == "REFRESH_TOKEN_NOT_FOUND"

    async def test_reset_password_invalid_or_expired_token(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
    ) -> None:
        mock_token_repo.consume_token_atomically.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.reset_password(
                ResetPasswordRequest(
                    token="raw_fake_token_12345", new_password="NewSecure#Password123"
                )
            )
        assert exc_info.value.code == "INVALID_RESET_TOKEN"

    async def test_confirm_email_verification_user_not_found(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        token = AuthToken(
            id=uuid4(),
            user_id=uuid4(),
            token_hash="hash",
            purpose="email_verification",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        mock_token_repo.consume_token_atomically.return_value = token
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.confirm_email_verification("valid_token_xyz12345")
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_confirm_email_verification_suspended_user_rejected(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        token = AuthToken(
            id=uuid4(),
            user_id=user_id,
            token_hash="hash",
            purpose="email_verification",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        mock_token_repo.consume_token_atomically.return_value = token

        suspended_user = User(
            id=user_id,
            email="suspended@test.edu",
            full_name="Suspended User",
            account_status=AccountStatus.SUSPENDED.value,
            is_active=False,
            deactivated_at=datetime.now(UTC),
            department_id=uuid4(),
            role_id=uuid4(),
        )
        mock_user_repo.get_by_id_unscoped.return_value = suspended_user

        with pytest.raises(BusinessRuleError) as exc_info:
            await auth_service.confirm_email_verification("valid_token_xyz12345")
        assert exc_info.value.code == "ACCOUNT_LIFECYCLE_RESTRICTED"

    async def test_confirm_email_verification_token_not_found(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
    ) -> None:
        mock_token_repo.consume_token_atomically.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.confirm_email_verification("missing_token_12345")
        assert exc_info.value.code == "INVALID_VERIFICATION_TOKEN"

    async def test_revoke_principal_sessions_target_not_found(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
    ) -> None:
        principal = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="principal@test.edu",
            full_name="Principal User",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )
        mock_session_repo.get_by_id.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.revoke_principal_sessions(
                principal,
                target_session_id=uuid4(),
            )
        assert exc_info.value.code == "SESSION_NOT_FOUND"

    async def test_get_current_user_profile_user_not_found(
        self,
        auth_service: AuthService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="missing@test.edu",
            full_name="Missing User",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.get_current_user_profile(principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_get_authenticated_principal_user_not_found(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        test_settings: Settings,
    ) -> None:
        user_id = uuid4()
        session_id = uuid4()
        token, _ = create_access_token(
            user_id=user_id,
            session_id=session_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            settings=test_settings,
        )

        sess = Session(
            id=session_id,
            user_id=user_id,
            status=SessionStatus.ACTIVE.value,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        mock_session_repo.get_by_id.return_value = sess
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.get_authenticated_principal(token)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_get_authenticated_principal_session_expired(
        self,
        auth_service: AuthService,
        mock_session_repo: AsyncMock,
        test_settings: Settings,
    ) -> None:
        user_id = uuid4()
        session_id = uuid4()
        token, _ = create_access_token(
            user_id=user_id,
            session_id=session_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            settings=test_settings,
        )

        expired_sess = Session(
            id=session_id,
            user_id=user_id,
            status=SessionStatus.ACTIVE.value,
            issued_at=datetime.now(UTC) - timedelta(days=10),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        mock_session_repo.get_by_id.return_value = expired_sess

        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.get_authenticated_principal(token)
        assert exc_info.value.code == "SESSION_EXPIRED"
