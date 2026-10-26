"""Authentication, refresh session, password reset, and verification service (Phases 16-18).

Coordinates user identity verification, Argon2id credential checks, secure JWT
and opaque refresh token issuance, token rotation, reuse detection, atomic one-time
token consumption, and email delivery.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Environment, Settings
from backend.app.core.exceptions import (
    AuthenticationError,
    BusinessRuleError,
    ConflictError,
    ResourceNotFoundError,
)
from backend.app.core.identity import (
    AccountStatus,
    AuthTokenPurpose,
    RoleCode,
    SessionStatus,
    normalize_email,
)
from backend.app.core.rate_limit import InMemoryRateLimiter, default_rate_limiter
from backend.app.core.tokens import (
    create_access_token,
    generate_opaque_token,
    hash_token,
    verify_and_decode_access_token,
)
from backend.app.models.session import Session
from backend.app.models.token import AuthToken
from backend.app.models.user import User
from backend.app.repositories.identity import (
    AuthTokenRepository,
    DepartmentRepository,
    RoleRepository,
    SessionRepository,
    UserRepository,
)
from backend.app.schemas.auth import (
    AcceptInvitationRequest,
    AuthenticatedPrincipal,
    ChangePasswordRequest,
    CurrentUserResponse,
    GenericActionResponse,
    LoginRequest,
    RefreshTokenRequest,
    ResetPasswordRequest,
    StudentRegisterRequest,
    StudentRegisterResponse,
    TokenResponse,
)
from backend.app.schemas.identity import DepartmentRead, RoleRead, UserRead
from backend.app.services.email import EmailDeliveryService, LoggingEmailDeliveryService
from backend.app.services.password import PasswordService

logger = logging.getLogger("ewitness.services.auth")

# Dummy hash for constant-time comparison when email is not found
DUMMY_TIMING_HASH: Final[str] = (
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$9S8/Qc3PZf4d8e7h2w1k9y5"
)


class AuthService:
    """Core domain service for user authentication and session credentials."""

    def __init__(
        self,
        *,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        auth_token_repo: AuthTokenRepository,
        password_service: PasswordService,
        settings: Settings,
        dept_repo: DepartmentRepository | None = None,
        role_repo: RoleRepository | None = None,
        email_service: EmailDeliveryService | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.auth_token_repo = auth_token_repo
        self.password_service = password_service
        self.settings = settings
        self.dept_repo = dept_repo or DepartmentRepository(user_repo._session)
        self.role_repo = role_repo or RoleRepository(user_repo._session)
        self.email_service = email_service or LoggingEmailDeliveryService()
        self.rate_limiter = rate_limiter or default_rate_limiter

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        email_service: EmailDeliveryService | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> AuthService:
        """Construct an AuthService wired with repositories bound to ``session``."""
        return cls(
            user_repo=UserRepository(session),
            session_repo=SessionRepository(session),
            auth_token_repo=AuthTokenRepository(session),
            dept_repo=DepartmentRepository(session),
            role_repo=RoleRepository(session),
            password_service=PasswordService(),
            settings=settings,
            email_service=email_service,
            rate_limiter=rate_limiter,
        )

    async def authenticate(
        self,
        request: LoginRequest,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> TokenResponse:
        """Authenticate user credentials and issue access + refresh tokens.

        Enforces rate limiting, generic failure responses, and account-state validation.
        """
        ip_key = client_ip or "unknown_ip"
        self.rate_limiter.check_rate_limit(
            key=ip_key,
            action="login",
            max_requests=10,
            window_seconds=60.0,
        )

        normalized_email = normalize_email(request.email)
        user = await self.user_repo.get_by_email_with_role(normalized_email)

        if user is None:
            # Perform dummy hash verification to preserve constant-time response behavior
            self.password_service.verify_password("dummy_credential_pad", DUMMY_TIMING_HASH)
            raise AuthenticationError(
                "Invalid email or password.",
                code="INVALID_CREDENTIALS",
            )

        if not self.password_service.verify_password(request.password, user.password_hash):
            raise AuthenticationError(
                "Invalid email or password.",
                code="INVALID_CREDENTIALS",
            )

        # Enforce account lifecycle eligibility rules
        if user.account_status == AccountStatus.PENDING_VERIFICATION.value:
            raise AuthenticationError(
                "Account email verification is required before login.",
                code="ACCOUNT_PENDING_VERIFICATION",
            )
        if user.account_status in {AccountStatus.SUSPENDED.value, AccountStatus.DISABLED.value}:
            raise AuthenticationError(
                "Account is not eligible to authenticate.",
                code="ACCOUNT_INACTIVE",
            )
        if not user.is_active:
            raise AuthenticationError(
                "Account is deactivated.",
                code="ACCOUNT_INACTIVE",
            )

        # Issue new session and credentials
        now = datetime.now(UTC)
        raw_refresh_token = generate_opaque_token(48)
        refresh_hash = hash_token(raw_refresh_token)
        session_expires_at = now + timedelta(days=self.settings.AUTH_REFRESH_TOKEN_EXPIRE_DAYS)

        new_session = Session(
            user_id=user.id,
            department_id=user.department_id,
            client_ip=client_ip,
            user_agent=user_agent,
            status=SessionStatus.ACTIVE.value,
            issued_at=now,
            expires_at=session_expires_at,
            last_activity_at=now,
            refresh_token_hash=refresh_hash,
            rotation_counter=0,
        )
        created_session = await self.session_repo.create(new_session)

        # Issue access token
        access_token, _ = create_access_token(
            user_id=user.id,
            session_id=created_session.id,
            role_code=user.role.code,
            department_id=user.department_id,
            settings=self.settings,
            now=now,
        )

        # Clear login rate limiter on successful authentication
        self.rate_limiter.reset(ip_key, "login")

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh_token,
            token_type="bearer",  # noqa: S106
            expires_in=self.settings.AUTH_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def rotate_refresh_token(
        self,
        request: RefreshTokenRequest,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> TokenResponse:
        """Rotate a refresh token credential and issue a replacement access token.

        Detects replay/reuse of rotated tokens and revokes the session immediately.
        """
        raw_token = request.refresh_token.strip()
        presented_hash = hash_token(raw_token)

        ip_key = client_ip or "unknown_ip"
        self.rate_limiter.check_rate_limit(
            key=ip_key,
            action="token_refresh",
            max_requests=20,
            window_seconds=60.0,
        )

        # 1. Search for session matching current active refresh token
        active_session = await self.session_repo.get_by_refresh_token_hash(presented_hash)

        if active_session is not None:
            # Pessimistically lock the session row to guarantee safe concurrency
            locked_session = await self.session_repo.get_by_id_with_lock(active_session.id)
            if locked_session is None or locked_session.refresh_token_hash != presented_hash:
                # Token was rotated in a parallel concurrent request
                raise AuthenticationError(
                    "Refresh token has already been rotated or invalidated.",
                    code="REFRESH_TOKEN_INVALIDATED",
                )

            # Validate session status and validity window
            now = datetime.now(UTC)
            if locked_session.status != SessionStatus.ACTIVE.value:
                raise AuthenticationError(
                    "Session is revoked or expired.",
                    code="SESSION_INVALID",
                )
            if locked_session.expires_at <= now:
                locked_session.mark_expired()
                raise AuthenticationError(
                    "Session has expired.",
                    code="SESSION_EXPIRED",
                )

            # Validate user account is still eligible
            user = await self.user_repo.get_by_id_unscoped(locked_session.user_id)
            if (
                user is None
                or not user.is_active
                or user.account_status != AccountStatus.ACTIVE.value
            ):
                locked_session.revoke(reason="user_ineligible_during_refresh")
                await self.session_repo._session.commit()
                raise AuthenticationError(
                    "Account is no longer active.",
                    code="ACCOUNT_INACTIVE",
                )

            # Generate new refresh credential and rotate session
            new_raw_refresh = generate_opaque_token(48)
            new_hash = hash_token(new_raw_refresh)
            locked_session.rotate_refresh_token(new_hash, when=now)
            if client_ip:
                locked_session.client_ip = client_ip
            if user_agent:
                locked_session.user_agent = user_agent

            # Issue replacement access token
            access_token, _ = create_access_token(
                user_id=user.id,
                session_id=locked_session.id,
                role_code=user.role.code,
                department_id=user.department_id,
                settings=self.settings,
                now=now,
            )

            return TokenResponse(
                access_token=access_token,
                refresh_token=new_raw_refresh,
                token_type="bearer",  # noqa: S106
                expires_in=self.settings.AUTH_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )

        # 2. Check if token matches previously rotated hash (REUSE DETECTION)
        reused_session = await self.session_repo.get_by_previous_refresh_token_hash(presented_hash)
        if reused_session is not None:
            logger.warning(
                "Security alert: Refresh token reuse detected for session %s (user %s)",
                reused_session.id,
                reused_session.user_id,
            )
            reused_session.revoke(reason="refresh_token_reuse_detected")
            await self.session_repo._session.commit()
            raise AuthenticationError(
                "Invalid or expired refresh token.",
                code="REFRESH_TOKEN_REUSE_DETECTED",
            )

        raise AuthenticationError(
            "Invalid or expired refresh token.",
            code="REFRESH_TOKEN_NOT_FOUND",
        )

    async def revoke_sessions_for_principal(
        self,
        principal: AuthenticatedPrincipal,
    ) -> GenericActionResponse:
        """Revoke the session associated with the active principal."""
        session = await self.session_repo.get_by_id(principal.session_id, user_id=principal.user_id)
        if session is not None:
            session.revoke(reason="user_logout")
        return GenericActionResponse(message="Successfully logged out.")

    async def revoke_principal_sessions(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_session_id: UUID | None = None,
        all_other_sessions: bool = False,
    ) -> GenericActionResponse:
        """Revoke targeted or other sessions for the principal."""
        if all_other_sessions:
            revoked_count = await self.session_repo.revoke_user_sessions(
                principal.user_id,
                reason="user_revoked_other_sessions",
                except_session_id=principal.session_id,
            )
            return GenericActionResponse(
                message=f"Revoked {revoked_count} other active session(s)."
            )

        target_id = target_session_id or principal.session_id
        session = await self.session_repo.get_by_id(target_id, user_id=principal.user_id)
        if session is None:
            raise AuthenticationError(
                "Target session not found or not owned by user.",
                code="SESSION_NOT_FOUND",
            )
        session.revoke(reason="user_revoked_session")
        return GenericActionResponse(message="Session successfully revoked.")

    async def request_password_reset(
        self,
        email: str,
        *,
        client_ip: str | None = None,
    ) -> GenericActionResponse:
        """Initiate self-service password recovery without revealing account existence."""
        ip_key = client_ip or "unknown_ip"
        self.rate_limiter.check_rate_limit(
            key=ip_key,
            action="password_reset_request",
            max_requests=5,
            window_seconds=60.0,
        )

        normalized = normalize_email(email)
        user = await self.user_repo.get_by_email_with_role(normalized)

        # Privacy invariant: Always return the identical response message
        if user is not None and user.account_status in {
            AccountStatus.ACTIVE.value,
            AccountStatus.PENDING_VERIFICATION.value,
        }:
            raw_token = generate_opaque_token(32)
            token_digest = hash_token(raw_token)
            expires_at = datetime.now(UTC) + timedelta(minutes=15)

            auth_token = AuthToken(
                user_id=user.id,
                token_hash=token_digest,
                purpose=AuthTokenPurpose.PASSWORD_RESET.value,
                expires_at=expires_at,
                created_by_ip=client_ip,
            )
            await self.auth_token_repo.create(auth_token)
            await self.email_service.send_password_reset_email(user.email, raw_token)
        else:
            # Dummy operations to balance execution timing against user enumeration
            dummy_token = generate_opaque_token(32)
            _ = hash_token(dummy_token)

        return GenericActionResponse(
            message="If the email address is registered, password recovery instructions have been sent."
        )

    async def reset_password(
        self,
        request: ResetPasswordRequest,
    ) -> GenericActionResponse:
        """Atomically consume password reset token and update account credential."""
        self.password_service.validate_password_policy(request.new_password)

        raw_token = request.token.strip()
        token_digest = hash_token(raw_token)
        now = datetime.now(UTC)

        consumed_token = await self.auth_token_repo.consume_token_atomically(
            token_digest,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            now=now,
        )
        if consumed_token is None:
            raise AuthenticationError(
                "Invalid, expired, or already-consumed password reset token.",
                code="INVALID_RESET_TOKEN",
            )

        # Hash new password credential
        new_hash = self.password_service.hash_password(request.new_password)
        await self.user_repo.update_password_hash(consumed_token.user_id, new_hash)

        # Security policy: Invalidate all existing sessions after password reset
        await self.session_repo.revoke_user_sessions(
            consumed_token.user_id,
            reason="password_reset",
            when=now,
        )

        return GenericActionResponse(message="Password has been successfully reset.")

    async def change_password(
        self,
        principal: AuthenticatedPrincipal,
        request: ChangePasswordRequest,
        *,
        client_ip: str | None = None,
    ) -> GenericActionResponse:
        """Allow an authenticated user to change their password with current password verification."""
        ip_key = client_ip or "unknown_ip"
        self.rate_limiter.check_rate_limit(
            key=f"{ip_key}:{principal.user_id}",
            action="password_change",
            max_requests=5,
            window_seconds=60.0,
        )

        user = await self.user_repo.get_by_id_unscoped(principal.user_id)
        if user is None or not user.is_active or user.account_status != AccountStatus.ACTIVE.value:
            raise AuthenticationError(
                "Account is not active or eligible for password change.",
                code="ACCOUNT_INACTIVE",
            )

        # Verify current password
        if not self.password_service.verify_password(request.current_password, user.password_hash):
            raise AuthenticationError(
                "Current password verification failed.",
                code="INVALID_CREDENTIALS",
            )

        # Enforce password policy on new password
        self.password_service.validate_password_policy(request.new_password)

        # Enforce password history / reuse prevention (cannot reuse current password)
        if self.password_service.verify_password(request.new_password, user.password_hash):
            raise BusinessRuleError(
                "New password cannot be identical to the current password.",
                code="PASSWORD_REUSE_DISALLOWED",
            )

        now = datetime.now(UTC)
        new_hash = self.password_service.hash_password(request.new_password)
        await self.user_repo.update_password_hash(user.id, new_hash)

        # Security policy: Invalidate all active sessions for the user after password change
        await self.session_repo.revoke_user_sessions(
            user.id,
            reason="password_change",
            when=now,
        )

        return GenericActionResponse(
            message="Password has been successfully changed. Please log in again."
        )

    async def request_email_verification(
        self,
        email: str,
        *,
        client_ip: str | None = None,
    ) -> GenericActionResponse:
        """Send account verification token without disclosing account presence."""
        ip_key = client_ip or "unknown_ip"
        self.rate_limiter.check_rate_limit(
            key=ip_key,
            action="verification_request",
            max_requests=5,
            window_seconds=60.0,
        )

        normalized = normalize_email(email)
        user = await self.user_repo.get_by_email_with_role(normalized)

        if user is not None and user.account_status == AccountStatus.PENDING_VERIFICATION.value:
            raw_token = generate_opaque_token(32)
            token_digest = hash_token(raw_token)
            expires_at = datetime.now(UTC) + timedelta(hours=24)

            auth_token = AuthToken(
                user_id=user.id,
                token_hash=token_digest,
                purpose=AuthTokenPurpose.EMAIL_VERIFICATION.value,
                expires_at=expires_at,
                created_by_ip=client_ip,
            )
            await self.auth_token_repo.create(auth_token)
            await self.email_service.send_verification_email(user.email, raw_token)

        return GenericActionResponse(
            message="If the account requires verification, a verification email has been sent."
        )

    async def confirm_email_verification(
        self,
        token: str,
    ) -> GenericActionResponse:
        """Atomically consume email verification token and activate user account."""
        raw_token = token.strip()
        token_digest = hash_token(raw_token)
        now = datetime.now(UTC)

        consumed_token = await self.auth_token_repo.consume_token_atomically(
            token_digest,
            purpose=AuthTokenPurpose.EMAIL_VERIFICATION,
            now=now,
        )
        if consumed_token is None:
            raise AuthenticationError(
                "Invalid, expired, or already-consumed verification token.",
                code="INVALID_VERIFICATION_TOKEN",
            )

        user = await self.user_repo.get_by_id_unscoped(consumed_token.user_id)
        if user is None:
            raise AuthenticationError("User not found.", code="USER_NOT_FOUND")

        if user.account_status in {AccountStatus.SUSPENDED.value, AccountStatus.DISABLED.value}:
            raise BusinessRuleError(
                "Cannot activate a suspended or disabled account via email verification.",
                code="ACCOUNT_LIFECYCLE_RESTRICTED",
            )

        if user.account_status == AccountStatus.PENDING_VERIFICATION.value:
            user.activate(when=now)

        return GenericActionResponse(message="Account email has been successfully verified.")

    async def get_authenticated_principal(
        self,
        token: str,
    ) -> AuthenticatedPrincipal:
        """Resolve and verify the server-side session and active user principal for ``token``.

        Enforces token signature, algorithm, expiration, session active state, and user active state.
        """
        claims = verify_and_decode_access_token(token, self.settings)
        user_uuid = UUID(claims.sub)
        session_uuid = UUID(claims.sid)

        # 1. Authoritative server-side session verification
        active_session = await self.session_repo.get_by_id(session_uuid, user_id=user_uuid)
        if active_session is None:
            raise AuthenticationError(
                "Session does not exist or has been invalidated.",
                code="SESSION_NOT_FOUND",
            )
        now = datetime.now(UTC)
        if active_session.status != SessionStatus.ACTIVE.value:
            raise AuthenticationError(
                "Session has been revoked.",
                code="SESSION_REVOKED",
            )
        if active_session.expires_at <= now:
            active_session.mark_expired()
            raise AuthenticationError(
                "Session has expired.",
                code="SESSION_EXPIRED",
            )

        # 2. Authoritative server-side user verification
        user = await self.user_repo.get_by_id_unscoped(user_uuid)
        if user is None:
            raise AuthenticationError(
                "Authenticated user account not found.",
                code="USER_NOT_FOUND",
            )
        if not user.is_active or user.account_status != AccountStatus.ACTIVE.value:
            raise AuthenticationError(
                "User account is inactive, suspended, or disabled.",
                code="ACCOUNT_INACTIVE",
            )

        return AuthenticatedPrincipal(
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            account_status=user.account_status,
            is_active=user.is_active,
            role_code=user.role.code,
            department_id=user.department_id,
            session_id=active_session.id,
        )

    async def get_current_user_profile(
        self,
        principal: AuthenticatedPrincipal,
    ) -> CurrentUserResponse:
        """Retrieve full verified user profile representation for introspection."""
        user = await self.user_repo.get_by_id_unscoped(principal.user_id)
        if user is None:
            raise AuthenticationError("User not found.", code="USER_NOT_FOUND")

        dept_read = DepartmentRead.model_validate(user.department) if user.department else None
        role_read = RoleRead.model_validate(user.role)
        user_read = UserRead.model_validate(user)

        return CurrentUserResponse(
            user=user_read,
            role=role_read,
            department=dept_read,
            session_id=principal.session_id,
        )

    async def register_student(
        self,
        payload: StudentRegisterRequest,
        *,
        client_ip: str | None = None,
    ) -> StudentRegisterResponse:
        """Register a new student account with rate limiting and verification dispatch (Phase 35)."""
        ip_key = client_ip or "unknown_ip"
        self.rate_limiter.check_rate_limit(
            key=ip_key,
            action="student_registration",
            max_requests=10,
            window_seconds=60.0,
        )

        # 1. Validate target department exists and is active
        dept = await self.dept_repo.get_by_id(payload.department_id)
        if dept is None:
            raise ResourceNotFoundError(
                f"Department '{payload.department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )
        if not dept.is_active:
            raise BusinessRuleError(
                "Cannot register with an inactive or deactivated department.",
                code="INACTIVE_DEPARTMENT_REGISTRATION",
            )

        # 2. Fetch canonical student role
        role = await self.role_repo.get_by_code(RoleCode.STUDENT.value)
        if role is None:
            raise ResourceNotFoundError(
                "Student role configuration was not found.",
                code="ROLE_NOT_FOUND",
            )

        # 3. Check for existing account with same email
        normalized_email = normalize_email(payload.email)
        existing = await self.user_repo.get_by_email(normalized_email)
        if existing is not None:
            raise ConflictError(
                f"An account with email '{normalized_email}' already exists.",
                code="EMAIL_ALREADY_EXISTS",
            )

        # 4. Hash password credential
        password_hash = self.password_service.hash_password(payload.password)

        # 5. Persist user with pending_verification state
        user = User(
            email=normalized_email,
            full_name=payload.full_name,
            role_id=role.id,
            department_id=dept.id,
            institutional_id=payload.institutional_id,
            password_hash=password_hash,
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
            verified_at=None,
        )
        created = await self.user_repo.create(user)

        # 6. Generate single-use email verification token
        raw_token = generate_opaque_token(32)
        token_digest = hash_token(raw_token)
        expires_at = datetime.now(UTC) + timedelta(hours=24)

        auth_token = AuthToken(
            user_id=created.id,
            token_hash=token_digest,
            purpose=AuthTokenPurpose.EMAIL_VERIFICATION.value,
            expires_at=expires_at,
            created_by_ip=client_ip,
        )
        await self.auth_token_repo.create(auth_token)
        await self.email_service.send_verification_email(created.email, raw_token)

        token_for_response = (
            raw_token if self.settings.ENVIRONMENT != Environment.PRODUCTION else None
        )

        return StudentRegisterResponse(
            status="success",
            message="Student registration submitted successfully. Please verify your email to activate your account.",
            user_id=created.id,
            verification_token=token_for_response,
        )

    async def accept_invitation(
        self,
        payload: AcceptInvitationRequest,
    ) -> GenericActionResponse:
        """Atomically consume staff invitation token, set credentials, and activate account (Phase 32)."""
        raw_token = payload.token.strip()
        token_digest = hash_token(raw_token)
        now = datetime.now(UTC)

        consumed_token = await self.auth_token_repo.consume_token_atomically(
            token_digest,
            purpose=AuthTokenPurpose.INVITATION,
            now=now,
        )
        if consumed_token is None:
            raise AuthenticationError(
                "Invalid, expired, or already-consumed invitation token.",
                code="INVALID_INVITATION_TOKEN",
            )

        user = await self.user_repo.get_by_id_unscoped(consumed_token.user_id)
        if user is None:
            raise AuthenticationError("User not found.", code="USER_NOT_FOUND")

        if user.account_status in {
            AccountStatus.SUSPENDED.value,
            AccountStatus.DISABLED.value,
        }:
            raise BusinessRuleError(
                "Cannot accept invitation for a suspended or disabled account.",
                code="ACCOUNT_LIFECYCLE_RESTRICTED",
            )

        if user.department_id is not None:
            dept = await self.dept_repo.get_by_id(user.department_id)
            if dept is not None and not dept.is_active:
                raise BusinessRuleError(
                    "Cannot activate account in a deactivated department.",
                    code="INACTIVE_DEPARTMENT_ASSIGNMENT",
                )

        new_hash = self.password_service.hash_password(payload.password)
        await self.user_repo.update_password_hash(user.id, new_hash)

        if payload.full_name is not None:
            user.full_name = payload.full_name.strip()

        user.activate(when=now)
        return GenericActionResponse(
            message="Staff invitation accepted successfully. You may now log in."
        )
