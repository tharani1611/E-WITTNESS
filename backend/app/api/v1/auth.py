"""Authentication, refresh sessions, password recovery, and verification endpoints (Phases 17-18).

Exposes routes for:
- POST /api/v1/auth/login
- POST /api/v1/auth/refresh
- POST /api/v1/auth/logout
- GET  /api/v1/auth/me
- POST /api/v1/auth/sessions/revoke
- POST /api/v1/auth/forgot-password
- POST /api/v1/auth/reset-password
- POST /api/v1/auth/verify-email/request
- POST /api/v1/auth/verify-email/confirm
"""

from __future__ import annotations

from fastapi import APIRouter, Request, status

from backend.app.api.dependencies import AuthServiceDep, ClientIpDep, CurrentUserDep
from backend.app.schemas.auth import (
    AcceptInvitationRequest,
    ChangePasswordRequest,
    CurrentUserResponse,
    ForgotPasswordRequest,
    GenericActionResponse,
    LoginRequest,
    RefreshTokenRequest,
    ResetPasswordRequest,
    RevokeSessionRequest,
    StudentRegisterRequest,
    StudentRegisterResponse,
    TokenResponse,
    VerifyEmailConfirmRequest,
    VerifyEmailRequestRequest,
)

v1_auth_router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])


@v1_auth_router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user credentials",
    description="Authenticates email and password, establishing an active session and returning JWT bearer + opaque refresh credentials.",
)
async def login(
    payload: LoginRequest,
    auth_service: AuthServiceDep,
    request: Request,
    client_ip: ClientIpDep,
) -> TokenResponse:
    user_agent = request.headers.get("user-agent")
    return await auth_service.authenticate(
        payload,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@v1_auth_router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate refresh token",
    description="Rotates opaque refresh token and issues a replacement access token. Detects token reuse and revokes compromised sessions.",
)
async def refresh_token(
    payload: RefreshTokenRequest,
    auth_service: AuthServiceDep,
    request: Request,
    client_ip: ClientIpDep,
) -> TokenResponse:
    user_agent = request.headers.get("user-agent")
    return await auth_service.rotate_refresh_token(
        payload,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@v1_auth_router.post(
    "/logout",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Terminate authenticated session",
    description="Revokes the active bearer session immediately.",
)
async def logout(
    current_user: CurrentUserDep,
    auth_service: AuthServiceDep,
) -> GenericActionResponse:
    return await auth_service.revoke_sessions_for_principal(current_user)


@v1_auth_router.get(
    "/me",
    response_model=CurrentUserResponse,
    status_code=status.HTTP_200_OK,
    summary="Introspect current authenticated user",
    description="Returns the verified profile, assigned role, department scope, and session metadata of the caller.",
)
async def get_current_user_profile(
    current_user: CurrentUserDep,
    auth_service: AuthServiceDep,
) -> CurrentUserResponse:
    return await auth_service.get_current_user_profile(current_user)


@v1_auth_router.post(
    "/sessions/revoke",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke sessions",
    description="Revokes a target session or all other active sessions for the calling user.",
)
async def revoke_sessions(
    payload: RevokeSessionRequest,
    current_user: CurrentUserDep,
    auth_service: AuthServiceDep,
) -> GenericActionResponse:
    return await auth_service.revoke_principal_sessions(
        principal=current_user,
        target_session_id=payload.session_id,
        all_other_sessions=payload.all_other_sessions,
    )


@v1_auth_router.post(
    "/forgot-password",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Request password recovery token",
    description="Initiates self-service password reset. Returns a privacy-preserving generic confirmation without disclosing account existence.",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    auth_service: AuthServiceDep,
    client_ip: ClientIpDep,
) -> GenericActionResponse:
    return await auth_service.request_password_reset(
        payload.email,
        client_ip=client_ip,
    )


@v1_auth_router.post(
    "/reset-password",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset account password",
    description="Atomically consumes one-time password reset token, updates account password hash, and invalidates all existing active sessions.",
)
async def reset_password(
    payload: ResetPasswordRequest,
    auth_service: AuthServiceDep,
) -> GenericActionResponse:
    return await auth_service.reset_password(payload)


@v1_auth_router.post(
    "/change-password",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Change authenticated user password",
    description="Allows an authenticated caller to change their password upon supplying their current credential. Revokes all active sessions upon success.",
)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: CurrentUserDep,
    auth_service: AuthServiceDep,
    client_ip: ClientIpDep,
) -> GenericActionResponse:
    return await auth_service.change_password(
        current_user,
        payload,
        client_ip=client_ip,
    )


@v1_auth_router.post(
    "/verify-email/request",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Request account verification email",
    description="Dispatches a single-use verification token to the specified account address.",
)
async def request_email_verification(
    payload: VerifyEmailRequestRequest,
    auth_service: AuthServiceDep,
    client_ip: ClientIpDep,
) -> GenericActionResponse:
    return await auth_service.request_email_verification(
        payload.email,
        client_ip=client_ip,
    )


@v1_auth_router.post(
    "/verify-email/confirm",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirm account verification",
    description="Atomically consumes single-use email verification token and transitions account to active status.",
)
async def confirm_email_verification(
    payload: VerifyEmailConfirmRequest,
    auth_service: AuthServiceDep,
) -> GenericActionResponse:
    return await auth_service.confirm_email_verification(payload.token)


@v1_auth_router.post(
    "/register",
    response_model=StudentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register student account",
    description="Self-service student registration with rate limiting, email verification dispatch, and active department validation.",
)
@v1_auth_router.post(
    "/register/student",
    response_model=StudentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def register_student(
    payload: StudentRegisterRequest,
    auth_service: AuthServiceDep,
    client_ip: ClientIpDep,
) -> StudentRegisterResponse:
    return await auth_service.register_student(payload, client_ip=client_ip)


@v1_auth_router.post(
    "/invitations/accept",
    response_model=GenericActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Accept staff invitation",
    description="Atomically consumes one-time invitation token, sets account credentials, and activates staff account.",
)
async def accept_invitation(
    payload: AcceptInvitationRequest,
    auth_service: AuthServiceDep,
) -> GenericActionResponse:
    return await auth_service.accept_invitation(payload)
