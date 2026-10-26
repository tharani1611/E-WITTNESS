"""User management and domain access control service (Phases 23-25).

Implements tenant-boundary enforcement, horizontal and vertical privilege
escalation defenses, self-service profile modification restrictions, and
paginated user lookups.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Environment, Settings
from backend.app.core.authorization import (
    DEPT_ADMIN_ASSIGNABLE_ROLES,
    Permission,
    has_permission,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import AccountStatus, AuthTokenPurpose, RoleCode
from backend.app.core.tokens import generate_opaque_token, hash_token
from backend.app.models.token import AuthToken
from backend.app.models.user import User
from backend.app.repositories.identity import (
    AuthTokenRepository,
    DepartmentRepository,
    RoleRepository,
    SessionRepository,
    UserRepository,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import (
    StaffInviteRequest,
    StaffInviteResponse,
    UserAdminCreate,
    UserProfileUpdate,
    UserRead,
    UserUpdate,
)
from backend.app.schemas.pagination import (
    PaginatedResponse,
    PaginationMetadata,
    PaginationParams,
)
from backend.app.services.email import EmailDeliveryService, LoggingEmailDeliveryService
from backend.app.services.password import PasswordService

logger = logging.getLogger("ewitness.services.user")


class UserService:
    """Domain service for managing users and enforcing authorization policies."""

    def __init__(
        self,
        *,
        user_repo: UserRepository,
        role_repo: RoleRepository,
        dept_repo: DepartmentRepository,
        password_service: PasswordService,
        settings: Settings,
        session_repo: SessionRepository | None = None,
        auth_token_repo: AuthTokenRepository | None = None,
        email_service: EmailDeliveryService | None = None,
    ) -> None:
        self.user_repo = user_repo
        self.role_repo = role_repo
        self.dept_repo = dept_repo
        self.password_service = password_service
        self.settings = settings
        self.session_repo = session_repo or SessionRepository(user_repo._session)
        self.auth_token_repo = auth_token_repo or AuthTokenRepository(user_repo._session)
        self.email_service = email_service or LoggingEmailDeliveryService()

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        email_service: EmailDeliveryService | None = None,
    ) -> UserService:
        """Construct a UserService wired with repositories bound to ``session``."""
        return cls(
            user_repo=UserRepository(session),
            role_repo=RoleRepository(session),
            dept_repo=DepartmentRepository(session),
            session_repo=SessionRepository(session),
            auth_token_repo=AuthTokenRepository(session),
            password_service=PasswordService(),
            settings=settings,
            email_service=email_service,
        )

    async def get_user_by_id(
        self,
        user_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Retrieve user details by ID subject to ownership and departmental boundaries.

        - A user may always view their own profile.
        - Super Admins may view any user across all departments.
        - Department Admins may view users within their own department.
        - Accessing users across department boundaries yields 403 Forbidden.
        - Non-existent users yield 404 Not Found.
        """
        # 1. Self-service access
        if principal.user_id == user_id:
            user = await self.user_repo.get_by_id_unscoped(user_id)
            if user is None:
                raise ResourceNotFoundError(
                    f"User '{user_id}' was not found.",
                    code="USER_NOT_FOUND",
                )
            return UserRead.model_validate(user)

        # 2. Super Admin global access
        if principal.role == RoleCode.SUPER_ADMIN:
            user = await self.user_repo.get_by_id_unscoped(user_id)
            if user is None:
                raise ResourceNotFoundError(
                    f"User '{user_id}' was not found.",
                    code="USER_NOT_FOUND",
                )
            return UserRead.model_validate(user)

        # 3. Department Admin access
        if principal.role == RoleCode.DEPT_ADMIN:
            user = await self.user_repo.get_by_id_unscoped(user_id)
            if user is None:
                raise ResourceNotFoundError(
                    f"User '{user_id}' was not found.",
                    code="USER_NOT_FOUND",
                )
            if user.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot access users belonging to other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            return UserRead.model_validate(user)

        # 4. Deny-by-default for all other roles attempting cross-user reads
        raise PermissionDeniedError(
            f"User role '{principal.role}' does not possess permission to read other user records.",
            code="PERMISSION_DENIED",
        )

    async def list_users(
        self,
        principal: AuthenticatedPrincipal,
        *,
        pagination: PaginationParams,
        department_id: UUID | None = None,
        role_code: str | None = None,
        account_status: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "asc",
    ) -> PaginatedResponse[UserRead]:
        """List users with pagination, allowlisted sorting, and department boundary enforcement."""
        # 1. Verify caller has either departmental or global user read permission
        has_dept = has_permission(principal.role, Permission.USER_READ_DEPT)
        has_global = has_permission(principal.role, Permission.USER_READ_GLOBAL)

        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to list users.",
                code="PERMISSION_DENIED",
            )

        # 2. Enforce department filter boundaries
        effective_dept_id: UUID | None = None
        if principal.role == RoleCode.SUPER_ADMIN:
            effective_dept_id = department_id
        else:
            # Dept Admin is strictly confined to their own department
            if department_id is not None and department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot query users from other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            effective_dept_id = principal.department_id

        # 3. Execute paginated query
        items, total_items = await self.user_repo.list_paginated(
            department_id=effective_dept_id,
            role_code=role_code,
            account_status=account_status,
            is_active=is_active,
            search=search,
            limit=pagination.limit,
            offset=pagination.offset,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        return PaginatedResponse(
            items=[UserRead.model_validate(u) for u in items],
            pagination=PaginationMetadata.from_counts(
                page=pagination.page,
                page_size=pagination.page_size,
                total_items=total_items,
            ),
        )

    async def create_user(
        self,
        data: UserAdminCreate,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Create a user with vertical and horizontal privilege escalation defenses."""
        # 1. Check create permissions
        has_dept = has_permission(principal.role, Permission.USER_CREATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_CREATE_GLOBAL)

        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to create users.",
                code="PERMISSION_DENIED",
            )

        # 2. Enforce department assignment boundaries
        target_dept_id = data.department_id
        if principal.role == RoleCode.DEPT_ADMIN:
            if target_dept_id is not None and target_dept_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot create users for other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            # Default to caller's department if omitted
            target_dept_id = principal.department_id

            # 3. Prevent vertical privilege escalation
            role = await self.role_repo.get_by_id(data.role_id)
            if role is None:
                raise BusinessRuleError(
                    "Assigned role does not exist.",
                    code="INVALID_ROLE_ASSIGNMENT",
                )
            try:
                role_code = RoleCode(role.code)
            except ValueError:
                role_code = None

            if role_code not in DEPT_ADMIN_ASSIGNABLE_ROLES:
                raise PermissionDeniedError(
                    f"Department Administrators cannot assign administrative role '{role.code}'.",
                    code="PRIVILEGE_ESCALATION_FORBIDDEN",
                )

        # 4. Validate target department exists and is active
        if target_dept_id is not None:
            dept = await self.dept_repo.get_by_id(target_dept_id)
            if dept is None:
                raise ResourceNotFoundError(
                    f"Department '{target_dept_id}' was not found.",
                    code="DEPARTMENT_NOT_FOUND",
                )
            if not dept.is_active:
                raise BusinessRuleError(
                    "Cannot assign users to an inactive or deactivated department.",
                    code="INACTIVE_DEPARTMENT_ASSIGNMENT",
                )

        # 5. Hash password
        password_hash = self.password_service.hash_password(data.password)

        # 6. Persist user identity
        user = User(
            email=data.email,
            full_name=data.full_name,
            role_id=data.role_id,
            department_id=target_dept_id,
            institutional_id=data.institutional_id,
            password_hash=password_hash,
            account_status=data.account_status.value,
            is_active=True,
        )
        created = await self.user_repo.create(user)
        return UserRead.model_validate(created)

    async def update_user(
        self,
        user_id: UUID,
        data: UserUpdate,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Update user properties enforcing self-modification, department, and escalation guards."""
        target = await self.user_repo.get_by_id_unscoped(user_id)
        if target is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )

        # 1. Self-modification guardrails
        if principal.user_id == user_id:
            if data.role_id is not None and data.role_id != target.role_id:
                raise PermissionDeniedError(
                    "Users cannot modify their own role.",
                    code="SELF_ROLE_MODIFICATION_FORBIDDEN",
                )
            if data.account_status is not None or (
                data.is_active is not None and not data.is_active
            ):
                raise PermissionDeniedError(
                    "Users cannot alter their own account status or deactivate their own account.",
                    code="SELF_STATUS_MODIFICATION_FORBIDDEN",
                )
            if data.department_id is not None and data.department_id != target.department_id:
                raise PermissionDeniedError(
                    "Users cannot reassign their own department.",
                    code="DEPARTMENT_REASSIGNMENT_RESTRICTED",
                )

        # 2. Administrative permission evaluation
        has_dept = has_permission(principal.role, Permission.USER_UPDATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_UPDATE_GLOBAL)

        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to modify users.",
                code="PERMISSION_DENIED",
            )

        # 3. Department Admin and administrative scope protections
        if principal.role == RoleCode.DEPT_ADMIN:
            if target.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot modify users belonging to other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            if data.department_id is not None and data.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot reassign users across departments.",
                    code="DEPARTMENT_REASSIGNMENT_RESTRICTED",
                )
            if data.role_id is not None and data.role_id != target.role_id:
                role = await self.role_repo.get_by_id(data.role_id)
                if role is None:
                    raise BusinessRuleError(
                        "Assigned role does not exist.",
                        code="INVALID_ROLE_ASSIGNMENT",
                    )
                try:
                    role_code = RoleCode(role.code)
                except ValueError:
                    role_code = None

                if role_code not in DEPT_ADMIN_ASSIGNABLE_ROLES:
                    raise PermissionDeniedError(
                        f"Department Administrators cannot assign administrative role '{role.code}'.",
                        code="PRIVILEGE_ESCALATION_FORBIDDEN",
                    )

            target_role = await self.role_repo.get_by_id(target.role_id)
            if target_role and target_role.code in {
                RoleCode.SUPER_ADMIN.value,
                RoleCode.DEPT_ADMIN.value,
            }:
                raise PermissionDeniedError(
                    "Department Administrators cannot modify administrative accounts.",
                    code="PRIVILEGE_ESCALATION_FORBIDDEN",
                )

        target_role = await self.role_repo.get_by_id(target.role_id)
        if (
            target_role
            and target_role.code == RoleCode.SUPER_ADMIN.value
            and principal.role != RoleCode.SUPER_ADMIN
        ):
            raise PermissionDeniedError(
                "Only Super Administrators can manage Super Administrator accounts.",
                code="PERMISSION_DENIED",
            )

        # 4. Validate target department exists and is active
        if data.department_id is not None and data.department_id != target.department_id:
            dept = await self.dept_repo.get_by_id(data.department_id)
            if dept is None:
                raise ResourceNotFoundError(
                    f"Department '{data.department_id}' was not found.",
                    code="DEPARTMENT_NOT_FOUND",
                )
            if not dept.is_active:
                raise BusinessRuleError(
                    "Cannot assign users to an inactive or deactivated department.",
                    code="INACTIVE_DEPARTMENT_ASSIGNMENT",
                )

        updated = await self.user_repo.update_admin(
            user_id=user_id,
            full_name=data.full_name,
            role_id=data.role_id,
            department_id=data.department_id,
            account_status=data.account_status,
            is_active=data.is_active,
        )

        role_changed = data.role_id is not None and data.role_id != target.role_id
        dept_changed = data.department_id is not None and data.department_id != target.department_id

        if data.is_active is False or (
            data.account_status in {AccountStatus.DISABLED, AccountStatus.SUSPENDED}
        ):
            await self.session_repo.revoke_user_sessions(
                user_id=user_id,
                reason="account_deactivated",
                when=datetime.now(UTC),
            )
        elif role_changed or dept_changed:
            await self.session_repo.revoke_user_sessions(
                user_id=user_id,
                reason="privilege_or_department_changed",
                when=datetime.now(UTC),
            )

        return UserRead.model_validate(updated)

    async def update_own_profile(
        self,
        data: UserProfileUpdate,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Update caller's own profile (full_name)."""
        updated = await self.user_repo.update_profile(
            principal.user_id,
            full_name=data.full_name,
        )
        return UserRead.model_validate(updated)

    async def invite_staff(
        self,
        data: StaffInviteRequest,
        principal: AuthenticatedPrincipal,
    ) -> StaffInviteResponse:
        """Invite a new staff or investigator account with secure token delivery (Phase 32)."""
        has_dept = has_permission(principal.role, Permission.USER_CREATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_CREATE_GLOBAL)

        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to invite staff accounts.",
                code="PERMISSION_DENIED",
            )

        target_dept_id = data.department_id
        if principal.role == RoleCode.DEPT_ADMIN:
            if target_dept_id is not None and target_dept_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot invite staff for other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            target_dept_id = principal.department_id

        # Validate role assignment
        role = await self.role_repo.get_by_id(data.role_id)
        if role is None:
            raise BusinessRuleError(
                "Assigned role does not exist.",
                code="INVALID_ROLE_ASSIGNMENT",
            )
        try:
            role_code = RoleCode(role.code)
        except ValueError:
            role_code = None

        if principal.role == RoleCode.DEPT_ADMIN and role_code not in DEPT_ADMIN_ASSIGNABLE_ROLES:
            raise PermissionDeniedError(
                f"Department Administrators cannot assign administrative role '{role.code}'.",
                code="PRIVILEGE_ESCALATION_FORBIDDEN",
            )

        # Validate target department exists and is active
        if target_dept_id is not None:
            dept = await self.dept_repo.get_by_id(target_dept_id)
            if dept is None:
                raise ResourceNotFoundError(
                    f"Department '{target_dept_id}' was not found.",
                    code="DEPARTMENT_NOT_FOUND",
                )
            if not dept.is_active:
                raise BusinessRuleError(
                    "Cannot assign users to an inactive or deactivated department.",
                    code="INACTIVE_DEPARTMENT_ASSIGNMENT",
                )

        # Check if email is already registered
        existing = await self.user_repo.get_by_email(data.email)
        if existing is not None:
            raise ConflictError(
                f"An account with email '{data.email}' already exists.",
                code="EMAIL_ALREADY_EXISTS",
            )

        # Persist pending user identity (no password hash yet)
        user = User(
            email=data.email,
            full_name=data.full_name,
            role_id=data.role_id,
            department_id=target_dept_id,
            institutional_id=data.institutional_id,
            password_hash=None,
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
        )
        created = await self.user_repo.create(user)

        # Generate single-use invitation token
        raw_token = generate_opaque_token(32)
        token_digest = hash_token(raw_token)
        expires_at = datetime.now(UTC) + timedelta(hours=48)

        auth_token = AuthToken(
            user_id=created.id,
            token_hash=token_digest,
            purpose=AuthTokenPurpose.INVITATION.value,
            expires_at=expires_at,
        )
        await self.auth_token_repo.create(auth_token)
        await self.email_service.send_invitation_email(created.email, raw_token)

        # Provide token in response only for non-production environments to support testing
        token_for_response = (
            raw_token if self.settings.ENVIRONMENT != Environment.PRODUCTION else None
        )

        return StaffInviteResponse(
            user=UserRead.model_validate(created),
            message="Staff invitation dispatched successfully.",
            invitation_token=token_for_response,
        )

    async def deactivate_user(
        self,
        user_id: UUID,
        principal: AuthenticatedPrincipal,
        *,
        reason: str | None = None,
    ) -> UserRead:
        """Deactivate a user account, invalidate all active sessions, and lock credentials (Phase 32)."""
        if principal.user_id == user_id:
            raise PermissionDeniedError(
                "Users cannot deactivate their own account.",
                code="SELF_DEACTIVATION_FORBIDDEN",
            )

        has_dept = has_permission(principal.role, Permission.USER_UPDATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_UPDATE_GLOBAL)
        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to deactivate users.",
                code="PERMISSION_DENIED",
            )

        target = await self.user_repo.get_by_id_unscoped(user_id)
        if target is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )

        # Department Admin scope check
        if principal.role == RoleCode.DEPT_ADMIN:
            if target.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot modify users belonging to other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            target_role = await self.role_repo.get_by_id(target.role_id)
            if target_role and target_role.code in {
                RoleCode.SUPER_ADMIN.value,
                RoleCode.DEPT_ADMIN.value,
            }:
                raise PermissionDeniedError(
                    "Department Administrators cannot deactivate administrative accounts.",
                    code="PRIVILEGE_ESCALATION_FORBIDDEN",
                )

        # Super Admin protection
        target_role = await self.role_repo.get_by_id(target.role_id)
        if (
            target_role
            and target_role.code == RoleCode.SUPER_ADMIN.value
            and principal.role != RoleCode.SUPER_ADMIN
        ):
            raise PermissionDeniedError(
                "Only Super Administrators can manage Super Administrator accounts.",
                code="PERMISSION_DENIED",
            )

        now = datetime.now(UTC)
        target.disable(reason=reason, when=now)
        await self.session_repo.revoke_user_sessions(
            user_id=user_id,
            reason="account_deactivated",
            when=now,
        )
        return UserRead.model_validate(target)

    async def activate_user(
        self,
        user_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Reactivate an eligible user account (Phase 32)."""
        if principal.user_id == user_id:
            raise PermissionDeniedError(
                "Users cannot activate their own account.",
                code="SELF_STATUS_MODIFICATION_FORBIDDEN",
            )

        has_dept = has_permission(principal.role, Permission.USER_UPDATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_UPDATE_GLOBAL)
        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to activate users.",
                code="PERMISSION_DENIED",
            )

        target = await self.user_repo.get_by_id_unscoped(user_id)
        if target is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )

        if principal.role == RoleCode.DEPT_ADMIN:
            if target.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot modify users belonging to other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            target_role = await self.role_repo.get_by_id(target.role_id)
            if target_role and target_role.code in {
                RoleCode.SUPER_ADMIN.value,
                RoleCode.DEPT_ADMIN.value,
            }:
                raise PermissionDeniedError(
                    "Department Administrators cannot activate administrative accounts.",
                    code="PRIVILEGE_ESCALATION_FORBIDDEN",
                )

        if target.account_status == AccountStatus.ACTIVE.value:
            return UserRead.model_validate(target)

        if target.account_status == AccountStatus.DISABLED.value:
            raise BusinessRuleError(
                "Cannot activate a permanently disabled account.",
                code="ACCOUNT_LIFECYCLE_RESTRICTED",
            )

        now = datetime.now(UTC)
        target.activate(when=now)
        return UserRead.model_validate(target)

    async def assign_department(
        self,
        user_id: UUID,
        target_dept_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Assign or reassign a user's department (Phase 34)."""
        has_dept = has_permission(principal.role, Permission.USER_UPDATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_DEPT_REASSIGN_GLOBAL)

        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to reassign departments.",
                code="PERMISSION_DENIED",
            )

        if principal.user_id == user_id:
            raise PermissionDeniedError(
                "Users cannot reassign their own department.",
                code="DEPARTMENT_REASSIGNMENT_RESTRICTED",
            )

        target = await self.user_repo.get_by_id_unscoped(user_id)
        if target is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )

        if principal.role == RoleCode.DEPT_ADMIN:
            if target_dept_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot assign users to other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            if target.department_id is not None and target.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot transfer users from other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            target_role = await self.role_repo.get_by_id(target.role_id)
            if target_role and target_role.code in {
                RoleCode.SUPER_ADMIN.value,
                RoleCode.DEPT_ADMIN.value,
            }:
                raise PermissionDeniedError(
                    "Department Administrators cannot reassign administrative accounts.",
                    code="PRIVILEGE_ESCALATION_FORBIDDEN",
                )

        dept = await self.dept_repo.get_by_id(target_dept_id)
        if dept is None:
            raise ResourceNotFoundError(
                f"Department '{target_dept_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )
        if not dept.is_active:
            raise BusinessRuleError(
                "Cannot assign users to an inactive or deactivated department.",
                code="INACTIVE_DEPARTMENT_ASSIGNMENT",
            )

        if target.department_id != target_dept_id:
            target.department_id = target_dept_id
            target.updated_at = datetime.now(UTC)
            await self.session_repo.revoke_user_sessions(
                user_id=user_id,
                reason="department_reassigned",
                when=datetime.now(UTC),
            )
        return UserRead.model_validate(target)

    async def assign_investigator(
        self,
        *,
        department_id: UUID,
        investigator_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> UserRead:
        """Assign an eligible investigator to an active department (Phase 36)."""
        has_dept = has_permission(principal.role, Permission.USER_UPDATE_DEPT)
        has_global = has_permission(principal.role, Permission.USER_DEPT_REASSIGN_GLOBAL)

        if not (has_dept or has_global):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to assign investigators.",
                code="PERMISSION_DENIED",
            )

        # 1. Target user exists
        target = await self.user_repo.get_by_id_unscoped(investigator_id)
        if target is None:
            raise ResourceNotFoundError(
                f"User '{investigator_id}' was not found.",
                code="USER_NOT_FOUND",
            )

        # 2. Target user must have INVESTIGATOR role
        target_role = await self.role_repo.get_by_id(target.role_id)
        if target_role is None or target_role.code != RoleCode.INVESTIGATOR.value:
            raise BusinessRuleError(
                f"User '{investigator_id}' does not have the required investigator role.",
                code="INVALID_ROLE_ASSIGNMENT",
            )

        # 3. Target user account must be active
        if target.account_status != AccountStatus.ACTIVE.value or not target.is_active:
            raise BusinessRuleError(
                "Only active accounts can receive investigator assignments.",
                code="ACCOUNT_LIFECYCLE_RESTRICTED",
            )

        # 4. Target department exists
        dept = await self.dept_repo.get_by_id(department_id)
        if dept is None:
            raise ResourceNotFoundError(
                f"Department '{department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )

        # 5. Target department must be active
        if not dept.is_active:
            raise BusinessRuleError(
                "Cannot assign investigators to an inactive or deactivated department.",
                code="INACTIVE_DEPARTMENT_ASSIGNMENT",
            )

        # 6. Scoped administrative permissions
        if principal.role == RoleCode.DEPT_ADMIN:
            if department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot assign investigators to other departments.",
                    code="DEPARTMENT_MISMATCH",
                )
            if target.department_id is not None and target.department_id != principal.department_id:
                raise PermissionDeniedError(
                    "Department Administrators cannot transfer investigators from other departments.",
                    code="DEPARTMENT_MISMATCH",
                )

        # 7. Idempotent check
        if target.department_id == department_id:
            return UserRead.model_validate(target)

        # 8. Apply assignment
        target.department_id = department_id
        target.updated_at = datetime.now(UTC)
        await self.session_repo.revoke_user_sessions(
            user_id=investigator_id,
            reason="investigator_department_assigned",
            when=datetime.now(UTC),
        )
        logger.info(
            "Assigned investigator %s to department %s by %s",
            investigator_id,
            department_id,
            principal.user_id,
            extra={
                "investigator_id": str(investigator_id),
                "department_id": str(department_id),
                "assigned_by": str(principal.user_id),
            },
        )
        return UserRead.model_validate(target)

    async def list_department_investigators(
        self,
        department_id: UUID,
        principal: AuthenticatedPrincipal,
        *,
        pagination: PaginationParams,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "asc",
    ) -> PaginatedResponse[UserRead]:
        """List investigators assigned to a department with tenant boundary checks (Phase 36 & 38)."""
        # 1. Target department exists
        dept = await self.dept_repo.get_by_id(department_id)
        if dept is None:
            raise ResourceNotFoundError(
                f"Department '{department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )

        # 2. Scope boundary
        if principal.role != RoleCode.SUPER_ADMIN:
            if principal.department_id != department_id:
                raise PermissionDeniedError(
                    "Users cannot access investigator directories outside their assigned department.",
                    code="DEPARTMENT_MISMATCH",
                )
            has_dept = has_permission(principal.role, Permission.USER_READ_DEPT)
            has_own = has_permission(principal.role, Permission.DEPARTMENT_READ_OWN)
            if not (has_dept or has_own):
                raise PermissionDeniedError(
                    f"User role '{principal.role}' lacks permission to read department investigators.",
                    code="PERMISSION_DENIED",
                )

        # 3. Query paginated investigators
        items, total_items = await self.user_repo.list_paginated(
            department_id=department_id,
            role_code=RoleCode.INVESTIGATOR.value,
            search=search,
            limit=pagination.limit,
            offset=pagination.offset,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        return PaginatedResponse(
            items=[UserRead.model_validate(u) for u in items],
            pagination=PaginationMetadata.from_counts(
                page=pagination.page,
                page_size=pagination.page_size,
                total_items=total_items,
            ),
        )
