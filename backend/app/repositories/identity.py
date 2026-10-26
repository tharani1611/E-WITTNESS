"""Persistence repositories for Department, Role, User, and Session entities (Phases 14-15).

Enforces:
- Multi-department tenant scoping on `UserRepository` (`TenantScopedRepositoryProtocol`)
- Role-to-department scope validation before persisting user identities
- Normalized lookups on `email`, `institutional_id`, and `department.code`
- Controlled account-state transitions and soft deactivation
- Safe translation of SQLAlchemy `IntegrityError`/`OperationalError` into
  sanitized domain exceptions (`ConflictError`, `BusinessRuleError`,
  `ServiceUnavailableError`) without leaking SQL or connection secrets
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.exceptions import BusinessRuleError, ResourceNotFoundError
from backend.app.core.identity import (
    AccountStatus,
    AuthTokenPurpose,
    RoleCode,
    SessionStatus,
    normalize_department_code,
    normalize_email,
    normalize_institutional_id,
    validate_role_department_binding,
)
from backend.app.infrastructure.database import translate_database_error
from backend.app.models.base import utc_now
from backend.app.models.department import Department
from backend.app.models.role import Role
from backend.app.models.session import Session
from backend.app.models.token import AuthToken
from backend.app.models.user import User

DEFAULT_SYSTEM_ROLES: tuple[tuple[RoleCode, str, str, bool], ...] = (
    (
        RoleCode.STUDENT,
        "Student",
        "Submits incident reports or witness disclosures and views permitted own-case updates.",
        True,
    ),
    (
        RoleCode.STAFF,
        "Staff",
        "Records institutional incidents and accesses authorized departmental submissions.",
        True,
    ),
    (
        RoleCode.DEPT_ADMIN,
        "Department Administrator",
        "Manages department users, intake workflows, triage, and investigator assignments.",
        True,
    ),
    (
        RoleCode.INVESTIGATOR,
        "Investigator",
        "Reviews explicitly assigned cases, verifies evidence, and records formal findings.",
        True,
    ),
    (
        RoleCode.SUPER_ADMIN,
        "Super Admin",
        "Manages platform configuration, department provisioning, and audit oversight.",
        False,
    ),
)


class DepartmentRepository:
    """Asynchronous repository for `Department` tenant persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, department: Department) -> Department:
        """Persist a new `Department` and flush to verify uniqueness and check constraints."""
        try:
            self._session.add(department)
            await self._session.flush()
            await self._session.refresh(department)
            return department
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_id(self, department_id: UUID) -> Department | None:
        """Retrieve a `Department` by its UUID primary key."""
        try:
            stmt = select(Department).where(Department.id == department_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_code(self, code: str) -> Department | None:
        """Retrieve a `Department` by its normalized uppercase code."""
        normalized = normalize_department_code(code)
        try:
            stmt = select(Department).where(Department.code == normalized)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def list_active(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Department]:
        """List active departments ordered by code."""
        try:
            stmt = (
                select(Department)
                .where(Department.is_active.is_(True))
                .order_by(Department.code.asc())
                .limit(limit)
                .offset(offset)
            )
            result = await self._session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def deactivate(
        self,
        department_id: UUID,
        *,
        when: datetime | None = None,
    ) -> Department:
        """Soft-deactivate a department by setting `is_active=False` and `deactivated_at`."""
        department = await self.get_by_id(department_id)
        if department is None:
            raise ResourceNotFoundError(
                f"Department '{department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )
        try:
            department.deactivate(when=when)
            await self._session.flush()
            await self._session.refresh(department)
            return department
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def activate(
        self,
        department_id: UUID,
    ) -> Department:
        """Activate an inactive department by setting `is_active=True` and clearing `deactivated_at`."""
        department = await self.get_by_id(department_id)
        if department is None:
            raise ResourceNotFoundError(
                f"Department '{department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )
        try:
            department.activate()
            await self._session.flush()
            await self._session.refresh(department)
            return department
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def list_paginated(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        is_active: bool | None = None,
        search: str | None = None,
        sort_by: str = "code",
        sort_order: str = "asc",
    ) -> tuple[Sequence[Department], int]:
        """List departments with pagination, filtering, and allowlisted sorting."""
        sort_fields = {
            "code": Department.code,
            "name": Department.name,
            "created_at": Department.created_at,
        }
        if sort_by not in sort_fields:
            raise BusinessRuleError(
                f"Invalid sort field '{sort_by}'. Allowed fields: {', '.join(sorted(sort_fields))}.",
                code="INVALID_SORT_FIELD",
                status_code=400,
            )
        if sort_order.lower() not in {"asc", "desc"}:
            raise BusinessRuleError(
                f"Invalid sort order '{sort_order}'. Allowed values: 'asc', 'desc'.",
                code="INVALID_SORT_ORDER",
                status_code=400,
            )
        col = sort_fields[sort_by]
        order_clause = col.desc() if sort_order.lower() == "desc" else col.asc()

        try:
            stmt = select(Department)
            count_stmt = select(func.count(Department.id))

            if is_active is not None:
                stmt = stmt.where(Department.is_active.is_(is_active))
                count_stmt = count_stmt.where(Department.is_active.is_(is_active))

            if search:
                pattern = f"%{search.strip()}%"
                search_filter = Department.name.ilike(pattern) | Department.code.ilike(pattern)
                stmt = stmt.where(search_filter)
                count_stmt = count_stmt.where(search_filter)

            total_items = (await self._session.execute(count_stmt)).scalar() or 0
            stmt = stmt.order_by(order_clause).limit(limit).offset(offset)
            items = list((await self._session.execute(stmt)).scalars().all())
            return items, int(total_items)
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def update(
        self,
        department_id: UUID,
        *,
        name: str | None = None,
        description: str | None = None,
        is_active: bool | None = None,
    ) -> Department:
        """Update department properties and flush."""
        dept = await self.get_by_id(department_id)
        if dept is None:
            raise ResourceNotFoundError(
                f"Department '{department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )
        try:
            if name is not None:
                dept.name = name.strip()
            if description is not None:
                dept.description = description
            if is_active is not None:
                if not is_active and dept.is_active:
                    dept.deactivate()
                elif is_active and not dept.is_active:
                    dept.is_active = True
                    dept.deactivated_at = None
            dept.updated_at = utc_now()
            await self._session.flush()
            await self._session.refresh(dept)
            return dept
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None


class RoleRepository:
    """Asynchronous repository for stakeholder `Role` definitions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, role: Role) -> Role:
        """Persist a new `Role` and flush to enforce constraints."""
        try:
            self._session.add(role)
            await self._session.flush()
            await self._session.refresh(role)
            return role
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_id(self, role_id: UUID) -> Role | None:
        """Retrieve a `Role` by its UUID primary key."""
        try:
            stmt = select(Role).where(Role.id == role_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_code(self, code: RoleCode | str) -> Role | None:
        """Retrieve a `Role` by its canonical `RoleCode`."""
        code_str = code.value if isinstance(code, RoleCode) else str(code).strip()
        try:
            stmt = select(Role).where(Role.code == code_str)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def ensure_default_roles(self) -> dict[RoleCode, Role]:
        """Idempotently seed the five canonical E-WITNESS stakeholder roles."""
        seeded: dict[RoleCode, Role] = {}
        for role_code, name, description, requires_dept in DEFAULT_SYSTEM_ROLES:
            existing = await self.get_by_code(role_code)
            if existing is not None:
                seeded[role_code] = existing
                continue
            role = Role(
                code=role_code.value,
                name=name,
                description=description,
                requires_department_scope=requires_dept,
                is_system_role=True,
            )
            seeded[role_code] = await self.create(role)
        return seeded


class UserRepository:
    """Tenant-aware asynchronous repository for `User` identity records.

    Conforms to `TenantScopedRepositoryProtocol[User]` by requiring keyword-only
    `department_id: UUID` on `get_by_id` and `list_for_department`.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, user: User) -> User:
        """Validate role-to-department scope and persist a new `User` identity."""
        try:
            role_stmt = select(Role).where(Role.id == user.role_id)
            role_result = await self._session.execute(role_stmt)
            role = role_result.scalar_one_or_none()
            if role is None:
                raise BusinessRuleError(
                    "Assigned role does not exist.",
                    code="INVALID_ROLE_ASSIGNMENT",
                )

            validate_role_department_binding(
                role.code,
                user.department_id,
                requires_department_scope=role.requires_department_scope,
            )

            if user.department_id is not None:
                dept_stmt = select(Department).where(Department.id == user.department_id)
                dept_result = await self._session.execute(dept_stmt)
                department = dept_result.scalar_one_or_none()
                if department is None:
                    raise BusinessRuleError(
                        "Assigned department does not exist.",
                        code="INVALID_DEPARTMENT_ASSIGNMENT",
                    )
                if not department.is_active:
                    raise BusinessRuleError(
                        "Cannot assign a user to a deactivated department.",
                        code="INACTIVE_DEPARTMENT_ASSIGNMENT",
                    )

            self._session.add(user)
            await self._session.flush()
            await self._session.refresh(user)
            return user
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_id(
        self,
        entity_id: UUID,
        *,
        department_id: UUID,
    ) -> User | None:
        """Retrieve a `User` strictly scoped to ``department_id`` (`SEC-002`)."""
        try:
            stmt = select(User).where(
                User.id == entity_id,
                User.department_id == department_id,
            )
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_id_unscoped(self, user_id: UUID) -> User | None:
        """Retrieve a `User` by primary key for platform-level identity checks."""
        try:
            stmt = select(User).where(User.id == user_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_email(
        self,
        email: str,
        *,
        department_id: UUID | None = None,
    ) -> User | None:
        """Retrieve a `User` by normalized email address, optionally scoped to `department_id`."""
        normalized = normalize_email(email)
        try:
            stmt = select(User).where(User.email == normalized)
            if department_id is not None:
                stmt = stmt.where(User.department_id == department_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_institutional_id(
        self,
        institutional_id: str,
        *,
        department_id: UUID | None = None,
    ) -> User | None:
        """Retrieve a `User` by normalized institutional identifier."""
        normalized = normalize_institutional_id(institutional_id)
        if normalized is None:
            return None
        try:
            stmt = select(User).where(User.institutional_id == normalized)
            if department_id is not None:
                stmt = stmt.where(User.department_id == department_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def list_for_department(
        self,
        *,
        department_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[User]:
        """List users strictly scoped to ``department_id`` (`SEC-002`)."""
        try:
            stmt = (
                select(User)
                .where(User.department_id == department_id)
                .order_by(User.created_at.asc())
                .limit(limit)
                .offset(offset)
            )
            result = await self._session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def transition_account_status(
        self,
        user_id: UUID,
        target_status: AccountStatus | str,
        *,
        department_id: UUID | None = None,
        reason: str | None = None,
        when: datetime | None = None,
    ) -> User:
        """Validate and apply an account status transition for a user."""
        user = (
            await self.get_by_id(user_id, department_id=department_id)
            if department_id is not None
            else await self.get_by_id_unscoped(user_id)
        )
        if user is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found in the authorized scope.",
                code="USER_NOT_FOUND",
            )
        try:
            user.transition_status(target_status, reason=reason, when=when)
            await self._session.flush()
            await self._session.refresh(user)
            return user
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_email_with_role(self, email: str) -> User | None:
        """Retrieve user by normalized email with eager-loaded role and department."""
        try:
            normalized = normalize_email(email)
            stmt = select(User).where(User.email == normalized)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def update_password_hash(
        self,
        user_id: UUID,
        password_hash: str,
    ) -> User:
        """Update password hash for a user."""
        user = await self.get_by_id_unscoped(user_id)
        if user is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )
        try:
            user.set_password_hash(password_hash)
            await self._session.flush()
            await self._session.refresh(user)
            return user
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def list_paginated(
        self,
        *,
        department_id: UUID | None = None,
        role_id: UUID | None = None,
        role_code: str | None = None,
        account_status: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
        limit: int = 20,
        offset: int = 0,
        sort_by: str = "created_at",
        sort_order: str = "asc",
    ) -> tuple[Sequence[User], int]:
        """List users with pagination, allowlisted sorting, and domain filtering."""
        sort_fields = {
            "created_at": User.created_at,
            "email": User.email,
            "full_name": User.full_name,
            "account_status": User.account_status,
        }
        if sort_by not in sort_fields:
            raise BusinessRuleError(
                f"Invalid sort field '{sort_by}'. Allowed fields: {', '.join(sorted(sort_fields))}.",
                code="INVALID_SORT_FIELD",
                status_code=400,
            )
        if sort_order.lower() not in {"asc", "desc"}:
            raise BusinessRuleError(
                f"Invalid sort order '{sort_order}'. Allowed values: 'asc', 'desc'.",
                code="INVALID_SORT_ORDER",
                status_code=400,
            )
        col = sort_fields[sort_by]
        order_clause = col.desc() if sort_order.lower() == "desc" else col.asc()

        try:
            stmt = select(User)
            count_stmt = select(func.count(User.id))

            if department_id is not None:
                stmt = stmt.where(User.department_id == department_id)
                count_stmt = count_stmt.where(User.department_id == department_id)

            if role_id is not None:
                stmt = stmt.where(User.role_id == role_id)
                count_stmt = count_stmt.where(User.role_id == role_id)

            if role_code is not None:
                stmt = stmt.join(Role, User.role_id == Role.id).where(Role.code == role_code)
                count_stmt = count_stmt.join(Role, User.role_id == Role.id).where(
                    Role.code == role_code
                )

            if account_status is not None:
                status_val = (
                    account_status.value
                    if isinstance(account_status, AccountStatus)
                    else str(account_status)
                )
                stmt = stmt.where(User.account_status == status_val)
                count_stmt = count_stmt.where(User.account_status == status_val)

            if is_active is not None:
                stmt = stmt.where(User.is_active.is_(is_active))
                count_stmt = count_stmt.where(User.is_active.is_(is_active))

            if search:
                pattern = f"%{search.strip()}%"
                search_filter = User.email.ilike(pattern) | User.full_name.ilike(pattern)
                stmt = stmt.where(search_filter)
                count_stmt = count_stmt.where(search_filter)

            total_items = (await self._session.execute(count_stmt)).scalar() or 0
            stmt = stmt.order_by(order_clause).limit(limit).offset(offset)
            items = list((await self._session.execute(stmt)).scalars().all())
            return items, int(total_items)
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def update_profile(
        self,
        user_id: UUID,
        *,
        full_name: str,
    ) -> User:
        """Update a user's self-service profile fields."""
        user = await self.get_by_id_unscoped(user_id)
        if user is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )
        try:
            user.full_name = full_name.strip()
            user.updated_at = utc_now()
            await self._session.flush()
            await self._session.refresh(user)
            return user
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def update_admin(
        self,
        user_id: UUID,
        *,
        full_name: str | None = None,
        role_id: UUID | None = None,
        department_id: UUID | None = None,
        explicit_department_none: bool = False,
        account_status: AccountStatus | str | None = None,
        is_active: bool | None = None,
    ) -> User:
        """Update user properties from an administrative context with constraint validation."""
        user = await self.get_by_id_unscoped(user_id)
        if user is None:
            raise ResourceNotFoundError(
                f"User '{user_id}' was not found.",
                code="USER_NOT_FOUND",
            )

        new_role_id = role_id if role_id is not None else user.role_id
        new_dept_id = (
            None
            if explicit_department_none
            else (department_id if department_id is not None else user.department_id)
        )

        try:
            if role_id is not None or department_id is not None or explicit_department_none:
                role_stmt = select(Role).where(Role.id == new_role_id)
                role = (await self._session.execute(role_stmt)).scalar_one_or_none()
                if role is None:
                    raise BusinessRuleError(
                        "Assigned role does not exist.",
                        code="INVALID_ROLE_ASSIGNMENT",
                    )
                validate_role_department_binding(
                    role.code,
                    new_dept_id,
                    requires_department_scope=role.requires_department_scope,
                )
                if new_dept_id is not None:
                    dept_stmt = select(Department).where(Department.id == new_dept_id)
                    dept = (await self._session.execute(dept_stmt)).scalar_one_or_none()
                    if dept is None:
                        raise BusinessRuleError(
                            "Assigned department does not exist.",
                            code="INVALID_DEPARTMENT_ASSIGNMENT",
                        )
                    if not dept.is_active:
                        raise BusinessRuleError(
                            "Cannot assign a user to an inactive department.",
                            code="INACTIVE_DEPARTMENT_ASSIGNMENT",
                        )

                user.role_id = new_role_id
                user.department_id = new_dept_id

            if full_name is not None:
                user.full_name = full_name.strip()

            if account_status is not None:
                user.transition_status(account_status)

            if is_active is not None and is_active != user.is_active:
                if not is_active:
                    user.disable(reason="Administrative deactivation")
                else:
                    user.activate()

            user.updated_at = utc_now()
            await self._session.flush()
            await self._session.refresh(user)
            return user
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None


class SessionRepository:
    """Asynchronous repository for `Session` (`user_sessions`) lifecycle records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, user_session: Session) -> Session:
        """Persist a new `Session` record after verifying user existence and active state."""
        try:
            user_stmt = select(User).where(User.id == user_session.user_id)
            user_result = await self._session.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if user is None:
                raise BusinessRuleError(
                    "Session user does not exist.",
                    code="INVALID_SESSION_USER",
                )
            if user.account_status != AccountStatus.ACTIVE.value or not user.is_active:
                raise BusinessRuleError(
                    "Sessions can only be created for active user accounts.",
                    code="INACTIVE_USER_SESSION_FORBIDDEN",
                )
            if (
                user_session.department_id is not None
                and user.department_id != user_session.department_id
            ):
                raise BusinessRuleError(
                    "Session department_id must match the user's assigned department.",
                    code="SESSION_DEPARTMENT_MISMATCH",
                )

            self._session.add(user_session)
            await self._session.flush()
            await self._session.refresh(user_session)
            return user_session
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_id(
        self,
        session_id: UUID,
        *,
        user_id: UUID | None = None,
    ) -> Session | None:
        """Retrieve a `Session` by ID, optionally scoped to `user_id`."""
        try:
            stmt = select(Session).where(Session.id == session_id)
            if user_id is not None:
                stmt = stmt.where(Session.user_id == user_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def list_active_for_user(self, user_id: UUID) -> Sequence[Session]:
        """Return all currently active, non-expired sessions owned by ``user_id``."""
        now = utc_now()
        try:
            stmt = (
                select(Session)
                .where(
                    Session.user_id == user_id,
                    Session.status == SessionStatus.ACTIVE.value,
                    Session.expires_at > now,
                )
                .order_by(Session.issued_at.desc())
            )
            result = await self._session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def revoke_session(
        self,
        session_id: UUID,
        *,
        reason: str | None = None,
        when: datetime | None = None,
    ) -> Session:
        """Mark a session as `revoked` with an explicit UTC revocation timestamp."""
        user_session = await self.get_by_id(session_id)
        if user_session is None:
            raise ResourceNotFoundError(
                f"Session '{session_id}' was not found.",
                code="SESSION_NOT_FOUND",
            )
        try:
            user_session.revoke(reason=reason, when=when)
            await self._session.flush()
            await self._session.refresh(user_session)
            return user_session
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_refresh_token_hash(self, token_hash: str) -> Session | None:
        """Find session matching the active ``refresh_token_hash`` digest."""
        try:
            stmt = select(Session).where(Session.refresh_token_hash == token_hash)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_previous_refresh_token_hash(self, token_hash: str) -> Session | None:
        """Find session where ``previous_refresh_token_hash`` matches for reuse detection."""
        try:
            stmt = select(Session).where(Session.previous_refresh_token_hash == token_hash)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_id_with_lock(self, session_id: UUID) -> Session | None:
        """Retrieve a session with a pessimistic write lock (FOR UPDATE) for safe rotation."""
        try:
            stmt = select(Session).where(Session.id == session_id).with_for_update()
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def revoke_user_sessions(
        self,
        user_id: UUID,
        *,
        reason: str,
        except_session_id: UUID | None = None,
        when: datetime | None = None,
    ) -> int:
        """Revoke all active sessions for a user (e.g. after password change/reset)."""
        revocation_time = when or utc_now()
        try:
            stmt = update(Session).where(
                Session.user_id == user_id,
                Session.status == SessionStatus.ACTIVE.value,
            )
            if except_session_id is not None:
                stmt = stmt.where(Session.id != except_session_id)
            stmt = stmt.values(
                status=SessionStatus.REVOKED.value,
                revoked_at=revocation_time,
                revocation_reason=reason,
            )
            result = await self._session.execute(stmt)
            await self._session.flush()
            rowcount = int(getattr(result, "rowcount", 0))
            return rowcount
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None


class AuthTokenRepository:
    """Asynchronous repository for one-time verification tokens (`auth_tokens`)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, auth_token: AuthToken) -> AuthToken:
        """Persist a new one-time token record."""
        try:
            self._session.add(auth_token)
            await self._session.flush()
            await self._session.refresh(auth_token)
            return auth_token
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def consume_token_atomically(
        self,
        token_hash: str,
        purpose: AuthTokenPurpose | str,
        *,
        now: datetime | None = None,
    ) -> AuthToken | None:
        """Atomically find, validate, and mark a token as consumed in a single atomic update.

        Guarantees single-use semantics under concurrency. Returns the consumed
        AuthToken if successful, or None if already used, expired, wrong purpose,
        or non-existent.
        """
        consumption_time = now or utc_now()
        purpose_val = purpose.value if isinstance(purpose, AuthTokenPurpose) else str(purpose)
        try:
            stmt = (
                update(AuthToken)
                .where(
                    AuthToken.token_hash == token_hash,
                    AuthToken.purpose == purpose_val,
                    AuthToken.consumed_at.is_(None),
                    AuthToken.expires_at > consumption_time,
                )
                .values(consumed_at=consumption_time)
                .returning(AuthToken)
            )
            result = await self._session.execute(stmt)
            consumed = result.scalar_one_or_none()
            if consumed is not None:
                await self._session.flush()
            return consumed
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None

    async def get_by_token_hash(self, token_hash: str) -> AuthToken | None:
        """Retrieve an AuthToken by its SHA-256 hash digest."""
        try:
            stmt = select(AuthToken).where(AuthToken.token_hash == token_hash)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise translate_database_error(exc) from None
