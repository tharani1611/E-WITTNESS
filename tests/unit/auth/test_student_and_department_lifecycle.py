"""Unit tests for department lifecycle, student self-registration, and invitation acceptance (Phases 32, 33, 35).

Validates:
- Department deactivation and activation administrative controls (Phase 33).
- Student self-registration, role locking, active department enforcement, rate limiting, and email verification dispatch (Phase 35).
- Staff invitation acceptance, atomic single-use token consumption, and account activation (Phase 32).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    AuthenticationError,
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    RateLimitExceededError,
)
from backend.app.core.identity import AccountStatus, AuthTokenPurpose, RoleCode
from backend.app.models.department import Department
from backend.app.models.role import Role
from backend.app.models.token import AuthToken
from backend.app.models.user import User
from backend.app.schemas.auth import (
    AcceptInvitationRequest,
    AuthenticatedPrincipal,
    StudentRegisterRequest,
)
from backend.app.services.auth import AuthService
from backend.app.services.department import DepartmentService
from backend.app.services.email import FakeEmailDeliveryService
from backend.app.services.password import PasswordService


def make_principal(
    role: RoleCode = RoleCode.STUDENT,
    department_id: UUID | None = None,
    user_id: UUID | None = None,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email="principal@institution.edu",
        full_name="Principal User",
        account_status=AccountStatus.ACTIVE.value,
        is_active=True,
        role_code=role.value,
        department_id=department_id,
        session_id=uuid4(),
    )


def make_dummy_dept(
    dept_id: UUID | None = None,
    code: str = "DEPT-CS",
    name: str = "Computer Science",
    is_active: bool = True,
) -> Department:
    now = datetime.now(UTC)
    dept = Department(code=code, name=name, is_active=is_active)
    dept.id = dept_id or uuid4()
    dept.created_at = now
    dept.updated_at = now
    return dept


def make_dummy_user(
    user_id: UUID | None = None,
    role_id: UUID | None = None,
    department_id: UUID | None = None,
    email: str = "student@institution.edu",
    full_name: str = "Student User",
    account_status: str = AccountStatus.PENDING_VERIFICATION.value,
    is_active: bool = False,
) -> User:
    now = datetime.now(UTC)
    user = User(
        email=email,
        full_name=full_name,
        role_id=role_id or uuid4(),
        department_id=department_id,
        account_status=account_status,
        is_active=is_active,
    )
    user.id = user_id or uuid4()
    user.created_at = now
    user.updated_at = now
    return user


@pytest.fixture
def fake_email_service() -> FakeEmailDeliveryService:
    return FakeEmailDeliveryService()


@pytest.mark.unit
class TestDepartmentLifecycleUnit:
    """Phase 33: Department activation, deactivation, and metadata updates."""

    async def test_deactivate_department_super_admin_success(self, test_settings: Settings) -> None:
        mock_dept_repo = AsyncMock()
        dept = make_dummy_dept(is_active=True)
        mock_dept_repo.deactivate.return_value = make_dummy_dept(dept_id=dept.id, is_active=False)

        service = DepartmentService(dept_repo=mock_dept_repo, settings=test_settings)
        principal = make_principal(RoleCode.SUPER_ADMIN)

        res = await service.deactivate_department(dept.id, principal)
        assert res.is_active is False
        mock_dept_repo.deactivate.assert_awaited_once_with(dept.id)

    async def test_deactivate_department_dept_admin_forbidden(
        self, test_settings: Settings
    ) -> None:
        mock_dept_repo = AsyncMock()
        service = DepartmentService(dept_repo=mock_dept_repo, settings=test_settings)
        principal = make_principal(RoleCode.DEPT_ADMIN)

        with pytest.raises(PermissionDeniedError) as exc_info:
            await service.deactivate_department(uuid4(), principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_activate_department_super_admin_success(self, test_settings: Settings) -> None:
        mock_dept_repo = AsyncMock()
        dept = make_dummy_dept(is_active=False)
        mock_dept_repo.activate.return_value = make_dummy_dept(dept_id=dept.id, is_active=True)

        service = DepartmentService(dept_repo=mock_dept_repo, settings=test_settings)
        principal = make_principal(RoleCode.SUPER_ADMIN)

        res = await service.activate_department(dept.id, principal)
        assert res.is_active is True
        mock_dept_repo.activate.assert_awaited_once_with(dept.id)

    async def test_activate_department_student_forbidden(self, test_settings: Settings) -> None:
        mock_dept_repo = AsyncMock()
        service = DepartmentService(dept_repo=mock_dept_repo, settings=test_settings)
        principal = make_principal(RoleCode.STUDENT)

        with pytest.raises(PermissionDeniedError) as exc_info:
            await service.activate_department(uuid4(), principal)
        assert exc_info.value.code == "PERMISSION_DENIED"


@pytest.mark.unit
class TestStudentRegistrationUnit:
    """Phase 35: Student self-service registration and verification lifecycle."""

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
    def mock_dept_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_role_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def auth_service(
        self,
        mock_user_repo: AsyncMock,
        mock_session_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        fake_email_service: FakeEmailDeliveryService,
        test_settings: Settings,
    ) -> AuthService:
        return AuthService(
            user_repo=mock_user_repo,
            session_repo=mock_session_repo,
            auth_token_repo=mock_token_repo,
            dept_repo=mock_dept_repo,
            role_repo=mock_role_repo,
            password_service=PasswordService(),
            email_service=fake_email_service,
            settings=test_settings,
        )

    async def test_student_registration_success(
        self,
        auth_service: AuthService,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        fake_email_service: FakeEmailDeliveryService,
    ) -> None:
        dept = make_dummy_dept(is_active=True)
        student_role = Role(code=RoleCode.STUDENT.value, name="Student")
        student_role.id = uuid4()

        mock_dept_repo.get_by_id.return_value = dept
        mock_role_repo.get_by_code.return_value = student_role
        mock_user_repo.get_by_email.return_value = None

        created = make_dummy_user(
            email="student1@institution.edu",
            full_name="Enrolled Student",
            department_id=dept.id,
            role_id=student_role.id,
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
        )
        mock_user_repo.create.return_value = created

        payload = StudentRegisterRequest(
            email="student1@institution.edu",
            password="StrongPassword123!",
            full_name="Enrolled Student",
            department_id=dept.id,
            institutional_id="STU-2026-001",
        )

        res = await auth_service.register_student(payload, client_ip="192.168.1.50")
        assert res.status == "success"
        assert res.user_id == created.id
        assert res.verification_token is not None
        assert (
            fake_email_service.get_last_token_for("student1@institution.edu", "email_verification")
            is not None
        )
        mock_token_repo.create.assert_awaited_once()

    async def test_student_registration_inactive_dept_rejected(
        self,
        auth_service: AuthService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        inactive_dept = make_dummy_dept(is_active=False)
        mock_dept_repo.get_by_id.return_value = inactive_dept

        payload = StudentRegisterRequest(
            email="student2@institution.edu",
            password="StrongPassword123!",
            full_name="Enrolled Student",
            department_id=inactive_dept.id,
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await auth_service.register_student(payload, client_ip="192.168.1.50")
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_REGISTRATION"

    async def test_student_registration_duplicate_email_rejected(
        self,
        auth_service: AuthService,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept = make_dummy_dept(is_active=True)
        student_role = Role(code=RoleCode.STUDENT.value, name="Student")
        student_role.id = uuid4()

        mock_dept_repo.get_by_id.return_value = dept
        mock_role_repo.get_by_code.return_value = student_role
        mock_user_repo.get_by_email.return_value = make_dummy_user(email="dup@institution.edu")

        payload = StudentRegisterRequest(
            email="dup@institution.edu",
            password="StrongPassword123!",
            full_name="Duplicate Student",
            department_id=dept.id,
        )

        with pytest.raises(ConflictError) as exc_info:
            await auth_service.register_student(payload, client_ip="192.168.1.50")
        assert exc_info.value.code == "EMAIL_ALREADY_EXISTS"

    async def test_student_registration_rate_limiting(
        self,
        auth_service: AuthService,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept = make_dummy_dept(is_active=True)
        student_role = Role(code=RoleCode.STUDENT.value, name="Student")
        student_role.id = uuid4()

        mock_dept_repo.get_by_id.return_value = dept
        mock_role_repo.get_by_code.return_value = student_role
        mock_user_repo.get_by_email.return_value = None
        mock_user_repo.create.return_value = make_dummy_user()

        payload = StudentRegisterRequest(
            email="flood@institution.edu",
            password="StrongPassword123!",
            full_name="Flood Student",
            department_id=dept.id,
        )

        # Trigger rate limit threshold (10 max requests)
        for _ in range(10):
            await auth_service.register_student(payload, client_ip="10.0.0.99")

        with pytest.raises(RateLimitExceededError) as exc_info:
            await auth_service.register_student(payload, client_ip="10.0.0.99")
        assert exc_info.value.code == "RATE_LIMIT_EXCEEDED"


@pytest.mark.unit
class TestStaffInvitationAcceptanceUnit:
    """Phase 32: Invitation token consumption and account activation."""

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
    def mock_dept_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_role_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def auth_service(
        self,
        mock_user_repo: AsyncMock,
        mock_session_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        fake_email_service: FakeEmailDeliveryService,
        test_settings: Settings,
    ) -> AuthService:
        return AuthService(
            user_repo=mock_user_repo,
            session_repo=mock_session_repo,
            auth_token_repo=mock_token_repo,
            dept_repo=mock_dept_repo,
            role_repo=mock_role_repo,
            password_service=PasswordService(),
            email_service=fake_email_service,
            settings=test_settings,
        )

    async def test_accept_invitation_success(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        dept = make_dummy_dept(is_active=True)
        auth_token = AuthToken(
            user_id=user_id,
            token_hash="fake_hash",
            purpose=AuthTokenPurpose.INVITATION.value,
            expires_at=datetime.now(UTC),
        )
        mock_token_repo.consume_token_atomically.return_value = auth_token

        user = make_dummy_user(
            user_id=user_id,
            department_id=dept.id,
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
        )
        mock_user_repo.get_by_id_unscoped.return_value = user
        mock_dept_repo.get_by_id.return_value = dept

        payload = AcceptInvitationRequest(
            token="valid_opaque_token_string_123",
            password="NewStaffPassword123!",
            full_name="Accepted Staff Name",
        )
        res = await auth_service.accept_invitation(payload)

        assert "successfully" in res.message.lower()
        assert user.account_status == AccountStatus.ACTIVE.value
        assert user.is_active is True
        assert user.full_name == "Accepted Staff Name"
        mock_user_repo.update_password_hash.assert_awaited_once()

    async def test_accept_invitation_invalid_token_rejected(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
    ) -> None:
        mock_token_repo.consume_token_atomically.return_value = None

        payload = AcceptInvitationRequest(
            token="invalid_token_string_xyz",
            password="NewStaffPassword123!",
        )
        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.accept_invitation(payload)
        assert exc_info.value.code == "INVALID_INVITATION_TOKEN"

    async def test_accept_invitation_disabled_user_rejected(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        auth_token = AuthToken(
            user_id=user_id,
            token_hash="fake_hash",
            purpose=AuthTokenPurpose.INVITATION.value,
            expires_at=datetime.now(UTC),
        )
        mock_token_repo.consume_token_atomically.return_value = auth_token

        user = make_dummy_user(
            user_id=user_id,
            account_status=AccountStatus.DISABLED.value,
            is_active=False,
        )
        mock_user_repo.get_by_id_unscoped.return_value = user

        payload = AcceptInvitationRequest(
            token="valid_opaque_token_string_123",
            password="NewStaffPassword123!",
        )
        with pytest.raises(BusinessRuleError) as exc_info:
            await auth_service.accept_invitation(payload)
        assert exc_info.value.code == "ACCOUNT_LIFECYCLE_RESTRICTED"

    async def test_accept_invitation_inactive_department_rejected(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        inactive_dept = make_dummy_dept(is_active=False)
        auth_token = AuthToken(
            user_id=user_id,
            token_hash="fake_hash",
            purpose=AuthTokenPurpose.INVITATION.value,
            expires_at=datetime.now(UTC),
        )
        mock_token_repo.consume_token_atomically.return_value = auth_token

        user = make_dummy_user(
            user_id=user_id,
            department_id=inactive_dept.id,
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
        )
        mock_user_repo.get_by_id_unscoped.return_value = user
        mock_dept_repo.get_by_id.return_value = inactive_dept

        payload = AcceptInvitationRequest(
            token="valid_opaque_token_string_123",
            password="NewStaffPassword123!",
        )
        with pytest.raises(BusinessRuleError) as exc_info:
            await auth_service.accept_invitation(payload)
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_ASSIGNMENT"

    async def test_accept_invitation_user_not_found_rejected(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        auth_token = AuthToken(
            user_id=user_id,
            token_hash="fake_hash",
            purpose=AuthTokenPurpose.INVITATION.value,
            expires_at=datetime.now(UTC),
        )
        mock_token_repo.consume_token_atomically.return_value = auth_token
        mock_user_repo.get_by_id_unscoped.return_value = None

        payload = AcceptInvitationRequest(
            token="valid_opaque_token_string_123",
            password="NewStaffPassword123!",
        )
        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.accept_invitation(payload)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_accept_invitation_without_full_name_preserves_existing(
        self,
        auth_service: AuthService,
        mock_token_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        dept = make_dummy_dept(is_active=True)
        auth_token = AuthToken(
            user_id=user_id,
            token_hash="fake_hash",
            purpose=AuthTokenPurpose.INVITATION.value,
            expires_at=datetime.now(UTC),
        )
        mock_token_repo.consume_token_atomically.return_value = auth_token

        user = make_dummy_user(
            user_id=user_id,
            department_id=dept.id,
            full_name="Original Invitee Name",
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
        )
        mock_user_repo.get_by_id_unscoped.return_value = user
        mock_dept_repo.get_by_id.return_value = dept

        payload = AcceptInvitationRequest(
            token="valid_opaque_token_string_123",
            password="NewStaffPassword123!",
            full_name=None,
        )
        res = await auth_service.accept_invitation(payload)
        assert "successfully" in res.message.lower()
        assert user.full_name == "Original Invitee Name"
        assert user.is_active is True
