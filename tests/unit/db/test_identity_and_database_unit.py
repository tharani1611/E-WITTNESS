"""Unit tests for identity normalization, account-state transitions, schemas, and DB error translation (Phases 11-15)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    ServiceUnavailableError,
)
from backend.app.core.identity import (
    AccountStatus,
    RoleCode,
    SessionStatus,
    normalize_department_code,
    normalize_email,
    normalize_institutional_id,
    parse_account_status,
    validate_account_status_transition,
    validate_role_department_binding,
)
from backend.app.infrastructure.database import (
    DatabaseSessionManager,
    create_database_readiness_probe,
    create_db_engine,
    translate_database_error,
    validate_database_target_isolation,
    verify_database_connectivity,
)
from backend.app.models import (
    Base,
    Department,
    Role,
    Session,
    User,
    UTCDateTime,
    utc_now,
)
from backend.app.repositories.base import TenantScopedRepositoryProtocol
from backend.app.repositories.identity import UserRepository
from backend.app.schemas.identity import (
    DepartmentCreate,
    DepartmentRead,
    RoleCreate,
    RoleRead,
    SessionCreate,
    SessionRead,
    UserCreate,
    UserRead,
)


@pytest.mark.unit
class TestIdentityNormalizationAndValidation:
    """Verify deterministic normalization and validation of identity fields."""

    def test_normalize_email_lowercases_and_trims(self) -> None:
        assert normalize_email("  Alice.Witness+01@University.EDU ") == (
            "alice.witness+01@university.edu"
        )

    @pytest.mark.parametrize(
        "bad_email",
        [
            "",
            "   ",
            "a@b",
            "not-an-email",
            "missing-domain@",
            "@missing-local.edu",
            "double@@university.edu",
            "newline\ninjected@university.edu",
            f"{'a' * 250}@university.edu",
        ],
    )
    def test_normalize_email_rejects_invalid_inputs(self, bad_email: str) -> None:
        with pytest.raises(ValueError):
            normalize_email(bad_email)

    def test_normalize_email_rejects_non_string(self) -> None:
        with pytest.raises(ValueError, match="must be a string"):
            normalize_email(12345)  # type: ignore[arg-type]

    def test_normalize_institutional_id_uppercases_and_handles_none(self) -> None:
        assert normalize_institutional_id(None) is None
        assert normalize_institutional_id("  stu-2026_001.a ") == "STU-2026_001.A"

    @pytest.mark.parametrize(
        "bad_id",
        [
            "",
            "   ",
            "ab",
            "-starts-with-hyphen",
            "contains space",
            "bad$char",
            "A" * 65,
        ],
    )
    def test_normalize_institutional_id_rejects_invalid_inputs(self, bad_id: str) -> None:
        with pytest.raises(ValueError):
            normalize_institutional_id(bad_id)

    def test_normalize_institutional_id_rejects_non_string(self) -> None:
        with pytest.raises(ValueError, match="must be a string or None"):
            normalize_institutional_id(999)  # type: ignore[arg-type]

    def test_normalize_department_code_uppercases_and_validates(self) -> None:
        assert normalize_department_code("  campus-safety_01 ") == "CAMPUS-SAFETY_01"
        with pytest.raises(ValueError):
            normalize_department_code("a")
        with pytest.raises(ValueError):
            normalize_department_code("-bad")
        with pytest.raises(ValueError, match="must be a string"):
            normalize_department_code(None)  # type: ignore[arg-type]


@pytest.mark.unit
class TestAccountStatusAndRoleDepartmentRules:
    """Verify explicit account state transitions and role-department scope rules."""

    def test_valid_account_status_transitions(self) -> None:
        assert (
            validate_account_status_transition(
                AccountStatus.PENDING_VERIFICATION, AccountStatus.ACTIVE
            )
            == AccountStatus.ACTIVE
        )
        assert (
            validate_account_status_transition(
                AccountStatus.PENDING_VERIFICATION, AccountStatus.DISABLED
            )
            == AccountStatus.DISABLED
        )
        assert (
            validate_account_status_transition(AccountStatus.ACTIVE, AccountStatus.SUSPENDED)
            == AccountStatus.SUSPENDED
        )
        assert (
            validate_account_status_transition(AccountStatus.SUSPENDED, AccountStatus.ACTIVE)
            == AccountStatus.ACTIVE
        )
        assert (
            validate_account_status_transition(AccountStatus.SUSPENDED, AccountStatus.DISABLED)
            == AccountStatus.DISABLED
        )
        # No-op transition to same state is permitted
        assert (
            validate_account_status_transition(AccountStatus.ACTIVE, AccountStatus.ACTIVE)
            == AccountStatus.ACTIVE
        )

    @pytest.mark.parametrize(
        ("current", "target"),
        [
            (AccountStatus.PENDING_VERIFICATION, AccountStatus.SUSPENDED),
            (AccountStatus.ACTIVE, AccountStatus.PENDING_VERIFICATION),
            (AccountStatus.SUSPENDED, AccountStatus.PENDING_VERIFICATION),
            (AccountStatus.DISABLED, AccountStatus.ACTIVE),
            (AccountStatus.DISABLED, AccountStatus.SUSPENDED),
            (AccountStatus.DISABLED, AccountStatus.PENDING_VERIFICATION),
        ],
    )
    def test_invalid_account_status_transitions_raise_business_rule_error(
        self,
        current: AccountStatus,
        target: AccountStatus,
    ) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            validate_account_status_transition(current, target)
        assert exc_info.value.code == "INVALID_ACCOUNT_STATE_TRANSITION"

    def test_parse_account_status_rejects_unknown_values(self) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            parse_account_status("archived_unknown")
        assert exc_info.value.code == "INVALID_ACCOUNT_STATUS"

        with pytest.raises(BusinessRuleError) as exc_info2:
            parse_account_status(123)  # type: ignore[arg-type]
        assert exc_info2.value.code == "INVALID_ACCOUNT_STATUS"

    def test_validate_role_department_binding_enforces_department_scope(self) -> None:
        dept_id = uuid4()
        for role_code in (
            RoleCode.STUDENT,
            RoleCode.STAFF,
            RoleCode.DEPT_ADMIN,
            RoleCode.INVESTIGATOR,
        ):
            validate_role_department_binding(role_code, dept_id)
            with pytest.raises(BusinessRuleError) as exc_info:
                validate_role_department_binding(role_code, None)
            assert exc_info.value.code == "DEPARTMENT_ASSIGNMENT_REQUIRED"

        # Super Admin is allowed without a department_id
        validate_role_department_binding(RoleCode.SUPER_ADMIN, None)
        validate_role_department_binding(RoleCode.SUPER_ADMIN, dept_id)

        with pytest.raises(BusinessRuleError) as bad_role:
            validate_role_department_binding("ROLE_UNKNOWN", dept_id)
        assert bad_role.value.code == "INVALID_ROLE_CODE"


@pytest.mark.unit
class TestModelsAndSchemasUnit:
    """Verify ORM model validators, UTCDateTime type decorator, and Pydantic DTO schemas."""

    def test_utcdatetime_decorator_normalizes_naive_and_offset_datetimes(self) -> None:
        decorator = UTCDateTime()
        naive = datetime(2026, 10, 13, 12, 0, 0)
        bound_naive = decorator.process_bind_param(naive, None)  # type: ignore[arg-type]
        assert bound_naive is not None
        assert bound_naive.tzinfo == UTC

        ist = timezone(timedelta(hours=5, minutes=30))
        aware_ist = datetime(2026, 10, 13, 17, 30, 0, tzinfo=ist)
        bound_aware = decorator.process_bind_param(aware_ist, None)  # type: ignore[arg-type]
        assert bound_aware is not None
        assert bound_aware.tzinfo == UTC
        assert bound_aware.hour == 12
        assert bound_aware.minute == 0

        assert decorator.process_bind_param(None, None) is None  # type: ignore[arg-type]
        assert decorator.process_result_value(None, None) is None  # type: ignore[arg-type]
        assert decorator.process_result_value(naive, None) == bound_naive  # type: ignore[arg-type]
        assert decorator.process_result_value(aware_ist, None) == bound_aware  # type: ignore[arg-type]
        assert decorator.process_result_value("not-a-datetime", None) is None  # type: ignore[arg-type]

    def test_orm_models_validation_and_lifecycle_helpers(self) -> None:
        dept = Department(code="  student-conduct ", name="  Student Conduct  ")
        assert dept.code == "STUDENT-CONDUCT"
        assert dept.name == "Student Conduct"
        dept.deactivate()
        assert dept.is_active is False
        assert dept.deactivated_at is not None
        dept.activate()
        assert dept.is_active is True
        assert dept.deactivated_at is None
        assert "STUDENT-CONDUCT" in repr(dept)

        with pytest.raises(ValueError, match="Department name must be a string"):
            Department(code="VALID", name=123)
        with pytest.raises(ValueError, match="between 2 and 160"):
            Department(code="VALID", name="A")

        role = Role(
            code=RoleCode.INVESTIGATOR,
            name="  Investigator ",
            description="  Reviews assigned cases. ",
        )
        assert role.code == "ROLE_INVESTIGATOR"
        assert role.requires_department_scope is True
        assert "ROLE_INVESTIGATOR" in repr(role)

        with pytest.raises(ValueError, match="Unsupported role code"):
            Role(code="ROLE_INVALID", name="Invalid", description="Invalid role code")
        with pytest.raises(ValueError, match="Role name"):
            Role(code=RoleCode.STAFF, name="X", description="Valid description")
        with pytest.raises(ValueError, match="Role description"):
            Role(code=RoleCode.STAFF, name="Staff", description="shrt")

        user = User(
            email="  Investigator.One@University.EDU ",
            institutional_id="  inv-9001 ",
            full_name="  Jordan Investigator ",
            role_id=uuid4(),
            department_id=uuid4(),
        )
        assert user.email == "investigator.one@university.edu"
        assert user.institutional_id == "INV-9001"
        assert user.full_name == "Jordan Investigator"
        user.activate()
        assert user.account_status == AccountStatus.ACTIVE.value
        assert user.is_active is True
        assert user.verified_at is not None
        user.suspend(reason="  Administrative review ")
        assert user.account_status == AccountStatus.SUSPENDED.value
        assert user.is_active is False
        assert user.deactivated_at is not None
        assert user.deactivation_reason == "Administrative review"
        user.activate()
        user.disable(reason="Account offboarded")
        assert user.account_status == AccountStatus.DISABLED.value
        assert user.is_active is False
        assert "investigator.one@university.edu" in repr(user)

        with pytest.raises(ValueError, match="Full name must be a string"):
            User(email="a@b.edu", full_name=123, role_id=uuid4())
        with pytest.raises(ValueError, match="between 2 and 160"):
            User(email="a@b.edu", full_name="X", role_id=uuid4())

        now = utc_now()
        sess = Session(
            user_id=uuid4(),
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        sess.revoke(reason="  User logout ")
        assert sess.status == SessionStatus.REVOKED.value
        assert sess.revoked_at is not None
        assert sess.revocation_reason == "User logout"
        sess.mark_expired()
        assert sess.status == SessionStatus.EXPIRED.value
        assert sess.revoked_at is None
        assert "expired" in repr(sess)

        with pytest.raises(ValueError, match="Invalid session status"):
            Session(
                user_id=uuid4(),
                status="unknown_status",
                issued_at=now,
                expires_at=now + timedelta(hours=1),
            )

    def test_pydantic_schemas_normalize_and_validate_boundaries(self) -> None:
        now = utc_now()
        dept_in = DepartmentCreate(code="  hr-dept ", name="  Human Resources ")
        assert dept_in.code == "HR-DEPT"
        assert dept_in.name == "Human Resources"
        with pytest.raises(ValidationError):
            DepartmentCreate(code="HR", name="   ")

        role_in = RoleCreate(
            code=RoleCode.STUDENT,
            name="Student",
            description="Student reporter role",
        )
        assert role_in.code == RoleCode.STUDENT

        user_in = UserCreate(
            email="  Student.User@Example.EDU ",
            institutional_id=" stu-1001 ",
            full_name="  Alex Student ",
            role_id=uuid4(),
            department_id=uuid4(),
        )
        assert user_in.email == "student.user@example.edu"
        assert user_in.institutional_id == "STU-1001"
        assert user_in.full_name == "Alex Student"
        with pytest.raises(ValidationError):
            UserCreate(
                email="student@example.edu",
                full_name="   ",
                role_id=uuid4(),
            )

        sess_in = SessionCreate(
            user_id=uuid4(),
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        assert sess_in.expires_at > sess_in.issued_at
        with pytest.raises(ValidationError, match="strictly greater than issued_at"):
            SessionCreate(
                user_id=uuid4(),
                issued_at=now,
                expires_at=now,
            )

        # Verify Read DTOs serialize from ORM attributes
        dept_id = uuid4()
        role_id = uuid4()
        user_id = uuid4()
        sess_id = uuid4()
        dept_dto = DepartmentRead.model_validate(
            {
                "id": dept_id,
                "code": "HR-DEPT",
                "name": "Human Resources",
                "description": None,
                "is_active": True,
                "deactivated_at": None,
                "created_at": now,
                "updated_at": now,
            }
        )
        assert dept_dto.id == dept_id
        role_dto = RoleRead.model_validate(
            {
                "id": role_id,
                "code": RoleCode.STUDENT,
                "name": "Student",
                "description": "Student reporter role",
                "requires_department_scope": True,
                "is_system_role": True,
                "created_at": now,
                "updated_at": now,
            }
        )
        assert role_dto.code == RoleCode.STUDENT
        user_dto = UserRead.model_validate(
            {
                "id": user_id,
                "email": "student@example.edu",
                "institutional_id": "STU-1001",
                "full_name": "Alex Student",
                "account_status": AccountStatus.ACTIVE,
                "is_active": True,
                "department_id": dept_id,
                "role_id": role_id,
                "verified_at": now,
                "deactivated_at": None,
                "deactivation_reason": None,
                "created_at": now,
                "updated_at": now,
            }
        )
        assert user_dto.account_status == AccountStatus.ACTIVE
        sess_dto = SessionRead.model_validate(
            {
                "id": sess_id,
                "user_id": user_id,
                "department_id": dept_id,
                "status": SessionStatus.ACTIVE,
                "client_ip": "127.0.0.1",
                "user_agent": "pytest",
                "issued_at": now,
                "expires_at": now + timedelta(minutes=15),
                "last_activity_at": now,
                "revoked_at": None,
                "revocation_reason": None,
                "created_at": now,
                "updated_at": now,
            }
        )
        assert sess_dto.id == sess_id


@pytest.mark.unit
class TestDatabaseIsolationAndErrorTranslation:
    """Verify database target isolation, error translation, and secret redaction."""

    def test_validate_database_target_isolation_blocks_non_test_targets(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError, match="must not reference a production database"):
            Settings(
                **{
                    **valid_testing_config_dict,
                    "DATABASE_URL": "postgresql+asyncpg://u:p@db.prod.internal:5432/ewitness_test",
                }
            )

        non_test_settings = Settings(
            **{
                **valid_testing_config_dict,
                "DATABASE_URL": "postgresql+asyncpg://u:p@localhost:5432/ewitness_dev",
            }
        )
        with pytest.raises(RuntimeError, match="Database isolation guard triggered"):
            validate_database_target_isolation(non_test_settings)

    def test_translate_database_error_maps_and_redacts_secrets(self) -> None:
        existing_app_err = ConflictError("Already handled")
        assert translate_database_error(existing_app_err) is existing_app_err

        class DummyOrig(Exception):
            def __init__(self, sqlstate: str, msg: str) -> None:
                super().__init__(msg)
                self.sqlstate = sqlstate

        unique_exc = IntegrityError(
            "INSERT INTO users ...",
            params={},
            orig=DummyOrig("23505", "duplicate key value violates unique constraint"),
        )
        translated_unique = translate_database_error(unique_exc)
        assert isinstance(translated_unique, ConflictError)
        assert translated_unique.code == "DATABASE_UNIQUE_CONFLICT"

        fk_exc = IntegrityError(
            "INSERT INTO users ...",
            params={},
            orig=DummyOrig("23503", "violates foreign key constraint"),
        )
        translated_fk = translate_database_error(fk_exc)
        assert isinstance(translated_fk, BusinessRuleError)
        assert translated_fk.code == "DATABASE_FOREIGN_KEY_VIOLATION"

        check_exc = IntegrityError(
            "INSERT INTO users ...",
            params={},
            orig=DummyOrig("23514", "violates check constraint"),
        )
        translated_check = translate_database_error(check_exc)
        assert isinstance(translated_check, BusinessRuleError)
        assert translated_check.code == "DATABASE_CONSTRAINT_VIOLATION"

        op_exc = OperationalError(
            "connect failed to postgresql+asyncpg://admin:SuperSecretDbPass99@host:5432/db",
            params={},
            orig=Exception("connection refused"),
        )
        translated_op = translate_database_error(op_exc)
        assert isinstance(translated_op, ServiceUnavailableError)
        assert translated_op.code == "DATABASE_UNAVAILABLE"
        assert "SuperSecretDbPass99" not in translated_op.message

        generic_db_exc = SQLAlchemyError("internal driver error")
        translated_generic = translate_database_error(generic_db_exc)
        assert isinstance(translated_generic, ServiceUnavailableError)
        assert translated_generic.code == "DATABASE_ERROR"

    async def test_sqlite_engine_and_session_manager_unit_lifecycle(
        self, test_settings: Settings
    ) -> None:
        manager = DatabaseSessionManager(test_settings)
        try:
            assert await manager.verify_connectivity() is True
            probe = create_database_readiness_probe(manager.engine)
            assert await probe() is True

            async with manager.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            async with manager.transactional_session() as session:
                user_repo = UserRepository(session)
                assert isinstance(user_repo, TenantScopedRepositoryProtocol)
        finally:
            await manager.dispose()

    async def test_verify_database_connectivity_returns_false_on_failure(
        self, settings_factory: Any
    ) -> None:
        unreachable_settings = settings_factory(
            DATABASE_URL="postgresql+asyncpg://user:SecretPass123@127.0.0.1:1/ewitness_test",
            DB_CONNECT_TIMEOUT_SECONDS=1.0,
        )
        engine = create_db_engine(unreachable_settings)
        try:
            assert await verify_database_connectivity(engine, timeout_seconds=1.0) is False
        finally:
            await engine.dispose()
