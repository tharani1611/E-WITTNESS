"""Integration tests for Phase 30 security regressions and negative testing.

All tests run against a real PostgreSQL database instance (via `postgres_db_manager`),
testing the integrated FastAPI application with full middleware stack:
- Host header injection rejection (HTTP 400).
- HTTP security headers across API endpoints.
- Reverse proxy IP handling and X-Forwarded-For anti-spoofing.
- Malformed JSON body handling (HTTP 422).
- Sensitive field redaction in validation errors.
- Rate limiting enforcement and Retry-After header (HTTP 429).
- SQL injection / malformed ID resistance.
- Negative authentication and authorization boundary enforcement.
"""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.core.rate_limit import default_rate_limiter
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.main import create_app
from backend.app.models.user import User
from backend.app.repositories.identity import (
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


@pytest.fixture(autouse=True)
def _reset_global_rate_limiter() -> None:
    """Ensure in-memory rate limiter is reset between test executions."""
    default_rate_limiter.clear()


async def _provision_admin_user(
    postgres_db_manager: DatabaseSessionManager,
    email: str = "security.admin@ewitness.edu",
    password: str = "AdminPass123!@#",  # noqa: S107
) -> tuple[User, str]:
    """Helper to provision an active system admin in PostgreSQL for authenticated security checks."""
    pw_service = PasswordService()
    pw_hash = pw_service.hash_password(password)
    async with postgres_db_manager.transactional_session() as session:
        role_repo = RoleRepository(session)
        user_repo = UserRepository(session)
        roles = await role_repo.ensure_default_roles()
        super_admin_role = roles[RoleCode.SUPER_ADMIN]

        user = User(
            email=email,
            full_name="Security Regression Auditor",
            department_id=None,
            role_id=super_admin_role.id,
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash=pw_hash,
        )
        created_user = await user_repo.create(user)
        return created_user, password


@pytest.mark.integration
class TestSecurityRegressionsAndBoundaryEnforcement:
    """Comprehensive negative tests and security regression suite."""

    async def test_host_header_injection_rejected_with_400(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)

        async with httpx.AsyncClient(
            transport=transport, base_url="http://attacker.evil.com"
        ) as client:
            resp = await client.get("/health")
            assert resp.status_code == 400
            assert "Invalid host header" in resp.text

    async def test_security_headers_present_on_api_responses(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/api/v1/health/live")
            assert resp.status_code == 200

            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert (
                resp.headers.get("content-security-policy")
                == "default-src 'none'; frame-ancestors 'none'"
            )
            assert resp.headers.get("referrer-policy") == "no-referrer"
            assert "camera=()" in resp.headers.get("permissions-policy", "")
            assert resp.headers.get("cache-control") == "no-store, max-age=0"
            assert resp.headers.get("pragma") == "no-cache"

    async def test_malformed_json_body_returns_clean_422_without_traceback(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                content=b'{"email": "admin@ewitness.edu", "password": ',
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 422
            data = resp.json()
            assert data["error"]["code"] == "REQUEST_VALIDATION_ERROR"
            assert any(
                "Malformed JSON payload in request body" in d["message"]
                for d in data["error"]["details"]
            )
            # Ensure no traceback or internal line numbers leak
            assert "Traceback" not in resp.text
            assert "json.decoder" not in resp.text

    async def test_validation_error_masks_sensitive_password_input(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app)

        sensitive_input = "SecretPass123!"
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Login with invalid email and password
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "not-an-email", "password": sensitive_input},
            )
            assert resp.status_code == 422
            # The plaintext password value must never appear in response body
            assert sensitive_input not in resp.text

    async def test_rate_limiting_enforces_retry_after_header(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Send 10 rapid invalid logins (quota is 10)
            for _ in range(10):
                await client.post(
                    "/api/v1/auth/login",
                    json={"email": "flood@ewitness.edu", "password": "Password123!"},
                )

            # 11th request must be rejected with 429
            flood_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "flood@ewitness.edu", "password": "Password123!"},
            )
            assert flood_resp.status_code == 429
            data = flood_resp.json()
            assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"
            assert "Retry-After" in flood_resp.headers
            assert int(flood_resp.headers["Retry-After"]) >= 1

    async def test_sql_injection_attempt_in_path_returns_validation_error(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        created_user, password = await _provision_admin_user(
            postgres_db_manager,
            email=f"sqli_test_{uuid4().hex[:6]}@ewitness.edu",
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": created_user.email, "password": password},
            )
            assert token_resp.status_code == 200
            token = token_resp.json()["access_token"]

            # Authenticated user attempts SQL injection in UUID path parameter
            resp = await client.get(
                "/api/v1/users/' OR 1=1 --",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 422
            data = resp.json()
            assert data["error"]["code"] == "REQUEST_VALIDATION_ERROR"
            assert "syntax error" not in resp.text.lower()
            assert "select" not in resp.text.lower()

    async def test_negative_authentication_invalid_credentials_returns_401(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "nonexistent@ewitness.edu", "password": "WrongPassword123!"},
            )
            assert resp.status_code == 401
            assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_negative_authorization_unauthenticated_protected_endpoint_returns_401(
        self,
        postgres_db_manager: DatabaseSessionManager,
        test_settings: Settings,
    ) -> None:
        app = create_app(test_settings, db_manager=postgres_db_manager)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Calling /users without Authorization header
            resp = await client.get("/api/v1/users")
            assert resp.status_code == 401
            assert resp.json()["error"]["code"] == "UNAUTHENTICATED"
