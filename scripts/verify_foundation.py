"""Automated verification script for E-WITNESS Batch 01 (Phases 01-10).

Executes repository layout checks, Python package import checks, AST
architectural boundary checks, dependency consistency checks, Ruff
formatting/linting, Mypy static type checking, Pytest with branch coverage,
and Git secret-exclusion verification.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

REQUIRED_DIRECTORIES: tuple[str, ...] = (
    "backend",
    "backend/app",
    "backend/app/api",
    "backend/app/api/v1",
    "backend/app/config",
    "backend/app/schemas",
    "backend/app/services",
    "backend/app/repositories",
    "backend/app/models",
    "backend/app/middleware",
    "backend/app/core",
    "backend/app/infrastructure",
    "ai_services",
    "frontend",
    "tests",
    "tests/unit/config",
    "tests/unit/architecture",
    "tests/unit/logging",
    "tests/unit/db",
    "tests/unit/auth",
    "tests/unit/security",
    "tests/integration/api",
    "tests/integration/db",
    "tests/integration/auth",
    "backend/migrations",
    "backend/migrations/versions",
    "docs/requirements",
    "docs/architecture",
    "docs/security",
    "docs/development",
    "scripts",
    "deployment",
    "infrastructure",
    "artifacts",
    ".github/workflows",
)

REQUIRED_FILES: tuple[str, ...] = (
    "README.md",
    ".gitignore",
    ".env.example",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    ".github/workflows/ci.yml",
    "alembic.ini",
    "backend/migrations/env.py",
    "backend/migrations/script.py.mako",
    "backend/migrations/versions/20261013_0001_initial_identity_and_tenant_schema.py",
    "backend/migrations/versions/20261013_0002_add_password_hash_and_auth_tokens.py",
    "backend/migrations/versions/20261013_0003_add_invitation_token_purpose.py",
    "backend/app/main.py",
    "backend/app/api/dependencies.py",
    "backend/app/api/errors.py",
    "backend/app/api/router.py",
    "backend/app/api/v1/health.py",
    "backend/app/api/v1/auth.py",
    "backend/app/api/v1/users.py",
    "backend/app/api/v1/departments.py",
    "backend/app/api/v1/router.py",
    "backend/app/config/settings.py",
    "backend/app/core/architecture.py",
    "backend/app/core/authorization.py",
    "backend/app/core/context.py",
    "backend/app/core/exceptions.py",
    "backend/app/core/identity.py",
    "backend/app/core/logging.py",
    "backend/app/core/proxy.py",
    "backend/app/core/rate_limit.py",
    "backend/app/core/secrets.py",
    "backend/app/core/tokens.py",
    "backend/app/core/upload.py",
    "backend/app/infrastructure/database.py",
    "backend/app/infrastructure/migrations.py",
    "backend/app/middleware/body_size_limit.py",
    "backend/app/middleware/request_context.py",
    "backend/app/middleware/security_headers.py",
    "backend/app/models/base.py",
    "backend/app/models/department.py",
    "backend/app/models/role.py",
    "backend/app/models/user.py",
    "backend/app/models/session.py",
    "backend/app/models/token.py",
    "backend/app/repositories/base.py",
    "backend/app/repositories/identity.py",
    "backend/app/schemas/common.py",
    "backend/app/schemas/health.py",
    "backend/app/schemas/identity.py",
    "backend/app/schemas/auth.py",
    "backend/app/schemas/pagination.py",
    "backend/app/services/health.py",
    "backend/app/services/password.py",
    "backend/app/services/email.py",
    "backend/app/services/auth.py",
    "backend/app/services/user.py",
    "backend/app/services/department.py",
    "docs/requirements/requirements-specification.md",
    "docs/requirements/stakeholder-permissions-matrix.md",
    "docs/requirements/traceability-matrix.md",
    "docs/architecture/system-architecture.md",
    "docs/architecture/architecture-decisions.md",
    "docs/architecture/trust-boundaries.md",
    "docs/architecture/data-flow.md",
    "docs/architecture/threat-model.md",
    "docs/architecture/layered-architecture.md",
    "docs/architecture/authorization-matrix.md",
    "docs/architecture/api-conventions.md",
    "docs/architecture/implementation-status.md",
    "docs/architecture/foundation-audit.md",
    "docs/security/configuration-and-secrets.md",
    "docs/development/environment-setup.md",
    "docs/development/coding-standards.md",
    "docs/development/database-setup.md",
    "docs/development/database-migrations.md",
    "tests/conftest.py",
    "tests/unit/config/test_settings.py",
    "tests/unit/config/test_redaction.py",
    "tests/unit/architecture/test_layer_boundaries.py",
    "tests/unit/logging/test_logging_and_context.py",
    "tests/unit/db/test_identity_and_database_unit.py",
    "tests/unit/auth/test_password_service.py",
    "tests/unit/auth/test_rate_limiter.py",
    "tests/unit/auth/test_tokens_and_jwt.py",
    "tests/unit/auth/test_auth_service_unit.py",
    "tests/unit/auth/test_authorization_policy.py",
    "tests/unit/auth/test_user_and_department_services.py",
    "tests/unit/security/test_error_handling_and_redaction.py",
    "tests/unit/security/test_http_security_and_transport.py",
    "tests/unit/security/test_rate_limiting_and_abuse.py",
    "tests/unit/security/test_input_hardening_and_uploads.py",
    "tests/integration/api/test_bootstrap_and_health.py",
    "tests/integration/api/test_authorization_and_rbac.py",
    "tests/integration/api/test_security_regressions.py",
    "tests/integration/db/test_postgres_migrations_and_integrity.py",
    "tests/integration/auth/test_auth_api_and_sessions.py",
    "artifacts/BATCH_01_GROUP_01_REPORT.md",
    "artifacts/BATCH_01_GROUP_02_REPORT.md",
    "artifacts/BATCH_02_GROUP_01_REPORT.md",
    "artifacts/BATCH_02_GROUP_02_REPORT.md",
    "artifacts/BATCH_03_GROUP_01_REPORT.md",
    "artifacts/BATCH_03_GROUP_02_REPORT.md",
)


def run_step(label: str, cmd: list[str]) -> bool:
    """Execute a verification command and report its exit status."""
    print(f"\n=== [CHECK] {label} ===")
    print(f"Command: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=ROOT_DIR, check=False)  # noqa: S603
    if proc.returncode == 0:
        print(f"Result: PASS ({label})")
        return True
    print(f"Result: FAIL ({label}) [exit code {proc.returncode}]")
    return False


def verify_structure() -> bool:
    """Verify all required directories and deliverables exist."""
    print("\n=== [CHECK] Repository Structure & Deliverables ===")
    missing: list[str] = []
    for rel_dir in REQUIRED_DIRECTORIES:
        if not (ROOT_DIR / rel_dir).is_dir():
            missing.append(f"Directory: {rel_dir}")
    for rel_file in REQUIRED_FILES:
        if not (ROOT_DIR / rel_file).is_file():
            missing.append(f"File: {rel_file}")
    if missing:
        for item in missing:
            print(f"  MISSING -> {item}")
        return False
    print(
        f"Result: PASS ({len(REQUIRED_DIRECTORIES)} directories and "
        f"{len(REQUIRED_FILES)} required files verified)"
    )
    return True


def verify_git_secret_exclusion() -> bool:
    """Ensure .env or sensitive key files are not tracked by Git."""
    print("\n=== [CHECK] Git Tracked Files Security Check ===")
    proc = subprocess.run(
        ["git", "ls-files"],  # noqa: S607
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print("Result: FAIL (Not a valid Git repository)")
        return False
    tracked = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    forbidden = [
        path
        for path in tracked
        if (path == ".env" or (path.startswith(".env.") and path != ".env.example"))
        or path.endswith((".pem", ".key", ".pfx", ".p12", ".secret"))
    ]
    if forbidden:
        print(f"Result: FAIL (Forbidden secret files tracked: {forbidden})")
        return False
    print("Result: PASS (Zero sensitive/secret files tracked in Git)")
    return True


def main() -> int:
    """Run all foundation verification gates."""
    python_exe = sys.executable
    checks = [
        verify_structure(),
        verify_git_secret_exclusion(),
        run_step(
            "Python Package Imports & Architectural Boundary Scan",
            [
                python_exe,
                "-c",
                "from pathlib import Path; "
                "import backend.app, backend.app.main, backend.app.config, backend.app.core, ai_services; "
                "from backend.app.core.architecture import scan_project_architecture; "
                "v = scan_project_architecture(Path('.')); "
                "assert not v, f'Violations: {v}'; "
                "print('Imports & Architecture Scan OK:', backend.app.__version__, ai_services.__version__)",
            ],
        ),
        run_step("Dependency Consistency (pip check)", [python_exe, "-m", "pip", "check"]),
        run_step("Ruff Format Check", [python_exe, "-m", "ruff", "format", "--check", "."]),
        run_step("Ruff Linter & Security Check", [python_exe, "-m", "ruff", "check", "."]),
        run_step("Mypy Strict Type Check", [python_exe, "-m", "mypy"]),
        run_step("Pytest Suite & Coverage", [python_exe, "-m", "pytest"]),
    ]
    if all(checks):
        print("\nALL FOUNDATION QUALITY GATES PASSED.")
        return 0
    print("\nONE OR MORE QUALITY GATES FAILED.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
