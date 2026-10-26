# E-WITNESS — BATCH 03 (GROUP 1) VERIFICATION REPORT
## PHASES 21–25: AUTHORIZATION, ACCESS POLICIES AND API DESIGN

**Execution Date:** October 13, 2026  
**Auditor / Architect:** Principal Backend Engineer, Application Security Engineer & Technical Auditor  
**Status:** COMPLETE & FULLY VERIFIED (347/347 tests passing, 90.51% branch coverage, 0 architecture violations, 0 mypy/ruff errors)

---

## 1. Executive Summary

Batch 03 (Group 1) establishes the comprehensive Role-Based Access Control (RBAC), multi-tenant departmental scoping, resource ownership guards, vertical/horizontal privilege escalation defenses, and standardized API conventions for **E-WITNESS**, covering **Phases 21 through 25** of the 120-phase master roadmap.

Key architectural and security deliverables:
1. **Explicit Role & Permission Matrix (Phase 21):** Defined 28 granular permission enumerations mapped deterministically across all five canonical system roles (`STUDENT`, `STAFF`, `INVESTIGATOR`, `DEPT_ADMIN`, `SUPER_ADMIN`). Formally specified in [`docs/architecture/authorization-matrix.md`](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/architecture/authorization-matrix.md) and [`backend/app/core/authorization.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/authorization.py).
2. **Reusable RBAC Dependency Factories (Phase 22):** Implemented composable FastAPI dependency injection factories (`require_permission`, `require_any_permission`, `require_all_permissions`) in [`backend/app/api/dependencies.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py) that evaluate decoded credentials from `AuthenticatedPrincipal` and return standardized HTTP 403 `PermissionDeniedError` envelopes without hitting database models.
3. **Department-Scoped Multi-Tenant Boundary Enforcement (Phase 23):** Department Administrators and investigators are strictly confined to their own department (`DEPARTMENT_MISMATCH`). Super Administrators possess global oversight. All departmental queries execute scoped filter clauses on indexed columns.
4. **Vertical Escalation & Self-Modification Defenses (Phase 24):** Strict guardrails prevent users from modifying their own roles (`SELF_ROLE_MODIFICATION_FORBIDDEN`), deactivating or altering their own status (`SELF_STATUS_MODIFICATION_FORBIDDEN`), or reassigning their department (`DEPARTMENT_REASSIGNMENT_RESTRICTED`). Department Administrators are explicitly forbidden from assigning administrative roles or reassigning users to external departments (`PRIVILEGE_ESCALATION_FORBIDDEN`).
5. **Uniform Pagination, Sorting & API Conventions (Phase 25):** Standardized 1-indexed pagination (`PaginationParams`), deterministic metadata (`PaginationMetadata`), allowlisted sorting (`SortOrder`), and generic response envelopes (`PaginatedResponse[ItemT]`). RESTful resources implemented at `/api/v1/users` and `/api/v1/departments`, documented in [`docs/architecture/api-conventions.md`](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/architecture/api-conventions.md).
6. **Live PostgreSQL Verification & Strict Layer Isolation:** Executed against ephemeral PostgreSQL clusters (`postgresql+asyncpg://`) with 0 mock databases for integration testing. Zero architectural violations (`ARCH-LAYER-IMPORT` AST checks 100% clean).

---

## 2. Phase-by-Phase Verification

### Phase 21 — Role and Permission Matrix
- **Granular Permissions:** Defined 28 domain-specific permission strings in [`backend/app/core/authorization.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/authorization.py) covering user management, department management, evidence management, chain of custody, audits, analytics, and system configurations.
- **Role Mappings:** Explicit dictionary mapping `ROLE_PERMISSIONS` configuring exact permission sets for:
  - `ROLE_STUDENT`: Self-service profile updates, evidence submission, viewing own submitted cases.
  - `ROLE_STAFF`: Institutional staff submissions and own record access.
  - `ROLE_INVESTIGATOR`: Departmental evidence inspection, custody logging, investigative notes, and reporting.
  - `ROLE_DEPT_ADMIN`: Scoped user management, department member administration, custody oversight.
  - `ROLE_SUPER_ADMIN`: Global system configuration, global user/department management, immutable audit log inspection.
- **Architectural Specification:** Comprehensive matrix authored in [`docs/architecture/authorization-matrix.md`](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/architecture/authorization-matrix.md) detailing separation of duties, non-delegable permissions, and escalation mitigation.
- **Unit Testing:** 27 tests in [`tests/unit/auth/test_authorization_policy.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/auth/test_authorization_policy.py) with 100% statement and branch coverage.

### Phase 22 — Reusable Permission Dependencies & Fast-Path Authorization
- **Dependency Factories:** Implemented `require_permission(perm)`, `require_any_permission(*perms)`, and `require_all_permissions(*perms)` in [`backend/app/api/dependencies.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py).
- **Stateless Verification:** Dependencies evaluate claims from `AuthenticatedPrincipal` in $O(1)$ memory without invoking database transactions.
- **Standardized Error Envelope:** Denied requests immediately raise `PermissionDeniedError` translated to HTTP 403 with machine-readable error codes.
- **Service Dependencies:** Clean dependency injection for `UserServiceDep` and `DepartmentServiceDep` scoping database sessions to request transactions.

### Phase 23 — Scoped Domain Policies & Horizontal Boundary Enforcement
- **Domain Services:** Implemented [`backend/app/services/user.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/services/user.py) (`UserService`) and [`backend/app/services/department.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/services/department.py) (`DepartmentService`).
- **Department Isolation:** Department Administrators attempting to list, view, create, or update users in other departments are rejected with HTTP 403 `DEPARTMENT_MISMATCH`.
- **Super Administrator Oversight:** Super Administrators operate globally across all departments and manage department provisioning.
- **Unit & Integration Testing:** 51 unit tests in [`tests/unit/auth/test_user_and_department_services.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/auth/test_user_and_department_services.py) and integration tests in [`tests/integration/api/test_authorization_and_rbac.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/integration/api/test_authorization_and_rbac.py).

### Phase 24 — Resource Ownership & Vertical Escalation Defenses
- **Self-Modification Restrictions:**
  - Users attempting to change their own `role_id` raise HTTP 403 `SELF_ROLE_MODIFICATION_FORBIDDEN`.
  - Users attempting to deactivate or suspend their own account raise HTTP 403 `SELF_STATUS_MODIFICATION_FORBIDDEN`.
  - Users attempting to reassign their own department raise HTTP 403 `DEPARTMENT_REASSIGNMENT_RESTRICTED`.
- **Vertical Escalation Mitigation:**
  - Department Administrators are restricted to assigning non-administrative roles (`STUDENT`, `STAFF`, `INVESTIGATOR`).
  - Attempts by Department Administrators to assign `SUPER_ADMIN` or `DEPT_ADMIN` raise HTTP 403 `PRIVILEGE_ESCALATION_FORBIDDEN`.
- **Self-Profile Endpoint:** Safe profile updates (`full_name`) via dedicated `update_own_profile` service method and `PATCH /api/v1/users/me/profile`.

### Phase 25 — API Conventions, Query Normalization & Documentation
- **Schemas:** Created [`backend/app/schemas/pagination.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/schemas/pagination.py) providing `PaginationParams`, `PaginationMetadata`, `SortOrder`, and generic `PaginatedResponse[ItemT]`.
- **Resource Endpoints:**
  - [`backend/app/api/v1/users.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/v1/users.py):
    - `GET /api/v1/users`: Paginated, sorted, and filtered user collection.
    - `POST /api/v1/users`: Admin user creation with escalation checks.
    - `PATCH /api/v1/users/me/profile`: Safe self-service profile updates.
    - `GET /api/v1/users/{user_id}`: Scoped user inspection.
    - `PATCH /api/v1/users/{user_id}`: Admin user property updates.
  - [`backend/app/api/v1/departments.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/v1/departments.py):
    - `GET /api/v1/departments`: Paginated list of departments.
    - `POST /api/v1/departments`: Global department provisioning.
    - `GET /api/v1/departments/{department_id}`: Department details inspection.
    - `PATCH /api/v1/departments/{department_id}`: Department attribute updates.
- **API Architectural Documentation:** Comprehensive protocol authored in [`docs/architecture/api-conventions.md`](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/architecture/api-conventions.md) detailing HTTP status semantics, error envelope standards, query parameter standards, and sorting allowlists.

---

## 3. Architecture & Layering Compliance

Validated using the automated AST architecture scanner ([`backend/app/core/architecture.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/architecture.py)):

| Architecture Rule | Layer Checked | Prohibited Imports | Result |
| :--- | :--- | :--- | :--- |
| `ARCH-LAYER-IMPORT` | `backend/app/api` | `models`, `repositories`, `sqlalchemy` | **PASS (0 violations)** |
| `ARCH-LAYER-IMPORT` | `backend/app/middleware` | `models`, `repositories`, `services`, `sqlalchemy` | **PASS (0 violations)** |
| `ARCH-LAYER-IMPORT` | `backend/app/services` | `fastapi`, `starlette`, `api`, `middleware` | **PASS (0 violations)** |
| `ARCH-LAYER-IMPORT` | `backend/app/schemas` | `fastapi`, `sqlalchemy`, `repositories`, `models`, `services` | **PASS (0 violations)** |
| `ARCH-ENV-ISOLATION`| Workspace | `os.environ` / `os.getenv` outside `backend/app/config/` | **PASS (0 violations)** |
| `ARCH-ASYNC-SLEEP`  | Workspace | `time.sleep()` in `async def` functions | **PASS (0 violations)** |

---

## 4. Security Verification & Defense-in-Depth

1. **Default-Deny Policy:** All collection and resource endpoints require explicit authentication (`CurrentUserDep`) and specific permission checks (`require_permission`). Unauthenticated requests yield HTTP 401 `UNAUTHENTICATED`.
2. **Horizontal Tenant Isolation:** Department boundaries are checked at the service layer before any repository query executes. Cross-department queries by non-super-admins are strictly forbidden.
3. **Vertical Escalation Prevention:** Enforced via `DEPT_ADMIN_ASSIGNABLE_ROLES` allowlist. Attempts to elevate users to higher privilege tiers are intercepted and rejected.
4. **Self-Modification Defense:** Callers are structurally barred from changing their own administrative attributes or deactivating their own accounts, preventing accidental or malicious privilege locking.
5. **SQL Injection & Sort Safety:** Sorting parameters are validated against strict allowlists per domain entity (`UserRepository.ALLOWED_SORT_FIELDS`, `DepartmentRepository.ALLOWED_SORT_FIELDS`), rejecting unverified column strings with HTTP 400 `INVALID_SORT_FIELD`.

---

## 5. Test Execution & Coverage Metrics

```text
============================= test session starts =============================
platform win32 -- Python 3.13.1, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\lenovo\Desktop\E-WITNESS
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1, platformdirs-4.13.0, asyncio-1.4.0, cov-7.1.0

collected 347 items

tests\integration\api\test_authorization_and_rbac.py ........            [  2%]
tests\integration\api\test_bootstrap_and_health.py ............          [  5%]
tests\integration\auth\test_auth_api_and_sessions.py ..................  [ 10%]
tests\integration\db\test_postgres_migrations_and_integrity.py ......... [ 13%]
tests\unit\architecture\test_layer_boundaries.py ...................     [ 19%]
tests\unit\auth\test_auth_service_unit.py ....................           [ 24%]
tests\unit\auth\test_authorization_policy.py ........................... [ 32%]
tests\unit\auth\test_password_service.py .....................           [ 38%]
tests\unit\auth\test_rate_limiter.py .....                               [ 40%]
tests\unit\auth\test_tokens_and_jwt.py ..........                        [ 42%]
tests\unit\auth\test_user_and_department_services.py ................... [ 48%]
................................                                         [ 57%]
tests\unit\config\test_redaction.py .................                    [ 62%]
tests\unit\config\test_settings.py ..................................... [ 73%]
....................................                                     [ 83%]
tests\unit\db\test_identity_and_database_unit.py ....................... [ 90%]
..............                                                           [ 94%]
tests\unit\logging\test_logging_and_context.py ....................      [100%]

=============================== tests coverage ================================
TOTAL: 3167 stmts, 254 miss, 720 branch, 77 brpart -> 90.51% Coverage
Required test coverage of 90% reached.
====================== 347 passed in 68.58s (0:01:08) =======================
```

---

## 6. Deliverable File Inventory

| Component | Path | Description |
| :--- | :--- | :--- |
| **Permissions & RBAC** | [`backend/app/core/authorization.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/authorization.py) | Permission enum, role-permission matrix, evaluation functions |
| **RBAC Dependencies** | [`backend/app/api/dependencies.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py) | Dependency factories: `require_permission`, `require_any_permission`, `require_all_permissions`, `UserServiceDep`, `DepartmentServiceDep` |
| **Pagination Schemas** | [`backend/app/schemas/pagination.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/schemas/pagination.py) | `PaginationParams`, `PaginationMetadata`, `SortOrder`, generic `PaginatedResponse[ItemT]` |
| **Identity Schemas** | [`backend/app/schemas/identity.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/schemas/identity.py) | `UserAdminCreate`, `UserUpdate`, `UserProfileUpdate`, `DepartmentCreate`, `DepartmentUpdate` |
| **User Service** | [`backend/app/services/user.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/services/user.py) | Scoped user orchestration, escalation defenses, self-modification guards |
| **Department Service** | [`backend/app/services/department.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/services/department.py) | Department provisioning, tenant inspection, and allowlisted pagination |
| **User Endpoints** | [`backend/app/api/v1/users.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/v1/users.py) | REST API endpoints for user collections and entities |
| **Department Endpoints** | [`backend/app/api/v1/departments.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/v1/departments.py) | REST API endpoints for department collections and entities |
| **API Router** | [`backend/app/api/v1/router.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/v1/router.py) | V1 router registry mounting `/users` and `/departments` |
| **RBAC Architecture Doc** | [`docs/architecture/authorization-matrix.md`](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/architecture/authorization-matrix.md) | Comprehensive authorization policy, role definitions, and escalation defenses |
| **API Conventions Doc** | [`docs/architecture/api-conventions.md`](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/architecture/api-conventions.md) | Standardized HTTP semantics, pagination, sorting, error envelopes |
| **Unit Tests (RBAC)** | [`tests/unit/auth/test_authorization_policy.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/auth/test_authorization_policy.py) | 27 unit tests verifying RBAC matrix and dependency behavior |
| **Unit Tests (Services)** | [`tests/unit/auth/test_user_and_department_services.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/auth/test_user_and_department_services.py) | 51 unit tests verifying domain boundary guards, self-modification, and escalation checks |
| **Integration Tests** | [`tests/integration/api/test_authorization_and_rbac.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/integration/api/test_authorization_and_rbac.py) | 8 PostgreSQL integration tests verifying complete HTTP request/response flows |
| **Foundation Script** | [`scripts/verify_foundation.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/scripts/verify_foundation.py) | Updated deliverable file manifest and automated quality gates runner |

---

## 7. Quality Gates & Foundation Audit Summary

All quality gates passed with zero warnings, zero suppressions, and zero failures:

1. **Git Tracked Files Check:** PASS (Zero secrets or tracked credential files).
2. **Architecture Boundary AST Scan:** PASS (Zero architectural layering violations across all packages).
3. **Dependency Consistency (`pip check`):** PASS (Clean dependency tree).
4. **Code Formatting (`ruff format --check .`):** PASS (113 files formatted).
5. **Linter & Security Scan (`ruff check .`):** PASS (Zero lint or security issues).
6. **Strict Type Checking (`mypy .`):** PASS (87 source files checked, 0 errors).
7. **Test Suite & Branch Coverage (`pytest`):** PASS (347 passed in 68.58s, 90.51% branch coverage).

**Batch 03 (Group 1: Phases 21–25) is fully implemented, verified, and complete.**
