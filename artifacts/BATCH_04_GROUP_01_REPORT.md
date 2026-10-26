# E-WITNESS — BATCH 04 (GROUP 1) VERIFICATION REPORT
## PHASES 31–35: USER PROFILES, STAFF ACCOUNTS, DEPARTMENT MANAGEMENT, MEMBERSHIP & STUDENT LIFECYCLE

**Execution Date:** October 14, 2026  
**Auditor / Architect:** Principal Backend Architect, Application Security Engineer & Technical Auditor  
**Status:** COMPLETE & FULLY VERIFIED (461/461 tests passing, 90.40% branch coverage, 0 architecture violations, 0 mypy errors, 0 ruff errors)

---

## 1. Executive Summary

Batch 04 (Group 1) delivers the complete user profile, administrative account provisioning, institutional department lifecycle, scoped department membership, and self-service student onboarding subsystems for **E-WITNESS**, covering **Phases 31 through 35** of the 120-phase master roadmap.

Key architectural, security, and verification deliverables:
1. **User Profile APIs, Account Status & Identity Validation (Phase 31):**
   - Implemented self-service caller profile inspection (`GET /api/v1/auth/me`) and display name updates (`PATCH /api/v1/users/me/profile`), strictly guarded by `Permission.USER_UPDATE_OWN`.
   - Prevented mass-assignment attacks by enforcing strict Pydantic schemas (`UserProfileUpdate`) that forbid tampering with email, role, department, password, or account status.
   - Enforced immutable identity validation: canonical email normalization, institutional ID whitespace stripping, and length constraints.
2. **Staff Account Creation, Invitation, Activation & Deactivation (Phase 32):**
   - Authored database migration `20261013_0003_add_invitation_token_purpose` extending the `ck_auth_tokens_purpose_allowed_values` check constraint to include `invitation`.
   - Implemented staff invitation workflow (`POST /api/v1/users/invite`): provisions a user in `pending_verification` state, generates a high-entropy 256-bit token digest with a 48-hour expiration, and delivers it via `send_invitation_email`.
   - Implemented invitation acceptance (`POST /api/v1/auth/invitations/accept`): atomically consumes the one-time token, sets an Argon2id password hash, and transitions the account to `active`.
   - Implemented account deactivation (`POST /api/v1/users/{id}/deactivate`): transitions user to `disabled`, records UTC deactivation timestamp and reason, immediately revokes all active sessions in `SessionRepository`, and rejects self-deactivation.
   - Protected Super Administrator accounts from deactivation by non-super-administrators or self.
   - Implemented account activation (`POST /api/v1/users/{id}/activate`): reactivates eligible suspended accounts while upholding the invariant that permanently `disabled` accounts cannot be reactivated.
3. **Department Creation, Updates, Activation & Metadata Management (Phase 33):**
   - Extended `DepartmentRepository` and `DepartmentService` with atomic soft-deactivation (`deactivate`) and reactivation (`activate`) methods.
   - Exposed `POST /api/v1/departments/{id}/deactivate` and `POST /api/v1/departments/{id}/activate` restricted to Super Administrators (`Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL`).
   - Maintained UTC deactivation timestamps and ensured inactive departments are preserved for referential audit integrity while preventing new user or student associations.
4. **Department Membership, Staff Assignments & Scoped Administrative Permissions (Phase 34):**
   - Implemented `POST /api/v1/users/{id}/department` allowing department assignment and transfers.
   - Enforced departmental scoping boundaries: Department Administrators (`ROLE_DEPT_ADMIN`) can only assign staff within their own department and are strictly prohibited from transferring staff across departments or managing administrative accounts (`PRIVILEGE_ESCALATION_FORBIDDEN`).
   - Enforced inactive department safeguards: attempting to assign any user or staff member to an inactive or deactivated department is rejected with `INACTIVE_DEPARTMENT_ASSIGNMENT` (HTTP 422).
5. **Student Registration, Verification & Account Lifecycle Management (Phase 35):**
   - Implemented self-service student onboarding (`POST /api/v1/auth/register` and alias `POST /api/v1/auth/register/student`).
   - Role locking invariant: role assignment is strictly locked to `ROLE_STUDENT` on the backend, regardless of client input.
   - Target department verification: student registrations targeting deactivated departments are rejected with `INACTIVE_DEPARTMENT_REGISTRATION` (HTTP 422).
   - In-memory sliding-window rate limiting enforced on student registration requests to mitigate registration spam and brute-force flooding.
   - Dispatches a 24-hour single-use email verification token digest; account remains in `pending_verification` (`is_active=False`) until verified via `POST /api/v1/auth/verify-email/confirm`.
6. **Code Quality, Architectural Integrity & Test Suite:**
   - Total test count expanded from 413 to **461 passing tests** in 40.58s.
   - Total test coverage maintained at **90.40% branch coverage** ($\ge 90.0\%$ threshold).
   - Zero architecture violations detected across all source layers (`scan_project_architecture`).
   - Clean linting and typing: 0 Ruff errors, 0 Mypy strict errors across 100 source files.

---

## 2. Phase-by-Phase Verification

### Phase 31 — User Profiles, Account Status & Identity Validation
- **Endpoints Implemented & Verified:**
  - `GET /api/v1/auth/me`: Returns verified `CurrentUserResponse` containing authenticated principal, user record, assigned role, and department context.
  - `PATCH /api/v1/users/me/profile`: Allows self-service modification of caller display name (`full_name`) within length boundaries (2–160 characters).
  - `GET /api/v1/users/{id}` & `PATCH /api/v1/users/{id}`: Administrative inspection and modification subject to departmental boundary checks (`Permission.USER_READ_DEPT` / `USER_READ_GLOBAL`).
- **Defenses Verified:**
  - Strict Pydantic model (`UserProfileUpdate` with `extra="forbid"`): Disallows injecting `email`, `role_id`, `department_id`, `account_status`, or credentials into self-service update payloads.
  - Ownership guards: Non-admin users attempting to inspect or modify other users' profiles receive `403 Forbidden` (`PERMISSION_DENIED`).

### Phase 32 — Staff Account Creation, Invitation, Activation & Deactivation
- **Schema & Migration:**
  - Migration [`20261013_0003_add_invitation_token_purpose.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/migrations/versions/20261013_0003_add_invitation_token_purpose.py): Updated Postgres check constraint `ck_auth_tokens_purpose_allowed_values` to allow `'invitation'`. Full downgrade and upgrade migrations verified on live PostgreSQL.
- **Staff Invitation (`POST /api/v1/users/invite`):**
  - Requires `USER_CREATE_DEPT` or `USER_CREATE_GLOBAL`.
  - Generates single-use 32-byte opaque invitation token hashed with SHA-256 (`AuthTokenPurpose.INVITATION`) expiring in 48 hours.
  - Dispatches invitation email via `EmailDeliveryService.send_invitation_email`.
  - Privilege escalation defense: Dept Admins cannot invite Super Admin or Dept Admin accounts.
  - Department boundary defense: Dept Admins cannot invite users to foreign departments (`DEPARTMENT_MISMATCH`).
- **Staff Invitation Acceptance (`POST /api/v1/auth/invitations/accept`):**
  - Atomically consumes token in database transaction via `consume_token_atomically` (preventing concurrent race condition replay).
  - Hashes supplied password using Argon2id (`time_cost=2`, `memory_cost=19456`, `parallelism=1`).
  - Verifies assigned department is active; if deactivated, rejects activation with `INACTIVE_DEPARTMENT_ASSIGNMENT`.
  - Rejects tokens belonging to suspended or disabled users (`ACCOUNT_LIFECYCLE_RESTRICTED`).
  - Sets account status to `active` and `is_active=True`.
- **User Deactivation (`POST /api/v1/users/{id}/deactivate`):**
  - Sets account status to `disabled` and `is_active=False` with UTC timestamp and audit reason.
  - Revokes all active sessions in `SessionRepository` immediately, instantly invalidating extant bearer tokens.
  - Defenses: Self-deactivation forbidden (`SELF_DEACTIVATION_FORBIDDEN`); Super Admin accounts protected against non-super-admins; Dept Admin scoped to their department.
- **User Activation (`POST /api/v1/users/{id}/activate`):**
  - Reactivates eligible suspended accounts to `active` status.
  - Defenses: Self-activation forbidden (`SELF_STATUS_MODIFICATION_FORBIDDEN`); permanently `disabled` accounts cannot be activated per domain lifecycle rules (`ACCOUNT_LIFECYCLE_RESTRICTED`).

### Phase 33 — Department Creation, Updates, Activation & Metadata Management
- **Endpoints Implemented & Verified:**
  - `POST /api/v1/departments`: Provisions new institutional department with normalized uppercase code (Super Admin only).
  - `PATCH /api/v1/departments/{id}`: Modifies department name, description, or status (Super Admin only).
  - `POST /api/v1/departments/{id}/deactivate`: Soft-deactivates department (`is_active=False`, `deactivated_at=now`).
  - `POST /api/v1/departments/{id}/activate`: Reactivates inactive department (`is_active=True`, `deactivated_at=None`).
  - `GET /api/v1/departments`: Lists departments with pagination, sorting, search, and `is_active` filtering.
- **Authorization & Audit:**
  - Controlled by `Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL` and `Permission.DEPARTMENT_UPDATE_GLOBAL`.
  - Department Administrators and standard staff receive `403 Forbidden` on activation/deactivation routes.

### Phase 34 — Department Membership, Staff Assignments & Scoped Administrative Permissions
- **Department Reassignment (`POST /api/v1/users/{id}/department`):**
  - Reassigns target user's `department_id` in database transaction.
  - Defenses:
    - Self-reassignment forbidden: Users cannot transfer themselves (`DEPARTMENT_REASSIGNMENT_RESTRICTED`).
    - Inactive department defense: Target department must exist and be active (`is_active=True`), returning `INACTIVE_DEPARTMENT_ASSIGNMENT` (HTTP 422) otherwise.
    - Dept Admin scoping: Dept Admins cannot transfer users from or to foreign departments (`DEPARTMENT_MISMATCH`).
    - Administrative protection: Dept Admins cannot reassign Super Admin or Dept Admin accounts (`PRIVILEGE_ESCALATION_FORBIDDEN`).

### Phase 35 — Student Registration, Verification & Account Lifecycle Management
- **Student Registration (`POST /api/v1/auth/register` and `/api/v1/auth/register/student`):**
  - Self-service endpoint accessible without authentication.
  - Role locked: System queries `RoleRepository` for `ROLE_STUDENT` directly; client cannot specify role.
  - Inactive department rejection: Rejects registrations targeting deactivated departments with `INACTIVE_DEPARTMENT_REGISTRATION` (HTTP 422).
  - Duplicate email rejection: Rejects already-registered emails with `EMAIL_ALREADY_EXISTS` (HTTP 409).
  - Rate limiting: Client IP checked against 10 requests per 60-second window; excess calls return `RATE_LIMIT_EXCEEDED` (HTTP 429).
  - Provisioning: Creates user with `account_status=pending_verification` and `is_active=False`.
  - Dispatches 24-hour verification token digest via `EmailDeliveryService.send_verification_email`.
- **Verification Confirmation (`POST /api/v1/auth/verify-email/confirm`):**
  - Consumes token atomically and sets account status to `active` (`is_active=True`, `verified_at=now`).
  - Student is permitted to authenticate only after verification; pre-verification logins return `ACCOUNT_PENDING_VERIFICATION` (HTTP 401).

---

## 3. Database Schema & Migration Verification

| Migration Revision | Description | Head Revision | Integrity Check |
|---|---|---|---|
| `20261013_0001` | Initial schema (users, roles, departments, user_sessions, auth_tokens) | `20261013_0003` | Verified |
| `20261013_0002` | Audit trigger function & triggers | `20261013_0003` | Verified |
| `20261013_0003` | Add `'invitation'` to `ck_auth_tokens_purpose_allowed_values` | `20261013_0003` | Verified |

- **PostgreSQL Migration Test Results:**
  - Upgraded cleanly from `base` to `head` (`20261013_0003`).
  - Downgraded cleanly from `head` to `base`.
  - Zero schema drift detected against SQLAlchemy declarative metadata models.
  - All check constraints (`user_status_lifecycle_consistency`, `ck_auth_tokens_purpose_allowed_values`) verified in PostgreSQL test transactions.

---

## 4. Test Suite Execution & Coverage Report

```
============================= test session starts =============================
platform win32 -- Python 3.13.1, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\lenovo\Desktop\E-WITNESS
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1, platformdirs-4.13.0, asyncio-1.4.0, cov-7.1.0
asyncio: mode=Mode.AUTO, debug=False
collected 461 items

tests\integration\api\test_authorization_and_rbac.py ........            [  1%]
tests\integration\api\test_bootstrap_and_health.py ............          [  4%]
tests\integration\api\test_security_regressions.py ........              [  6%]
tests\integration\api\test_user_and_department_lifecycle.py .....        [  7%]
tests\integration\auth\test_auth_api_and_sessions.py ..................  [ 11%]
tests\integration\db\test_postgres_migrations_and_integrity.py ......... [ 13%]
tests\unit\architecture\test_layer_boundaries.py ...................     [ 17%]
tests\unit\auth\test_auth_service_unit.py ....................           [ 21%]
tests\unit\auth\test_authorization_policy.py ........................... [ 27%]
tests\unit\auth\test_password_service.py .....................           [ 31%]
tests\unit\auth\test_rate_limiter.py .....                               [ 32%]
tests\unit\auth\test_student_and_department_lifecycle.py ..............  [ 36%]
tests\unit\auth\test_tokens_and_jwt.py ..........                        [ 38%]
tests\unit\auth\test_user_and_department_services.py ................... [ 42%]
....................................                                     [ 50%]
tests\unit\auth\test_user_profiles_and_lifecycle.py .................... [ 54%]
.............                                                            [ 57%]
tests\unit\config\test_redaction.py .................                    [ 60%]
tests\unit\config\test_settings.py ..................................... [ 68%]
....................................                                     [ 76%]
tests\unit\db\test_identity_and_database_unit.py ....................... [ 81%]
..............                                                           [ 84%]
tests\unit\logging\test_logging_and_context.py ....................      [ 89%]
tests\unit\security\test_error_handling_and_redaction.py ..............  [ 92%]
tests\unit\security\test_http_security_and_transport.py .........        [ 94%]
tests\unit\security\test_input_hardening_and_uploads.py ................ [ 97%]
.....                                                                    [ 98%]
tests\unit\security\test_rate_limiting_and_abuse.py ......               [100%]

=============================== tests coverage ================================
TOTAL: 3732 Stmts, 293 Miss, 946 Branch, 110 BrPart -> 90.40% Branch Coverage
Required test coverage of 90% reached.
============================ 461 passed in 40.58s =============================
```

### Module Coverage Highlights
- `backend/app/api/v1/auth.py`: **100%**
- `backend/app/api/v1/departments.py`: **100%**
- `backend/app/api/v1/users.py`: **100%**
- `backend/app/services/department.py`: **100%**
- `backend/app/services/user.py`: **93%**
- `backend/app/services/email.py`: **94%**
- `backend/app/schemas/auth.py`: **97%**
- `backend/app/schemas/identity.py`: **94%**
- `backend/app/models/user.py`: **96%**
- `backend/app/models/department.py`: **100%**

---

## 5. Security & Architectural Invariants Verification

1. **AST Layer Boundary Scan (`scan_project_architecture`):**
   - Result: `PASS` — 0 violations detected.
   - Strict separation maintained: `api` imports only schemas/services/core; `services` imports only models/repositories/core; zero cross-layer leakages.
2. **Type Safety & Linting:**
   - `mypy .`: `PASS` (0 type errors in 100 source files).
   - `ruff check .`: `PASS` (0 lint warnings).
   - `ruff format --check .`: `PASS` (128 files formatted).
   - `pip check`: `PASS` (0 broken requirements).
3. **Sensitive Data Protection:**
   - Git tracked file inspection verified: zero `.env` or credential files tracked.
   - Tokens logged with redaction masks only (`***REDACTED***: 43`).
   - Passwords hashed exclusively using Argon2id with 32-byte hash length.
4. **Foundation Verification Gate:**
   - `python scripts/verify_foundation.py`: `PASS` across all 8 checks.

---

## 6. Status of the 120-Phase Master Roadmap

- **Batch 01 (Phases 01–10):** Complete & Verified.
- **Batch 02 (Phases 11–20):** Complete & Verified.
- **Batch 03 (Phases 21–30):** Complete & Verified.
- **Batch 04, Group 01 (Phases 31–35):** **COMPLETE & VERIFIED.**
- **Next Scheduled Scope:** Batch 04, Group 02 (Phases 36–40: Evidence Custody, Integrity Models & Digital Signatures).
