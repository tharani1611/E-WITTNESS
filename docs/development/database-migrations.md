# E-WITNESS — Database Migrations, Schema Versioning, and Rollback Procedures

**Document ID:** `EW-DOC-DEV-004`  
**Phases:** Phase 13 (Alembic Migrations & Schema Versioning) & Phase 15 (User Identity & Database Integrity)  
**Version:** 1.0.0  
**Status:** Implemented & Verified  

---

## 1. Migration Architecture

E-WITNESS manages relational schema evolution through **Alembic** configured at:
- [`alembic.ini`](file:///c:/Users/lenovo/Desktop/E-WITNESS/alembic.ini) — Root Alembic configuration (contains **zero hardcoded credentials**; `sqlalchemy.url` is blank).
- [`backend/migrations/env.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/migrations/env.py) — Async-capable migration environment wired to [`get_settings().DATABASE_URL`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/config/settings.py) and [`Base.metadata`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/models/base.py).
- [`backend/migrations/versions/`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/migrations/versions) — Linear, version-controlled migration scripts.
- [`backend/app/infrastructure/migrations.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/infrastructure/migrations.py) — Programmatic helpers (`run_migrations_upgrade`, `run_migrations_downgrade`, `get_current_database_revision`, `detect_schema_drift`) with built-in credential redaction on error.

---

## 2. Naming and Review Conventions

### 2.1 Revision File Naming
Every migration script in `backend/migrations/versions/` must follow a chronological, linear naming convention:
- Format: `<YYYYMMDD>_<4-digit-sequence>_<descriptive_slug>.py`
- Initial Revision (Phases 13–15): [`20261013_0001_initial_identity_and_tenant_schema.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/migrations/versions/20261013_0001_initial_identity_and_tenant_schema.py) (`revision = "20261013_0001"`, `down_revision = None`).

### 2.2 Constraint Naming Convention (`NAMING_CONVENTION`)
[`Base.metadata`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/models/base.py#L22-L28) enforces deterministic names across all tables so `alembic downgrade` can reliably drop constraints by name:
- Primary Key: `pk_<table_name>`
- Unique Constraint: `uq_<table_name>_<column_0_name>`
- Index: `ix_<column_0_label>`
- Check Constraint: `ck_<table_name>_<constraint_name>`
- Foreign Key: `fk_<table_name>_<column_0_name>_<referred_table_name>`

### 2.3 Mandatory Migration Review Checklist
Before merging any new migration:
1. **No Historical Rewrites**: Never edit an already-committed migration to hide schema drift; always author a new forward migration.
2. **Autogenerate Inspection**: Always inspect `alembic revision --autogenerate` output manually—verify `CheckConstraint`, `ServerDefault`, `Index`, and `ondelete` rules.
3. **Zero Drift Verification**: Run `detect_schema_drift(engine)` against a migrated PostgreSQL test database and confirm it returns `[]`.
4. **No Destructive Data Loss**: Never drop populated production columns or tables without a multi-step deprecation and backup plan.

---

## 3. Running Forward Migrations and Verifying State

```powershell
# 1. Inspect current applied revision
.\.venv\Scripts\alembic.exe current

# 2. Preview SQL in offline mode (no database connection required)
.\.venv\Scripts\alembic.exe upgrade head --sql

# 3. Apply all pending forward migrations to the configured database
.\.venv\Scripts\alembic.exe upgrade head

# 4. Verify migration history
.\.venv\Scripts\alembic.exe history --verbose
```

---

## 4. Rollback Procedures, Limitations, and Recovery

### 4.1 Standard Step-Down Rollback (Development & Staging)
```powershell
# Revert the most recent migration
.\.venv\Scripts\alembic.exe downgrade -1

# Revert all migrations back to an empty schema (TESTING / LOCAL DEV ONLY)
.\.venv\Scripts\alembic.exe downgrade base
```

### 4.2 Rollback Limitations & Irreversible Operations
1. **Data Destruction on Table/Column Drop**: Running `downgrade()` on a migration that created tables (such as `20261013_0001`) executes `DROP TABLE` on `user_sessions`, `users`, `roles`, and `departments`, permanently deleting any rows stored in those tables.
2. **Constraint Tightening**: A forward migration that normalizes data or widens a column is reversible at the schema level, whereas a downgrade that narrows a column or removes an enum value will fail if existing rows contain the removed state.
3. **Immutable Audit & Custody Tables (Future Phases 61–65)**: Once chain-of-custody and tamper-evident audit tables are introduced in later phases, production database roles will prohibit `DROP` or `DELETE` on those tables.

### 4.3 Production Recovery Procedure
In production (`ENVIRONMENT=production`):
1. **Pre-Migration Snapshot**: Always capture a verified PostgreSQL logical backup (`pg_dump --format=custom`) or cloud storage snapshot immediately before running `alembic upgrade head`.
2. **Transactional DDL**: PostgreSQL executes Alembic DDL inside a transaction (`BEGIN ... COMMIT`); if any statement in `upgrade()` fails, PostgreSQL rolls back the entire migration atomically.
3. **Post-Commit Failure**: Prefer a **forward-fix migration** (`2026xxxx_000N_fix_...`) over running `alembic downgrade` against live user data. If catastrophic corruption occurs, restore from the pre-migration snapshot / Point-in-Time Recovery (PITR).

---

## 5. Phase 14–15 Schema and Data-Integrity Rules

The initial schema (`20261013_0001`) enforces the following database-level integrity guarantees:

| Table | Key Constraints & Indexes | Security / Integrity Guarantee |
| :--- | :--- | :--- |
| `departments` | `ix_departments_code` (`UNIQUE`), `uq_departments_name` (`UNIQUE`), `ck_departments_department_code_normalized`, `ck_departments_department_deactivation_consistency` | Department codes are normalized uppercase (`>= 2` chars); active departments cannot have `deactivated_at` set, and inactive departments must record `deactivated_at`. |
| `roles` | `ix_roles_code` (`UNIQUE`), `uq_roles_name` (`UNIQUE`), `ck_roles_role_code_allowed_values`, `ck_roles_role_department_scope_enforcement` | Only the 5 SRS stakeholder roles are permitted; every role except `ROLE_SUPER_ADMIN` enforces `requires_department_scope = true` at the database level. |
| `users` | `ix_users_email` (`UNIQUE`), `ix_users_institutional_id` (`UNIQUE`), `uq_users_id_department_id` (`UNIQUE`), `fk_users_department_id_departments` (`RESTRICT`), `fk_users_role_id_roles` (`RESTRICT`), `ck_users_user_email_normalized`, `ck_users_user_institutional_id_normalized`, `ck_users_user_account_status_allowed_values`, `ck_users_user_status_lifecycle_consistency` | Prevents duplicate identities under concurrent registration races; blocks un-normalized emails (`email = lower(trim(email))`); enforces valid `account_status` (`pending_verification`, `active`, `suspended`, `disabled`) and lifecycle flag consistency; blocks deletion of referenced roles or departments (`ON DELETE RESTRICT`). |
| `user_sessions` | `fk_user_sessions_user_id_users` (`CASCADE`), `fk_user_sessions_department_id_departments` (`SET NULL`), `ix_user_sessions_user_id_status`, `ck_user_sessions_session_status_allowed_values`, `ck_user_sessions_session_expiry_after_issued`, `ck_user_sessions_session_revocation_consistency` | Binds sessions to owning user and department; guarantees `expires_at > issued_at`; ensures revoked sessions always record `revoked_at`. |
