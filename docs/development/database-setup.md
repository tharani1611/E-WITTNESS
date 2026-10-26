# E-WITNESS — PostgreSQL Database Setup, Async Engine, and Session Architecture

**Document ID:** `EW-DOC-DEV-003`  
**Phases:** Phase 11 (PostgreSQL Setup & Connectivity) & Phase 12 (SQLAlchemy Async Engine & Session Management)  
**Version:** 1.0.0  
**Status:** Implemented & Verified  

---

## 1. Overview

E-WITNESS uses **PostgreSQL** (`15+`, verified against **PostgreSQL 18.6**) as its primary relational data store, accessed exclusively through **SQLAlchemy 2.x Asynchronous I/O** (`postgresql+asyncpg://`) in [`backend/app/infrastructure/database.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/infrastructure/database.py).

All database components enforce five non-negotiable guarantees:
1. **Zero Import-Time Side Effects**: Importing `backend.app.main`, `backend.app.infrastructure.database`, or `backend.app.models` never opens a network socket or requires a running database server.
2. **Strict Environment Isolation**: Test suites are blocked by both [`Settings`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/config/settings.py) and [`validate_database_target_isolation()`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/infrastructure/database.py#L46-L61) from connecting to any database URL that references `prod` or lacks a `test` / `:memory:` target.
3. **Bounded Connection Pooling & Timeouts**: Connection establishment, command execution, pool acquisition, and connection recycling are bounded by explicit settings (`NFR-005`).
4. **Per-Request Session Isolation**: FastAPI routes receive a dedicated `AsyncSession` per request via [`DbSessionDep`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py#L58) that is never shared across concurrent requests or tasks.
5. **Credential Redaction & Safe Error Translation**: Database connection failures and constraint violations are translated via [`translate_database_error()`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/infrastructure/database.py#L121-L176) into sanitized [`AppError`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/exceptions.py) subclasses (`409`, `422`, `503`) without leaking DSNs, passwords, or raw SQL statements.

---

## 2. Database Configuration and Pool Settings

All database parameters are validated by [`Settings`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/config/settings.py):

| Setting | Type | Default | Bounds | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `DATABASE_URL` | `str` | *Mandatory* | `postgresql+asyncpg://...` (or `sqlite+aiosqlite://...` in dev/test) | Asynchronous SQLAlchemy connection URL. |
| `DB_POOL_SIZE` | `int` | `10` | `1 .. 100` | Steady-state number of persistent connections kept open in the SQLAlchemy `AsyncAdaptedQueuePool`. |
| `DB_MAX_OVERFLOW` | `int` | `20` | `0 .. 100` | Maximum burst connections permitted above `DB_POOL_SIZE`. |
| `DB_POOL_TIMEOUT_SECONDS` | `float` | `30.0` | `1.0 .. 120.0` | Maximum seconds to wait for an available connection from the pool before raising a timeout error. |
| `DB_CONNECT_TIMEOUT_SECONDS` | `float` | `10.0` | `1.0 .. 60.0` | Maximum seconds to wait when establishing a new TCP/TLS socket to PostgreSQL (`asyncpg` `timeout`). |
| `DB_COMMAND_TIMEOUT_SECONDS` | `float` | `60.0` | `1.0 .. 300.0` | Maximum execution time (`asyncpg` `command_timeout`) for any single SQL statement before cancellation. |
| `DB_POOL_RECYCLE_SECONDS` | `int` | `1800` | `60 .. 86400` | Maximum age (30 minutes default) of a pooled connection before it is recycled. |
| `DB_POOL_PRE_PING` | `bool` | `True` | `True / False` | Emits a lightweight liveness check when checking out a connection from the pool to discard stale sockets. |
| `DB_ECHO` | `bool` | `False` | Forbidden `True` in `production` | Enables SQL statement logging in local development only (`SEC-015`). |

### 2.1 Environment-Specific Rules
- **Development (`ENVIRONMENT=development`)**: Connects to an isolated local development database (e.g., `postgresql+asyncpg://ewitness_dev_user:<password>@localhost:5432/ewitness_dev`).
- **Testing (`ENVIRONMENT=testing`)**:
  - Must target an isolated test database whose name contains `test` (e.g., `ewitness_test` on an ephemeral test PostgreSQL cluster) or `sqlite+aiosqlite:///:memory:` for fast unit tests.
  - Any URL containing `prod` in the hostname or path is rejected immediately.
- **Production (`ENVIRONMENT=production`)**:
  - Must use `postgresql+asyncpg://` (`sqlite+aiosqlite://` is strictly forbidden).
  - Must not point to `localhost`, `127.0.0.1`, or `::1`.
  - Must include explicit username and high-entropy password credentials (weak/placeholder passwords fail startup validation).
  - `DB_ECHO=True` is strictly forbidden.

---

## 3. PostgreSQL Extensions Policy

In accordance with Phase 11 rules (*"Document PostgreSQL setup and required extensions only where justified by the roadmap"*), **no third-party or superuser-only PostgreSQL extensions are required for Phases 11–15**:
- **UUID Generation**: Primary keys (`UUIDPrimaryKeyMixin`) use standard SQLAlchemy 2.x `Uuid(as_uuid=True)` backed by PostgreSQL's native `UUID` data type, avoiding any dependency on the legacy `uuid-ossp` extension.
- **Case-Insensitive Identity Uniqueness**: Rather than requiring the `citext` extension (which complicates cross-dialect testing and index comparisons), E-WITNESS enforces canonical normalization (`lower(trim(email))`, `upper(trim(institutional_id))`, `upper(trim(code))`) at both the application layer ([`backend/app/core/identity.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/identity.py)) and the PostgreSQL `CHECK` constraint + `UNIQUE` B-tree index layer.

---

## 4. Local PostgreSQL Setup

### 4.1 Provisioning a Local Development Database (Windows PowerShell / Linux)
Using an existing local PostgreSQL 15–18 installation:

```sql
-- Execute as PostgreSQL superuser (e.g. psql -U postgres)
CREATE ROLE ewitness_dev_user WITH LOGIN PASSWORD 'REPLACE_WITH_LOCAL_DB_PASSWORD';
CREATE DATABASE ewitness_dev OWNER ewitness_dev_user ENCODING 'UTF8';
REVOKE ALL ON DATABASE ewitness_dev FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE ewitness_dev TO ewitness_dev_user;
```

### 4.2 Ephemeral Isolated PostgreSQL Cluster for Automated Testing
For integration tests in `tests/integration/db/`, the test harness in `tests/conftest.py` automatically provisions an ephemeral PostgreSQL 18 cluster in a temporary directory (using `initdb` and `pg_ctl` on an unused localhost port with database `ewitness_test`) whenever `EWITNESS_TEST_POSTGRES_URL` is not explicitly set in the environment. This guarantees:
- **Real PostgreSQL Verification**: All migrations, foreign keys, `CHECK` constraints, `UNIQUE` indexes, and concurrent transactions run against real PostgreSQL (`postgresql+asyncpg`).
- **Complete Host Isolation**: The test suite never touches or modifies any database on the host's default port `5432`.

---

## 5. Transaction Ownership and Session Lifecycle (`DatabaseSessionManager`)

[`DatabaseSessionManager`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/infrastructure/database.py#L204-L295) provides two explicit context managers:

1. **Read / Controller-Managed Scope (`async with db_manager.session() as session:`)**:
   - Used by FastAPI's [`get_db_session`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py#L51-L55) dependency (`DbSessionDep`).
   - Yields a fresh `AsyncSession` with `expire_on_commit=False` and `autoflush=False`.
   - If any unhandled exception occurs during request processing, `await session.rollback()` is executed automatically before `await session.close()`.
2. **Atomic Unit-of-Work Scope (`async with db_manager.transactional_session() as session:`)**:
   - Commits (`await session.commit()`) automatically when the `async with` block exits normally.
   - Rolls back (`await session.rollback()`) automatically if any exception is raised inside the block or during commit, and translates `SQLAlchemyError` into a sanitized `AppError`.
3. **Application Shutdown Disposal**:
   - FastAPI's [`_app_lifespan`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/main.py#L37-L56) calls `await db_manager.dispose()` inside its `finally:` block to cleanly close all pooled database connections on shutdown.
