# E-WITNESS — Engineering and Coding Standards

**Document ID:** `EW-DOC-DEV-002`  
**Phase:** Phase 07 — Layered Architecture and Coding Standards  
**Version:** 1.0.0  
**Status:** Enforced  

---

## 1. Module, Class, Function, and Variable Naming Conventions

| Construct | Convention | Example |
| :--- | :--- | :--- |
| **Packages & Modules** | `snake_case` | `backend/app/middleware/request_context.py` |
| **Classes, Exceptions & Protocols** | `PascalCase` | `HealthService`, `ResourceNotFoundError`, `TenantScopedRepositoryProtocol` |
| **Pydantic Request/Response Schemas** | `PascalCase` with explicit suffix (`Request`, `Response`, `Detail`, `Body`) | `LivenessResponse`, `ReadinessResponse`, `ErrorResponse` |
| **FastAPI Dependency Aliases** | `PascalCase` ending with `Dep` | `SettingsDep`, `CorrelationIdDep`, `HealthServiceDep` |
| **Functions, Methods & Coroutines** | `snake_case` verb phrases | `evaluate_readiness()`, `validate_or_generate_request_id()` |
| **Constants & Settings Fields** | `UPPER_SNAKE_CASE` | `CORRELATION_ID_HEADER`, `MAX_REQUEST_BODY_BYTES` |
| **Module-Internal Helpers** | Leading underscore `_snake_case` | `_extract_incoming_request_id()`, `_app_lifespan()` |

---

## 2. Asynchronous Programming Standards (`ARCH-ASYNC-BLOCK`)

1. **Zero Blocking Calls on Async Request Paths**:
   - Route handlers, ASGI middleware, async services, and async repositories execute on the ASGI event loop thread.
   - Never call `time.sleep()`, synchronous `requests.*`, `urllib.request.urlopen()`, or synchronous database drivers inside `async def` functions.
   - [`backend/app/core/architecture.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/architecture.py) automatically scans all `async def` AST nodes and fails if `time.sleep()` is invoked (`ARCH-ASYNC-BLOCK`).
2. **Context-Local State (`contextvars`)**:
   - Never store request-scoped state (such as `request_id` or authenticated user context) in module-level globals or thread-local variables.
   - Always use `contextvars.ContextVar` and restore state via `ContextVar.reset(token)` in a `try ... finally` block.
3. **Safe Module Imports**:
   - Importing any module under `backend/` or `ai_services/` must never execute network I/O, connect to databases/Redis/S3, or require production environment variables to be present at import time.

---

## 3. FastAPI Dependency Injection Conventions

1. **Application Factory Pattern (`create_app`)**:
   - Always instantiate the FastAPI application through [`create_app(settings=...)`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/main.py#L51-L120).
   - Validated [`Settings`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/config/settings.py#L112-L645) are attached to `app.state.settings` and resolved via [`get_app_settings`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py#L20-L25) (`SettingsDep`).
2. **Typed `Annotated` Dependencies**:
   - Define reusable `Annotated[..., Depends(...)]` aliases in [`backend/app/api/dependencies.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py) rather than repeating `Depends(...)` default arguments across route signatures.
3. **Explicit Response Models and Status Codes**:
   - Every API route decorator (`@router.get`, `@router.post`, etc.) must declare `response_model=...` and `status_code=status.HTTP_...`.
   - Never return SQLAlchemy ORM model instances directly from route handlers.

---

## 4. Exception, Transaction, and Logging Conventions

### 4.1 Exception Handling
- **Services**: Raise subclasses of [`AppError`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/exceptions.py#L13-L34) with clear domain error codes.
- **API Boundary**: [`register_exception_handlers(app)`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/errors.py#L178-L196) maps:
  - `RequestValidationError` $\rightarrow$ `HTTP 422` (`REQUEST_VALIDATION_ERROR`)
  - `AppError` $\rightarrow$ `exc.status_code` (`exc.code`)
  - `StarletteHTTPException` $\rightarrow$ `exc.status_code` (`HTTP_<STATUS>` or `INTERNAL_SERVER_ERROR` for 5xx)
  - Unhandled `Exception` $\rightarrow$ `HTTP 500` (`INTERNAL_SERVER_ERROR` with generic message `"An unexpected internal server error occurred."`)
- **Zero Client Information Disclosure**: Never include stack traces, exception class names, SQL queries, file system paths, or raw secret inputs in client-facing error payloads.

### 4.2 Database Transaction Conventions (Prepared for Phase 11+)
- Repositories execute queries and `session.flush()` within an injected async session, but do not call `session.commit()` autonomously when part of a multi-step business operation.
- Business services own the unit-of-work transaction boundary so domain mutations and audit/custody ledger entries commit or roll back atomically.

### 4.3 Safe Structured Logging
- Obtain loggers via [`get_logger(__name__)`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/logging.py#L246-L250).
- Pass structured metadata via `extra={...}`.
- Never log raw request bodies, evidence binary payloads, authorization headers, or unredacted query strings.
- All log messages and `extra` fields are automatically sanitized against CRLF log injection (`\r` $\rightarrow$ `\\r`, `\n` $\rightarrow$ `\\n`) and secret leakage (`***REDACTED***`) by [`RedactingCorrelationFilter`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/logging.py#L97-L138).

---

## 5. Automated Quality Gates

Every code change must pass all automated checks configured in [`pyproject.toml`](file:///c:/Users/lenovo/Desktop/E-WITNESS/pyproject.toml):

1. **Formatting**: `ruff format --check .` (`line-length = 100`, double quotes)
2. **Linting & Security**: `ruff check .` (`E`, `W`, `F`, `I`, `B`, `C4`, `UP`, `SIM`, `S` bandit security rules, `RUF`)
3. **Static Type Checking**: `mypy` (`strict = true` + `pydantic.mypy` plugin)
4. **Architectural Boundary Check**: `scan_project_architecture(ROOT_DIR)` (`0` violations)
5. **Unit & Integration Tests + Coverage**: `pytest` ($\ge 90\%$ branch and line coverage)
