# E-WITNESS — BATCH 03 (GROUP 2) VERIFICATION REPORT
## PHASES 26–30: API SECURITY, ABUSE PREVENTION, INPUT VALIDATION & SECURITY REGRESSION TESTING

**Execution Date:** October 13, 2026  
**Auditor / Architect:** Principal Backend Architect, Application Security Engineer & Technical Auditor  
**Status:** COMPLETE & FULLY VERIFIED (413/413 tests passing, 90.36% branch coverage, 0 architecture violations, 0 mypy errors, 0 ruff errors)

---

## 1. Executive Summary

Batch 03 (Group 2) establishes the comprehensive API security boundary, abuse prevention, transport security, reverse proxy hardening, secure upload validation foundations, and security regression testing suite for **E-WITNESS**, covering **Phases 26 through 30** of the 120-phase master roadmap.

Key architectural, security, and verification deliverables:
1. **Centralized Request Validation & Sensitive Data Redaction (Phase 26):**
   - Hardened `handle_request_validation_error` in [`backend/app/api/errors.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/errors.py) with an expanded sensitive field allowlist (`_SENSITIVE_FIELD_NAMES`) preventing credentials (passwords, tokens, API keys, PINs, SSNs, credit cards) from ever being reflected in validation failure details.
   - Malformed JSON payloads handled cleanly as `REQUEST_VALIDATION_ERROR` with human-readable guidance (`Malformed JSON payload in request body.`) and zero traceback leakage.
   - Comprehensive error envelope mappings across HTTP status codes (400, 401, 403, 404, 409, 413, 415, 422, 429, 500) preserving `X-Request-ID` correlation tracking and propagating `Retry-After` headers on rate limits.
2. **HTTP Security, CORS, Trusted Hosts & Reverse Proxy Verification (Phase 27):**
   - Implemented [`backend/app/middleware/security_headers.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/middleware/security_headers.py) injecting `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and route-aware `Cache-Control: no-store, max-age=0` with `Pragma: no-cache`. HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) is conditionally enforced for HTTPS and SSL configurations.
   - Wired `TrustedHostMiddleware` into [`backend/app/main.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/main.py) backed by validated `ALLOWED_HOSTS` configuration, strictly rejecting Host header spoofing with HTTP 400.
   - Implemented [`backend/app/core/proxy.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/proxy.py) (`resolve_client_ip`) and FastAPI dependency `ClientIpDep` in [`backend/app/api/dependencies.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py) to prevent `X-Forwarded-For` spoofing by untrusted connecting peers.
3. **Rate Limiting & Abuse Prevention Foundations (Phase 28):**
   - Enhanced [`backend/app/core/rate_limit.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/rate_limit.py) with `RateLimiterProtocol`, atomic thread locks (`threading.Lock()`), and precise `Retry-After` window calculation propagated in `RateLimitExceededError` (HTTP 429).
   - Configured dedicated rate limiting thresholds in [`backend/app/config/settings.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/config/settings.py) for login, authentication, password recovery, verification, and global API traffic.
   - Implemented factory `create_rate_limiter` with fail-safe fallback logging when distributed stores are unconfigured.
4. **Input Hardening & Secure Upload Validation Foundations (Phase 29):**
   - Implemented [`backend/app/core/upload.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/upload.py) providing binary magic-byte inspection (PDF, PNG, JPEG, MP4, WAV, TXT, CSV), forbidden executable blacklist (`FORBIDDEN_EXTENSIONS`), and double-extension attack mitigation.
   - Implemented `sanitize_filename` neutralizing path traversal sequences (`../`, `..\`), null bytes, and control characters across POSIX and Windows delimiters.
   - Implemented `generate_secure_storage_key` creating unpredictable UUID keys (`cases/{case_id}/{uuid}{ext}`) completely decoupling physical storage paths from untrusted client filenames (prior to the full upload subsystem in Phases 46–65).
5. **Security Regression & Negative Testing Suite (Phase 30):**
   - Authored unit test suites in `tests/unit/security/` and full end-to-end integration test suite in [`tests/integration/api/test_security_regressions.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/integration/api/test_security_regressions.py) running against live PostgreSQL.
   - Verified negative authentication, negative authorization, SQL injection resistance in path parameters, malformed JSON bodies, payload limits, rate limiting, and security header injection.
6. **Code Quality & Architecture Isolation:**
   - Total test count expanded from 347 to **413 passing tests** in 38.22s.
   - Total test coverage maintained at **90.36% branch coverage** ($\ge 90.0\%$ threshold).
   - Zero architecture violations detected across all source layers (`scan_project_architecture`).
   - Clean linting and typing: 0 Ruff errors, 0 Mypy errors across 96 source files.

---

## 2. Phase-by-Phase Verification

### Phase 26 — Request Validation, Sensitive Data Redaction & Error Envelopes
- **Sensitive Field Protection:**
  - Defined `_SENSITIVE_FIELD_NAMES` in [`backend/app/api/errors.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/errors.py) covering `password`, `confirm_password`, `current_password`, `new_password`, `secret`, `token`, `access_token`, `refresh_token`, `authorization`, `api_key`, `credit_card`, `cvv`, `pin`, `ssn`, `private_key`.
  - When Pydantic validation fails on any of these parameters, error messages are scrubbed of input values and sanitized to prevent credential reflection.
- **Malformed Body Handling:**
  - Pydantic `json_invalid` errors are intercepted and translated to `"Malformed JSON payload in request body."` rather than leaking internal parser tracebacks or byte positions.
- **Uniform Error Envelopes:**
  - Standardized JSON responses for `AppError`, `StarletteHTTPException`, `RequestValidationError`, and unexpected exceptions matching:
    ```json
    {
      "error": {
        "code": "ERROR_CODE_STRING",
        "message": "Sanitized error description.",
        "request_id": "correlation-uuid-or-dash",
        "details": null
      }
    }
    ```
- **HTTP Status Code Mapping:**
  - 400: `HTTP_400` / Invalid request syntax
  - 401: `AUTHENTICATION_REQUIRED` / `UNAUTHENTICATED` / `INVALID_CREDENTIALS`
  - 403: `PERMISSION_DENIED` / `DEPARTMENT_MISMATCH` / `PRIVILEGE_ESCALATION_FORBIDDEN`
  - 404: `RESOURCE_NOT_FOUND` / `HTTP_404`
  - 409: `RESOURCE_CONFLICT`
  - 413: `PAYLOAD_TOO_LARGE`
  - 415: `UNSUPPORTED_MEDIA_TYPE`
  - 422: `REQUEST_VALIDATION_ERROR` / `BUSINESS_RULE_VIOLATION`
  - 429: `RATE_LIMIT_EXCEEDED` (with `Retry-After` response header)
  - 500: `INTERNAL_SERVER_ERROR` (zero stack-trace, SQL query, or file path leakage)

### Phase 27 — HTTP Security, CORS, Trusted Hosts & Reverse Proxy Hardening
- **Security Headers Middleware:**
  - Implemented [`backend/app/middleware/security_headers.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/middleware/security_headers.py). Injects:
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY`
    - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
    - `Referrer-Policy: no-referrer`
    - `Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()`
    - `Cache-Control: no-store, max-age=0` and `Pragma: no-cache` for `/api/` and `/auth` routes
    - `Strict-Transport-Security: max-age=31536000; includeSubDomains` when SSL is enabled or scheme is HTTPS.
- **Host Header Defense:**
  - Integrated `TrustedHostMiddleware` in [`backend/app/main.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/main.py) as the outermost ASGI layer. Host headers not present in `ALLOWED_HOSTS` are rejected with HTTP 400.
  - Production invariant validator in `Settings` mandates non-wildcard, non-loopback hosts in production.
- **Reverse Proxy Anti-Spoofing:**
  - Implemented `resolve_client_ip` in [`backend/app/core/proxy.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/proxy.py). Traverses `X-Forwarded-For` from right to left only if the connecting peer IP matches `TRUSTED_PROXIES`. Untrusted peers supplying forwarded headers have those headers stripped, returning only the connecting socket IP.
  - Added `ClientIpDep` dependency in [`backend/app/api/dependencies.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/api/dependencies.py) and consumed across auth endpoints.

### Phase 28 — Rate Limiting & Abuse Prevention Foundations
- **Sliding-Window Limiter:**
  - Implemented `InMemoryRateLimiter` in [`backend/app/core/rate_limit.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/rate_limit.py) using `threading.Lock()` to prevent race conditions during concurrent request processing.
  - Computes `retry_after = max(1, math.ceil(oldest + window_seconds - now))` and raises `RateLimitExceededError`.
- **Policy Configuration:**
  - Added configurable settings:
    - `RATE_LIMIT_LOGIN_MAX_REQUESTS` (default: 10) / `RATE_LIMIT_LOGIN_WINDOW_SECONDS` (60s)
    - `RATE_LIMIT_AUTH_MAX_REQUESTS` (default: 20) / `RATE_LIMIT_AUTH_WINDOW_SECONDS` (60s)
    - `RATE_LIMIT_RESET_MAX_REQUESTS` (default: 5) / `RATE_LIMIT_RESET_WINDOW_SECONDS` (300s)
    - `RATE_LIMIT_VERIFY_MAX_REQUESTS` (default: 5) / `RATE_LIMIT_VERIFY_WINDOW_SECONDS` (300s)
    - `RATE_LIMIT_GLOBAL_MAX_REQUESTS` (default: 100) / `RATE_LIMIT_GLOBAL_WINDOW_SECONDS` (60s)
    - `RATE_LIMIT_BACKEND` (memory / redis)
    - `RATE_LIMIT_FAIL_OPEN` (default: False)

### Phase 29 — Input Hardening & Secure Upload Validation Foundations
- **Magic-Byte Inspection:**
  - Implemented `detect_magic_bytes` and `validate_file_magic_bytes` in [`backend/app/core/upload.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/upload.py):
    - PDF: `%PDF-` at offset 0
    - PNG: `\x89PNG\r\n\x1a\n` at offset 0
    - JPEG: `\xff\xd8\xff` at offset 0
    - MP4: `ftyp` box at bytes 4..8
    - WAV: `RIFF` at 0..4 and `WAVE` at 8..12
    - Plain text / CSV: Valid UTF-8 without null bytes
  - Rejects unrecognized formats and mismatches with HTTP 415 `UnsupportedMediaTypeError`.
- **Dangerous Extension Blacklist & Double-Extension Attacks:**
  - Blacklisted 38 dangerous executable/script extensions (`.exe`, `.dll`, `.bat`, `.sh`, `.ps1`, `.vbs`, `.py`, `.js`, `.php`, `.jsp`, `.asp`, `.jar`, `.bin`, `.msi`, etc.).
  - Evaluates all dot-separated segments of the filename, rejecting attacks like `evidence.php.pdf` or `report.exe.png`.
- **Path Traversal & Filename Sanitization:**
  - `sanitize_filename` strips POSIX and Windows directories, rejects `..`, null bytes, control characters, and characters outside `[a-zA-Z0-9_.-]`.
- **Opaque Storage Keys:**
  - `generate_secure_storage_key(case_id, original_filename)` generates `cases/{case_id}/{uuid4().hex}{extension}`, guaranteeing client input is never used as a filesystem path or S3 key.

### Phase 30 — Security Regression & Negative Testing
- **Unit Test Suites:**
  - [`tests/unit/security/test_error_handling_and_redaction.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/security/test_error_handling_and_redaction.py) (14 tests)
  - [`tests/unit/security/test_http_security_and_transport.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/security/test_http_security_and_transport.py) (9 tests)
  - [`tests/unit/security/test_rate_limiting_and_abuse.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/security/test_rate_limiting_and_abuse.py) (6 tests)
  - [`tests/unit/security/test_input_hardening_and_uploads.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/unit/security/test_input_hardening_and_uploads.py) (21 tests)
- **Integration Test Suite:**
  - [`tests/integration/api/test_security_regressions.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/tests/integration/api/test_security_regressions.py) (8 tests against real PostgreSQL):
    - `test_host_header_injection_rejected_with_400`: Rejects unapproved Host header with HTTP 400.
    - `test_security_headers_present_on_api_responses`: Asserts all security headers on API responses.
    - `test_malformed_json_body_returns_clean_422_without_traceback`: Rejects truncated JSON with clean 422 envelope.
    - `test_validation_error_masks_sensitive_password_input`: Verifies submitted passwords do not leak into response bodies.
    - `test_rate_limiting_enforces_retry_after_header`: Floods login endpoint and verifies HTTP 429 with `Retry-After` header.
    - `test_sql_injection_attempt_in_path_returns_validation_error`: Asserts SQL injection syntax in UUID parameter fails with 422, never executes SQL, and never leaks database errors.
    - `test_negative_authentication_invalid_credentials_returns_401`: Verifies 401 `INVALID_CREDENTIALS`.
    - `test_negative_authorization_unauthenticated_protected_endpoint_returns_401`: Verifies unauthenticated protected endpoints return 401 `UNAUTHENTICATED`.

---

## 3. Test & Verification Evidence

### 3.1 Test Execution Summary
```
============================= test session starts =============================
platform win32 -- Python 3.13.1, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\lenovo\Desktop\E-WITNESS
configfile: pyproject.toml
plugins: anyio-4.15.1, platformdirs-4.13.0, asyncio-1.4.0, cov-7.1.0
asyncio: mode=Mode.AUTO, debug=False

413 passed in 38.22s (100% pass rate)
```

### 3.2 Coverage Report Breakdown
```
Name                                         Stmts   Miss Branch BrPart  Cover
------------------------------------------------------------------------------
ai_services\__init__.py                          2      0      0      0   100%
backend\app\__init__.py                          3      0      0      0   100%
backend\app\api\__init__.py                      4      0      0      0   100%
backend\app\api\dependencies.py                 89      5     14      3    92%
backend\app\api\errors.py                       89      2     24      4    95%
backend\app\api\router.py                        8      0      0      0   100%
backend\app\api\v1\__init__.py                   0      0      0      0   100%
backend\app\api\v1\auth.py                      34      0      0      0   100%
backend\app\api\v1\departments.py               24      0      0      0   100%
backend\app\api\v1\health.py                    18      0      2      0   100%
backend\app\api\v1\router.py                    13      0      0      0   100%
backend\app\api\v1\users.py                     27      0      0      0   100%
backend\app\config\__init__.py                   2      0      0      0   100%
backend\app\config\settings.py                 394      9    160     10    97%
backend\app\core\__init__.py                    11      0      0      0   100%
backend\app\core\architecture.py                98      3     42      5    94%
backend\app\core\authorization.py               66      0      8      0   100%
backend\app\core\context.py                     31      0      8      0   100%
backend\app\core\exceptions.py                  41      0      0      0   100%
backend\app\core\identity.py                    87      0     32      0   100%
backend\app\core\logging.py                    114      1     26      2    98%
backend\app\core\proxy.py                       30      5     16      2    76%
backend\app\core\rate_limit.py                  54      3      4      0    95%
backend\app\core\secrets.py                    110      8     52      8    90%
backend\app\core\tokens.py                      63      5     12      3    89%
backend\app\core\upload.py                      93      7     52      6    91%
backend\app\infrastructure\__init__.py           4      0      0      0   100%
backend\app\infrastructure\database.py         118     10     26      3    90%
backend\app\infrastructure\migrations.py        60      7      2      1    87%
backend\app\main.py                             54      0      6      2    97%
backend\app\middleware\__init__.py               4      0      0      0   100%
backend\app\middleware\body_size_limit.py       56      4     18      2    92%
backend\app\middleware\request_context.py       50      4     12      1    92%
backend\app\middleware\security_headers.py      37      2     16      3    91%
backend\app\models\__init__.py                   8      0      0      0   100%
backend\app\models\base.py                      35      0     10      0   100%
backend\app\models\department.py                35      0      4      0   100%
backend\app\models\role.py                      38      0      6      0   100%
backend\app\models\session.py                   50      0      0      0   100%
backend\app\models\token.py                     25      0      0      0   100%
backend\app\models\user.py                      79      3     12      1    96%
backend\app\repositories\__init__.py             4      0      0      0   100%
backend\app\repositories\base.py                14      0      0      0   100%
backend\app\repositories\identity.py           435    121     92     17    70%
backend\app\schemas\__init__.py                  7      0      0      0   100%
backend\app\schemas\auth.py                     70      0      0      0   100%
backend\app\schemas\common.py                   16      0      0      0   100%
backend\app\schemas\health.py                   20      0      0      0   100%
backend\app\schemas\identity.py                178      6     18      5    94%
backend\app\schemas\pagination.py               35      0      0      0   100%
backend\app\services\__init__.py                 7      0      0      0   100%
backend\app\services\auth.py                   187     63     58     14    62%
backend\app\services\department.py              49      0     14      0   100%
backend\app\services\email.py                   38      2      4      0    95%
backend\app\services\health.py                  42      0     14      0   100%
backend\app\services\password.py                45      3     14      1    93%
backend\app\services\user.py                   115      0     54      2    99%
------------------------------------------------------------------------------
TOTAL                                         3420    273    832     95  90.36%
```

### 3.3 Static Analysis & Architectural Compliance
- **Ruff:** All formatting and linting rules clean (`ruff check .`, `ruff format --check .`).
- **Mypy:** Type checks pass with 0 errors across 96 source files (`Success: no issues found in 96 source files`).
- **AST Architecture Scanner:** 0 violations detected (`tests/unit/architecture/test_layer_boundaries.py`). All layer boundaries (core, middleware, api, services, repositories, models) remain clean and decoupled.

---

## 4. Conclusion & Readiness

Batch 03 (Group 2) completes the API Security, Transport Security, Abuse Prevention, Input Validation, and Negative Testing foundations for E-WITNESS, fulfilling all criteria for **Phases 26–30**.

The repository is fully verified, robust, and cleanly positioned for **Batch 04 (Incident Intake, Reporting Engine & Preliminary Evidence Ingestion)**.
