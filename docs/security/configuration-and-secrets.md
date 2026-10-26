# E-WITNESS — Configuration Validation and Secrets Management Guide

**Document ID:** `EW-DOC-SEC-001`  
**Phase:** Phase 05 — Application Configuration and Secrets Management  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## 1. Overview and Security Design Principles

E-WITNESS implements a **Zero-Trust, Fail-Fast Configuration and Secrets Management Architecture** across [`backend/app/config/settings.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/config/settings.py) and [`backend/app/core/secrets.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/secrets.py):

1. **No Silent Insecure Defaults**: Critical connection URLs (`DATABASE_URL`, `REDIS_URL`, `STORAGE_ENDPOINT_URL`, `STORAGE_BUCKET_NAME`) and secrets (`AUTH_SECRET_KEY`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`) have **no hardcoded fallback defaults** in Python source code. Missing mandatory configuration causes immediate startup rejection.
2. **Environment-Specific Guardrails (`development`, `testing`, `production`)**:
   - `development` and `testing` allow isolated local endpoints (`localhost`) and test-only database schemes (`sqlite+aiosqlite://`), while still enforcing universal safety rules (such as `STORAGE_VERIFY_TLS=True` and `AUTH_ALGORITHM != "none"`).
   - `production` activates `_enforce_production_security_gate()`, which rejects `DEBUG=True`, `DB_ECHO=True`, `LOG_LEVEL=DEBUG`, placeholder/weak secrets, low Shannon entropy keys, unencrypted `redis://` or `http://` endpoints, `localhost` hosts, and wildcard `*` CORS origins.
3. **Secret Encapsulation and Automatic Redaction**:
   - Secret fields are typed as `pydantic.SecretStr`.
   - `Settings.__repr__()`, `Settings.__str__()`, and `Settings.to_safe_dict()` replace all secrets and URL userinfo passwords with `***REDACTED***`.
   - [`backend/app/core/secrets.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/secrets.py) provides `redact_text()`, `redact_url()`, `redact_mapping()`, and `sanitize_validation_errors()` to prevent credential disclosure in logs, tracebacks, and audit records.

---

## 2. Environment Variable Precedence

`Settings` uses `pydantic-settings` (`BaseSettings`) with deterministic precedence from highest priority (1) to lowest priority (4):

1. **Explicit Keyword Arguments (`load_settings(**overrides)`)**: Used primarily in isolated unit tests (`tests/conftest.py`) to inject deterministic test configurations without mutating host environment state.
2. **Process Environment Variables (`os.environ`)**: The primary mechanism for production and CI/CD secret injection. An environment variable set in the OS process always overrides values in `.env`.
3. **Local `.env` File (`env_file=".env"`)**: Used strictly for local developer convenience in `development`. Excluded from version control by `.gitignore`.
4. **Validated Non-Sensitive Field Defaults**: Safe defaults defined in `Settings` (e.g., `DB_POOL_SIZE=10`, `STORAGE_VERIFY_TLS=True`, `AI_ENABLED=False`, `AI_CONNECT_ON_STARTUP=False`).

---

## 3. Cryptographic Key Requirements and Generation

| Secret Configuration Key | Minimum Length | Production Entropy & Diversity Rules | Recommended Generation Command |
| :--- | :--- | :--- | :--- |
| `AUTH_SECRET_KEY` | $\ge 32$ chars (All envs) | $\ge 32$ chars, $\ge 10$ unique chars, Shannon entropy $\ge 3.20$ bits/char; zero forbidden placeholder substrings | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `STORAGE_ACCESS_KEY` | $\ge 8$ chars (Dev/Test)<br>$\ge 12$ chars (Prod) | $\ge 6$ unique chars, Shannon entropy $\ge 2.50$ bits/char; rejects `minioadmin`, `example`, `replace_with`, etc. | Issued by S3/IAM provider or `secrets.token_hex(16)` |
| `STORAGE_SECRET_KEY` | $\ge 8$ chars (Dev/Test)<br>$\ge 20$ chars (Prod) | $\ge 6$ unique chars, Shannon entropy $\ge 2.50$ bits/char; rejects placeholders | Issued by S3/IAM provider or `secrets.token_urlsafe(36)` |
| `DATABASE_URL` (Password) | $\ge 12$ chars (Prod) | $\ge 6$ unique chars, Shannon entropy $\ge 2.50$ bits/char; rejects `postgres`, `password`, `replace_with`, etc. | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `REDIS_URL` (Password) | Required in Prod | Must use `rediss://` TLS scheme with non-placeholder password in production | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `AI_API_KEY` | $\ge 16$ chars (When external AI enabled) | Required only when `AI_ENABLED=True` and `AI_PROVIDER` is `openai`, `anthropic`, or `gemini` | Issued by model provider |

---

## 4. Secret Rotation Procedures

1. **`AUTH_SECRET_KEY` (Token Signing Key)**:
   - **Scheduled Rotation**: Rotate every 90 days or immediately upon suspected compromise.
   - **Procedure**:
     1. Generate a new 48-byte URL-safe token (`secrets.token_urlsafe(48)`).
     2. Inject the updated `AUTH_SECRET_KEY` into the deployment environment secret store.
     3. Perform a rolling restart of backend API instances.
     4. Note: Because access tokens are short-lived (`AUTH_ACCESS_TOKEN_EXPIRE_MINUTES=15` default), rotating a symmetric `HS256` signing key immediately invalidates active sessions, requiring users to re-authenticate. (Multi-key `kid` keyring support is scheduled for the authentication roadmap phases).
2. **Database & Redis Credentials (`DATABASE_URL`, `REDIS_URL`)**:
   - Use dual-user alternating rotation:
     1. Provision secondary database/Redis user with identical least-privilege grants.
     2. Update `DATABASE_URL` / `REDIS_URL` in the deployment environment and perform a rolling restart.
     3. Revoke/rotate the previous database user's credentials once active connections drain.
3. **Object Storage Credentials (`STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`)**:
   - Create a secondary IAM access key pair on the storage service account, deploy the new key pair to the runtime environment, verify health checks, and deactivate/delete the old key pair.

---

## 5. Secure Deployment Injection Guidelines

> [!WARNING]
> **No Cloud Secret Manager Claimed in Phase 05**: In accordance with Phase 05 execution rules, E-WITNESS does **not** claim an active AWS Secrets Manager, HashiCorp Vault, or GCP Secret Manager SDK integration at this stage. Secrets are consumed via validated OS environment variables.

When deploying E-WITNESS in staging or production environments (scheduled in later deployment phases):
- **Never Bake Secrets into Images**: Container images (`Dockerfile`) and CI artifacts must never contain `.env` files or `ENV AUTH_SECRET_KEY=...` declarations.
- **Runtime Environment Injection**: Inject secrets at container/process startup via orchestrator secret mounts or environment injection (e.g., Kubernetes `Secret` envFrom, systemd `EnvironmentFile` with `0400` permissions, or cloud workload identity environment injection).
- **Startup Verification**: If any mandatory production secret is missing or fails entropy/placeholder checks, `Settings` raises a `ValidationError` before Uvicorn binds the socket. Use `sanitize_validation_errors(exc)` to log configuration errors without printing the rejected secret value.
