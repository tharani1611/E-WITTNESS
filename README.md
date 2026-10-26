# E-WITNESS

**High-Assurance Institutional Incident Reporting, Digital Evidence Custody, and Investigation Platform**

---

## 1. Project Purpose

**E-WITNESS** is a security-first, multi-department institutional incident reporting, digital evidence custody, and case investigation platform designed for educational and organizational environments. It provides:

- **Role-Scoped, Least-Privilege Workflows**: Strictly separated capabilities for **Students**, **Staff**, **Department Administrators**, **Investigators**, and **Super Admins**.
- **Hard Multi-Department / Tenant Isolation**: Defense-in-depth department scoping across API dependencies, domain services, repositories, and database constraints.
- **Verifiable Digital Evidence Integrity**: Controlled chunked streaming uploads, MIME and magic-byte verification, immediate `SHA-256` cryptographic hashing, isolated S3-compatible object storage, and append-only chain-of-custody ledgers.
- **Isolated Non-Authoritative AI Boundary**: Asynchronous background AI advisory analysis (`ai_services/`) that never executes at application startup and never mutates authoritative evidence or official findings.
- **Fail-Fast Configuration & Secret Redaction**: Validated startup configuration (`pydantic-settings`) that rejects weak/placeholder secrets, disabled TLS verification, or unsafe production defaults, combined with automatic credential scrubbing across logs and configuration outputs.

> **Current Roadmap Status**: **Batch 01 (Phases 01–10)** completed (Repository Initialization, Requirements & Stakeholder Analysis, System Architecture & Threat Model, Development Environment & Dependency Management, Application Configuration & Secrets Management, FastAPI Application Bootstrap, Layered Architecture & Coding Standards, Centralized Logging & Request Tracing, Testing Foundation & Quality Gates, and Foundation Audit). Next scheduled batch: **Batch 02 — Phases 11–20: Database, Schema, and Authentication Foundation**.

---

## 2. Prerequisites

- **Python**: `3.12+` (verified on `Python 3.13.1`)
- **Git**: `2.40+` (`git version 2.52.0.windows.1` verified)
- **Local Testing**: No live PostgreSQL, Redis, S3, or external AI credentials are required to run the automated unit and integration test suites or quality gates.

---

## 3. Repository Layout

```text
E-WITNESS/
├── .github/workflows/ci.yml      # Credential-free CI quality gates
├── ai_services/                  # Isolated asynchronous AI processing boundary
│   └── __init__.py
├── artifacts/                    # Audit reports and verification evidence
│   ├── BATCH_01_GROUP_01_REPORT.md
│   └── BATCH_01_GROUP_02_REPORT.md
├── backend/                      # FastAPI backend application workspace
│   ├── __init__.py
│   └── app/
│       ├── __init__.py
│       ├── main.py               # FastAPI create_app() factory & lifespan
│       ├── api/                  # Versioned HTTP route controllers & error handlers
│       │   ├── dependencies.py   # Typed FastAPI DI providers
│       │   ├── errors.py         # Sanitized exception handlers
│       │   ├── router.py         # Top-level router registration
│       │   └── v1/
│       │       ├── health.py     # Liveness & readiness endpoints
│       │       └── router.py     # API v1 router builder
│       ├── config/               # Centralized validated Settings (Phase 05)
│       │   ├── __init__.py
│       │   └── settings.py
│       ├── core/                 # Security, logging, context, exceptions & AST audit
│       │   ├── architecture.py   # AST architectural boundary verifier (Phase 07)
│       │   ├── context.py        # ContextVar request correlation IDs (Phase 08)
│       │   ├── exceptions.py     # Domain AppError hierarchy (Phases 06-07)
│       │   ├── logging.py        # Structured JSON/console logging & CRLF guard
│       │   └── secrets.py        # Entropy validation & credential redaction
│       ├── infrastructure/       # Database, Redis, and S3 adapters (Phase 11+)
│       ├── middleware/           # Pure ASGI tracing & body-size guardrails
│       │   ├── body_size_limit.py
│       │   └── request_context.py
│       ├── models/               # SQLAlchemy 2.x async ORM models (Phase 11+)
│       ├── repositories/         # Tenant-scoped & append-only protocols
│       │   └── base.py
│       ├── schemas/              # Pydantic v2 request/response DTO contracts
│       │   ├── common.py
│       │   └── health.py
│       └── services/             # Domain business logic
│           └── health.py
├── deployment/                   # Reserved for container & release configurations
├── docs/                         # Requirements, architecture, security & dev guides
│   ├── architecture/
│   │   ├── architecture-decisions.md
│   │   ├── data-flow.md
│   │   ├── foundation-audit.md
│   │   ├── implementation-status.md
│   │   ├── layered-architecture.md
│   │   ├── system-architecture.md
│   │   ├── threat-model.md
│   │   └── trust-boundaries.md
│   ├── development/
│   │   ├── coding-standards.md
│   │   └── environment-setup.md
│   ├── requirements/
│   │   ├── requirements-specification.md
│   │   ├── stakeholder-permissions-matrix.md
│   │   └── traceability-matrix.md
│   └── security/
│       └── configuration-and-secrets.md
├── frontend/                     # Reserved workspace for future web client
├── infrastructure/               # Reserved for IaC, network, and storage policies
├── scripts/                      # Verification and maintenance utilities
│   └── verify_foundation.py
├── tests/                        # Automated unit and integration test suites
│   ├── conftest.py
│   ├── integration/
│   │   └── api/
│   │       └── test_bootstrap_and_health.py
│   └── unit/
│       ├── architecture/
│       │   └── test_layer_boundaries.py
│       ├── config/
│       │   ├── test_redaction.py
│       │   └── test_settings.py
│       └── logging/
│           └── test_logging_and_context.py
├── .env.example                  # Sanitized configuration template (placeholders only)
├── .gitignore                    # Strict exclusions for venvs, caches, .env & secrets
├── pyproject.toml                # Pinned metadata & Ruff / Mypy / Pytest / Coverage config
├── requirements.txt              # Pinned runtime dependencies
├── requirements-dev.txt          # Pinned development, testing & security dependencies
└── README.md                     # Project overview and operational guide
```

---

## 4. Setup and Local Startup Instructions

### 4.1 Windows PowerShell

```powershell
# 1. Create a project-local virtual environment
py -m venv .venv

# 2. Install pinned runtime and development dependencies
.\.venv\Scripts\pip.exe install -r requirements-dev.txt

# 3. Copy .env.example to .env for local development
Copy-Item .env.example .env

# 4. Start the local FastAPI server using the application factory
.\.venv\Scripts\uvicorn.exe backend.app.main:create_app --factory --host 127.0.0.1 --port 8000
```

### 4.2 Linux / macOS (Bash / Zsh)

```bash
# 1. Create and activate a project-local virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install pinned runtime and development dependencies
python -m pip install -r requirements-dev.txt

# 3. Copy .env.example to .env for local development
cp .env.example .env

# 4. Start the local FastAPI server using the application factory
uvicorn backend.app.main:create_app --factory --host 127.0.0.1 --port 8000
```

### 4.3 Basic API Health & Readiness Verification

Once the local server is running (or via `httpx.AsyncClient` in tests):
- `GET http://127.0.0.1:8000/health` — Root liveness check (`status: "ok"`).
- `GET http://127.0.0.1:8000/api/v1/health/live` — Versioned liveness check (`status: "ok"`).
- `GET http://127.0.0.1:8000/api/v1/health/ready` — Versioned readiness check (`status: "unverified"` with per-component `not_checked` status until database/Redis/S3 probes are wired in Phase 11+).

---

## 5. Testing, Linting, Type Checking, and Security Verification

Run the quality gates directly from the repository root:

```powershell
# Run full test suite (unit + integration) with branch coverage (enforces >= 90% coverage)
.\.venv\Scripts\pytest.exe

# Run only unit tests or only integration tests
.\.venv\Scripts\pytest.exe -m unit
.\.venv\Scripts\pytest.exe -m integration

# Check code formatting (Ruff)
.\.venv\Scripts\ruff.exe format --check .

# Run linting and security rules (Ruff + flake8-bandit)
.\.venv\Scripts\ruff.exe check .

# Run strict static type checking (Mypy + pydantic.mypy)
.\.venv\Scripts\mypy.exe

# Verify dependency graph consistency and scan for known CVEs
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\pip-audit.exe -r requirements.txt
.\.venv\Scripts\pip-audit.exe -r requirements-dev.txt

# Run the complete foundation verification suite
.\.venv\Scripts\python.exe scripts/verify_foundation.py
```

---

## 6. Security Expectations

1. **Zero Committed Secrets**: Never commit `.env` files, private keys (`*.pem`, `*.key`), certificates, or real credentials. `.gitignore` enforces these exclusions.
2. **Mandatory TLS Verification**: `STORAGE_VERIFY_TLS=True` is enforced across all environments (`development`, `testing`, and `production`). Never disable certificate verification.
3. **Production Hardening Gate**: Running with `ENVIRONMENT=production` enforces strong secret entropy, `https://` and `rediss://` transport encryption, explicit non-wildcard `https://` CORS origins, `DEBUG=False`, `DB_ECHO=False`, and disables public OpenAPI/Swagger endpoints.
4. **Least-Privilege & Tenant Isolation**: Authorization is enforced server-side across all five roles (`Student`, `Staff`, `Department Administrator`, `Investigator`, `Super Admin`). Never rely on frontend checks for security enforcement.
5. **Immutable Evidence & Audit Trails**: Authoritative digital evidence and security audit logs are append-only and cryptographically verified (`SHA-256`).
