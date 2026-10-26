# E-WITNESS — Architecture Decision Records (ADRs)

**Document ID:** `EW-DOC-ARCH-002`  
**Phase:** Phase 03 — System Architecture and Service Boundaries  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## ADR-001: Modular Layered Backend with FastAPI and Async SQLAlchemy 2.x

- **Status**: Accepted
- **Context**: E-WITNESS must handle concurrent incident submissions, streaming digital evidence transfers, strict schema validation, and fine-grained authorization checks while remaining simple to audit and maintain across a 120-phase roadmap.
- **Options Considered**:
  1. *Microservices from Day 1*: High operational overhead, distributed transaction complexity, and expanded network attack surface.
  2. *Synchronous WSGI Framework (Flask/Django)*: Requires thread-pool scaling for streaming I/O and external storage/AI calls; less native integration with Pydantic v2.
  3. *Modular Layered Monolith in FastAPI with Async SQLAlchemy 2.x and Isolated Worker Boundary*: Combines strong in-process module boundaries (`api`, `schemas`, `services`, `repositories`, `models`, `infrastructure`) with non-blocking ASGI I/O and separate worker processes for heavy/AI tasks.
- **Decision**: Adopt **Option 3** (FastAPI + Pydantic v2 + Async SQLAlchemy 2.x + Alembic + Uvicorn, with `ai_services/` isolated for background processing).
- **Consequences & Security Impact**:
  - Enforces strict separation between HTTP transport schemas (`schemas/`) and database entities (`models/`), preventing mass-assignment vulnerabilities and accidental internal field exposure.
  - Non-blocking async I/O supports chunked evidence streaming without starving API worker threads.

---

## ADR-002: Multi-Department and Tenant Isolation Strategy

- **Status**: Accepted
- **Context**: E-WITNESS serves multiple institutional departments (e.g., Academic Integrity, Student Conduct, Campus Safety, HR/Staff Relations). A `Department Administrator` or `Investigator` in one department must never be able to view or modify records in another department.
- **Options Considered**:
  1. *Database-per-Department*: Complete physical isolation, but high operational burden for migrations, connection pooling, and platform-wide Super Admin audit oversight.
  2. *Application-Only Filtering*: Simple schema, but a single developer oversight in a query could cause cross-department data leakage (`RSK-001`).
  3. *Defense-in-Depth Shared Schema (Mandatory Repository Scoping + Composite Foreign Keys + PostgreSQL Row-Level Security)*: Every multi-tenant table carries a non-null `department_id` UUID enforced by base repository signatures, composite foreign keys `(id, department_id)`, and PostgreSQL RLS policies.
- **Decision**: Adopt **Option 3**.
- **Consequences & Security Impact**:
  - Eliminates cross-department relational linking at the database constraint level.
  - Even if an application query omits a filter, PostgreSQL RLS and mandatory repository method signatures act as redundant barriers.
  - Client-side checks are never relied upon for authorization.

---

## ADR-003: Hybrid Evidence Storage (S3 Object Vault + PostgreSQL Custody Metadata + Streaming SHA-256)

- **Status**: Accepted
- **Context**: Digital evidence includes documents, images, audio, and video up to tens of megabytes. Evidence must be protected against tampering, unauthorized access, and repudiation.
- **Options Considered**:
  1. *Store Evidence as PostgreSQL `BYTEA` Blobs*: Bloats relational backups, degrades query cache performance, and increases database memory pressure.
  2. *Direct Client-to-S3 Uploads without Backend Inspection*: Fast, but bypasses synchronous server-side magic-byte inspection, streaming `SHA-256` calculation before persistence, and strict custody attribution.
  3. *Backend-Mediated Chunked Streaming to S3-Compatible Storage with PostgreSQL Metadata & Custody Ledger*: The backend validates size, MIME type, and magic bytes in bounded chunks (`UPLOAD_CHUNK_SIZE_BYTES`), computes the `SHA-256` digest in flight, writes the binary to an opaque UUID key in private S3 storage over TLS, and records immutable metadata and custody events in PostgreSQL.
- **Decision**: Adopt **Option 3**.
- **Consequences & Security Impact**:
  - Guarantees cryptographic hash calculation (`EVI-001`) and file signature inspection (`SEC-010`) before an object is marked `SEALED`.
  - Prevents direct public bucket access and hides raw S3 credentials from clients (`SEC-011`).

---

## ADR-004: Isolated AI Processing Boundary and Non-Authoritative Advisory Model

- **Status**: Accepted
- **Context**: E-WITNESS plans to offer AI-assisted capabilities (case narrative summarization, timeline extraction, entity indexing) in later roadmap phases, but AI models are probabilistic, susceptible to prompt injection, and may rely on external network providers.
- **Options Considered**:
  1. *Inline Synchronous AI Calls Inside API Routes*: Blocks HTTP workers, causes startup/request failures when AI providers are down, and blurs authoritative vs. generated data.
  2. *Isolated Asynchronous AI Boundary (`ai_services/`) with Non-Authoritative Advisory Storage*: AI features are disabled by default (`AI_ENABLED=False`), prohibited from running at startup (`AI_CONNECT_ON_STARTUP=False`), executed asynchronously by background workers on scoped input snapshots, and saved in a separate advisory table (`ai_advisory_artifacts`) clearly marked as non-authoritative.
- **Decision**: Adopt **Option 2**.
- **Consequences & Security Impact**:
  - Core platform startup and incident/evidence operations have zero dependency on AI availability (`NFR-001`, `NFR-002`).
  - Untrusted report narratives are wrapped in strict structural delimiters before model invocation (`SEC-012`).
  - Authoritative evidence and official investigator findings can never be overwritten by AI outputs (`FR-016`, `EVI-006`).

---

## ADR-005: Centralized Fail-Fast Configuration and Zero-Trust Secret Redaction

- **Status**: Accepted
- **Context**: Misconfigured production environments (e.g., leftover placeholder keys, `DEBUG=True`, disabled TLS verification, wildcard CORS, or leaked database passwords in logs) are a leading cause of security breaches.
- **Options Considered**:
  1. *Scattered `os.getenv()` Calls with Permissive Defaults*: Easy to write, but allows missing or weak settings to go unnoticed until runtime failure or exploitation.
  2. *Centralized Pydantic Settings v2 Module with Environment-Aware Validators and Secret Redaction Utilities*: Validates all settings at startup, wraps secrets in `SecretStr`, rejects weak/placeholder values or insecure flags in `production`, and automatically redacts sensitive patterns from logs, URLs, and configuration representations.
- **Decision**: Adopt **Option 2** (implemented in `backend/app/config/settings.py` and `backend/app/core/secrets.py` in Phase 05).
- **Consequences & Security Impact**:
  - Production startup fails safely and immediately if mandatory security settings are absent or insecure (`SEC-005`–`SEC-009`, `SEC-015`).
  - `repr(settings)`, `str(settings)`, and `settings.to_safe_dict()` never expose plaintext secrets (`SEC-008`).

---

## ADR-006: Append-Only, Hash-Chained Audit and Custody Ledger

- **Status**: Accepted
- **Context**: In an institutional investigation platform, administrators, investigators, and external auditors must trust that access logs and chain-of-custody records have not been altered or deleted after the fact.
- **Options Considered**:
  1. *Standard Mutable Application Log Files*: Easily rotated, truncated, or edited by host operators; difficult to query by department/case scope.
  2. *Append-Only Relational Audit & Custody Ledger with Cryptographic Hash Chaining*: Every security and custody event is inserted into an append-only PostgreSQL table where each row records `previous_hash` and computes `entry_hash = SHA256(previous_hash || canonical_payload)`.
- **Decision**: Adopt **Option 2** (architected in Phase 03, implemented in Phases 08 and 61–65/96).
- **Consequences & Security Impact**:
  - Provides mathematical tamper-evidence against unauthorized row modification or deletion (`AUD-001`, `AUD-003`, `EVI-004`).
