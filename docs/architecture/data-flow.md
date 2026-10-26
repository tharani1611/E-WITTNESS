# E-WITNESS — Sensitive Data-Flow Architecture

**Document ID:** `EW-DOC-ARCH-004`  
**Phase:** Phase 03 — System Architecture and Service Boundaries  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## 1. Classification of Sensitive Data in E-WITNESS

| Data Class | Classification | Examples | Storage & Transit Protection |
| :--- | :--- | :--- | :--- |
| **DC-1: Cryptographic Secrets & Credentials** | **Restricted / Critical** | `AUTH_SECRET_KEY`, `DATABASE_URL` password, `STORAGE_SECRET_KEY`, `AI_API_KEY`, Bearer JWTs. | Wrapped in `SecretStr`; never committed to Git; never written to logs (`***REDACTED***`); injected via runtime environment. |
| **DC-2: Authoritative Digital Evidence Binaries** | **Highly Confidential / Immutable** | Uploaded PDFs, images, audio/video recordings, text logs attached to incident reports. | Streamed in chunks (`UPLOAD_CHUNK_SIZE_BYTES`); hashed with `SHA-256`; stored under UUID keys in private S3 over TLS; never modified in place. |
| **DC-3: Case Narratives & Investigation Records** | **Confidential (Tenant & Role Scoped)** | Witness statements, reporter identity, investigator notes, formal findings. | Scoped by `department_id` and `case_id` assignment; internal notes stripped from submitter responses (`FR-006`). |
| **DC-4: Chain-of-Custody & Security Audit Ledger** | **High Integrity / Append-Only** | Evidence access events, authentication/authorization logs, break-glass events. | Append-only PostgreSQL storage (`INSERT`/`SELECT` only); SHA-256 hash-chained; secrets redacted prior to persistence. |
| **DC-5: AI Advisory Artifacts** | **Confidential / Non-Authoritative** | Generated case summaries, extracted timelines, entity indexes. | Clearly labeled `is_authoritative = False`; stored separately from primary evidence; includes model/prompt provenance. |

---

## 2. Data-Flow Diagram (DFD): Sensitive Evidence Lifecycle

The following Mermaid Data-Flow Diagram traces how sensitive digital evidence flows through E-WITNESS from initial upload to authorized investigative retrieval and isolated AI analysis.

```mermaid
flowchart TB
    subgraph ExternalActors["Authenticated Stakeholders (TZ-0)"]
        Uploader["Authorized Uploader (Student / Staff / Assigned Investigator)"]
        Reviewer["Assigned Investigator (Department-Scoped)"]
    end

    subgraph IngressAndCore["Validation & Authorization Core (TZ-1 & TZ-2)"]
        P1["Process 1.0: Authenticate & Verify Case/Report Ownership"]
        P2["Process 2.0: Chunked Stream Validator (Size, MIME, Magic Bytes, Filename Sanitizer)"]
        P3["Process 3.0: Streaming SHA-256 Digest Calculator & UUID Key Generator"]
        P4["Process 4.0: Evidence Retrieval Guard & Integrity Verifier"]
        P5["Process 5.0: Redacted Audit & Custody Event Emitter"]
    end

    subgraph DataStores["Authoritative Vault (TZ-3)"]
        DS1[("D1: Private S3 Evidence Vault (UUID.bin Objects)")]
        DS2[("D2: PostgreSQL Evidence Metadata & Case Store")]
        DS3[("D3: PostgreSQL Append-Only Custody & Audit Ledger")]
        DS4[("D4: Redis Async Job Queue")]
    end

    subgraph IsolatedAI["Isolated AI Boundary (TZ-4)"]
        P6["Process 6.0: Scoped AI Worker & Prompt Delimiter Guard"]
        DS5[("D5: PostgreSQL AI Advisory Artifacts (is_authoritative = False)")]
    end

    Uploader -->|"1. Multipart Evidence Stream + Bearer JWT"| P1
    P1 -->|"2. Verified Principal + Scoped Stream"| P2
    P2 -->|"3. Validated Chunks (<= MAX_EVIDENCE_FILE_BYTES)"| P3
    P3 -->|"4a. Encrypted TLS Object Stream (Opaque UUID Key)"| DS1
    P3 -->|"4b. Metadata + 64-Char SHA-256 Digest + Sanitized Filename"| DS2
    P3 -->|"4c. EVIDENCE_INGESTED & SEALED Event"| P5
    P5 -->|"5. Append Hash-Chained Record"| DS3

    Reviewer -->|"6. Request Evidence / Case Review + Bearer JWT"| P4
    DS2 -->|"7a. Read Stored SHA-256 & Check Case Assignment"| P4
    DS1 -->|"7b. Stream Encrypted Object Bytes"| P4
    P4 -->|"8a. Mandatory EVIDENCE_ACCESSED Event"| P5
    P4 -->|"8b. Integrity-Verified Evidence Stream (nosniff)"| Reviewer

    Reviewer -->|"9. Trigger Async AI Analysis (Case ID)"| P1
    P1 -->|"10. Enqueue Scoped Job Descriptor"| DS4
    DS4 -->|"11. Dequeue Job"| P6
    DS2 -->|"12. Read Scoped Narrative / Text Snapshot"| P6
    P6 -->|"13a. Persist Non-Authoritative Advisory Output"| DS5
    P6 -->|"13b. AI_ANALYSIS_COMPLETED Event"| P5
```

---

## 3. Sequence Diagram: Evidence Upload, Hashing, and Custody Sealing

```mermaid
sequenceDiagram
    autonumber
    actor User as Uploader (Student / Staff / Investigator)
    participant API as FastAPI Ingress & Auth Guard (TZ-1/TZ-2)
    participant Svc as Evidence Custody Service (TZ-2)
    participant S3 as Private S3 Evidence Vault (TZ-3)
    participant DB as PostgreSQL Metadata & Custody Ledger (TZ-3)

    User->>API: POST /api/v1/cases/{case_id}/evidence (Bearer JWT + Multipart Stream)
    API->>API: Verify JWT Signature, Role & Case/Report Ownership (SEC-001..004)
    alt Unauthorized or Invalid Token
        API->>DB: Append AUDIT_ACCESS_DENIED (Redacted Context)
        API-->>User: HTTP 401 / 403 Structured Error
    else Authorized
        API->>Svc: Initiate Chunked Ingestion (UPLOAD_CHUNK_SIZE_BYTES)
        Svc->>Svc: Sanitize Original Filename & Verify Magic Bytes vs ALLOWED_EVIDENCE_MIME_TYPES
        alt Disallowed MIME / Magic Bytes or > MAX_EVIDENCE_FILE_BYTES
            Svc->>DB: Append EVIDENCE_UPLOAD_REJECTED Audit Event
            Svc-->>User: HTTP 415 Unsupported Media Type / HTTP 413 Payload Too Large
        else Validated Stream
            Svc->>Svc: Compute Running SHA-256 Digest & Generate Opaque Key (<dept>/<case>/<uuid>.bin)
            Svc->>S3: Stream Object over Verified TLS (STORAGE_VERIFY_TLS=True, No Overwrite)
            S3-->>Svc: Storage ETag & Write Confirmation
            Svc->>DB: Atomic Transaction: Insert Evidence Metadata (SHA-256, Size, SEALED) + Custody Ledger Entry
            DB-->>Svc: Commit Confirmed
            Svc-->>User: HTTP 201 Created (Evidence ID, SHA-256 Digest, Custody Timestamp)
        end
    end
```

---

## 4. Sequence Diagram: Authorized Evidence Retrieval and Integrity Verification

```mermaid
sequenceDiagram
    autonumber
    actor Inv as Assigned Investigator
    participant API as FastAPI Auth & ABAC Guard (TZ-2)
    participant Svc as Evidence Custody Service (TZ-2)
    participant DB as PostgreSQL (Tenant Repo & Custody Ledger)
    participant S3 as Private S3 Evidence Vault (TZ-3)

    Inv->>API: GET /api/v1/cases/{case_id}/evidence/{evidence_id}/download
    API->>DB: Query Case Assignment & Evidence Metadata (WHERE department_id = :dept_id)
    alt Not Assigned or Cross-Department Request
        API->>DB: Append SECURITY_UNAUTHORIZED_EVIDENCE_ACCESS
        API-->>Inv: HTTP 403 Forbidden
    else Explicitly Assigned Investigator
        API->>Svc: Authorize Retrieval (Principal, Evidence Metadata)
        Svc->>S3: Open Encrypted Object Stream (<dept>/<case>/<evidence_uuid>.bin)
        Svc->>Svc: Verify Stream SHA-256 Digest Against Authoritative DB Digest (EVI-003)
        alt SHA-256 Mismatch Detected
            Svc->>DB: Append CRITICAL EVIDENCE_INTEGRITY_VIOLATION Event
            Svc-->>Inv: HTTP 500 Integrity Verification Failure Alert
        else SHA-256 Verified
            Svc->>DB: Append EVIDENCE_DOWNLOADED Custody & Audit Event (AUD-002, EVI-004)
            Svc-->>Inv: Stream Bytes (Content-Disposition: attachment; X-Content-Type-Options: nosniff)
        end
    end
```

---

## 5. Data Protection Invariants Across All Flows

1. **Zero Secret Persistence in Logs or Errors**:
   - Before any log message, configuration summary, or exception traceback leaves `TZ-2`, `redact_text()`, `redact_url()`, and `redact_mapping()` in [`backend/app/core/secrets.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/secrets.py) replace credentials, DSN passwords, bearer tokens, and secret keys with `***REDACTED***`.
2. **Zero Unscoped Database Queries**:
   - Data flows from `TZ-2` to `TZ-3` always carry the authenticated principal's `department_id` (and `user_id` for `Student`/`Staff`/`Investigator`).
3. **Strict Separation of Authoritative vs. Advisory Data**:
   - Flow `13a` in the DFD writes strictly to `D5` (`ai_advisory_artifacts`) and has zero write path to `D1` (S3 Evidence Vault) or `D2` (Authoritative Evidence & Case Metadata).
