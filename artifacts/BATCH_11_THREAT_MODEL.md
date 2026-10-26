# E-WITNESS — BATCH 11, PHASE 101 THREAT MODEL REVIEW
## High-Assurance Evidence Management System Threat Analysis

**Document Version:** 1.0.0  
**Date:** 2026-10-22  
**Scope:** Phases 01–105 Backend Architecture, APIs, Data Stores, Cryptography, and Evidence Custody  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) combined with Defense-in-Depth Assessment.

---

## 1. Executive Summary

E-WITNESS is an enterprise digital evidence and incident management platform designed for educational and public-sector institutions. It processes sensitive disciplinary reports, video evidence, chain-of-custody ledgers, and automated AI candidate detections. Because the platform's outputs may be introduced into formal legal or disciplinary proceedings, its security invariants must ensure zero cross-department data leakage, absolute evidence immutability, cryptographic non-repudiation, strict fail-closed malware containment, and immediate session invalidation upon privilege alteration.

This Threat Model Review covers 10 critical security domains, analyzes high-impact abuse scenarios, documents existing controls, and defines residual risk postures across the backend architecture.

---

## 2. Architecture & Trust Boundaries

```
[ Untrusted Public Internet / Campus Network ]
                     │  (HTTPS / TLS 1.3 Strict)
                     ▼
       ┌───────────────────────────┐
       │     Reverse Proxy /       │  ◄── Boundary 1: External Edge
       │  API Gateway (Rate Limits)│
       └─────────────┬─────────────┘
                     │  (Sanitized Request Headers / Correlation ID)
                     ▼
       ┌───────────────────────────┐
       │   FastAPI Application     │  ◄── Boundary 2: Application Layer
       │ ┌───────────────────────┐ │
       │ │ Authentication / RBAC │ │
       │ └───────────┬───────────┘ │
       │             ▼             │
       │ ┌───────────────────────┐ │
       │ │   Domain Services     │ │
       │ └───────────┬───────────┘ │
       └─────────────┼─────────────┘
                     │
       ┌─────────────┴─────────────┐
       │                           │
       ▼                           ▼
┌──────────────┐            ┌──────────────┐
│ PostgreSQL 16│            │  Redis 7+    │  ◄── Boundary 3: State & Coordination
│  (Data Store)│            │  (TLS rediss)│
└──────────────┘            └──────────────┘
       ▲
       │
       ▼
┌──────────────┐            ┌──────────────┐
│ S3-Compatible│            │ Background   │  ◄── Boundary 4: Evidence Vault & Async
│ Storage Vault│            │ AI & Scanners│
└──────────────┘            └──────────────┘
```

### Trust Boundary Definitions
1. **TB-1: Client to API Gateway / Web Layer:** Untrusted public and campus networks connecting to public HTTP/HTTPS endpoints. All client input, headers, cookies, and query parameters are untrusted.
2. **TB-2: Application Core & Domain Services:** Authenticated principals operating under RBAC and departmental scoping. Cross-department traversal is forbidden.
3. **TB-3: Persistence Layer (PostgreSQL & Redis):** High-trust, encrypted at rest and in transit. Direct database access is restricted to application connection pools.
4. **TB-4: Evidence Object Storage (S3-Compatible Vault):** High-security vault storing binary payloads. Direct access by clients is prohibited; all transfers require short-lived, pre-signed URLs or streaming through authenticated gateways.
5. **TB-5: Asynchronous Worker & AI Pipeline:** Isolated processing subsystem for video segmentation, malware scanning, and notification dispatch. Zero direct internet exposure.

---

## 3. STRIDE Threat Analysis Across 10 Core Domains

### Domain 1: User Accounts and Authentication
- **Assets:** User credentials, Argon2id password hashes, JWT bearer tokens, opaque refresh tokens, session records.
- **Threat Actors:** Malicious insiders, opportunistic external attackers, automated credential stuffing bots.
- **STRIDE Analysis:**
  - **Spoofing (High):** Credential stuffing, brute-force password guessing, stolen refresh token replay.
  - **Information Disclosure (Medium):** User enumeration via response timing discrepancies or differing error messages in login/recovery workflows.
  - **Repudiation (Low):** Shared accounts or untracked authentications.
- **Controls & Mitigations:**
  - Strict Argon2id hashing with unique salts (`m=19456, t=2, p=1`).
  - IP-based rate limiting on login (5/min), password reset requests (5/min), and token refresh (20/min).
  - Refresh token rotation with immediate reuse detection and automated session revocation upon replay.
  - Authenticated `POST /api/v1/auth/change-password` endpoint requiring current password verification, enforcing password history/reuse rules, and revoking all active sessions upon change.
  - Cryptographic timing normalization during password recovery to defeat user enumeration.
- **Residual Risk:** Low. Protected by rate limiting, Argon2id, and automatic token replay revocation.

---

### Domain 2: APIs and Object/Function-Level Authorization
- **Assets:** Incident records, case dossiers, evidence attachments, user directories, analytics, audit logs.
- **Threat Actors:** Malicious campus users (students, staff, unauthorized investigators), compromised accounts.
- **STRIDE Analysis:**
  - **Elevation of Privilege (High):** BOLA/IDOR (accessing arbitrary incident or case UUIDs), BFLA (calling administrative routes with student roles).
  - **Information Disclosure (High):** Viewing sensitive case files or witness identities across departmental lines.
- **Controls & Mitigations:**
  - Explicit Deny-by-Default authorization architecture (`backend/app/core/authorization.py`).
  - Strict role-to-permission mapping with no implicit escalation.
  - Department-scoping enforcement at repository and service boundaries: principals can only access records matching their `department_id`, unless holding `SUPER_ADMIN` global authority.
  - Mandatory UUID primary keys preventing predictable sequence enumeration.
- **Residual Risk:** Low. Audited across all 13 route families with automated boundary tests.

---

### Domain 3: Tenant and Department Isolation
- **Assets:** Departmental data partitions, case files, student records, department administrator assignments.
- **Threat Actors:** Cross-department staff, rogue department administrators.
- **STRIDE Analysis:**
  - **Information Disclosure (Critical):** Department A administrator inspecting sensitive cases belonging to Department B.
  - **Tampering (High):** Cross-department assignment of investigators or reassigning incidents across department boundaries without global permission.
- **Controls & Mitigations:**
  - Pure SQL department filtering applied at database query layer.
  - Immediate revocation of user sessions (`privilege_or_department_changed`, `department_reassigned`, `investigator_department_assigned`) whenever a user's role or department assignment is modified.
  - Explicit `DEPARTMENT_MISMATCH` permission checks in `UserService`, `IncidentService`, and `CaseService`.
- **Residual Risk:** Low. Enforced at both domain service and repository layers.

---

### Domain 4: Evidence Uploads, Downloads, Storage, and Chain of Custody
- **Assets:** Video recordings, audio statements, photographic evidence, forensic chain-of-custody ledger.
- **Threat Actors:** Evidence tampering actors, unauthorized downloaders, malware distribution campaigns.
- **STRIDE Analysis:**
  - **Tampering (Critical):** Modification of stored evidence files, altering metadata, tampering with chain of custody.
  - **Information Disclosure (Critical):** Downloading confidential evidence without valid case assignment.
  - **Denial of Service (High):** Uploading excessively large files to exhaust institutional storage quotas.
- **Controls & Mitigations:**
  - Dual SHA-256 verification: digest computed at ingestion and cryptographically chained in append-only `evidence_custody_events` ledger.
  - Fail-closed malware scanning: files marked `QUARANTINED` or `INFECTED` are strictly blocked from download (`EVIDENCE_NOT_RELEASED`, HTTP 403).
  - Short-lived pre-signed download URLs with bounded 300-second TTL.
  - Strict magic byte validation (`validate_file_magic_bytes`) preventing file extension spoofing.
  - Filename sanitization (`sanitize_filename`) stripping path traversal (`../`, `..\`) and rejecting executable extensions (`.exe`, `.sh`, `.php`, etc.).
  - Storage quotas enforced per-incident (250 MB), per-user (500 MB), and per-department (5 GB).
- **Residual Risk:** Very Low. Cryptographic ledger non-repudiation and fail-closed quarantine policies.

---

### Domain 5: AI Inference Endpoints, Model Artifacts, and Asynchronous Processing
- **Assets:** Video segmentation models, inference pipelines, candidate leads, review queue.
- **Threat Actors:** Litigants seeking to challenge automated AI determinations, adversarial inputs.
- **STRIDE Analysis:**
  - **Repudiation (High):** Claiming an AI model made a binding judicial/disciplinary decision without human review.
  - **Tampering (High):** Enabling automated biometric face matching or unauthorized model updates.
- **Controls & Mitigations:**
  - Statutory Advisory: All AI outputs are labeled as non-binding candidate leads requiring independent human review.
  - Mandatory disclaimer banners embedded in all generated PDF and export reports.
  - `BIOMETRIC_MATCHING_ENABLED=False` strictly enforced in production settings gate; face matching or automated biometric identification is prohibited.
  - Isolated asynchronous processing with background job queues and resource bounds.
- **Residual Risk:** Low. Human-in-the-loop requirement is structurally enforced.

---

### Domain 6: Background Workers and Queues
- **Assets:** Task queues, scheduled jobs, worker heartbeats, report export queues.
- **Threat Actors:** Internal attackers attempting to poison task queues, resource starvation attackers.
- **STRIDE Analysis:**
  - **Denial of Service (High):** Flooding background queues with malformed jobs, starving report generation.
  - **Elevation of Privilege (Medium):** Injecting administrative commands into worker message queues.
- **Controls & Mitigations:**
  - Worker health monitoring (`worker_heartbeats`) tracking active/stale/offline status.
  - Operational alert evaluation with 15-minute deduplication cooldown preventing notification storms.
  - Structured payloads validated with Pydantic schemas prior to queue entry.
- **Residual Risk:** Low. Monitored through `/api/v1/health/system` and `/api/v1/health/workers`.

---

### Domain 7: Database Access, Migrations, Backups, and Administrative Operations
- **Assets:** PostgreSQL relational database, Alembic schema migrations, backup archives.
- **Threat Actors:** Database administrators, SQL injection attackers, infrastructure compromise.
- **STRIDE Analysis:**
  - **Information Disclosure (Critical):** SQL injection leading to total database exfiltration.
  - **Tampering (Critical):** Direct database modification bypassing audit logs.
- **Controls & Mitigations:**
  - 100% parameterized queries via SQLAlchemy 2.0 ORM; zero dynamic SQL concatenation.
  - Production settings gate rejects `sqlite` or `localhost` database targets in production.
  - Password and token redaction (`redacted_database_url`, `redacted_redis_url`) preventing leakages in logs.
  - Zero-schema-drift testing enforced in CI (`test_postgres_migrations_and_integrity.py`).
- **Residual Risk:** Low. Protected by parameterized ORM and strict connection transport rules.

---

### Domain 8: Privileged Administrators, Role Assignment, and Account Recovery
- **Assets:** Super Administrator accounts, Department Administrator roles, staff invitations.
- **Threat Actors:** Compromised administrative accounts, rogue department administrators attempting privilege escalation.
- **STRIDE Analysis:**
  - **Elevation of Privilege (Critical):** Department administrator creating a Super Admin or modifying another department's users.
  - **Spoofing (High):** Self-service password recovery account takeover.
- **Controls & Mitigations:**
  - Department Admins are strictly restricted to assigning only non-administrative roles (`DEPT_ADMIN_ASSIGNABLE_ROLES`).
  - Self-modification guards: Users cannot elevate their own role, change their own department, or reactivate disabled accounts.
  - Changing roles or department assignments immediately revokes all active sessions for the target user.
  - Password reset tokens are single-use, 256-bit entropy, 15-minute TTL, and hashed before database storage.
- **Residual Risk:** Low. Robust hierarchy and automated session invalidation.

---

### Domain 9: Secrets, Encryption Keys, Logs, and Operational Interfaces
- **Assets:** JWT signing keys (`AUTH_SECRET_KEY`), storage credentials, TLS certificates, structured log streams.
- **Threat Actors:** Log-reading unauthorized staff, network eavesdroppers, credential scrapers.
- **STRIDE Analysis:**
  - **Information Disclosure (High):** Secrets committed to Git, leaked via configuration dumps, or logged in plaintext.
  - **Tampering (Medium):** Disabling TLS verification or logging sensitive personal data.
- **Controls & Mitigations:**
  - High-entropy secret validation: Production gate rejects weak keys, known placeholders, or keys under 32 characters.
  - Secret redaction: `LOG_REDACT_SENSITIVE=True` mandatory in production; passwords and tokens masked as `***REDACTED***`.
  - Transport Layer Security: Production settings enforce `ENFORCE_SSL=True`, `STORAGE_USE_SSL=True`, `STORAGE_VERIFY_TLS=True`, and `rediss://` encrypted Redis transport.
- **Residual Risk:** Low. Enforced via automated production configuration gates.

---

### Domain 10: Notification Delivery, Reporting, and Exported Files
- **Assets:** Email delivery channel, in-app notification records, exported CSV and PDF reports.
- **Threat Actors:** Phishing actors, spreadsheet injection attackers, notification spam attackers.
- **STRIDE Analysis:**
  - **Tampering / Client Execution (High):** CSV formula injection (`=cmd|' /C ...'`) executing code on auditor machines.
  - **Information Disclosure (High):** Sending confidential incident details or OTP tokens over unencrypted email bodies.
- **Controls & Mitigations:**
  - CSV formula sanitization (`sanitize_csv_cell`): Prepends single quote `'` to any cell starting with `=`, `+`, `-`, `@`, `\t`, or `\r`.
  - Notification redaction: Tokens and passwords are never included in operational logs or notification bodies.
  - Rate limiting on notification dispatches and email queues with bounded retries.
  - Cryptographic attestation headers (`X-Content-SHA256`) on all generated export documents.
- **Residual Risk:** Low. Thoroughly sanitized before serialization.

---

## 4. High-Impact Abuse Scenarios & Mitigations

| Scenario ID | Attack Vector | Potential Impact | Implemented Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **ABUSE-01** | **Cross-Department Evidence Exfiltration:** An authenticated investigator in Dept A requests download URL for an attachment in Dept B. | Confidential evidence exposure; breach of privacy. | `_assert_incident_visible` verifies caller department matching or global privileges; rejects with HTTP 403. | `test_generate_download_url_cross_department_denied` |
| **ABUSE-02** | **Refresh Token Theft & Replay:** Attacker captures an old rotated refresh token and presents it to `/auth/refresh`. | Session hijacking, persistence after token rotation. | Token rotation hash history matches previous tokens; immediately triggers `REFRESH_TOKEN_REUSE_DETECTED` and revokes session. | `test_rotate_refresh_token_replay_revokes_session` |
| **ABUSE-03** | **Stale Claim Privilege Exploitation:** A user is transferred to another department or demoted, but uses old JWT claims. | Unauthorized access under old department or higher role scope. | User role or department modification immediately invokes `session_repo.revoke_user_sessions`, terminating active tokens. | `test_update_user_role_change_revokes_sessions`, `test_assign_department_revokes_sessions` |
| **ABUSE-04** | **Malicious Quarantined Evidence Retrieval:** Attacker or curious user attempts to download evidence flagged as infected. | Malware execution on endpoint device; evidence pollution. | Fail-closed policy in `generate_download_url`: checks `evidence_status == 'quarantined'` and `scan_status != 'clean'`, returning HTTP 403 `EVIDENCE_NOT_RELEASED`. | `test_quarantined_evidence_download_blocked_fail_closed` |
| **ABUSE-05** | **Path Traversal Evidence Ingestion:** Attacker uploads file named `../../../../etc/shadow.pdf`. | Overwriting system files or arbitrary file placement. | `sanitize_filename` strips path delimiters (`/`, `\`) and traversal tokens (`..`), producing safe basename. Server storage keys use random UUIDs. | `test_sanitize_filename_rejects_path_traversal_and_malicious_extensions` |
| **ABUSE-06** | **CSV Formula Injection in Auditing Export:** Malicious incident title entered as `=1+1` exported to CSV. | Arbitrary command execution on analyst spreadsheet software. | `sanitize_csv_cell` detects formula indicators and prefixes with single quote. | `test_csv_formula_injection_sanitization` |

---

## 5. Residual Risk Summary & Recommendations

1. **Client-Side Storage (Frontend Phase 111–120):** Tokens stored in browser memory or secure `HttpOnly` cookies must be implemented during frontend phases with strict CSRF protections.
2. **External Scanner Latency (Operational):** Production deployment should monitor ClamAV scanner daemon responsiveness to prevent queue delays during high-volume intake periods.
3. **Audit Log External Mirroring (Phase 106–110):** Security audit events should be forwarded to an immutable external syslog or WORM archive.

**Approval Status:** Passed Security Review for Batch 11 Group 01.
