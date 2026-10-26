# E-WITNESS — Requirements Traceability Matrix (RTM)

**Document ID:** `EW-DOC-REQ-003`  
**Phase:** Phase 02 — Requirements and Stakeholder Analysis  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## 1. Overview and 120-Phase Roadmap Alignment

This traceability matrix links every uniquely identified E-WITNESS requirement (`FR`, `NFR`, `SEC`, `EVI`, `AUD`) to:
1. **Stakeholder(s)**: Primary and secondary roles impacted.
2. **Security & Privacy Implications**: Core risk or security control addressed.
3. **Verification Method & Acceptance Criteria Summary**: How the requirement is tested and proven.
4. **Target Roadmap Phase(s)**: Where the requirement is designed, implemented, and verified across the 120-phase master roadmap:
   - **Phases 01–10 (Batch 01)**: Foundation, Requirements, Architecture, Environment, Config/Secrets, FastAPI Bootstrap, Layered Standards, Logging/Tracing, Testing Foundation, Foundation Audit.
   - **Phases 11–25**: Database Connectivity, Alembic Migrations, Tenant/Department Core Models, User & Role Models, Authentication, Token Lifecycle, RBAC/ABAC Enforcement.
   - **Phases 26–45**: Incident Intake, Witness Reporting, Department Workflows, Case Triage, Investigator Assignment, Submitter Status Updates.
   - **Phases 46–65**: Digital Evidence Ingestion, Streaming Validation, SHA-256 Integrity, S3 Object Storage Adapters, Quarantine Pipeline, Chain-of-Custody Ledger, Controlled Evidence Retrieval.
   - **Phases 66–80**: Investigation Workspace, Append-Only Notes, Formal Findings, Case Dispositions, Export Manifests, Retention & Legal Hold.
   - **Phases 81–95**: Isolated Background Workers, AI Service Boundary, Advisory Summarization/Timeline Extraction, Prompt Guardrails, AI Auditability.
   - **Phases 96–110**: Tamper-Evident Audit Chaining, Break-Glass Controls, Departmental Analytics, Frontend Integration, Accessibility & Usability Hardening.
   - **Phases 111–120**: Performance/Load Testing, Penetration & Security Verification, Deployment Hardening, Production Readiness & Final Certification Audit.

---

## 2. Functional Requirements Traceability (`FR-001` – `FR-020`)

| Req ID | Title | Stakeholder(s) | Security Implications | Verification & Acceptance Criteria | Roadmap Phase(s) | Current Status (Phases 01–05) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `FR-001` | Role-Scoped User Authentication | All 5 Roles | Prevents spoofing; binds identity, role, and department claims to signed tokens (`SEC-001`, `SEC-006`). | Auth unit/integration tests; token claim & expiration validation; HTTP 401 on invalid token. | Spec: Ph 02–03; Config: Ph 05; Impl: Ph 16–20 | Specified & Config Ready |
| `FR-002` | Tenant & Department Provisioning | Super Admin, Dept Admin | Establishes hard multi-tenant isolation boundaries (`SEC-002`). | Integration tests verifying only `Super Admin` can create/modify departments (HTTP 403 otherwise). | Spec: Ph 02–03; Impl: Ph 13–15, 22 | Specified |
| `FR-003` | Departmental User Management | Dept Admin, Staff, Investigator | Prevents cross-department privilege escalation; restricts Dept Admin to own `department_id`. | RBAC/ABAC tests confirming cross-department user administration fails with HTTP 403. | Spec: Ph 02–03; Impl: Ph 21–25 | Specified |
| `FR-004` | Student Incident & Witness Reporting | Student | Protects reporter identity and binds submission to student & target department (`SEC-004`). | API integration test submitting report as Student; verifies immutable timestamp and ownership. | Spec: Ph 02–03; Impl: Ph 26–30 | Specified |
| `FR-005` | Staff Incident Recording & Reporting | Staff, Dept Admin | Ensures accurate attribution and departmental routing of staff-reported incidents. | API integration test submitting report as Staff; verifies department routing and initial status. | Spec: Ph 02–03; Impl: Ph 26–30 | Specified |
| `FR-006` | Permitted Case Status Tracking | Student, Staff | Prevents disclosure of internal investigative notes or risk scores to submitters (`SEC-004`). | Schema serialization and integration tests verifying internal fields are stripped from submitter responses. | Spec: Ph 02–03; Impl: Ph 31–35 | Specified |
| `FR-007` | Supplemental Information Submission | Student, Staff, Investigator | Preserves original statement integrity by enforcing append-only supplemental entries. | Database and API tests confirming original report record is never overwritten on addendum submission. | Spec: Ph 02–03; Impl: Ph 31–35 | Specified |
| `FR-008` | Department Workflow Configuration | Dept Admin | Isolates workflow rules and categories per department. | Tests verifying Department A workflow rules cannot be mutated by Department B admin. | Spec: Ph 02–03; Impl: Ph 36–40 | Specified |
| `FR-009` | Case Triage & Investigator Assignment | Dept Admin, Investigator | Establishes explicit `case_id` $\leftrightarrow$ `investigator_id` authorization link (`SEC-003`). | Tests confirming assignment requires matching department and emits audit event (`AUD-002`). | Spec: Ph 02–03; Impl: Ph 41–45 | Specified |
| `FR-010` | Assigned Case Workspace | Investigator | Prevents horizontal snooping by investigators on unassigned departmental cases (`SEC-003`). | Authorization tests confirming Investigator receives HTTP 403/404 on unassigned cases. | Spec: Ph 02–03; Impl: Ph 41–45, 66–70 | Specified |
| `FR-011` | Append-Only Investigation Notes | Investigator | Prevents repudiation or retrospective alteration of investigative history (`AUD-001`). | Repository and API tests verifying notes allow `INSERT`/`SELECT` only; `UPDATE`/`DELETE` rejected. | Spec: Ph 02–03; Impl: Ph 66–70 | Specified |
| `FR-012` | Formal Case Findings & Disposition | Investigator, Dept Admin | Ensures accountable, immutable disposition recording attributed to assigned Investigator. | Workflow state transition tests and immutability checks on finalized findings. | Spec: Ph 02–03; Impl: Ph 71–75 | Specified |
| `FR-013` | Controlled Digital Evidence Upload | Student, Staff, Investigator | Mitigates malicious file upload, DoS, and unverified evidence intake (`SEC-010`, `EVI-001`). | Upload validation tests for size limits, MIME allowlist, magic bytes, and SHA-256 hashing. | Spec: Ph 02–03; Limits Config: Ph 05; Impl: Ph 46–55 | Specified & Limits Configured |
| `FR-014` | Authorized Evidence Retrieval | Investigator, Student, Staff | Prevents unauthorized evidence exfiltration and enforces mandatory access auditing (`SEC-011`, `EVI-004`). | Retrieval authorization tests, hash verification checks, and audit emission tests. | Spec: Ph 02–03; Impl: Ph 56–65 | Specified |
| `FR-015` | Asynchronous AI Analysis Trigger | Investigator | Isolates slow/external AI processing from core request threads (`NFR-002`, `SEC-012`). | Worker dispatch tests confirming non-blocking job creation by assigned Investigator only. | Spec: Ph 02–03; Config: Ph 05; Impl: Ph 81–90 | Specified & Config Ready |
| `FR-016` | Non-Authoritative AI Presentation | Investigator | Prevents AI hallucinations from corrupting authoritative evidence or case findings (`EVI-006`). | Schema and storage separation tests confirming AI outputs are stored as advisory records only. | Spec: Ph 02–03; Impl: Ph 85–95 | Specified |
| `FR-017` | Departmental Oversight Reporting | Dept Admin | Prevents cross-tenant metric leakage in aggregations (`SEC-002`). | Aggregation query tests verifying strict `department_id` scoping. | Spec: Ph 02–03; Impl: Ph 96–100 | Specified |
| `FR-018` | Platform Operational Administration | Super Admin | Enforces separation of duties and secret redaction in operational views (`SEC-008`, `AUD-006`). | Admin endpoint tests verifying secret redaction and Super Admin role check. | Spec: Ph 02–03; Redaction: Ph 05; Impl: Ph 96–100 | Specified & Redaction Implemented |
| `FR-019` | Centralized Validated Configuration | Super Admin (DevOps) | Prevents misconfiguration, missing secrets, and insecure production defaults (`SEC-005`–`SEC-009`). | Unit tests in `tests/unit/config/test_settings.py` verifying startup validation across environments. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `FR-020` | Scoped Search and Filtering | All 5 Roles | Prevents search-based data enumeration across unauthorized records (`SEC-002`–`SEC-004`). | Repository search tests verifying mandatory injection of tenant/role predicates. | Spec: Ph 02–03; Impl: Ph 66–75 | Specified |

---

## 3. Nonfunctional Requirements Traceability (`NFR-001` – `NFR-012`)

| Req ID | Category | Stakeholder(s) | Security / Operational Implication | Verification & Acceptance Criteria | Roadmap Phase(s) | Current Status (Phases 01–05) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `NFR-001` | Availability & No Startup AI Calls | All Roles | Prevents external AI outages from blocking core platform availability. | Startup config forces `AI_CONNECT_ON_STARTUP=False`; verified by unit tests in Ph 05 & bootstrap tests in Ph 06. | Arch: Ph 03; Config: Ph 05; Bootstrap: Ph 06 | **Config Enforced (🟢 GREEN)** |
| `NFR-002` | Worker & AI Fault Isolation | All Roles | Isolates external integration failures from core intake/custody workflows. | Circuit-breaker and worker isolation tests under simulated provider failure. | Arch: Ph 03; Impl: Ph 81–90 | Architected |
| `NFR-003` | API Response Performance (`p95 <= 300ms`) | All Roles | Mitigates slow-loris / resource exhaustion and ensures responsive UX. | Automated latency assertions in integration and load test suites. | Arch: Ph 03; Impl: Ph 111–115 | Architected |
| `NFR-004` | Streaming Upload Efficiency | Student, Staff, Investigator | Prevents RAM exhaustion (OOM DoS) during concurrent evidence uploads. | Chunked streaming configuration (`UPLOAD_CHUNK_SIZE_BYTES`) in Ph 05; streaming adapter tests in Ph 46–50. | Arch: Ph 03; Config: Ph 05; Impl: Ph 46–50 | **Config Enforced (🟢 GREEN)** |
| `NFR-005` | Async Database Pooling & Timeouts | All Roles | Prevents connection pool starvation and hung database queries. | Pool size, overflow, and command timeout validated in Ph 05; SQLAlchemy async engine in Ph 11. | Arch: Ph 03; Config: Ph 05; Impl: Ph 11–12 | **Config Enforced (🟢 GREEN)** |
| `NFR-006` | Multi-Department Scalability | Dept Admin, Super Admin | Supports institutional growth without per-department database silos. | Composite index and multi-tenant query plan verification. | Arch: Ph 03; Impl: Ph 13–15 | Architected |
| `NFR-007` | Structured Error Envelope & Safety | All Roles | Prevents information disclosure via raw stack traces or internal exception dumps. | Error handler tests verifying structured JSON and secret redaction. | Arch: Ph 03; Redaction: Ph 05; Impl: Ph 06–08 | Redaction Implemented |
| `NFR-008` | Accessibility Readiness (WCAG 2.1 AA) | All Roles | Ensures equitable access for students and staff with disabilities. | Semantic schema validation and frontend accessibility audits. | Spec: Ph 02; Impl: Ph 101–108 | Specified |
| `NFR-009` | Layered Architecture Separation | Engineering / Audit | Prevents authorization bypasses caused by tangled route-to-DB code. | Directory structure established in Ph 01; architectural boundary checks in Ph 07 & Ph 10. | **Repo Layout: Ph 01; Arch: Ph 03**; Impl: Ph 07 | **Structure Established (🟢 GREEN)** |
| `NFR-010` | Static Type Safety & Linting | Engineering / Audit | Catches type bugs, security anti-patterns (`ruff` S rules), and formatting drift early. | `ruff check`, `ruff format --check`, and `mypy` executed and passing in Ph 04–05. | **Ph 04–05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `NFR-011` | Offline Test Reproducibility | Engineering / Audit | Enables deterministic CI/local verification without live cloud secrets. | `pytest` runs with isolated test settings in `tests/conftest.py` and passes 100%. | **Ph 04–05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `NFR-012` | Request Correlation & Observability | Super Admin, Audit | Enables end-to-end forensic reconstruction across logs and audit trails. | Request correlation middleware and structured logger tests. | Arch: Ph 03; Impl: Ph 08 | Architected |

---

## 4. Security and Privacy Requirements Traceability (`SEC-001` – `SEC-015`)

| Req ID | Title | Stakeholder(s) | Security Implications | Verification & Acceptance Criteria | Roadmap Phase(s) | Current Status (Phases 01–05) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-001` | Default-Deny Authorization | All Roles | Eliminates unauthenticated or implicitly permitted endpoints. | Route security matrix tests verifying HTTP 401/403 on all protected routes. | Spec: Ph 02–03; Impl: Ph 21–25 | Specified & Architected |
| `SEC-002` | Mandatory Department Isolation | Dept Admin, Investigator, Staff | Prevents cross-tenant data leakage (`RSK-001`). | Repository & RLS isolation tests across multiple departments. | Spec: Ph 02–03; Impl: Ph 13–15, 21–25 | Specified & Architected |
| `SEC-003` | Assigned-Case Isolation | Investigator | Enforces need-to-know access among investigators within the same department. | ABAC case-assignment verification tests. | Spec: Ph 02–03; Impl: Ph 23–25, 41–45 | Specified & Architected |
| `SEC-004` | Submitter Privacy & UUIDs | Student, Staff | Prevents ID enumeration (IDOR) and unauthorized peer snooping. | UUID identifier checks and IDOR negative test suite. | Spec: Ph 02–03; Impl: Ph 13–15, 26–35 | Specified & Architected |
| `SEC-005` | Production Secret Entropy & Validation | Super Admin (DevOps) | Prevents deployment with default/placeholder or weak signing keys (`RSK-002`). | Unit tests in `tests/unit/config/test_settings.py` verifying rejection of weak/placeholder secrets in `production`. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `SEC-006` | Token Signing Algorithm Pinning | All Roles | Prevents JWT `"none"` algorithm and weak algorithm downgrade attacks. | Unit tests in `tests/unit/config/test_settings.py` verifying algorithm allowlist enforcement. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `SEC-007` | Mandatory TLS Verification | Super Admin (DevOps) | Prevents MITM interception of evidence objects, DB queries, and cache traffic. | Unit tests verifying `STORAGE_VERIFY_TLS=False` is rejected in all environments and non-SSL/non-TLS URLs fail in `production`. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `SEC-008` | Comprehensive Secret Redaction | All Roles / Audit | Prevents credential, token, and DSN leakage in logs, reprs, and config dumps (`RSK-004`). | Unit tests in `tests/unit/config/test_redaction.py` and `test_settings.py`. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `SEC-009` | Strict CORS Policy Enforcement | All Roles | Prevents unauthorized cross-origin credentialed requests in production. | Unit tests verifying rejection of `"*"` and `http://` CORS origins in `production`. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |
| `SEC-010` | Safe File Upload Validation | Student, Staff, Investigator | Blocks malicious executables, polyglots, and path traversal (`RSK-005`). | Config limits verified in Ph 05; magic-byte and filename sanitization tests in Ph 46–50. | Spec: Ph 02–03; Config: Ph 05; Impl: Ph 46–50 | **Limits Configured (🟢 GREEN)** |
| `SEC-011` | Isolated Object Storage Access | Investigator, Student, Staff | Prevents direct public bucket enumeration or credential exposure. | Storage adapter and controlled retrieval tests. | Spec: Ph 02–03; Config: Ph 05; Impl: Ph 51–60 | Specified & Architected |
| `SEC-012` | AI Data Boundary & Prompt Safety | Investigator | Prevents uncontrolled AI access to database and mitigates prompt injection (`RSK-006`). | AI configuration guardrails in Ph 05; isolated worker & prompt delimiter tests in Ph 81–90. | Spec: Ph 02–03; Config: Ph 05; Impl: Ph 81–90 | **Config Enforced (🟢 GREEN)** |
| `SEC-013` | Adaptive Password Hashing | All Roles | Protects stored credentials against offline cracking if DB is compromised. | Password hashing unit tests (`Argon2id`/`bcrypt`). | Spec: Ph 02–03; Impl: Ph 16–18 | Specified |
| `SEC-014` | Rate Limiting & Payload Ceilings | All Roles | Mitigates brute-force login attacks and payload-based DoS. | Request body ceiling configured in Ph 05 (`MAX_REQUEST_BODY_BYTES`); middleware tests in Ph 06/20. | Spec: Ph 02–03; Config: Ph 05; Impl: Ph 06, 20 | **Limits Configured (🟢 GREEN)** |
| `SEC-015` | Production Debug Prohibition | Super Admin (DevOps) | Prevents debug endpoints, verbose tracebacks, and SQL query dumps in production. | Unit tests verifying `DEBUG=True` and `DB_ECHO=True` fail validation when `ENVIRONMENT=production`. | **Ph 05 (Implemented & Verified)** | **Complete (🟢 GREEN)** |

---

## 5. Evidence Integrity and Traceability (`EVI-001` – `EVI-010`)

| Req ID | Title | Stakeholder(s) | Security / Evidentiary Implication | Verification & Acceptance Criteria | Roadmap Phase(s) | Current Status (Phases 01–05) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `EVI-001` | Immediate Cryptographic Hashing (`SHA-256`) | Student, Staff, Investigator | Establishes mathematical proof of exact evidence content at ingestion (`RSK-003`). | Hashing stream unit and integration tests verifying 64-char hex `SHA-256`. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 46–50 | Specified & Architected |
| `EVI-002` | Authoritative Evidence Immutability | All Roles | Guarantees zero alteration or deletion of sealed primary evidence. | Storage key write-once checks and repository immutability tests. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 51–55 | Specified & Architected |
| `EVI-003` | Integrity Verification on Retrieval | Investigator, Audit | Detects any storage-level corruption or tampering before investigative reliance. | Retrieval test simulating corrupted object bytes verifying `EVIDENCE_INTEGRITY_VIOLATION` alert. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 56–60 | Specified & Architected |
| `EVI-004` | Chain-of-Custody Event Ledger | Investigator, Dept Admin, Audit | Provides complete chronological custody history for evidentiary admissibility. | Custody ledger integration tests verifying append-only events on every lifecycle action. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 61–65 | Specified & Architected |
| `EVI-005` | Evidence Ownership & Case Binding | Student, Staff, Investigator | Prevents orphaned or unattributed evidence objects. | DB constraint and service tests enforcing mandatory case/report and uploader binding. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 46–50 | Specified & Architected |
| `EVI-006` | Derivative & AI Artifact Separation | Investigator | Ensures OCR, redactions, and AI summaries never masquerade as primary evidence. | Schema and storage partition tests distinguishing primary vs. derivative artifacts. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 85–95 | Specified & Architected |
| `EVI-007` | Safe Quarantine & Malware Hook | All Roles | Prevents distribution of malicious payloads to investigator workstations. | Ingestion state-machine tests (`QUARANTINED` $\rightarrow$ `SEALED` or `REJECTED`). | Spec: Ph 02; Arch: Ph 03; Impl: Ph 46–55 | Specified & Architected |
| `EVI-008` | Controlled Retention & Legal Hold | Super Admin, Dept Admin | Prevents premature destruction of evidence under active investigation or litigation. | Retention job tests confirming `legal_hold=True` blocks archival/deletion. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 76–80 | Specified & Architected |
| `EVI-009` | Deterministic Evidence Export Manifest | Investigator, Dept Admin | Enables third-party/legal verification of exported case packages. | Manifest generation and cryptographic verification tests. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 76–80 | Specified & Architected |
| `EVI-010` | Storage Key Randomization | All Roles | Eliminates path traversal and filename-based object collisions in S3 storage. | Storage key generator tests confirming UUID-based object paths. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 51–55 | Specified & Architected |

---

## 6. Auditability and Accountability Traceability (`AUD-001` – `AUD-008`)

| Req ID | Title | Stakeholder(s) | Security / Compliance Implication | Verification & Acceptance Criteria | Roadmap Phase(s) | Current Status (Phases 01–05) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `AUD-001` | Append-Only Audit Trail | Super Admin, Dept Admin, Audit | Prevents attackers or rogue insiders from erasing tracks. | Repository and database permission tests confirming no `UPDATE`/`DELETE` on audit table. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 61–65, 96 | Specified & Architected |
| `AUD-002` | Comprehensive Security Event Coverage | All Roles / Audit | Ensures forensic visibility across auth, RBAC denials, cases, and evidence. | Integration assertions checking audit emission across all domain workflows. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 20–96 | Specified & Architected |
| `AUD-003` | Cryptographic Hash Chaining | Super Admin / External Auditor | Makes out-of-band DB row tampering mathematically detectable. | Hash-chain verifier unit and integration tests detecting simulated row mutation. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 61–65, 96 | Specified & Architected |
| `AUD-004` | Non-Repudiation Context Capture | All Roles / Audit | Binds every action to actor ID, role, department, timestamp, IP, and `request_id`. | Audit schema validation tests. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 08, 61–65 | Specified & Architected |
| `AUD-005` | Zero Secret Leakage in Audit Logs | All Roles / Audit | Prevents audit logs from becoming a secondary credential leak vector. | Redaction utility tests (`tests/unit/config/test_redaction.py`) verified in Ph 05. | **Ph 05 (Redaction Core Implemented)**; Audit Hook: Ph 08 | **Core Utility Ready (🟢 GREEN)** |
| `AUD-006` | Break-Glass Emergency Access Auditing | Super Admin, Audit | Enforces accountability on rare administrative escalation events. | Break-glass workflow tests requiring justification and emitting high-severity alerts. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 96–100 | Specified & Architected |
| `AUD-007` | AI Invocation Auditing | Investigator, Audit | Tracks every AI model invocation, prompt version, and case scope. | AI worker audit emission tests. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 85–95 | Specified & Architected |
| `AUD-008` | Scoped Audit Inspection | Super Admin, Dept Admin, Investigator | Prevents unauthorized cross-department disclosure via audit log queries. | RBAC/ABAC tests on audit query endpoints. | Spec: Ph 02; Arch: Ph 03; Impl: Ph 96–100 | Specified & Architected |
