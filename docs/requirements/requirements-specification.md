# E-WITNESS — Software Requirements Specification (SRS)

**Document ID:** `EW-DOC-REQ-001`  
**Phase:** Phase 02 — Requirements and Stakeholder Analysis  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## 1. Product Vision and Scope

### 1.1 Product Vision
**E-WITNESS** is a high-assurance, multi-department institutional incident reporting, digital evidence management, and case investigation platform. It enables students and staff to securely report incidents and submit digital evidence while equipping department administrators and investigators with structured workflows, verifiable cryptographic evidence integrity, strict tenant/department isolation, tamper-evident audit trails, and isolated AI-assisted analytical tools.

### 1.2 Scope
The platform encompasses:
1. **Secure Incident & Witness Intake**: Structured reporting workflows for authenticated Students and Staff, with support for confidential disclosures and controlled follow-up communication.
2. **Digital Evidence Custody & Integrity**: Controlled upload, MIME/magic-byte verification, cryptographic hashing (`SHA-256`), isolated object storage, immutable metadata recording, and audited retrieval.
3. **Departmental Triage & Case Management**: Multi-department tenant isolation, configurable intake categories, investigator assignment, and lifecycle state management.
4. **Investigative Workspace**: Restricted case review, append-only investigation notes, evidence examination, and formal disposition recording.
5. **Isolated AI Advisory Services**: Asynchronous, non-authoritative AI assistance (e.g., summarization, entity/timeline extraction) operating in an isolated worker boundary that never mutates authoritative evidence or makes automated disciplinary decisions.
6. **Compliance & Auditability**: Append-only, tamper-evident audit logging across all authentication, authorization, administrative, case, and evidence access events.

---

## 2. Stakeholders and Access Boundaries

E-WITNESS defines five core stakeholder roles governed by strict least-privilege access controls. Refer to [stakeholder-permissions-matrix.md](file:///c:/Users/lenovo/Desktop/E-WITNESS/docs/requirements/stakeholder-permissions-matrix.md) for the granular CRUD and ABAC enforcement matrix:

| Role Identifier | Stakeholder Name | Core Responsibility Summary | Access Boundary Summary |
| :--- | :--- | :--- | :--- |
| `ROLE_STUDENT` | **Student** | Submits incident reports or witness disclosures, uploads supporting evidence, and views permitted case status updates. | Strictly restricted to their own personal records and explicitly shared external updates. |
| `ROLE_STAFF` | **Staff** | Records institutional incidents, submits reports/evidence, and accesses records required by assigned responsibilities. | Restricted to personal submissions and specific records explicitly authorized within their department. |
| `ROLE_DEPT_ADMIN` | **Department Administrator** | Manages department-level users, intake workflows, case triage, investigator assignments, and departmental oversight records. | Strictly isolated to their assigned `department_id`; cannot access other departments or modify raw evidence. |
| `ROLE_INVESTIGATOR` | **Investigator** | Reviews assigned cases, verifies and examines authorized evidence, triggers AI advisory jobs, and records findings/history. | Strictly restricted to cases explicitly assigned to them within their department; append-only notes/findings. |
| `ROLE_SUPER_ADMIN` | **Super Admin** | Manages platform-wide configuration, tenant/department provisioning, operational controls, and audit log oversight. | Platform-wide operational scope, but bound by separation-of-duties: cannot mutate evidence/audit logs or silently snoop on raw evidence without break-glass auditing. |

---

## 3. Functional Requirements (`FR`)

| ID | Requirement Title | Specification | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `FR-001` | **Role-Scoped User Authentication** | The system shall authenticate users across all five stakeholder roles (`Student`, `Staff`, `Department Administrator`, `Investigator`, `Super Admin`) and issue cryptographically signed, short-lived access tokens and refresh tokens bound to role and department claims. | Valid credentials return signed tokens with accurate claims; expired, malformed, or tampered tokens are rejected with HTTP 401. |
| `FR-002` | **Tenant and Department Provisioning** | The system shall allow a `Super Admin` to create, configure, and deactivate institutional departments/tenants and assign initial `Department Administrator` accounts. | Only `Super Admin` can create/modify departments; non-Super Admin requests are rejected with HTTP 403 and logged. |
| `FR-003` | **Departmental User Management** | The system shall allow a `Department Administrator` to provision, activate, deactivate, and manage role assignments (`Staff`, `Investigator`) strictly for users within their assigned department. | `Dept Admin` can manage users in their own department; attempts to manage users in another department or escalate to `Super Admin` fail with HTTP 403. |
| `FR-004` | **Student Incident & Witness Reporting** | The system shall enable a `Student` to create and submit structured incident reports including incident category, timestamp, location, narrative statement, and witness declarations. | Submitted report is persisted with unique tracking ID, immutable submission timestamp, and bound to the submitting Student's identity and target department. |
| `FR-005` | **Staff Incident Recording & Reporting** | The system shall enable a `Staff` member to record institutional incidents and submit mandated or observational reports routed to the appropriate department. | Staff report is persisted with reporter identity, departmental routing metadata, and initial workflow status `SUBMITTED`. |
| `FR-006` | **Permitted Case Status Tracking** | The system shall allow `Student` and `Staff` submitters to view permitted external status updates and respond to clarification requests on their own reports without exposing internal investigator notes. | Submitter queries return only their own reports and external-facing status milestones; internal fields (`investigator_notes`, `internal_risk_score`) are absent from response schemas. |
| `FR-007` | **Supplemental Information Submission** | The system shall allow `Student` and `Staff` submitters to append supplemental statements or additional evidence to an existing report without overwriting the original submission. | Supplemental submissions create new timestamped child records linked to the parent case; original report text remains unaltered. |
| `FR-008` | **Department Workflow Configuration** | The system shall allow a `Department Administrator` to configure department-specific incident categories, priority levels, and intake routing rules. | Configured rules apply exclusively to the administrator's department and validate incoming departmental reports. |
| `FR-009` | **Case Triage and Investigator Assignment** | The system shall allow a `Department Administrator` to triage incoming departmental reports, convert or link them to formal investigation cases, and assign or reassign one or more `Investigator` users within the same department. | Case assignment succeeds only when both case and Investigator belong to the administrator's department; assignment triggers an audit entry. |
| `FR-010` | **Assigned Case Workspace for Investigators** | The system shall provide an `Investigator` with a workspace displaying only cases explicitly assigned to them, including full submission details, linked evidence metadata, and timeline history. | Investigator queries return only assigned cases; requests for unassigned cases (even within the same department) return HTTP 403/404. |
| `FR-011` | **Append-Only Investigation History & Notes** | The system shall allow an assigned `Investigator` to record timestamped investigation notes, interview records, and procedural actions as append-only entries. | Notes are persisted with author ID and UTC timestamp; update/delete attempts on existing notes are rejected. |
| `FR-012` | **Formal Case Findings and Disposition** | The system shall allow an assigned `Investigator` to record formal findings, evidentiary conclusions, and final case disposition states. | Finalized findings require mandatory rationale fields, transition case state according to workflow rules, and lock findings against silent modification. |
| `FR-013` | **Controlled Digital Evidence Upload** | The system shall allow authorized users (`Student` on own report, `Staff` on authorized report, `Investigator` on assigned case) to upload digital evidence files subject to MIME-type, magic-byte, and file-size validation. | Valid files within size/MIME limits are accepted, hashed, and stored; disallowed file types or oversized payloads are rejected with HTTP 415/413. |
| `FR-014` | **Authorized Evidence Retrieval** | The system shall allow authorized principals (specifically assigned `Investigator` or original uploader where policy permits) to retrieve evidence files through a controlled, authenticated mechanism. | Unauthorized retrieval attempts fail with HTTP 403; authorized retrievals verify integrity and emit a mandatory audit record before streaming/issuing short-lived access. |
| `FR-015` | **Asynchronous AI Analysis Trigger** | The system shall allow an assigned `Investigator` to request asynchronous AI analysis (e.g., narrative summarization, entity extraction, chronology construction) on an assigned case. | Request queues an isolated background job without blocking the HTTP thread; returns job status handle. |
| `FR-016` | **Non-Authoritative AI Advisory Presentation** | The system shall store and display AI-generated outputs in a dedicated advisory structure clearly separated from authoritative evidence and official investigator findings. | AI results include model/version provenance, confidence/advisory disclaimers, and require explicit Investigator review; AI never alters case status or evidence records. |
| `FR-017` | **Departmental Oversight Reporting** | The system shall allow a `Department Administrator` to view aggregated departmental case metrics, SLA compliance statuses, and workload distribution within their department. | Metrics accurately reflect only the administrator's department records without leaking cross-department counts. |
| `FR-018` | **Platform Operational Administration** | The system shall allow a `Super Admin` to manage platform-level settings, inspect system health checks, and view platform-wide audit logs. | Health and operational endpoints validate `Super Admin` privileges and redact all secret values in responses. |
| `FR-019` | **Centralized Validated Configuration** | The system shall load and validate all runtime configuration settings at startup across `development`, `testing`, and `production` environments, failing fast on invalid or insecure settings. | Application startup succeeds with valid configuration and terminates immediately with descriptive, secret-redacted validation errors when required settings are missing or unsafe. |
| `FR-020` | **Search and Filtering Within Authorized Scope** | The system shall allow users to search and filter cases and reports strictly within their authorized visibility boundary (`Own`, `Assigned`, or `Department`). | Search queries automatically inject mandatory tenant/department/ownership predicates at the repository layer. |

---

## 4. Nonfunctional Requirements (`NFR`)

| ID | Category | Specification | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `NFR-001` | **Availability & Reliability** | The backend API shall be designed for stateless horizontal scaling and graceful startup/shutdown lifecycle management, without mandatory external AI network calls during startup. | Application starts cleanly even when external AI providers are unreachable; readiness/liveness probes accurately report dependency state. |
| `NFR-002` | **Fault Isolation** | Failures or timeouts in asynchronous background jobs or external AI providers shall not degrade core synchronous incident reporting, evidence upload, or case retrieval APIs. | Simulated AI service failure or timeout leaves core API endpoints operational with HTTP 2xx responses. |
| `NFR-003` | **API Response Performance** | Standard synchronous metadata read/write API endpoints (excluding large binary file transfers) shall target a 95th percentile (`p95`) latency of $\le 300\text{ ms}$ under normal institutional load. | Automated benchmark/integration tests verify non-binary API endpoint execution within target latency bounds. |
| `NFR-004` | **Streaming Upload Efficiency** | Evidence file uploads and downloads shall process payloads in bounded memory chunks (`UPLOAD_CHUNK_SIZE_BYTES`) rather than buffering entire multi-megabyte files simultaneously in application RAM. | Uploading a maximum-sized file (e.g., 50 MB) processes via chunked streaming without unbounded memory spikes. |
| `NFR-005` | **Database Concurrency & Pooling** | All relational database operations shall use SQLAlchemy 2.x asynchronous sessions (`asyncpg` in production) with bounded connection pooling and command timeouts. | No synchronous blocking DB calls occur inside async routes; pool size and command timeouts are enforced via configuration. |
| `NFR-006` | **Scalability & Multi-Tenancy** | The data model and repository architecture shall support multiple concurrent institutional departments without schema duplication per department. | All multi-tenant tables include indexed `department_id` foreign keys and composite query indexes. |
| `NFR-007` | **Usability & Error Clarity** | All API error responses shall return a consistent, structured JSON envelope containing an error code, human-readable message, and request correlation ID, without exposing internal stack traces or secrets. | Client receives structured error JSON on 4xx/5xx responses; raw Python tracebacks and sensitive config values never appear in HTTP responses. |
| `NFR-008` | **Accessibility Readiness** | All user-facing workflows, status labels, and future frontend components shall conform to WCAG 2.1 Level AA semantic structure, keyboard navigability, and screen-reader compatibility. | API schemas provide descriptive human-readable status/error metadata; future UI components pass automated accessibility checks. |
| `NFR-009` | **Maintainability & Layered Architecture** | The codebase shall enforce strict separation between API routes (`api`), schemas (`schemas`), business logic (`services`), data access (`repositories`), ORM models (`models`), and external adapters (`infrastructure`). | Static analysis and architectural tests confirm route handlers do not execute raw SQL and models are not exposed directly without schemas. |
| `NFR-010` | **Static Type Safety & Code Quality** | All Python modules shall pass strict static type checking (`mypy --strict`) and automated linting/formatting checks (`ruff`). | `mypy` and `ruff check` / `ruff format --check` exit with code `0` across `backend/`, `ai_services/`, and `tests/`. |
| `NFR-011` | **Test Reproducibility** | Automated unit and integration test suites shall run deterministically in local and CI environments without requiring live production credentials or external cloud services. | Running `pytest` in a clean checkout with test settings passes 100% of tests offline. |
| `NFR-012` | **Observability & Correlation** | Every incoming request and background task shall be assigned a unique correlation/request ID propagated across structured logs and audit events. | Log records emitted during request handling include `request_id` and environment metadata in structured format. |

---

## 5. Security and Privacy Requirements (`SEC`)

| ID | Requirement Title | Specification | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `SEC-001` | **Default-Deny Authorization** | Every API endpoint (except explicit public health/auth-login endpoints) shall require an authenticated principal and explicit permission evaluation before executing business logic. | Unauthenticated requests receive HTTP 401; authenticated requests lacking explicit role/attribute permission receive HTTP 403. |
| `SEC-002` | **Mandatory Department/Tenant Isolation** | Every query and mutation on departmental resources (`Reports`, `Cases`, `Evidence`, `Workflows`, `Department Users`) shall enforce `department_id` scoping at both the service and repository layers, backed by database-level safeguards. | Cross-department access tests verify that a user in Department A cannot read, update, or enumerate any resource in Department B. |
| `SEC-003` | **Assigned-Case Isolation for Investigators** | An `Investigator` shall only be permitted to access cases and evidence where an active case-assignment record binds their `user_id` to the target `case_id`. | Investigator A attempting to access Investigator B's case within the same department receives HTTP 403/404 and triggers a security audit warning. |
| `SEC-004` | **Submitter Privacy & Record Isolation** | A `Student` or `Staff` member shall never be able to enumerate, view, or infer the existence of reports or evidence submitted by other users. | Resource IDs use non-sequential UUIDv4/UUIDv7 identifiers; unauthorized ID probing returns consistent access denial without leaking record metadata. |
| `SEC-005` | **Production Secret Validation & Entropy** | Production configuration (`ENVIRONMENT=production`) shall reject missing secrets, known placeholder strings, signing keys shorter than 32 characters, or low-entropy keys at startup. | Unit tests verify `Settings` raises `ValidationError` when initialized in `production` with weak, short, or placeholder secrets. |
| `SEC-006` | **Strong Token Signing & Algorithm Pinning** | Token signing and verification shall explicitly enforce an approved cryptographic algorithm allowlist (`HS256`, `HS384`, `HS512`, `RS256`, `ES256`) and strictly reject the `"none"` algorithm or unsigned tokens. | Configuring `AUTH_ALGORITHM="none"` or an unrecognized algorithm fails startup validation immediately. |
| `SEC-007` | **Mandatory TLS Verification** | All external storage, database, cache, and AI service connections in production shall require encrypted transport (`SSL`/`TLS`), and TLS certificate verification (`STORAGE_VERIFY_TLS`) shall never be disabled in any environment. | Setting `STORAGE_VERIFY_TLS=False` fails configuration validation in all environments; setting `STORAGE_USE_SSL=False` or insecure `redis://` / `http://` CORS origins fails in `production`. |
| `SEC-008` | **Comprehensive Secret Redaction** | Passwords, secret keys, API tokens, authorization headers, and database/Redis connection credentials shall be automatically redacted (`***REDACTED***`) in string representations, configuration dumps, logs, and exception messages. | Inspecting `repr(settings)`, `str(settings)`, `settings.to_safe_dict()`, or running `redact_text()` / `redact_url()` confirms zero plaintext secret exposure. |
| `SEC-009` | **Strict CORS Policy Enforcement** | Cross-Origin Resource Sharing (`CORS_ALLOWED_ORIGINS`) shall require explicit origin URLs and shall reject wildcard (`"*"`) or unencrypted `http://` origins in `production`. | Production configuration with `CORS_ALLOWED_ORIGINS=["*"]` or `["http://example.com"]` raises `ValidationError`. |
| `SEC-010` | **Safe File Upload Validation** | File uploads shall enforce strict byte-size limits, an explicit MIME-type allowlist, magic-byte file signature verification, and filename sanitization to prevent path traversal and malicious executable uploads. | Uploading disguised executables, path-traversal filenames (`../../etc/passwd`), or oversized payloads is rejected before storage persistence. |
| `SEC-011` | **Isolated Object Storage Access** | Evidence buckets in S3-compatible storage shall never be publicly readable. Clients shall never receive long-lived raw storage credentials. | Evidence retrieval requires backend authorization and streams data or issues tightly scoped, short-lived access bound to the authorized request. |
| `SEC-012` | **AI Data Boundary & Prompt Safety** | External or local AI services shall only receive explicitly scoped, task-necessary text/data dispatched by an authorized job, with Untrusted User Input clearly delimited from system instructions to mitigate prompt injection. | AI worker adapters enforce structured system/user message separation, token limits, and output schema validation. |
| `SEC-013` | **Password Hashing & Credential Storage** | User passwords (when local authentication is used) shall be hashed using a memory-hard adaptive algorithm (`Argon2id` or `bcrypt` with strong work factor) and never stored or logged in plaintext. | Password storage verification confirms salted `Argon2id`/`bcrypt` hashes and zero plaintext persistence. |
| `SEC-014` | **Rate Limiting & Abuse Protection** | Authentication endpoints, report submission endpoints, and evidence upload/download routes shall enforce request rate limiting and payload size ceilings (`MAX_REQUEST_BODY_BYTES`). | Requests exceeding rate thresholds or `MAX_REQUEST_BODY_BYTES` are rejected with HTTP 429 or HTTP 413. |
| `SEC-015` | **Production Debug Prohibition** | The application shall forbid `DEBUG=True` and verbose SQL query echoing (`DB_ECHO=True`) when running in `ENVIRONMENT=production`. | Initializing `Settings` with `ENVIRONMENT="production"` and `DEBUG=True` (or `DB_ECHO=True`) raises `ValidationError`. |

---

## 6. Evidence Integrity and Traceability Requirements (`EVI`)

*Note: Full chain-of-custody persistence and storage workflows are implemented across designated evidence roadmap phases. Phase 02–03 establishes the mandatory specification and architectural controls.*

| ID | Requirement Title | Specification | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `EVI-001` | **Immediate Cryptographic Hashing** | Upon evidence ingestion, the system shall compute a cryptographic `SHA-256` digest over the exact raw byte stream before or during storage persistence. | Every stored evidence metadata record contains a validated 64-character lowercase hexadecimal `SHA-256` digest and exact byte length. |
| `EVI-002` | **Authoritative Evidence Immutability** | Once an evidence file is sealed and persisted, neither its binary object in storage nor its original `SHA-256` digest and ingestion metadata may be overwritten, modified, or truncated by any user role. | Storage adapter forbids overwrite keys; repository layer omits update/delete methods on authoritative evidence binary records. |
| `EVI-003` | **Integrity Verification on Retrieval** | Whenever an evidence file is retrieved for investigative review or export, the system shall support verifying the stored `SHA-256` digest against the retrieved object and flag any integrity mismatch immediately. | Any hash discrepancy raises a critical `EVIDENCE_INTEGRITY_VIOLATION` alert, blocks silent consumption, and logs an immutable security event. |
| `EVI-004` | **Chain-of-Custody Event Ledger** | Every lifecycle action on an evidence item (`INGESTED`, `HASH_VERIFIED`, `QUARANTINED`, `SEALED`, `ACCESSED`, `DOWNLOADED`, `AI_ANALYZED`, `EXPORTED`, `RETENTION_ARCHIVED`) shall be recorded in an append-only chain-of-custody ledger. | Ledger entries record actor ID, role, department ID, timestamp, source IP/request ID, action type, and evidence SHA-256 digest. |
| `EVI-005` | **Evidence Ownership & Case Binding** | Every evidence item shall be immutably linked to its originating report/case, department boundary, and uploading principal at creation time. | Orphaned or unbound evidence uploads are impossible; database foreign-key and check constraints enforce parent binding. |
| `EVI-006` | **Derivative & AI Artifact Separation** | Any derivative artifact (e.g., extracted text, OCR output, redacted copy, or AI summary) shall be stored as a distinct, clearly labeled secondary artifact that references—but never replaces—the original authoritative evidence item. | Authoritative evidence queries return only original sealed evidence unless derivative/advisory artifacts are explicitly requested. |
| `EVI-007` | **Safe Quarantine & Malware Inspection Hook** | Uploaded files shall pass through an ingestion validation pipeline (size, MIME, magic-byte header verification, and pluggable malware/content scanner hook) before being marked `SEALED` and available for investigator download. | Files failing magic-byte/MIME consistency or scanner checks are rejected or isolated in `QUARANTINED` status and cannot be downloaded as normal evidence. |
| `EVI-008` | **Controlled Retention and Legal Hold** | The system architecture shall support department/institutional retention schedules and a `legal_hold` flag on cases and evidence that blocks automated retention purging while active. | Any evidence or case marked `legal_hold=True` is strictly excluded from retention expiration or archival purge routines. |
| `EVI-009` | **Deterministic Evidence Export Manifest** | When an authorized `Investigator` exports a case package, the system shall generate a verifiable manifest listing all included evidence files, their `SHA-256` hashes, ingestion timestamps, and custody history. | Export manifest JSON/PDF matches stored SHA-256 digests and custody ledger entries byte-for-byte. |
| `EVI-010` | **Storage Key Randomization** | Object storage keys shall use opaque, non-guessable paths (e.g., `<tenant_or_dept_uuid>/<case_uuid>/<evidence_uuid>.bin`) rather than user-supplied filenames. | Original user filenames are sanitized and stored only as database metadata; S3 object keys never contain user-supplied strings. |

---

## 7. Auditability and Accountability Requirements (`AUD`)

| ID | Requirement Title | Specification | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `AUD-001` | **Append-Only Audit Trail** | The system shall maintain an append-only audit log table where application service accounts and user roles have `INSERT` and scoped `SELECT` privileges, with zero `UPDATE` or `DELETE` pathways. | Repository and database designs prohibit update or deletion of audit log rows. |
| `AUD-002` | **Comprehensive Security Event Coverage** | Audit logs shall record all authentication attempts (success/failure), role/permission changes, cross-tenant/unauthorized access denials, case assignments, workflow transitions, evidence uploads/retrievals, and break-glass actions. | Every security-sensitive operation emits a structured audit event verified by integration tests. |
| `AUD-003` | **Cryptographic Hash Chaining for Tamper Evidence** | Audit log entries shall be designed to support cryptographic hash chaining (`previous_entry_hash` + current entry payload $\rightarrow$ `entry_hash`) so any out-of-band database row tampering or deletion is mathematically detectable. | Audit verification utility detects any modified or deleted historical audit row in the chain. |
| `AUD-004` | **Non-Repudiation Context Capture** | Every audit record shall capture: `event_id`, `timestamp_utc`, `actor_user_id`, `actor_role`, `department_id`, `action_type`, `target_resource_type`, `target_resource_id`, `request_id`, `client_ip`, and `outcome` (`SUCCESS`/`DENIED`/`ERROR`). | Schema validation enforces required attribution fields on all persisted audit records. |
| `AUD-005` | **Zero Secret Leakage in Audit Logs** | Audit log payloads and metadata diffs shall pass through the centralized secret redaction filter before persistence so credentials, tokens, or raw sensitive payloads are never written to audit storage. | Automated redaction tests verify that sensitive fields passed to audit loggers are masked with `***REDACTED***`. |
| `AUD-006` | **Break-Glass Emergency Access Auditing** | Any exceptional administrative action by a `Super Admin` requiring elevated metadata inspection shall require a mandatory written justification code and emit a high-severity `BREAK_GLASS_ACCESS` audit event. | Break-glass requests without a valid justification reason are rejected; valid requests log immutable high-priority events. |
| `AUD-007` | **AI Invocation Auditing** | Every AI advisory request shall be audited with the requesting `Investigator` ID, `case_id`, AI provider/model identifier, prompt template version, and execution outcome. | AI job execution records corresponding `AI_ANALYSIS_REQUESTED` and `AI_ANALYSIS_COMPLETED` audit trail entries. |
| `AUD-008` | **Scoped Audit Inspection** | `Department Administrators` may inspect audit events strictly scoped to their department; `Investigators` may inspect custody/audit history for their assigned cases; `Super Admins` may inspect platform-wide audit trails. | Queries against audit endpoints enforce role and `department_id`/`case_id` filters identically to domain endpoints. |

---

## 8. Regulatory and Institutional Policy Considerations

> [!IMPORTANT]
> **No Invented Certifications**: E-WITNESS does **not** claim pre-existing legal compliance certifications (such as SOC 2 Type II, ISO 27001 certification, or FedRAMP authorization). Instead, the architecture implements technical controls designed to support institutional compliance workflows. Deployment owners and legal counsel must validate jurisdiction-specific obligations prior to production rollout.

### 8.1 Jurisdiction-Specific Obligations Requiring Institutional Validation
1. **Educational Privacy Regulations (e.g., US FERPA / State Student Privacy Laws)**:
   - Incident reports and disciplinary investigation records involving students frequently constitute protected education records.
   - *Technical Support*: Strict RBAC/ABAC (`SEC-001`–`SEC-004`), department isolation, and audit logs of every record access (`AUD-002`).
   - *Institutional Validation Required*: Determining permissible disclosure exceptions (e.g., health/safety emergencies, judicial subpoenas) and institutional directory integration rules.
2. **Data Protection & Privacy Laws (e.g., EU/UK GDPR, India DPDP Act 2023, CCPA/CPRA)**:
   - Processing personal data of reporters, witnesses, and subjects requires lawful basis definition, data minimization, purpose limitation, and retention governance.
   - *Technical Support*: Encryption in transit (`SEC-007`), configurable retention/legal hold (`EVI-008`), and strict boundary controls on external AI providers (`SEC-012`).
   - *Institutional Validation Required*: Data Processing Agreements (DPAs) with cloud/AI providers, cross-border data transfer impact assessments, and handling Data Subject Access/Erasure Requests when balanced against evidentiary legal holds.
3. **Title IX / Institutional Harassment & Misconduct Procedures (Jurisdiction-Dependent)**:
   - Many educational institutions operate under strict procedural fairness, notice, and evidence-preservation mandates.
   - *Technical Support*: Append-only investigation history (`FR-011`), immutable original evidence (`EVI-002`), and verifiable export manifests (`EVI-009`).
   - *Institutional Validation Required*: Aligning configurable departmental workflow states (`FR-008`) with specific institutional hearing and appeal timelines.
4. **Digital Evidence Admissibility & Handling Guidelines (e.g., ISO/IEC 27037, NIST SP 800-86 Principles)**:
   - If institutional cases escalate to civil litigation or law enforcement referral, evidentiary integrity and chain of custody are scrutinized.
   - *Technical Support*: Immediate `SHA-256` hashing (`EVI-001`), WORM/immutability guarantees (`EVI-002`), and hash-chained custody ledgers (`EVI-004`, `AUD-003`).
   - *Institutional Validation Required*: Formal standard operating procedures (SOPs) for physical-to-digital evidence intake and law enforcement handoff protocols.

---

## 9. Assumptions, Constraints, Dependencies, and Out-of-Scope Features

### 9.1 Assumptions
- Institutional deployments will run behind TLS-terminating reverse proxies or load balancers in production.
- Users will authenticate via institutional credentials or platform-managed accounts provisioned according to role rules.
- External infrastructure services (PostgreSQL 15+, Redis 7+, S3-compatible object storage) will be provisioned in networked environments accessible to the backend in later infrastructure phases.

### 9.2 Constraints
- **Phase Discipline**: Implementation follows a strict 120-phase roadmap. Phases 01–05 establish repository structure, requirements, architecture, development tooling, and validated configuration/secrets management only.
- **Zero Production Secret Commits**: No credentials, private keys, or live `.env` files may ever enter Git history.
- **Non-Authoritative AI**: AI components must never make autonomous disciplinary determinations or mutate primary evidence.

### 9.3 Dependencies
- **Runtime Baseline**: Python 3.12+ (verified compatible with Python 3.13), FastAPI, Pydantic v2, Pydantic Settings v2, SQLAlchemy 2.x (async), Alembic, Uvicorn.
- **Storage Baseline**: PostgreSQL (primary relational store), Redis (cache & coordination), S3-compatible object storage (evidence binaries).

### 9.4 Explicitly Out of Scope
- Autonomous AI decision-making, automated guilt/credibility scoring, or biometric/facial recognition surveillance.
- Public anonymous unauthenticated file hosting or unrestricted public case browsing.
- Modifying or deleting sealed digital evidence or historical audit logs.
- Native mobile applications (iOS/Android) during the initial 120-phase web/backend roadmap.

---

## 10. Risks and Mitigation Strategies

| Risk ID | Risk Description | Likelihood | Impact | Mitigation Strategy |
| :--- | :--- | :---: | :---: | :--- |
| `RSK-001` | **Cross-Department Data Leakage**: A bug in an API endpoint omits the department filter, exposing another department's sensitive cases. | Medium | Critical | Enforce mandatory `department_id` scoping in base repository methods and design PostgreSQL Row-Level Security (RLS) policies as defense-in-depth (`SEC-002`). |
| `RSK-002` | **Insecure Production Deployment**: Operator deploys to production using default `.env.example` secrets or `DEBUG=True`. | Medium | Critical | Enforce strict startup validation in `Settings` that detects placeholder strings, weak keys, `DEBUG=True`, and non-TLS settings in `production`, aborting startup (`SEC-005`, `SEC-015`). |
| `RSK-003` | **Evidence Tampering or Repudiation**: An insider or attacker modifies an uploaded evidence file in storage or disputes when it was submitted. | Low | Critical | Compute `SHA-256` upon ingestion (`EVI-001`), store objects under randomized immutable keys (`EVI-002`, `EVI-010`), verify hashes on read (`EVI-003`), and maintain hash-chained audit logs (`AUD-003`). |
| `RSK-004` | **Secret Exposure in Logs or Tracebacks**: Database passwords, JWT signing keys, or API tokens leak into application logs or error responses. | Medium | High | Wrap secrets in `SecretStr`, implement centralized redaction utilities (`backend/app/core/secrets.py`), and sanitize configuration representations (`SEC-008`). |
| `RSK-005` | **Malicious File Upload / Memory Exhaustion**: Attacker uploads a polyglot executable or multi-gigabyte stream to crash the server or compromise an investigator's workstation. | Medium | High | Enforce chunked streaming size limits (`NFR-004`), strict MIME + magic-byte validation (`SEC-010`), randomized storage keys (`EVI-010`), and `Content-Disposition: attachment` with `X-Content-Type-Options: nosniff`. |
| `RSK-006` | **Uncontrolled AI Data Exposure or Hallucination**: Sensitive case records are sent to an unconfigured external LLM, or an investigator treats an AI hallucination as factual evidence. | Medium | High | Disable AI by default (`AI_ENABLED=False`), execute AI jobs in an isolated worker boundary (`ai_services/`), label all outputs as non-authoritative advisory artifacts (`FR-016`), and audit every invocation (`AUD-007`). |
