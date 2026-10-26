# E-WITNESS — Stakeholder Roles and Least-Privilege Permissions Matrix

**Document ID:** `EW-DOC-REQ-002`  
**Phase:** Phase 02 — Requirements and Stakeholder Analysis  
**Status:** Baseline Approved  

---

## 1. Security Principle: Default-Deny and Least Privilege

E-WITNESS enforces a strict **Default-Deny**, **Role-Based Access Control (RBAC)**, and **Attribute-Based Access Control (ABAC)** model combined with **Department/Tenant Isolation**:

1. **No Implicit Global Visibility**: No stakeholder role automatically inherits unrestricted read/write access to all records across the platform.
2. **Server-Side Enforcement**: Every authorization decision is evaluated at the backend API dependency, domain service, and database repository layers. Client-side UI visibility is strictly informational.
3. **Separation of Duties**: Administrative control (user provisioning, system configuration) is separated from investigative custody (evidence examination, case findings). Even **Super Admin** accounts cannot alter submitted evidence payloads, cryptographic digests, or append-only audit logs.

---

## 2. Stakeholder Definitions and Access Boundaries

### 2.1 Student (`ROLE_STUDENT`)
- **Primary Purpose**: Submit incident reports or witness statements, attach supporting digital evidence, and track permitted status updates on personally submitted cases.
- **Authorized Capabilities**:
  - Create and submit new incident reports and witness disclosures.
  - Upload supporting digital evidence files to their own active submission within configured size and MIME-type guardrails.
  - View their own submitted reports and explicitly shared external status updates or follow-up questions.
  - Submit supplemental clarifications or evidence when requested by an assigned Investigator.
- **Explicit Access Restrictions**:
  - Cannot view reports, cases, or evidence submitted by any other Student or Staff member.
  - Cannot view internal investigative notes, risk classifications, investigator assignments, or AI advisory outputs.
  - Cannot modify or delete previously submitted reports or evidence once sealed (amendments are recorded as append-only supplemental entries).
  - Cannot access department administration, user directories, or audit logs.

### 2.2 Staff (`ROLE_STAFF`)
- **Primary Purpose**: Record institutional incidents, submit mandated or observational reports, and view or contribute to records strictly permitted by assigned operational responsibilities.
- **Authorized Capabilities**:
  - Submit incident reports, witness statements, and supporting digital evidence.
  - View their own submitted reports and permitted status updates.
  - Access specific incident records where explicitly designated as an authorized reporting officer or departmental liaison within their assigned department.
- **Explicit Access Restrictions**:
  - Cannot browse all departmental cases or access unassigned student/staff reports.
  - Cannot conduct formal investigations, record official case findings, or alter case lifecycle states unless separately granted Investigator privileges.
  - Cannot access raw evidence files belonging to unassigned cases.
  - Cannot manage users, workflows, or system configurations.

### 2.3 Department Administrator (`ROLE_DEPT_ADMIN`)
- **Primary Purpose**: Manage department-level users, intake routing workflows, investigator assignments, and authorized departmental records within their designated department boundary.
- **Authorized Capabilities**:
  - Manage role assignments and user activation states for Staff and Investigators strictly within their assigned department(s).
  - Configure department-specific intake categories, SLA thresholds, and routing workflows.
  - Triage incoming departmental reports and assign/reassign cases to qualified Investigators within the same department.
  - View departmental case metadata, workflow status metrics, and authorized departmental records required for operational oversight.
  - View department-scoped audit summaries for compliance oversight.
- **Explicit Access Restrictions**:
  - **Strict Tenant/Department Isolation**: Cannot view or manage users, workflows, cases, or evidence belonging to other departments.
  - Cannot modify, replace, or delete submitted evidence files or chain-of-custody records.
  - Cannot author or alter formal investigative findings on behalf of an Investigator without an explicit, audited role transition.
  - Cannot modify platform-wide security configurations or provision new tenants/departments.

### 2.4 Investigator (`ROLE_INVESTIGATOR`)
- **Primary Purpose**: Review explicitly assigned cases, examine authorized digital evidence, verify cryptographic evidence integrity, request clarifications, record formal findings, and maintain a complete investigation history.
- **Authorized Capabilities**:
  - View full case details, witness statements, and metadata for cases **explicitly assigned** to them within their department scope.
  - Retrieve and examine authorized digital evidence files associated with assigned cases (every access generates an immutable audit log entry).
  - Trigger and review non-authoritative AI advisory analyses (e.g., timeline extraction, summarization, entity indexing) on assigned case records.
  - Record timestamped investigative notes, interview summaries, evidence assessments, and formal case findings.
  - Transition assigned case workflow states (e.g., `UNDER_REVIEW`, `AWAITING_INFO`, `FINDINGS_RECORDED`, `CLOSED`) according to departmental workflow rules.
- **Explicit Access Restrictions**:
  - Cannot access cases or evidence within their department (or any other department) to which they are not explicitly assigned or granted co-investigator access.
  - Cannot overwrite, mutate, or delete original evidence files or alter initial cryptographic hashes (`SHA-256`).
  - Cannot delete historical investigative notes or audit trail entries (all corrections must be append-only addenda).
  - Cannot manage user accounts, department settings, or platform configurations.

### 2.5 Super Admin (`ROLE_SUPER_ADMIN`)
- **Primary Purpose**: Manage platform-wide operational configuration, provision tenants and departments, administer Department Administrators, monitor platform health, and oversee security and audit compliance.
- **Authorized Capabilities**:
  - Provision, configure, and deactivate institutional tenants and departments.
  - Provision and manage `ROLE_DEPT_ADMIN` accounts and platform-wide security policies.
  - Manage system-level operational controls, retention schedules, storage quotas, and integration configurations.
  - Inspect platform-wide security logs, system health telemetry, and tamper-evident audit logs.
- **Explicit Access Restrictions (Separation of Duties)**:
  - **No Unaudited Investigative Snooping**: Super Admins do not have routine read access to unredacted student/staff evidence payloads or confidential investigative notes; any emergency administrative access requires an explicit, justification-logged break-glass workflow that triggers high-priority audit alerts.
  - **Immutable Custody Boundary**: Cannot modify, forge, or delete submitted evidence binaries, SHA-256 hashes, chain-of-custody logs, or audit records.

---

## 3. Granular Resource Permissions Matrix

Legend:
- **C**: Create / Submit (Append-Only where applicable)
- **R (Own)**: Read only records created by the authenticated principal
- **R (Assigned)**: Read only records explicitly assigned to the principal within their department
- **R (Dept)**: Read metadata/records scoped strictly to the principal's authorized department
- **R (All-Meta)**: Read platform-level metadata / operational telemetry (excludes raw confidential evidence payloads by default)
- **U (Scoped)**: Update permitted workflow state or metadata within scope
- **D**: Delete (Note: Authoritative evidence, chain-of-custody, and audit logs disallow hard deletion except via automated, policy-governed legal retention purge jobs)
- **—**: Explicitly Denied

| Domain Resource / Action | Student | Staff | Dept Admin | Investigator | Super Admin | Enforcement Layer & Conditions |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Incident Report Submission** | C, R (Own) | C, R (Own) | R (Dept) | R (Assigned) | — | Scoped by `submitter_id` or `department_id` + case assignment |
| **Supplemental Statement / Clarification** | C (Own Case) | C (Own/Auth) | R (Dept) | C, R (Assigned) | — | Append-only; requires open/active case state |
| **Public/Submitter Case Status Updates** | R (Own) | R (Own/Auth) | R (Dept) | C, R (Assigned) | — | Filtered view; strips internal investigator metadata |
| **Case Assignment & Triage Routing** | — | — | C, R, U (Dept) | R (Assigned) | — | Enforced by `department_id` boundary |
| **Internal Investigation Notes & Timeline** | — | — | — | C, R (Assigned) | — | Append-only; strictly restricted to assigned Investigators |
| **Formal Case Findings & Disposition** | — | — | R (Dept) | C, R (Assigned) | — | Digitally signed/attributed to Investigator; immutable once finalized |
| **Evidence File Upload** | C (Own) | C (Own/Auth) | — | C (Assigned) | — | Validated MIME/magic bytes, size limits, immediate SHA-256 digest |
| **Evidence Metadata & Hash Verification** | R (Own) | R (Own/Auth) | R (Dept) | R (Assigned) | R (All-Meta) | Displays SHA-256 hash, timestamp, custody status |
| **Evidence Binary Retrieval / Download** | R (Own) | R (Own) | — | R (Assigned) | — | Generates mandatory `EVIDENCE_ACCESSED` audit event; short-lived stream |
| **Evidence Modification / Overwrite** | — | — | — | — | — | **Strictly Prohibited for ALL roles** (Immutability invariant) |
| **AI Advisory Analysis (Trigger / View)** | — | — | — | C, R (Assigned) | — | Runs in isolated worker; labeled non-authoritative advisory output |
| **Department Workflows & Categories** | — | — | C, R, U (Dept) | R (Dept) | R (All-Meta) | Scoped to `department_id` |
| **Department User & Role Management** | — | — | C, R, U (Dept) | — | C, R, U (All) | Dept Admin restricted to Staff/Investigator within own department |
| **Tenant / Department Provisioning** | — | — | — | — | C, R, U | Super Admin only; audited |
| **System & Security Configuration** | — | — | — | — | R, U | Runtime secrets redacted; critical config via deployment environment |
| **Tamper-Evident Audit Logs** | — | — | R (Dept) | R (Assigned Case) | R (All) | Append-only; **No role has Update or Delete permissions** |
