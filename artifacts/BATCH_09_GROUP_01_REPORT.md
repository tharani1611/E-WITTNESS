# E-WITNESS — Batch 09 · Group 01 Implementation & Verification Report
## Phases 81–85: Investigation, Evidence Inventory and Human Review

**Date:** October 15, 2026  
**Status:** GREEN / ACCEPTED (Technical Implementation Complete; Strict Department Isolation & Human Review Invariants Enforced)  
**Scope:** Batch 09, Group 01 — Phases 81–85 only (Strictly No Frontend UI)  
**Execution Environment:** Python 3.13.1, PostgreSQL 16 (live), Redis, Alembic (Head `20261014_0012`)  

---

## 1. Executive Summary

Batch 09 Group 01 establishes the core formal Case Management and Investigation subsystem for E-WITNESS. This implementation unifies incident records, digital evidence attachments, and AI candidate segments into structured, auditable investigation cases while preserving institutional tenant/department boundaries, strict human review workflows, and immutable chain-of-custody controls.

### Core Architecture & Investigation Invariants Enforced

1. **Formal Case Lifecycle & Canonical Reference Numbers (Phase 81)**:
   - Case identifiers are uniquely generated in the collision-resistant canonical format `CASE-YYYY-XXXXXXXX` (e.g. `CASE-2026-A1B2C3D4`) using cryptographic entropy.
   - Formal case lifecycle states (`CaseStatus`): `DRAFT`, `OPEN`, `UNDER_INVESTIGATION`, `PENDING_REVIEW`, `SUSPENDED`, `RESOLVED`, `CLOSED`.
   - Authorized lifecycle state transitions are strictly validated (`VALID_CASE_TRANSITIONS`).
   - Terminal state immutability: closed cases cannot undergo arbitrary modifications (`CASE_TERMINAL_IMMUTABLE`). Transitions to terminal statuses (`RESOLVED`, `CLOSED`) require documented investigative rationale (`STATUS_REASON_REQUIRED`).
   - Incident linkage allows binding one or more incidents to a case (`primary`, `related`, `evidence_source`) with department boundary verification.

2. **Case Assignment, Audit History & Workload Capacity Limits (Phase 82)**:
   - Concurrency safety is enforced using optimistic locking via an integer `version_id`. Out-of-date update/assign payloads fail with HTTP 409 (`CONCURRENCY_CONFLICT`).
   - Append-only case assignment history (`case_assignments`) records every assignment, reassignment, assigner ID, timestamp, and formal justification.
   - Active case workload capacity limit is enforced (`INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES = 10`). Assigning an investigator who has reached maximum capacity immediately rejects with HTTP 422 (`INVESTIGATOR_CAPACITY_EXCEEDED`).
   - Capacity inspection endpoint `/api/v1/cases/investigators/{id}/workload` enables department admins and global admins to audit investigator load.

3. **Enriched Evidence Inventory & Legal Hold Protections (Phase 83)**:
   - Links evidence attachments (`case_evidence`) with investigative notes and exhibit flags (`is_exhibiting`).
   - Cryptographic integrity check: all linked evidence attachments must possess a valid 64-character hexadecimal SHA-256 digest (`EVIDENCE_INTEGRITY_COMPROMISED`).
   - Zero storage credential leakage: case evidence responses expose file metadata, SHA-256 digest, and custody verification status, but **never** internal S3/MinIO bucket names, storage keys, or presigned URLs.
   - Legal hold preservation: placing a case on legal hold (`is_legal_hold=True`) requires a documented reason (`LEGAL_HOLD_REASON_REQUIRED`). While a legal hold is active, unlinking evidence or incidents is strictly prohibited (`LEGAL_HOLD_ACTIVE`).

4. **AI Candidate Segments & Advisory Disclaimers (Phase 84)**:
   - AI candidate segments (`case_ai_segments`) link model findings into cases with investigative relevance tagging (`candidate_lead`, `corroborating`, `exculpatory`, `dismissed`).
   - Model metadata preservation: captures job ID, evidence ID, timestamps, raw/calibrated scores, model name/version, and detected label.
   - Non-negotiable advisory disclaimer: every AI segment response payload embeds the mandatory statutory advisory notice:
     > *"Candidate video segments, scores, and classifications produced by AI analysis are probabilistic and advisory only. They do not establish that an incident occurred, constitute proof of guilt, identity, or wrongdoing, or justify autonomous disciplinary actions. All consequential investigative decisions require authorized human review and corroborating evidence."*

5. **Human Review & Conflict-of-Interest Controls (Phase 85)**:
   - Review determinations (`CONFIRMED`, `ESCALATED`, `INCONCLUSIVE`, `REJECTED`) allow qualified human reviewers to correct model classifications (`corrected_label`) and document review notes.
   - Rejecting an AI candidate segment automatically updates case investigative relevance to `DISMISSED`.
   - **Conflict-of-Interest Prevention**: if the assigned reviewer was the original reporter of the linked incident, the review request fails closed with HTTP 403 (`REVIEWER_CONFLICT_OF_INTEREST`).

6. **Preservation of Batch 08 Biometric Invariants**:
   - Biometric matching remains disabled (`BIOMETRIC_MATCHING_ENABLED=False`) and NO-GO for production.
   - Missing configuration or unauthorized access fails closed across all endpoints.

---

## 2. Phase-by-Phase Verification Matrix

| Phase | Title | Status | Primary Code Artifacts | Verification Highlights |
|---|---|---|---|---|
| **Phase 81** | Case Records, Incident Linkage and Ownership | **GREEN** | `backend/app/core/case.py`<br>`backend/app/models/case.py`<br>`backend/app/repositories/case.py`<br>`backend/app/schemas/case.py`<br>`backend/app/services/case.py`<br>`backend/app/api/v1/cases.py` | `Case` and `CaseIncident` models; migration `20261014_0012`; reference number format `CASE-YYYY-XXXXXXXX`; department scoping and 404 cross-dept masking. |
| **Phase 82** | Case Assignment, History and Capacity Controls | **GREEN** | `backend/app/models/case.py`<br>`backend/app/services/case.py`<br>`backend/app/api/v1/cases.py` | Append-only `case_assignments`; optimistic concurrency via `version_id`; capacity check `< 10` active cases (`INVESTIGATOR_CAPACITY_EXCEEDED`); workload inspection API. |
| **Phase 83** | Evidence Inventory, Integrity and Legal Hold | **GREEN** | `backend/app/models/case.py`<br>`backend/app/services/case.py`<br>`backend/app/schemas/case.py` | `CaseEvidence` link; SHA-256 digest validation (64 hex); legal hold locking preventing unlinking; zero credential / storage key leakage. |
| **Phase 84** | AI Candidate Segments in Case Files | **GREEN** | `backend/app/models/case.py`<br>`backend/app/schemas/case.py`<br>`backend/app/services/case.py` | `CaseAISegment` link; relevance tagging; model provenance preserved; mandatory non-authoritative advisory disclaimer on all responses. |
| **Phase 85** | Human Review and AI-Classification Correction | **GREEN** | `backend/app/services/case.py`<br>`backend/app/api/v1/cases.py` | Case-scoped review determination (`CONFIRMED`, `ESCALATED`, `INCONCLUSIVE`, `REJECTED`); label correction; conflict-of-interest check fails closed. |

---

## 3. Test & Verification Evidence

### 3.1 Test Suite Summary
- **Total Tests Collected & Executed:** 950
- **Passed:** 950
- **Failed:** 0
- **Skipped / Environmental Skips:** 0
- **Overall Branch Coverage:** **90.20%** (exceeds `--cov-fail-under=90` threshold)
- **Execution Time:** 162.25s (~2 min 42 s)

```text
======================= 950 passed in 162.25s (0:02:42) =======================
Required test coverage of 90% reached. Total coverage: 90.20%
```

### 3.2 Batch 09 Group 01 Component Breakdown

| Module | Statements | Missing | Branches | Partial | Coverage |
|---|---|---|---|---|---|
| `backend/app/core/case.py` | 38 | 0 | 12 | 0 | **100%** |
| `backend/app/models/case.py` | 92 | 5 | 0 | 0 | **95%** |
| `backend/app/repositories/case.py` | 135 | 7 | 24 | 8 | **91%** |
| `backend/app/schemas/case.py` | 201 | 13 | 30 | 10 | **90%** |
| `backend/app/services/case.py` | 412 | 27 | 182 | 33 | **90%** |
| `backend/app/api/v1/cases.py` | 128 | 8 | 16 | 4 | **91%** |

### 3.3 PostgreSQL Live Integration & Migration Verification
- **Active Migration Head:** `20261014_0012` (`add_investigation_cases_and_linkages`)
- **Alembic Downgrade/Upgrade & Zero-Drift Tests:** 9 of 9 PASSED in `tests/integration/db/test_postgres_migrations_and_integrity.py`
  - Validates bidirectional migrations from initial revision to head `20261014_0012`.
  - Zero schema drift confirmed between SQLAlchemy declarative metadata and live PostgreSQL tables (`cases`, `case_incidents`, `case_assignments`, `case_evidence`, `case_ai_segments`).
- **Batch 09 Group 01 Live Regression Tests:** 4 of 4 PASSED in `tests/integration/api/test_batch09_group01_regressions.py` (20.11s):
  1. `test_phase81_case_creation_and_department_isolation`: Verifies case creation, reference format `CASE-YYYY-XXXXXXXX`, department isolation, and 404 masking.
  2. `test_phase82_optimistic_locking_assignment_and_capacity_limits`: Verifies optimistic locking with `version_id`, assignment history recording, and investigator capacity limit (`INVESTIGATOR_CAPACITY_EXCEEDED`).
  3. `test_phase83_evidence_inventory_integrity_and_legal_hold`: Verifies evidence inventory enrichment, zero storage credential leakage, SHA-256 integrity validation, and legal hold unlinking restrictions.
  4. `test_phase84_and_85_ai_candidate_segments_and_human_review_with_conflict_of_interest`: Verifies AI segment linking, statutory advisory disclaimer, human review determination, label correction, and conflict-of-interest check failing closed when the reviewer reported the incident.

### 3.4 Unit Test Suite
- **Cases Unit Suite:** 36 of 36 PASSED in `tests/unit/cases/test_cases_domain_and_service.py` (0.39s):
  - Domain primitives: reference number generation format, status and priority parsing, valid/invalid lifecycle status transitions.
  - Service methods: creation, permissions, optimistic locking concurrency conflicts, terminal status rationale enforcement, legal hold toggle, incident linkage, evidence linkage and integrity check, AI segment linkage and advisory disclaimers, workload capacity limits, and reviewer conflict-of-interest enforcement.
  - Repository methods: paginated listings, filter options, active case count queries, and link/unlink execution.
  - Schema validations: request payload lengths, field sanitization, and review rationale constraints.

### 3.5 Code Quality, Formatting & Static Typing
- **Ruff Linter:** `ruff check .` -> **All checks passed!**
- **Ruff Formatter:** `ruff format --check .` -> **247 files already formatted**
- **Mypy Static Typing:** `mypy backend` -> **Success: no issues found in 115 source files**

---

## 4. Security & Safety Compliance

1. **Department & Tenant Isolation**:
   - Enforced on all operations (`GET`, `POST`, `PATCH`, `DELETE`).
   - Cross-department case access attempts are masked as 404 (`ResourceNotFoundError`) to prevent information enumeration.
2. **Deny-by-Default RBAC**:
   - Unauthorized roles (e.g. `STUDENT`) are denied on all management endpoints with HTTP 403 (`PERMISSION_DENIED`).
   - Investigator role is scoped strictly to department boundaries.
3. **Audit Ledger**:
   - Every creation, status transition, assignment, evidence link/unlink, and AI segment review generates an append-only `SecurityAuditEvent` with actor ID, actor role, IP address, user agent, target type (`CASE`), and structured details.
4. **Biometric Safety Locked**:
   - Biometric matching remained disabled throughout all implementations and tests (`BIOMETRIC_MATCHING_ENABLED=False`).
   - Production biometric matching remains strictly NO-GO.

---

## 5. Summary Conclusion

Batch 09 Group 01 (Phases 81–85) meets all functional, security, legal governance, and test coverage requirements. The database migration is clean with zero schema drift against live PostgreSQL, static analysis and formatting are 100% compliant, and overall test coverage is **90.20%**. The codebase is verified and ready for the next scheduled roadmap phase.
