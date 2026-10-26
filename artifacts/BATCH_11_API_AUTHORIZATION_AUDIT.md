# E-WITNESS — BATCH 11, PHASE 103 API AUTHORIZATION AUDIT MATRIX
## Comprehensive Object-Level and Function-Level Access Control Audit

**Document Version:** 1.0.0  
**Date:** 2026-10-22  
**Scope:** All 13 Backend API Route Families (Phases 01–105)  
**Security Standard:** OWASP API Security Top 10 (API1:2023 BOLA, API2:2023 Broken Authentication, API5:2023 BFLA) & Zero-Trust Deny-by-Default

---

## 1. Executive Summary

This audit verifies object-level and function-level access control across all 13 API route families in E-WITNESS. Every endpoint is audited against:
1. **Authentication Requirement:** Whether anonymous access is permitted or authenticated principal is required (`CurrentUserDep`).
2. **Function-Level Authorization (BFLA):** RBAC permission check enforcing caller role eligibility.
3. **Object-Level Authorization (BOLA/IDOR):** Scoping mechanisms ensuring caller ownership or departmental boundary compliance.
4. **Deny-by-Default Posture:** Fallback behavior for unrecognized roles, missing permissions, or inactive principals.

---

## 2. API Authorization Matrix by Route Family

### Route Family 1: Authentication & Identity (`/api/v1/auth`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Public (Anonymous) | None (Returns JWT + Opaque Refresh) | Rate limit (5/min) |
| `POST` | `/api/v1/auth/refresh` | Public / Bearer Refresh | Session ID binding from hash | Rate limit (20/min), Replay revocation |
| `POST` | `/api/v1/auth/logout` | Authenticated Caller | Caller active session ID | 401 if unauthenticated |
| `GET` | `/api/v1/auth/me` | Authenticated Caller | Introspects caller principal only | 401 if unauthenticated |
| `POST` | `/api/v1/auth/sessions/revoke`| Authenticated Caller | Caller sessions only (unless super admin) | 403 on other users' sessions |
| `POST` | `/api/v1/auth/forgot-password`| Public (Anonymous) | Privacy-preserving generic response | Rate limit (5/min), Timing padding |
| `POST` | `/api/v1/auth/reset-password` | Public (Opaque Token) | Token hash matching database | Atomic token consumption |
| `POST` | `/api/v1/auth/change-password`| Authenticated Caller | Caller user ID only | Current password verification, Session revocation |
| `POST` | `/api/v1/auth/register` | Public (Student) | Requires active department ID | 404/400 on inactive department |
| `POST` | `/api/v1/auth/invitations/accept` | Public (Opaque Token) | Validates single-use invitation token | 401 on expired/consumed token |

---

### Route Family 2: Users & Profiles (`/api/v1/users`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/users/me` | Authenticated Caller | Caller profile only | 401 if unauthenticated |
| `PATCH`| `/api/v1/users/me` | Authenticated Caller | Updates caller full_name only | Cannot alter role/dept/status |
| `GET` | `/api/v1/users/{id}` | `USER_READ_DEPT` / `GLOBAL`| Own profile, Dept Admin (same dept), Super Admin (all) | 403 on cross-dept access |
| `GET` | `/api/v1/users` | `USER_LIST_DEPT` / `GLOBAL`| Filtered to caller department (Dept Admin) or global | 403 for unauthorized roles |
| `POST` | `/api/v1/users` | `USER_CREATE_DEPT` / `GLOBAL`| Dept Admin can create in own dept; Super Admin in any | 403 on privilege escalation |
| `PATCH`| `/api/v1/users/{id}` | `USER_UPDATE_DEPT` / `GLOBAL`| Same dept only (Dept Admin); Session revoked on role/dept change | 403 on self-role/dept change |
| `POST` | `/api/v1/users/invitations`| `USER_CREATE_DEPT` / `GLOBAL`| Target department scoped to caller (Dept Admin) | 403 on cross-dept invite |
| `POST` | `/api/v1/users/{id}/deactivate`| `USER_UPDATE_DEPT` / `GLOBAL`| Same dept only; Immediate session revocation | 403 on self-deactivation |
| `POST` | `/api/v1/users/{id}/activate`| `USER_UPDATE_DEPT` / `GLOBAL`| Same dept only; Cannot activate disabled accounts | 403 on self-activation |
| `POST` | `/api/v1/users/{id}/department`| `USER_DEPT_REASSIGN_GLOBAL`| Super Admin global reassignment; Revokes sessions | 403 for non-Super Admin |

---

### Route Family 3: Departments (`/api/v1/departments`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/departments` | Authenticated Caller | Public institutional directory of active depts | Inactive hidden unless admin |
| `GET` | `/api/v1/departments/{id}` | Authenticated Caller | Department details | 404 if non-existent |
| `POST` | `/api/v1/departments` | `DEPT_CREATE_GLOBAL` | Super Admin only | 403 for all other roles |
| `PATCH`| `/api/v1/departments/{id}` | `DEPT_UPDATE_GLOBAL` | Super Admin only | 403 for all other roles |

---

### Route Family 4: Roles & Permissions (`/api/v1/roles`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/roles` | Authenticated Caller | List of system roles | Read-only introspection |
| `GET` | `/api/v1/roles/{id}` | Authenticated Caller | Role details and codes | 404 if non-existent |

---

### Route Family 5: Incidents & Routing (`/api/v1/incidents`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/incidents` | `INCIDENT_CREATE` | Submitter bound to caller user_id | 400 on inactive dept |
| `GET` | `/api/v1/incidents/{id}` | `INCIDENT_READ_OWN` / `DEPT` / `GLOBAL` | Submitter (own), Dept Admin/Reviewer (same dept), Super Admin | 403 cross-dept access denied |
| `GET` | `/api/v1/incidents` | `INCIDENT_LIST_OWN` / `DEPT` / `GLOBAL` | Scoped to submitter (students) or department | 403 for unmapped roles |
| `PATCH`| `/api/v1/incidents/{id}` | `INCIDENT_UPDATE_OWN` | Editable only by submitter while in DRAFT status | 403 once submitted |
| `POST` | `/api/v1/incidents/{id}/transition` | `INCIDENT_STATUS_TRANSITION` | Reviewer/Dept Admin in incident department | 403 if status transition invalid |
| `POST` | `/api/v1/incidents/{id}/route` | `INCIDENT_ROUTE_OVERRIDE` | Dept Admin in target/source department | 403 cross-dept override |

---

### Route Family 6: Evidence Custody & Storage (`/api/v1/evidence` & `/api/v1/incidents/{id}/evidence`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/incidents/{id}/evidence/sessions` | `EVIDENCE_ATTACH` | Submitter on open incident or assigned investigator | 403 on closed incident |
| `POST` | `/api/v1/incidents/{id}/evidence/multipart/init` | `EVIDENCE_ATTACH` | Validates file size, quota, authorized MIME extensions | 413 / 415 on invalid metadata |
| `POST` | `/api/v1/incidents/{id}/evidence/multipart/complete` | `EVIDENCE_ATTACH` | Assembles chunks, runs magic bytes check & virus scan | 403 fail-closed quarantine |
| `GET` | `/api/v1/incidents/{id}/evidence` | `EVIDENCE_READ` | Incident department matching or global authority | 403 cross-dept access |
| `GET` | `/api/v1/incidents/{id}/evidence/{att_id}/download` | `EVIDENCE_READ` | Clean scan status mandatory; Generates 300s presigned URL | 403 if quarantined/infected |
| `GET` | `/api/v1/evidence/{att_id}/custody` | `EVIDENCE_CUSTODY_READ` | Cryptographic ledger event list; Dept scoped | 403 cross-dept access |
| `POST` | `/api/v1/evidence/{att_id}/rescan` | `EVIDENCE_SCAN_RETRY` | Administrative or investigative roles in department | 400 if already clean |

---

### Route Family 7: Case Management (`/api/v1/cases`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/cases` | `CASE_CREATE` | Department Admin or Lead in case department | 403 cross-dept creation |
| `GET` | `/api/v1/cases/{id}` | `CASE_READ_DEPT` / `GLOBAL` | Assigned investigator, Dept Admin (same dept), Super Admin | 403 cross-dept access |
| `GET` | `/api/v1/cases` | `CASE_LIST_DEPT` / `GLOBAL` | Scoped to caller department | 403 unassigned roles |
| `PATCH`| `/api/v1/cases/{id}` | `CASE_UPDATE_DEPT` | Dept Admin / Assigned lead in department | 403 cross-dept update |
| `POST` | `/api/v1/cases/{id}/assign` | `CASE_ASSIGN_DEPT` | Assignee must be active investigator in department | 400 on cross-dept assignee |
| `POST` | `/api/v1/cases/{id}/incidents` | `CASE_LINK_INCIDENT` | Both case and incident must belong to department | 403 on cross-dept link |
| `POST` | `/api/v1/cases/{id}/evidence` | `CASE_LINK_EVIDENCE` | Evidence must belong to linked incident | 403 unassociated evidence |

---

### Route Family 8: AI Processing & Candidate Reviews (`/api/v1/ai`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/ai/jobs` | `AI_JOB_SUBMIT` | Evidence attachment must belong to caller department | 403 cross-dept evidence |
| `GET` | `/api/v1/ai/jobs/{id}` | `AI_JOB_READ` | Department of underlying evidence | 403 cross-dept access |
| `GET` | `/api/v1/ai/segments` | `AI_SEGMENT_LIST` | Scoped to caller department review queue | 403 unassigned roles |
| `POST` | `/api/v1/ai/segments/{id}/review` | `AI_SEGMENT_REVIEW` | Reviewer in department; Records mandatory human determination | 403 cross-dept review |
| `POST` | `/api/v1/ai/datasets` | `AI_DATASET_MANAGE` | Super Admin or authorized data steward | 403 for standard roles |

---

### Route Family 9: Biometric Governance & Face Detection (`/api/v1/biometrics`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/biometrics/detect` | `BIOMETRIC_DETECT` | Detection bounding boxes only; Matching strictly disabled | 400 if BIOMETRIC_MATCHING=True |
| `POST` | `/api/v1/biometrics/governance`| `BIOMETRIC_GOVERNANCE_MANAGE`| Policy records scoped to department | 403 cross-dept access |
| `POST` | `/api/v1/biometrics/consent/withdraw` | `BIOMETRIC_CONSENT_WITHDRAW` | Principal can withdraw own consent; Dept Admin for dept | Immediate reference deactivation |

---

### Route Family 10: Notifications & Templates (`/api/v1/notifications`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/notifications/inbox` | Authenticated Caller | Caller user_id recipient inbox only | Cannot view other users' inboxes |
| `POST` | `/api/v1/notifications/{id}/read`| Authenticated Caller | Must be recipient of notification | 404 / 403 on other users' records |
| `POST` | `/api/v1/notifications/{id}/dismiss`| Authenticated Caller | Must be recipient of notification | 404 / 403 on other users' records |
| `GET` | `/api/v1/notifications/templates`| `NOTIFICATION_TEMPLATE_MANAGE`| Administrative roles only | 403 for students/investigators |

---

### Route Family 11: Operational Dashboards (`/api/v1/dashboards`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/dashboards/incidents` | `DASHBOARD_VIEW_DEPT` / `GLOBAL`| Scoped to caller department | 403 cross-dept access |
| `GET` | `/api/v1/dashboards/cases` | `DASHBOARD_VIEW_DEPT` / `GLOBAL`| Scoped to caller department | 403 cross-dept access |
| `GET` | `/api/v1/dashboards/operations`| `DASHBOARD_VIEW_GLOBAL` | Super Admin global visibility | 403 for department roles |

---

### Route Family 12: Analytics & Workload Metrics (`/api/v1/analytics`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/analytics/overview` | `ANALYTICS_VIEW_DEPT` / `GLOBAL`| Scoped to caller department | 403 on cross-dept filter |
| `GET` | `/api/v1/analytics/incidents`| `ANALYTICS_VIEW_DEPT` / `GLOBAL`| Department aggregation only | 403 on unauthorized dept |
| `GET` | `/api/v1/analytics/cases` | `ANALYTICS_VIEW_DEPT` / `GLOBAL`| Department aggregation only | 403 on unauthorized dept |
| `GET` | `/api/v1/analytics/reviews` | `ANALYTICS_VIEW_DEPT` / `GLOBAL`| Department review performance | 403 on unauthorized dept |
| `GET` | `/api/v1/analytics/workload`| `ANALYTICS_VIEW_DEPT` / `GLOBAL`| Reviewers and investigators in department | 403 unassigned roles |
| `GET` | `/api/v1/analytics/processing-metrics`| `ANALYTICS_VIEW_GLOBAL`| Super Admin system telemetry | 403 for dept roles |

---

### Route Family 13: Report Exports & Health Monitoring (`/api/v1/reports` & `/api/v1/health`)
| HTTP Method | Route Endpoint | Required Role / Perm | Object-Level Scope / Tenancy | Deny-by-Default |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/reports/export` | `REPORT_EXPORT_DEPT` / `GLOBAL` | Scoped to caller department; Sanitized CSV/PDF | 403 cross-dept export |
| `GET` | `/api/v1/reports/{id}/download`| `REPORT_EXPORT_DEPT` / `GLOBAL` | Creator or Dept Admin in department; Verified TTL | 403 on expired or cross-dept |
| `GET` | `/api/v1/health/live` | Public (Anonymous) | Process liveness only (no infrastructure secrets) | 200 OK |
| `GET` | `/api/v1/health/ready` | Public (Anonymous) | Database and object storage readiness probe | 503 if dependencies down |
| `GET` | `/api/v1/health/system` | `HEALTH_VIEW_DETAILED` | Deep diagnostics (workers, queues, alerts); Super Admin | 403 for non-super admins |
| `GET` | `/api/v1/health/workers` | `HEALTH_VIEW_DETAILED` | Worker heartbeat listings; Super Admin | 403 for non-super admins |
| `POST` | `/api/v1/health/workers/heartbeat`| Internal Worker Token | Validates worker registration | 401 on missing token |
| `POST` | `/api/v1/health/alerts/evaluate`| System Scheduler / Admin | Alert threshold evaluation (15-min cooldown) | 403 unauthorized caller |

---

## 3. Audit Findings & Verified Hardening Actions

1. **Session Invalidation on Role/Department Reassignment (Remediated in Phase 102):**
   - *Finding:* Updating user roles or departments previously left existing JWT bearer tokens active until natural expiration (up to 15 minutes).
   - *Fix:* Enforced explicit calls to `self.session_repo.revoke_user_sessions` across `update_user`, `assign_department`, and `assign_investigator`. Old tokens are rejected on the very next authenticated request.
2. **Authenticated Password Change (Remediated in Phase 102):**
   - *Finding:* Authenticated callers had no endpoint to change credentials without invoking unauthenticated email reset tokens.
   - *Fix:* Added `POST /api/v1/auth/change-password` requiring current password verification, enforcing reuse prevention and complexity rules, and terminating all active sessions.
3. **Token Refresh Rate Limiting (Remediated in Phase 102):**
   - *Finding:* Refresh rotation lacked IP-level rate limiting, allowing rapid token generation.
   - *Fix:* Added rate limit check (`max_requests=20, window_seconds=60.0`) in `rotate_refresh_token`.
4. **Timing Normalization in Password Reset (Remediated in Phase 102):**
   - *Finding:* Early return for non-existent emails created a microsecond-scale timing side-channel.
   - *Fix:* Added constant-time dummy token generation and hashing before returning generic privacy response.
5. **Production HTTPS & Security Headers Gate (Remediated in Phase 104):**
   - *Finding:* `ENFORCE_SSL` and `SECURITY_HEADERS_ENABLED` were not asserted in `_enforce_production_security_gate`.
   - *Fix:* Production gate now raises `ValueError` if either setting is `False`.

**Conclusion:** All 13 route families strictly implement deny-by-default access control, tenant/department isolation, and zero-trust verification.
