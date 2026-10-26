# E-WITNESS RESTful API Conventions & Query Protocols

## 1. Overview and Core Invariants

E-WITNESS REST endpoints follow consistent structural conventions across all versioned resources (`/api/v1/...`). The API enforces:
- **Default-deny authorization**: Every endpoint is protected by bearer authentication and fine-grained RBAC permission dependencies unless explicitly declared public (such as health probes and login).
- **Strict multi-tenant departmental boundaries**: Operations on department-scoped entities require either Global (Super Admin) authority or explicit matching against the caller's assigned `department_id`.
- **Deterministic response envelopes**: All responses adhere to typed schemas (`Pydantic v2`), forbidding extra fields (`extra="forbid"`) and standardizing success and error structures.
- **Fail-safe pagination**: Collection endpoints require explicit pagination constraints, preventing unbounded memory consumption and database denial-of-service.

---

## 2. HTTP Methods and Status Codes

| Method | Idempotent | Standard Success Code | Use Case |
|---|---|---|---|
| `GET` | Yes | `200 OK` | Retrieve single resource or paginated collection. |
| `POST` | No | `201 Created` | Create new entity (user, department, incident report). |
| `PATCH` | No | `200 OK` | Partial update of entity fields. |
| `DELETE`| Yes | `200 OK` / `204 No Content` | Soft-deactivation or session revocation. |

### Standard Error Status Codes

| Status Code | Token | Description |
|---|---|---|
| `400 Bad Request` | `INVALID_SORT_FIELD`, `BUSINESS_RULE_VIOLATION` | Malformed request or domain invariant failure. |
| `401 Unauthorized` | `UNAUTHENTICATED`, `TOKEN_EXPIRED`, `TOKEN_REVOKED` | Missing, expired, or invalid credentials. |
| `403 Forbidden` | `PERMISSION_DENIED`, `DEPARTMENT_MISMATCH`, `PRIVILEGE_ESCALATION_FORBIDDEN` | Caller lacks required permissions or violated tenant boundaries. |
| `404 Not Found` | `USER_NOT_FOUND`, `DEPARTMENT_NOT_FOUND` | Resource does not exist or is invisible to caller. |
| `409 Conflict` | `DEPARTMENT_CODE_EXISTS`, `RESOURCE_CONFLICT` | Uniqueness or state conflict. |
| `422 Unprocessable Entity` | `REQUEST_VALIDATION_ERROR` | Schema validation failure (Pydantic). |
| `429 Too Many Requests` | `RATE_LIMIT_EXCEEDED` | Request frequency threshold exceeded. |
| `500 Internal Server Error` | `INTERNAL_SERVER_ERROR` | Unhandled error (details redacted in production). |

---

## 3. Standard Response Envelopes

### 3.1 Single Resource Response
Individual entity responses return the resource schema directly:
```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "email": "investigator@institution.edu",
  "institutional_id": "FAC-8801",
  "full_name": "Senior Investigator",
  "account_status": "active",
  "is_active": true,
  "department_id": "22222222-2222-2222-2222-222222222222",
  "role_id": "33333333-3333-3333-3333-333333333333",
  "verified_at": "2026-10-13T10:00:00Z",
  "deactivated_at": null,
  "deactivation_reason": null,
  "created_at": "2026-10-13T10:00:00Z",
  "updated_at": "2026-10-13T10:00:00Z"
}
```

### 3.2 Standard Error Envelope (NFR-007)
All error responses wrap errors inside a top-level `error` object:
```json
{
  "error": {
    "code": "PRIVILEGE_ESCALATION_FORBIDDEN",
    "message": "Department Administrators cannot assign administrative role 'role_dept_admin'.",
    "request_id": "req-a1b2c3d4-e5f6-7890",
    "details": null
  }
}
```

---

## 4. Standard Pagination Protocol (Phase 25)

All collection endpoints accept uniform pagination query parameters and return a standardized `PaginatedResponse[T]` envelope.

### 4.1 Query Parameters
- `page` (`integer`, optional, default: `1`, minimum: `1`): 1-indexed page number.
- `page_size` (`integer`, optional, default: `20`, minimum: `1`, maximum: `100`): Upper-bounded item limit per page.

### 4.2 Paginated Response Envelope
```json
{
  "items": [
    { ... }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 47,
    "total_pages": 3,
    "has_next": true,
    "has_prev": false
  }
}
```

---

## 5. Standard Sorting Protocol (Phase 25)

Sorting query parameters allow clients to order collections using explicit, allowlisted database column mappings.

### 5.1 Query Parameters
- `sort_by` (`string`, optional): The field name to order by. Unallowlisted fields are rejected with `400 Bad Request` (`INVALID_SORT_FIELD`).
- `sort_order` (`string`, optional, default: `"asc"`): Sort direction, restricted to `"asc"` or `"desc"`.

### 5.2 Resource Sort Allowlist Matrix

| Resource | Default Sort | Allowed `sort_by` Values |
|---|---|---|
| `/api/v1/users` | `created_at` | `created_at`, `email`, `full_name`, `account_status` |
| `/api/v1/departments` | `code` | `code`, `name`, `created_at` |

---

## 6. Standard Filtering Protocol (Phase 25)

Collection endpoints support optional domain filters. Invalid filter values fail at the schema parsing boundary.

### 6.1 Users Collection (`/api/v1/users`)
- `department_id` (`UUID`, optional): Filter by department. For `ROLE_DEPT_ADMIN`, this must match their assigned department; querying other departments raises `403 Forbidden` (`DEPARTMENT_MISMATCH`).
- `role_code` (`string`, optional): Filter by role token (e.g. `role_student`, `role_investigator`).
- `account_status` (`string`, optional): Filter by lifecycle state (`pending_verification`, `active`, `suspended`, `deactivated`).
- `is_active` (`boolean`, optional): Filter active/inactive users.
- `search` (`string`, optional): Case-insensitive substring match against `email` and `full_name`.

### 6.2 Departments Collection (`/api/v1/departments`)
- `is_active` (`boolean`, optional): Filter active/deactivated departments.
- `search` (`string`, optional): Case-insensitive substring match against `code` and `name`.

---

## 7. Security and Tenant Isolation Invariants

1. **Horizontal Privilege Escalation Guard**:
   - `ROLE_DEPT_ADMIN` callers cannot list, read, or mutate users outside their department.
   - Any attempt to target an entity outside the caller's department immediately triggers `403 Forbidden` (`DEPARTMENT_MISMATCH`).
2. **Vertical Privilege Escalation Guard**:
   - `ROLE_DEPT_ADMIN` can only assign non-administrative roles (`ROLE_STUDENT`, `ROLE_STAFF`, `ROLE_INVESTIGATOR`).
   - Attempting to assign `ROLE_DEPT_ADMIN` or `ROLE_SUPER_ADMIN` triggers `403 Forbidden` (`PRIVILEGE_ESCALATION_FORBIDDEN`).
3. **Department Reassignment Guard**:
   - `ROLE_DEPT_ADMIN` cannot alter the department of an existing user or assign a user to another department (`DEPARTMENT_REASSIGNMENT_RESTRICTED`).
4. **Self-Modification Guard**:
   - Authenticated callers cannot alter their own `role_id` (`SELF_ROLE_MODIFICATION_FORBIDDEN`).
   - Authenticated callers cannot alter their own `account_status` or deactivate themselves (`SELF_STATUS_MODIFICATION_FORBIDDEN`).
   - Authenticated callers can only update their display name (`full_name`) via `/api/v1/users/me/profile`.
