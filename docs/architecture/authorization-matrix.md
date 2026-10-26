# E-WITNESS — Comprehensive Authorization Matrix & Access Policies

**Document ID:** `EW-DOC-ARCH-007`  
**Phase:** Phase 21 — Roles, Permissions and Authorization Matrix  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## 1. Executive Summary & Security Philosophy

The E-WITNESS platform safeguards sensitive institutional disclosures, digital evidence, and disciplinary investigations. Its authorization architecture adheres to four non-negotiable security principles:

1. **Strict Default-Deny:** Access is denied unless an explicit allow rule matches. Unmapped actions, undefined roles, unknown permissions, or malformed credentials immediately evaluate to denial.
2. **Decoupling Authentication from Authorization:** Authentication proves identity (validating bearer credentials, cryptographic signatures, and active session state); authorization determines whether the verified identity holds the required permission to execute an operation on a specific resource.
3. **Decoupling Roles from Permissions:** Application endpoints and domain services evaluate fine-grained *permissions* (e.g., `user:create:dept`), never coarse, hardcoded role comparisons. Roles act purely as administrative bundles of permissions.
4. **Hard Multi-Department Isolation (Tenant Boundaries):** Users and Department Administrators cannot query, enumerate, modify, or assign resources outside their authorized department. Cross-department access is strictly restricted to platform-level operators (`ROLE_SUPER_ADMIN`) and auditable assigned investigator workflows.

---

## 2. Canonical System Roles & Responsibilities

E-WITNESS defines five canonical stakeholder roles corresponding to distinct institutional functions:

| System Role | Code | Department Scoped? | Core Responsibilities & Authority Scope |
| :--- | :--- | :---: | :--- |
| **Student** | `ROLE_STUDENT` | Yes | Reporters and witnesses. Can create incident disclosures, view and update own profile, manage own active sessions. Strictly prohibited from accessing administrative tools, user directories, or cross-user data. |
| **Staff** | `ROLE_STAFF` | Yes | Institutional employees and liaisons. Can submit incident reports, maintain own profile and sessions. Restricted from cross-department data and administrative actions unless assigned explicit duties. |
| **Investigator** | `ROLE_INVESTIGATOR` | Yes | Assigned case reviewers. Examines authorized evidence, views own department metadata, manages own profile and sessions. Cannot administer users or departments. |
| **Department Administrator** | `ROLE_DEPT_ADMIN` | Yes | Operational managers for a specific department. Administers users (`ROLE_STAFF`, `ROLE_INVESTIGATOR`, `ROLE_STUDENT`) strictly within their assigned department. Cannot cross department boundaries or grant administrative roles. |
| **Super Administrator** | `ROLE_SUPER_ADMIN` | No | System operators. Provisions departments, manages department administrators, configures global policies, inspects platform-wide telemetry. Does not routinely view confidential case evidence without an auditable break-glass trail. |

---

## 3. Granular Action Permissions

Permissions follow the standard `resource:action:scope` format:

```text
<resource>:<action>:<scope>
```

Where:
- `<resource>`: `user`, `department`, `role`, `session`, `system`
- `<action>`: `read`, `create`, `update`, `status_update`, `role_assign`, `dept_reassign`, `revoke`, `manage`
- `<scope>`:
  - `own`: Restricted strictly to the authenticated caller's own resource instance.
  - `dept`: Scoped to the caller's assigned department boundary.
  - `global`: System-wide, cross-department administrative scope.

### Permission Inventory

| Permission String | Description | Permitted Scopes |
| :--- | :--- | :--- |
| `user:read:own` | Read own user profile and account details | Caller only |
| `user:update:own` | Update non-privileged own profile fields (e.g., full name) | Caller only |
| `session:read:own` | List caller's active and historical login sessions | Caller only |
| `session:revoke:own` | Terminate caller's active login sessions | Caller only |
| `user:create:dept` | Provision new users within assigned department | Department-scoped |
| `user:read:dept` | List and view users within assigned department | Department-scoped |
| `user:update:dept` | Modify user metadata within assigned department | Department-scoped |
| `user:status_update:dept` | Suspend, activate, or disable department users | Department-scoped |
| `user:role_assign:dept` | Assign permitted roles (`STUDENT`, `STAFF`, `INVESTIGATOR`) within department | Department-scoped |
| `session:read:dept` | Inspect active sessions for department members | Department-scoped |
| `session:revoke:dept` | Terminate sessions for department members | Department-scoped |
| `department:read:own` | View metadata of caller's assigned department | Assigned department only |
| `user:create:global` | Provision users in any department with any role | Global |
| `user:read:global` | List and view users across all departments | Global |
| `user:update:global` | Modify user records across all departments | Global |
| `user:status_update:global` | Modify user lifecycle status across all departments | Global |
| `user:role_assign:global` | Assign any system role, including `DEPT_ADMIN` and `SUPER_ADMIN` | Global |
| `user:dept_reassign:global` | Move a user from one department to another | Global |
| `session:read:global` | Inspect login sessions across the platform | Global |
| `session:revoke:global` | Terminate any user's login session | Global |
| `department:create:global` | Provision a new institutional department | Global |
| `department:read:global` | List and inspect all departments | Global |
| `department:update:global` | Rename or modify any department | Global |
| `department:status_update:global` | Activate or deactivate a department | Global |
| `role:read:global` | List and inspect system role definitions | Global |
| `system:config:manage` | Manage platform configuration and operational controls | Global |

---

## 4. Role-to-Permission Mapping Matrix

The following table provides the authoritative mapping implemented in [`backend/app/core/authorization.py`](file:///c:/Users/lenovo/Desktop/E-WITNESS/backend/app/core/authorization.py):

| Permission | Student | Staff | Investigator | Department Admin | Super Admin |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `user:read:own` | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| `user:update:own` | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| `session:read:own` | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| `session:revoke:own` | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| `department:read:own` | DENY | DENY | ALLOW | ALLOW | ALLOW |
| `user:create:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `user:read:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `user:update:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `user:status_update:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `user:role_assign:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `session:read:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `session:revoke:dept` | DENY | DENY | DENY | ALLOW | ALLOW* |
| `user:create:global` | DENY | DENY | DENY | DENY | ALLOW |
| `user:read:global` | DENY | DENY | DENY | DENY | ALLOW |
| `user:update:global` | DENY | DENY | DENY | DENY | ALLOW |
| `user:status_update:global` | DENY | DENY | DENY | DENY | ALLOW |
| `user:role_assign:global` | DENY | DENY | DENY | DENY | ALLOW |
| `user:dept_reassign:global` | DENY | DENY | DENY | DENY | ALLOW |
| `session:read:global` | DENY | DENY | DENY | DENY | ALLOW |
| `session:revoke:global` | DENY | DENY | DENY | DENY | ALLOW |
| `department:create:global` | DENY | DENY | DENY | DENY | ALLOW |
| `department:read:global` | DENY | DENY | DENY | DENY | ALLOW |
| `department:update:global` | DENY | DENY | DENY | DENY | ALLOW |
| `department:status_update:global`| DENY | DENY | DENY | DENY | ALLOW |
| `role:read:global` | DENY | DENY | DENY | DENY | ALLOW |
| `system:config:manage` | DENY | DENY | DENY | DENY | ALLOW |

*\*Note: `ROLE_SUPER_ADMIN` satisfies department-level operations through its broader global permissions.*

---

## 5. Privilege Escalation & Boundary Protections

### 5.1 Departmental Isolation (Horizontal Privilege Defense)
A `ROLE_DEPT_ADMIN` assigned to Department $A$ cannot:
- View users belonging to Department $B$.
- Create users assigned to Department $B$.
- Update, deactivate, or reassign users belonging to Department $B$.
- Reassign a user from Department $A$ to Department $B$.
- View metadata for Department $B$.

Service layer methods automatically derive the department scope from the verified session principal (`principal.department_id`), rejecting client attempts to pass arbitrary `department_id` parameters with HTTP 403 `DEPARTMENT_ACCESS_RESTRICTED`.

### 5.2 Role Escalation Defense (Vertical Privilege Defense)
A `ROLE_DEPT_ADMIN` can only assign roles from `DEPT_ADMIN_ASSIGNABLE_ROLES`:
- `ROLE_STUDENT`
- `ROLE_STAFF`
- `ROLE_INVESTIGATOR`

Attempts by a Department Administrator to grant `ROLE_DEPT_ADMIN` or `ROLE_SUPER_ADMIN` are rejected at the service layer with HTTP 403 `PRIVILEGE_ESCALATION_FORBIDDEN`.

### 5.3 Self-Modification Protections
To prevent account lockouts and rogue administrative changes:
- An authenticated user cannot alter their own `role_id` (`SELF_ROLE_MODIFICATION_FORBIDDEN`).
- An authenticated user cannot alter their own `department_id` (`DEPARTMENT_REASSIGNMENT_RESTRICTED`).
- An authenticated user cannot suspend or disable their own account via administrative endpoints (`SELF_STATUS_MODIFICATION_FORBIDDEN`). Self-service profile updates are restricted to `full_name` and password reset flows.
