# E-WITNESS Frontend Workspace (Reserved)

This directory is reserved for the future E-WITNESS web client implementation as scheduled in later phases of the 120-phase master roadmap.

## Security Boundary Notice

1. **Zero Client-Side Authorization Reliance**: All role-based access control (RBAC), attribute-based access control (ABAC), and department/tenant isolation rules are strictly enforced by the `backend/` API and database layers. Frontend routing and UI visibility checks are exclusively for user experience.
2. **Zero Secret Storage**: No API keys, service credentials, signing keys, or direct object-storage credentials may ever be embedded in frontend source code or build artifacts.
