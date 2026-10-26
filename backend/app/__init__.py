"""E-WITNESS core application package.

Houses the layered backend components:
- api: HTTP route controllers and request/response boundaries
- config: Centralized, validated environment configuration
- core: Security, redaction, logging, correlation, and foundational utilities
- infrastructure: External storage, cache, and database adapters
- middleware: Request tracing, security headers, and payload size guardrails
- models: SQLAlchemy 2.x ORM declarations
- repositories: Data access and tenant-scoped persistence queries
- schemas: Pydantic v2 request/response contracts
- services: Domain business logic and authorization enforcement
"""

from backend.app.main import create_app

__version__ = "0.1.0"
__all__ = ["__version__", "create_app"]
