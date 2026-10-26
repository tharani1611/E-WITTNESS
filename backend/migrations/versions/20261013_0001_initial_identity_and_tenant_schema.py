"""Initial identity, role, department, and session schema (Phases 13-15).

Revision ID: 20261013_0001
Revises: None
Create Date: 2026-10-13 12:15:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261013_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create initial `departments`, `roles`, `users`, and `user_sessions` tables."""
    # 1. departments table
    op.create_table(
        "departments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("deactivated_at", UTCDateTime(), nullable=True),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "code = upper(trim(code)) AND length(trim(code)) >= 2",
            name=op.f("ck_departments_department_code_normalized"),
        ),
        sa.CheckConstraint(
            "length(trim(name)) >= 2",
            name=op.f("ck_departments_department_name_non_empty"),
        ),
        sa.CheckConstraint(
            "(is_active = true AND deactivated_at IS NULL) "
            "OR (is_active = false AND deactivated_at IS NOT NULL)",
            name=op.f("ck_departments_department_deactivation_consistency"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_departments")),
        sa.UniqueConstraint("name", name=op.f("uq_departments_name")),
    )
    op.create_index(op.f("ix_departments_code"), "departments", ["code"], unique=True)
    op.create_index(op.f("ix_departments_is_active"), "departments", ["is_active"], unique=False)

    # 2. roles table
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "requires_department_scope",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "is_system_role",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "code IN ('ROLE_STUDENT', 'ROLE_STAFF', 'ROLE_DEPT_ADMIN', "
            "'ROLE_INVESTIGATOR', 'ROLE_SUPER_ADMIN')",
            name=op.f("ck_roles_role_code_allowed_values"),
        ),
        sa.CheckConstraint(
            "length(trim(name)) >= 2",
            name=op.f("ck_roles_role_name_non_empty"),
        ),
        sa.CheckConstraint(
            "length(trim(description)) >= 5",
            name=op.f("ck_roles_role_description_non_empty"),
        ),
        sa.CheckConstraint(
            "(code = 'ROLE_SUPER_ADMIN') OR (requires_department_scope = true)",
            name=op.f("ck_roles_role_department_scope_enforcement"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )
    op.create_index(op.f("ix_roles_code"), "roles", ["code"], unique=True)

    # 3. users table
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("institutional_id", sa.String(length=64), nullable=True),
        sa.Column("full_name", sa.String(length=160), nullable=False),
        sa.Column(
            "account_status",
            sa.String(length=32),
            server_default="pending_verification",
            nullable=False,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("department_id", sa.Uuid(), nullable=True),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("verified_at", UTCDateTime(), nullable=True),
        sa.Column("deactivated_at", UTCDateTime(), nullable=True),
        sa.Column("deactivation_reason", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "email = lower(trim(email)) AND length(email) >= 5 AND email LIKE '%_@_%'",
            name=op.f("ck_users_user_email_normalized"),
        ),
        sa.CheckConstraint(
            "institutional_id IS NULL OR "
            "(institutional_id = upper(trim(institutional_id)) AND length(institutional_id) >= 3)",
            name=op.f("ck_users_user_institutional_id_normalized"),
        ),
        sa.CheckConstraint(
            "length(trim(full_name)) >= 2",
            name=op.f("ck_users_user_full_name_non_empty"),
        ),
        sa.CheckConstraint(
            "account_status IN ('pending_verification', 'active', 'suspended', 'disabled')",
            name=op.f("ck_users_user_account_status_allowed_values"),
        ),
        sa.CheckConstraint(
            "(account_status = 'active' AND is_active = true AND deactivated_at IS NULL) "
            "OR (account_status = 'pending_verification' AND is_active = false AND deactivated_at IS NULL) "
            "OR (account_status IN ('suspended', 'disabled') AND is_active = false AND deactivated_at IS NOT NULL)",
            name=op.f("ck_users_user_status_lifecycle_consistency"),
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            name=op.f("fk_users_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_users_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("id", "department_id", name="uq_users_id_department_id"),
    )
    op.create_index(op.f("ix_users_account_status"), "users", ["account_status"], unique=False)
    op.create_index(op.f("ix_users_department_id"), "users", ["department_id"], unique=False)
    op.create_index(
        "ix_users_department_id_account_status",
        "users",
        ["department_id", "account_status"],
        unique=False,
    )
    op.create_index(
        "ix_users_department_id_role_id",
        "users",
        ["department_id", "role_id"],
        unique=False,
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_institutional_id"), "users", ["institutional_id"], unique=True)
    op.create_index(op.f("ix_users_is_active"), "users", ["is_active"], unique=False)
    op.create_index(op.f("ix_users_role_id"), "users", ["role_id"], unique=False)

    # 4. user_sessions table
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default="active",
            nullable=False,
        ),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "issued_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column(
            "last_activity_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.Column("revocation_reason", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'expired', 'revoked')",
            name=op.f("ck_user_sessions_session_status_allowed_values"),
        ),
        sa.CheckConstraint(
            "expires_at > issued_at",
            name=op.f("ck_user_sessions_session_expiry_after_issued"),
        ),
        sa.CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL) "
            "OR (status IN ('active', 'expired') AND revoked_at IS NULL)",
            name=op.f("ck_user_sessions_session_revocation_consistency"),
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            name=op.f("fk_user_sessions_department_id_departments"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
    )
    op.create_index(
        op.f("ix_user_sessions_department_id"),
        "user_sessions",
        ["department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_sessions_expires_at"),
        "user_sessions",
        ["expires_at"],
        unique=False,
    )
    op.create_index(op.f("ix_user_sessions_status"), "user_sessions", ["status"], unique=False)
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False)
    op.create_index(
        "ix_user_sessions_user_id_status",
        "user_sessions",
        ["user_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    """Drop `user_sessions`, `users`, `roles`, and `departments` tables in reverse order."""
    op.drop_index("ix_user_sessions_user_id_status", table_name="user_sessions")
    op.drop_index(op.f("ix_user_sessions_user_id"), table_name="user_sessions")
    op.drop_index(op.f("ix_user_sessions_status"), table_name="user_sessions")
    op.drop_index(op.f("ix_user_sessions_expires_at"), table_name="user_sessions")
    op.drop_index(op.f("ix_user_sessions_department_id"), table_name="user_sessions")
    op.drop_table("user_sessions")

    op.drop_index(op.f("ix_users_role_id"), table_name="users")
    op.drop_index(op.f("ix_users_is_active"), table_name="users")
    op.drop_index(op.f("ix_users_institutional_id"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_index("ix_users_department_id_role_id", table_name="users")
    op.drop_index("ix_users_department_id_account_status", table_name="users")
    op.drop_index(op.f("ix_users_department_id"), table_name="users")
    op.drop_index(op.f("ix_users_account_status"), table_name="users")
    op.drop_table("users")

    op.drop_index(op.f("ix_roles_code"), table_name="roles")
    op.drop_table("roles")

    op.drop_index(op.f("ix_departments_is_active"), table_name="departments")
    op.drop_index(op.f("ix_departments_code"), table_name="departments")
    op.drop_table("departments")
