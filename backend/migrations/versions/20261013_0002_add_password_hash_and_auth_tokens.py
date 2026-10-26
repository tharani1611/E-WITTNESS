"""Add password hash, refresh session rotation, and one-time auth tokens (Phases 16-18).

Revision ID: 20261013_0002
Revises: 20261013_0001
Create Date: 2026-10-13 14:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261013_0002"
down_revision: str | None = "20261013_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply schema extensions for credential hashing, refresh sessions, and auth tokens."""
    # 1. Extend `users` table with nullable password_hash and length constraint
    op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=True))
    op.create_check_constraint(
        op.f("ck_users_user_password_hash_min_length"),
        "users",
        "password_hash IS NULL OR length(password_hash) >= 20",
    )

    # 2. Extend `user_sessions` with refresh token digests and rotation counter
    op.add_column(
        "user_sessions",
        sa.Column("refresh_token_hash", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "user_sessions",
        sa.Column("previous_refresh_token_hash", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "user_sessions",
        sa.Column(
            "rotation_counter",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.create_index(
        op.f("ix_user_sessions_refresh_token_hash"),
        "user_sessions",
        ["refresh_token_hash"],
        unique=True,
    )
    op.create_index(
        op.f("ix_user_sessions_previous_refresh_token_hash"),
        "user_sessions",
        ["previous_refresh_token_hash"],
        unique=False,
    )

    # 3. Create `auth_tokens` table for password-reset and email-verification one-time tokens
    op.create_table(
        "auth_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("consumed_at", UTCDateTime(), nullable=True),
        sa.Column("created_by_ip", sa.String(length=45), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_auth_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_tokens")),
        sa.CheckConstraint(
            "purpose IN ('password_reset', 'email_verification')",
            name=op.f("ck_auth_tokens_purpose_allowed_values"),
        ),
        sa.CheckConstraint(
            "length(token_hash) = 64",
            name=op.f("ck_auth_tokens_token_hash_sha256_length"),
        ),
    )
    op.create_index(
        op.f("ix_auth_tokens_consumed_at"), "auth_tokens", ["consumed_at"], unique=False
    )
    op.create_index(op.f("ix_auth_tokens_expires_at"), "auth_tokens", ["expires_at"], unique=False)
    op.create_index(op.f("ix_auth_tokens_purpose"), "auth_tokens", ["purpose"], unique=False)
    op.create_index(op.f("ix_auth_tokens_token_hash"), "auth_tokens", ["token_hash"], unique=True)
    op.create_index(op.f("ix_auth_tokens_user_id"), "auth_tokens", ["user_id"], unique=False)
    op.create_index(
        op.f("ix_auth_tokens_user_id_purpose"),
        "auth_tokens",
        ["user_id", "purpose"],
        unique=False,
    )


def downgrade() -> None:
    """Revert schema changes for auth tokens and credential hashing."""
    op.drop_index(op.f("ix_auth_tokens_user_id_purpose"), table_name="auth_tokens")
    op.drop_index(op.f("ix_auth_tokens_user_id"), table_name="auth_tokens")
    op.drop_index(op.f("ix_auth_tokens_token_hash"), table_name="auth_tokens")
    op.drop_index(op.f("ix_auth_tokens_purpose"), table_name="auth_tokens")
    op.drop_index(op.f("ix_auth_tokens_expires_at"), table_name="auth_tokens")
    op.drop_index(op.f("ix_auth_tokens_consumed_at"), table_name="auth_tokens")
    op.drop_table("auth_tokens")

    op.drop_index(op.f("ix_user_sessions_previous_refresh_token_hash"), table_name="user_sessions")
    op.drop_index(op.f("ix_user_sessions_refresh_token_hash"), table_name="user_sessions")
    op.drop_column("user_sessions", "rotation_counter")
    op.drop_column("user_sessions", "previous_refresh_token_hash")
    op.drop_column("user_sessions", "refresh_token_hash")

    op.drop_constraint(op.f("ck_users_user_password_hash_min_length"), "users", type_="check")
    op.drop_column("users", "password_hash")
