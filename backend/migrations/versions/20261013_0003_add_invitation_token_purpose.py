"""Add invitation token purpose to auth_tokens check constraint (Phase 32).

Revision ID: 20261013_0003
Revises: 20261013_0002
Create Date: 2026-10-13 18:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20261013_0003"
down_revision: str | None = "20261013_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Extend auth_tokens check constraint to include invitation purpose."""
    op.drop_constraint(
        op.f("ck_auth_tokens_purpose_allowed_values"),
        "auth_tokens",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_auth_tokens_purpose_allowed_values"),
        "auth_tokens",
        "purpose IN ('password_reset', 'email_verification', 'invitation')",
    )


def downgrade() -> None:
    """Revert auth_tokens check constraint back to password_reset and email_verification."""
    op.drop_constraint(
        op.f("ck_auth_tokens_purpose_allowed_values"),
        "auth_tokens",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_auth_tokens_purpose_allowed_values"),
        "auth_tokens",
        "purpose IN ('password_reset', 'email_verification')",
    )
