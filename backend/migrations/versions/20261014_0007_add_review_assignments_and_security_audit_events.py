"""Add review assignments, security audit events, and evidence exports (Phases 56-60).

Revision ID: 20261014_0007
Revises: 20261014_0006
Create Date: 2026-10-14 07:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0007"
down_revision: str | None = "20261014_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply Phase 56-60 schema additions."""
    # 1. Add reviewer assignment fields to incidents table
    op.add_column(
        "incidents",
        sa.Column(
            "assigned_reviewer_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "assignment_status",
            sa.String(length=32),
            nullable=False,
            server_default="unassigned",
        ),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "assigned_at",
            UTCDateTime(),
            nullable=True,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "acknowledged_at",
            UTCDateTime(),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_incidents_assigned_reviewer_id",
        "incidents",
        ["assigned_reviewer_id"],
    )
    op.create_index(
        "ix_incidents_assignment_status",
        "incidents",
        ["assignment_status"],
    )
    op.create_index(
        "ix_incidents_assigned_reviewer_id_status",
        "incidents",
        ["assigned_reviewer_id", "status"],
    )
    op.create_index(
        "ix_incidents_department_id_assignment_status",
        "incidents",
        ["department_id", "assignment_status"],
    )
    op.create_check_constraint(
        "ck_incidents_assignment_status_allowed_values",
        "incidents",
        "assignment_status IN ('unassigned', 'assigned', 'acknowledged', 'under_review', 'reassigned')",
    )

    # 2. Create incident_assignments table
    op.create_table(
        "incident_assignments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "reviewer_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "assigned_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="assigned",
        ),
        sa.Column("reason", sa.String(length=1000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "status IN ('assigned', 'acknowledged', 'reassigned', 'unassigned')",
            name="ck_incident_assignments_status_allowed_values",
        ),
    )
    op.create_index(
        "ix_incident_assignments_incident_id",
        "incident_assignments",
        ["incident_id"],
    )
    op.create_index(
        "ix_incident_assignments_reviewer_id",
        "incident_assignments",
        ["reviewer_id"],
    )
    op.create_index(
        "ix_incident_assignments_assigned_by_id",
        "incident_assignments",
        ["assigned_by_id"],
    )
    op.create_index(
        "ix_incident_assignments_status",
        "incident_assignments",
        ["status"],
    )
    op.create_index(
        "ix_incident_assignments_created_at",
        "incident_assignments",
        ["created_at"],
    )

    # 3. Create security_audit_events table
    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column(
            "actor_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_role", sa.String(length=64), nullable=True),
        sa.Column("actor_ip", sa.String(length=64), nullable=True),
        sa.Column("actor_user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("previous_event_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')",
            name="ck_security_audit_events_outcome_allowed_values",
        ),
    )
    op.create_index(
        "ix_security_audit_events_sequence_number",
        "security_audit_events",
        ["sequence_number"],
    )
    op.create_index(
        "ix_security_audit_events_action",
        "security_audit_events",
        ["action"],
    )
    op.create_index(
        "ix_security_audit_events_actor_id",
        "security_audit_events",
        ["actor_id"],
    )
    op.create_index(
        "ix_security_audit_events_department_id",
        "security_audit_events",
        ["department_id"],
    )
    op.create_index(
        "ix_security_audit_events_target_type",
        "security_audit_events",
        ["target_type"],
    )
    op.create_index(
        "ix_security_audit_events_target_id",
        "security_audit_events",
        ["target_id"],
    )
    op.create_index(
        "ix_security_audit_events_outcome",
        "security_audit_events",
        ["outcome"],
    )
    op.create_index(
        "ix_security_audit_events_event_hash",
        "security_audit_events",
        ["event_hash"],
    )
    op.create_index(
        "ix_security_audit_events_created_at",
        "security_audit_events",
        ["created_at"],
    )
    op.create_index(
        "ix_security_audit_events_target_type_id",
        "security_audit_events",
        ["target_type", "target_id"],
    )
    op.create_index(
        "ix_security_audit_events_department_created",
        "security_audit_events",
        ["department_id", "created_at"],
    )

    # 4. Create evidence_exports table
    op.create_table(
        "evidence_exports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "exported_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "export_scope", sa.String(length=32), nullable=False, server_default="incident_package"
        ),
        sa.Column("export_format", sa.String(length=32), nullable=False, server_default="zip"),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="completed"),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "export_scope IN ('single_evidence', 'incident_package', 'custody_bundle')",
            name="ck_evidence_exports_scope_allowed_values",
        ),
        sa.CheckConstraint(
            "export_format IN ('zip', 'json_manifest', 'tar_gz')",
            name="ck_evidence_exports_format_allowed_values",
        ),
    )
    op.create_index(
        "ix_evidence_exports_incident_id",
        "evidence_exports",
        ["incident_id"],
    )
    op.create_index(
        "ix_evidence_exports_department_id",
        "evidence_exports",
        ["department_id"],
    )
    op.create_index(
        "ix_evidence_exports_exported_by_id",
        "evidence_exports",
        ["exported_by_id"],
    )
    op.create_index(
        "ix_evidence_exports_status",
        "evidence_exports",
        ["status"],
    )
    op.create_index(
        "ix_evidence_exports_created_at",
        "evidence_exports",
        ["created_at"],
    )


def downgrade() -> None:
    """Revert Phase 56-60 schema additions."""
    op.drop_table("evidence_exports")
    op.drop_table("security_audit_events")
    op.drop_table("incident_assignments")
    op.drop_constraint("ck_incidents_assignment_status_allowed_values", "incidents", type_="check")
    op.drop_index("ix_incidents_department_id_assignment_status", table_name="incidents")
    op.drop_index("ix_incidents_assigned_reviewer_id_status", table_name="incidents")
    op.drop_index("ix_incidents_assignment_status", table_name="incidents")
    op.drop_index("ix_incidents_assigned_reviewer_id", table_name="incidents")
    op.drop_column("incidents", "acknowledged_at")
    op.drop_column("incidents", "assigned_at")
    op.drop_column("incidents", "assignment_status")
    op.drop_column("incidents", "assigned_reviewer_id")
