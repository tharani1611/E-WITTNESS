"""Add custody events, provenance fields, and incident routing decisions (Phases 51-55).

Revision ID: 20261014_0006
Revises: 20261014_0005
Create Date: 2026-10-14 06:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0006"
down_revision: str | None = "20261014_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply Phase 51-55 schema additions."""
    # 1. Add severity to incidents
    op.add_column(
        "incidents",
        sa.Column(
            "severity",
            sa.String(length=32),
            server_default=sa.text("'medium'"),
            nullable=False,
        ),
    )
    op.create_index(
        op.f("ix_incidents_severity"),
        "incidents",
        ["severity"],
        unique=False,
    )
    op.create_check_constraint(
        "ck_incidents_severity_allowed_values",
        "incidents",
        "severity IN ('low', 'medium', 'high', 'critical')",
    )

    # 2. Add provenance columns to evidence_attachments
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "ingested_at",
            UTCDateTime(),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_evidence_attachments_ingested_at"),
        "evidence_attachments",
        ["ingested_at"],
        unique=False,
    )
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "client_reported_at",
            UTCDateTime(),
            nullable=True,
        ),
    )
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "uploader_ip",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "user_agent",
            sa.String(length=255),
            nullable=True,
        ),
    )

    # 3. Create evidence_custody_events table
    op.create_table(
        "evidence_custody_events",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("evidence_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("department_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("actor_role", sa.String(length=64), nullable=False),
        sa.Column("actor_department_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("timestamp", UTCDateTime(), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("previous_event_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("details", sa.String(length=2000), nullable=True),
        sa.Column("compensates_event_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("compensation_reason", sa.String(length=1000), nullable=True),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_attachments.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["actor_department_id"],
            ["departments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["compensates_event_id"],
            ["evidence_custody_events.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "evidence_id",
            "sequence_number",
            name="uq_custody_events_evidence_sequence",
        ),
        sa.CheckConstraint(
            "sequence_number > 0",
            name="ck_custody_events_sequence_positive",
        ),
        sa.CheckConstraint(
            "action_type IN ('ingested', 'hash_verified', 'quarantined', 'sealed', 'accessed', 'downloaded', 'scan_failed', 'scan_retry', 'compensating_correction', 'tamper_detected')",
            name="ck_custody_events_action_type",
        ),
    )
    op.create_index(
        op.f("ix_evidence_custody_events_evidence_id"),
        "evidence_custody_events",
        ["evidence_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_custody_events_incident_id"),
        "evidence_custody_events",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_custody_events_department_id"),
        "evidence_custody_events",
        ["department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_custody_events_action_type"),
        "evidence_custody_events",
        ["action_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_custody_events_actor_id"),
        "evidence_custody_events",
        ["actor_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_custody_events_timestamp"),
        "evidence_custody_events",
        ["timestamp"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_custody_events_compensates_event_id"),
        "evidence_custody_events",
        ["compensates_event_id"],
        unique=False,
    )
    op.create_index(
        "ix_custody_events_evidence_sequence",
        "evidence_custody_events",
        ["evidence_id", "sequence_number"],
        unique=False,
    )

    # 4. Create incident_routing_decisions table
    op.create_table(
        "incident_routing_decisions",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_department_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("target_department_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("assigned_by_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column(
            "routing_type",
            sa.String(length=32),
            server_default=sa.text("'system_rule'"),
            nullable=False,
        ),
        sa.Column("rule_applied", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=1000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_department_id"],
            ["departments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_department_id"],
            ["departments.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "routing_type IN ('system_rule', 'authorized_override')",
            name="ck_incident_routing_decisions_type",
        ),
    )
    op.create_index(
        op.f("ix_incident_routing_decisions_incident_id"),
        "incident_routing_decisions",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_routing_decisions_source_department_id"),
        "incident_routing_decisions",
        ["source_department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_routing_decisions_target_department_id"),
        "incident_routing_decisions",
        ["target_department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_routing_decisions_assigned_by_id"),
        "incident_routing_decisions",
        ["assigned_by_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_routing_decisions_routing_type"),
        "incident_routing_decisions",
        ["routing_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_routing_decisions_created_at"),
        "incident_routing_decisions",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Revert Phase 51-55 schema additions."""
    op.drop_table("incident_routing_decisions")
    op.drop_table("evidence_custody_events")

    op.drop_index(
        op.f("ix_evidence_attachments_ingested_at"),
        table_name="evidence_attachments",
    )
    op.drop_column("evidence_attachments", "user_agent")
    op.drop_column("evidence_attachments", "uploader_ip")
    op.drop_column("evidence_attachments", "client_reported_at")
    op.drop_column("evidence_attachments", "ingested_at")

    op.drop_constraint(
        "ck_incidents_severity_allowed_values",
        "incidents",
        type_="check",
    )
    op.drop_index(
        op.f("ix_incidents_severity"),
        table_name="incidents",
    )
    op.drop_column("incidents", "severity")
