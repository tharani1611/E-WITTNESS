"""Add investigation cases, assignments, and relational linkages schema (Phases 81-85).

Revision ID: 20261014_0012
Revises: 20261014_0011
Create Date: 2026-10-14 22:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0012"
down_revision: str | None = "20261014_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUS_VALUES = (
    "'draft', 'open', 'under_investigation', 'pending_review', 'suspended', 'resolved', 'closed'"
)
_PRIORITY_VALUES = "'low', 'medium', 'high', 'critical'"
_LINK_TYPE_VALUES = "'primary', 'related', 'evidence_source'"
_RELEVANCE_VALUES = "'candidate_lead', 'corroborating', 'exculpatory', 'dismissed'"


def upgrade() -> None:
    """Apply Phase 81-85 investigation case, assignment, and linkage tables."""
    # 1. Cases table
    op.create_table(
        "cases",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("reference_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.String(length=10000), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(length=32), nullable=False, server_default="medium"),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "lead_investigator_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("version_id", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("is_legal_hold", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("legal_hold_reason", sa.String(length=1000), nullable=True),
        sa.Column("closed_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_cases_title_length",
        ),
        sa.CheckConstraint(
            "length(trim(summary)) >= 10 AND length(summary) <= 10000",
            name="ck_cases_summary_length",
        ),
        sa.CheckConstraint(
            f"status IN ({_STATUS_VALUES})",
            name="ck_cases_status_allowed_values",
        ),
        sa.CheckConstraint(
            f"priority IN ({_PRIORITY_VALUES})",
            name="ck_cases_priority_allowed_values",
        ),
        sa.CheckConstraint(
            "reference_number = upper(trim(reference_number)) AND length(reference_number) >= 13",
            name="ck_cases_reference_number_normalized",
        ),
        sa.CheckConstraint(
            "version_id >= 1",
            name="ck_cases_version_id_positive",
        ),
    )
    op.create_index(
        "ix_cases_reference_number",
        "cases",
        ["reference_number"],
        unique=True,
    )
    op.create_index(
        "ix_cases_department_id_status",
        "cases",
        ["department_id", "status"],
    )
    op.create_index(
        "ix_cases_lead_investigator_id_status",
        "cases",
        ["lead_investigator_id", "status"],
    )
    op.create_index(
        "ix_cases_created_by_id",
        "cases",
        ["created_by_id"],
    )
    op.create_index(
        "ix_cases_created_at",
        "cases",
        ["created_at"],
    )

    # 2. Case Incidents table
    op.create_table(
        "case_incidents",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "linked_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("link_type", sa.String(length=32), nullable=False, server_default="primary"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("case_id", "incident_id", name="uq_case_incidents_case_incident"),
        sa.CheckConstraint(
            f"link_type IN ({_LINK_TYPE_VALUES})",
            name="ck_case_incidents_link_type",
        ),
    )
    op.create_index("ix_case_incidents_case_id", "case_incidents", ["case_id"])
    op.create_index("ix_case_incidents_incident_id", "case_incidents", ["incident_id"])

    # 3. Case Assignments table
    op.create_table(
        "case_assignments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "previous_investigator_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "new_investigator_id",
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
        sa.Column("assignment_reason", sa.String(length=1000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
    )
    op.create_index(
        "ix_case_assignments_case_created",
        "case_assignments",
        ["case_id", "created_at"],
    )
    op.create_index(
        "ix_case_assignments_investigator",
        "case_assignments",
        ["new_investigator_id"],
    )

    # 4. Case Evidence table
    op.create_table(
        "case_evidence",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("evidence_attachments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "linked_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("notes", sa.String(length=1000), nullable=True),
        sa.Column("is_exhibiting", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("case_id", "evidence_id", name="uq_case_evidence_case_evidence"),
    )
    op.create_index("ix_case_evidence_case_id", "case_evidence", ["case_id"])
    op.create_index("ix_case_evidence_evidence_id", "case_evidence", ["evidence_id"])

    # 5. Case AI Segments table
    op.create_table(
        "case_ai_segments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "segment_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("ai_candidate_segments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "linked_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "investigative_relevance",
            sa.String(length=64),
            nullable=False,
            server_default="candidate_lead",
        ),
        sa.Column("relevance_notes", sa.String(length=1000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("case_id", "segment_id", name="uq_case_ai_segments_case_segment"),
        sa.CheckConstraint(
            f"investigative_relevance IN ({_RELEVANCE_VALUES})",
            name="ck_case_ai_segments_relevance",
        ),
    )
    op.create_index("ix_case_ai_segments_case_id", "case_ai_segments", ["case_id"])
    op.create_index("ix_case_ai_segments_segment_id", "case_ai_segments", ["segment_id"])


def downgrade() -> None:
    """Revert Phase 81-85 case, assignment, and linkage tables."""
    op.drop_table("case_ai_segments")
    op.drop_table("case_evidence")
    op.drop_table("case_assignments")
    op.drop_table("case_incidents")
    op.drop_table("cases")
