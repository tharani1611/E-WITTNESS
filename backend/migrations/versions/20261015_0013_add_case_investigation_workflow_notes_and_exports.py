"""Add case investigation workflow, notes, findings, and exports schema (Phases 86-90).

Revision ID: 20261015_0013
Revises: 20261014_0012
Create Date: 2026-10-15 01:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261015_0013"
down_revision: str | None = "20261014_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NOTE_VISIBILITY_VALUES = "'internal', 'confidential', 'restricted'"
_FINDING_TYPE_VALUES = "'inculpatory', 'exculpatory', 'procedural', 'inconclusive', 'preliminary'"
_APPROVAL_DECISION_VALUES = "'approved', 'rejected', 'changes_requested'"
_ESCALATION_LEVEL_VALUES = "'department_head', 'internal_affairs', 'legal_counsel', 'super_admin'"
_REFERRAL_STATUS_VALUES = "'pending', 'accepted', 'rejected', 'transferred'"
_EXPORT_SCOPE_VALUES = "'summary', 'full_investigation', 'evidence_manifest_only', 'court_package'"
_EXPORT_FORMAT_VALUES = "'json', 'zip', 'pdf_summary'"


def upgrade() -> None:
    """Apply Phase 86-90 investigation workflow, notes, findings, and export tables."""
    # 1. Case Notes table
    op.create_table(
        "case_notes",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "visibility",
            sa.String(length=32),
            nullable=False,
            server_default="internal",
        ),
        sa.Column("content", sa.String(length=10000), nullable=False),
        sa.Column("version_id", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("is_archived", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("evidence_reference_ids_json", sa.Text(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"visibility IN ({_NOTE_VISIBILITY_VALUES})",
            name="ck_case_notes_visibility",
        ),
        sa.CheckConstraint(
            "length(trim(content)) >= 5 AND length(content) <= 10000",
            name="ck_case_notes_content_length",
        ),
        sa.CheckConstraint(
            "version_id >= 1",
            name="ck_case_notes_version_id_positive",
        ),
    )
    op.create_index("ix_case_notes_case_id", "case_notes", ["case_id"])
    op.create_index("ix_case_notes_author_id", "case_notes", ["author_id"])
    op.create_index("ix_case_notes_created_at", "case_notes", ["created_at"])

    # 2. Case Note History table
    op.create_table(
        "case_note_history",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "note_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("case_notes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "author_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "editor_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("content", sa.String(length=10000), nullable=False),
        sa.Column("edit_reason", sa.String(length=1000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "length(trim(content)) >= 5 AND length(content) <= 10000",
            name="ck_case_note_history_content_length",
        ),
        sa.CheckConstraint(
            "version_id >= 1",
            name="ck_case_note_history_version_id_positive",
        ),
    )
    op.create_index(
        "ix_case_note_history_note_version", "case_note_history", ["note_id", "version_id"]
    )

    # 3. Case Findings table
    op.create_table(
        "case_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "finding_type",
            sa.String(length=32),
            nullable=False,
            server_default="preliminary",
        ),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=10000), nullable=False),
        sa.Column("evidence_ids_json", sa.Text(), nullable=True),
        sa.Column("ai_segment_ids_json", sa.Text(), nullable=True),
        sa.Column("incident_ids_json", sa.Text(), nullable=True),
        sa.Column("version_id", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("is_preliminary", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"finding_type IN ({_FINDING_TYPE_VALUES})",
            name="ck_case_findings_type",
        ),
        sa.CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_case_findings_title_length",
        ),
        sa.CheckConstraint(
            "length(trim(description)) >= 10 AND length(description) <= 10000",
            name="ck_case_findings_description_length",
        ),
        sa.CheckConstraint(
            "version_id >= 1",
            name="ck_case_findings_version_id_positive",
        ),
    )
    op.create_index("ix_case_findings_case_id", "case_findings", ["case_id"])
    op.create_index("ix_case_findings_author_id", "case_findings", ["author_id"])

    # 4. Case Finding History table
    op.create_table(
        "case_finding_history",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "finding_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("case_findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "editor_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=10000), nullable=False),
        sa.Column("reason", sa.String(length=1000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_case_finding_history_title_length",
        ),
        sa.CheckConstraint(
            "length(trim(description)) >= 10 AND length(description) <= 10000",
            name="ck_case_finding_history_desc_length",
        ),
        sa.CheckConstraint(
            "version_id >= 1",
            name="ck_case_finding_history_version_id_positive",
        ),
    )
    op.create_index(
        "ix_case_finding_history_finding_version",
        "case_finding_history",
        ["finding_id", "version_id"],
    )

    # 5. Case Approvals table
    op.create_table(
        "case_approvals",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "approver_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=False),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.String(length=2000), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"decision IN ({_APPROVAL_DECISION_VALUES})",
            name="ck_case_approvals_decision",
        ),
        sa.CheckConstraint(
            "length(trim(rationale)) >= 10 AND length(rationale) <= 2000",
            name="ck_case_approvals_rationale_length",
        ),
    )
    op.create_index("ix_case_approvals_case_id", "case_approvals", ["case_id"])
    op.create_index("ix_case_approvals_approver_id", "case_approvals", ["approver_id"])

    # 6. Case Escalations table
    op.create_table(
        "case_escalations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "escalated_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "escalated_to_department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("reason", sa.String(length=1000), nullable=False),
        sa.Column("escalation_level", sa.String(length=32), nullable=False),
        sa.Column("case_version_id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"escalation_level IN ({_ESCALATION_LEVEL_VALUES})",
            name="ck_case_escalations_level",
        ),
        sa.CheckConstraint(
            "length(trim(reason)) >= 10 AND length(reason) <= 1000",
            name="ck_case_escalations_reason_length",
        ),
    )
    op.create_index("ix_case_escalations_case_id", "case_escalations", ["case_id"])
    op.create_index(
        "ix_case_escalations_escalated_to_dept", "case_escalations", ["escalated_to_department_id"]
    )

    # 7. Case Referrals table
    op.create_table(
        "case_referrals",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "referred_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target_external_agency", sa.String(length=200), nullable=True),
        sa.Column("referral_purpose", sa.String(length=1000), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("resolution_notes", sa.String(length=2000), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"status IN ({_REFERRAL_STATUS_VALUES})",
            name="ck_case_referrals_status",
        ),
        sa.CheckConstraint(
            "length(trim(referral_purpose)) >= 10 AND length(referral_purpose) <= 1000",
            name="ck_case_referrals_purpose_length",
        ),
        sa.CheckConstraint(
            "target_department_id IS NOT NULL OR target_external_agency IS NOT NULL",
            name="ck_case_referrals_target_present",
        ),
    )
    op.create_index("ix_case_referrals_case_id", "case_referrals", ["case_id"])
    op.create_index("ix_case_referrals_target_dept", "case_referrals", ["target_department_id"])

    # 8. Case Exports table
    op.create_table(
        "case_exports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
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
        sa.Column("export_scope", sa.String(length=32), nullable=False),
        sa.Column("export_format", sa.String(length=32), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("manifest_payload", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="completed"),
        sa.Column("purpose", sa.String(length=1000), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"export_scope IN ({_EXPORT_SCOPE_VALUES})",
            name="ck_case_exports_scope",
        ),
        sa.CheckConstraint(
            f"export_format IN ({_EXPORT_FORMAT_VALUES})",
            name="ck_case_exports_format",
        ),
        sa.CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_case_exports_manifest_sha256_len",
        ),
    )
    op.create_index("ix_case_exports_case_id", "case_exports", ["case_id"])
    op.create_index("ix_case_exports_exported_by_id", "case_exports", ["exported_by_id"])
    op.create_index("ix_case_exports_department_id", "case_exports", ["department_id"])


def downgrade() -> None:
    """Revert Phase 86-90 investigation workflow, notes, findings, and export tables."""
    op.drop_table("case_exports")
    op.drop_table("case_referrals")
    op.drop_table("case_escalations")
    op.drop_table("case_approvals")
    op.drop_table("case_finding_history")
    op.drop_table("case_findings")
    op.drop_table("case_note_history")
    op.drop_table("case_notes")
