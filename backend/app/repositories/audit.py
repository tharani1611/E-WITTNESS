"""Security audit repository and tamper-evident ledger access (Phases 58-59).

Enforces:
- Append-only sequence generation and hash chain persistence.
- Strict bounded search pagination (max 100 items per page).
- Cryptographic chain verification across consecutive records.
- Evidence export persistence and audit retrieval.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.audit import AUDIT_DISCLAIMER, compute_security_audit_event_hash
from backend.app.models.audit import EvidenceExport, SecurityAuditEvent


class AuditRepository:
    """Async repository for tamper-evident security audit events and evidence exports."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_latest_event(self) -> SecurityAuditEvent | None:
        """Fetch the most recent security audit event in the chain."""
        result = await self.session.execute(
            select(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence_number.desc()).limit(1)
        )
        return result.scalars().first()

    async def get_next_sequence_number(self) -> int:
        """Calculate the next monotonic sequence number for the ledger."""
        result = await self.session.execute(
            select(func.coalesce(func.max(SecurityAuditEvent.sequence_number), 0))
        )
        current_max = result.scalar_one()
        return int(current_max) + 1

    async def append_event(
        self,
        *,
        action: str,
        actor_id: UUID | None,
        actor_role: str | None,
        target_type: str,
        target_id: str,
        outcome: str,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
        department_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> SecurityAuditEvent:
        """Append a new tamper-evident security audit event into the ledger."""
        latest = await self.get_latest_event()
        next_seq = (latest.sequence_number + 1) if latest else 1
        prev_hash = latest.event_hash if latest else None
        now = datetime.now(UTC)

        event_hash = compute_security_audit_event_hash(
            sequence_number=next_seq,
            action=action,
            actor_id=actor_id,
            department_id=department_id,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            created_at=now,
            previous_event_hash=prev_hash,
            details=details,
        )

        details_json = json.dumps(details, sort_keys=True) if details else None

        event = SecurityAuditEvent(
            sequence_number=next_seq,
            action=action,
            actor_id=actor_id,
            actor_role=actor_role,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=department_id,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            details=details_json,
            previous_event_hash=prev_hash,
            event_hash=event_hash,
            created_at=now,
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def list_events_paginated(
        self,
        *,
        actor_id: UUID | None = None,
        action: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        department_id: UUID | None = None,
        outcome: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[SecurityAuditEvent], int]:
        """Search security audit events with strict bounds and scoping."""
        if limit > 100:
            limit = 100
        if limit < 1:
            limit = 1

        predicates = []
        if actor_id is not None:
            predicates.append(SecurityAuditEvent.actor_id == actor_id)
        if action is not None:
            predicates.append(SecurityAuditEvent.action == action.strip().lower())
        if target_type is not None:
            predicates.append(SecurityAuditEvent.target_type == target_type.strip().lower())
        if target_id is not None:
            predicates.append(SecurityAuditEvent.target_id == target_id.strip())
        if department_id is not None:
            predicates.append(SecurityAuditEvent.department_id == department_id)
        if outcome is not None:
            predicates.append(SecurityAuditEvent.outcome == outcome.strip().lower())
        if start_time is not None:
            predicates.append(SecurityAuditEvent.created_at >= start_time)
        if end_time is not None:
            predicates.append(SecurityAuditEvent.created_at <= end_time)

        count_stmt = select(func.count(SecurityAuditEvent.id))
        if predicates:
            count_stmt = count_stmt.where(*predicates)
        total_items = (await self.session.execute(count_stmt)).scalar_one()

        if total_items == 0:
            return [], 0

        query = select(SecurityAuditEvent)
        if predicates:
            query = query.where(*predicates)
        query = (
            query.order_by(SecurityAuditEvent.sequence_number.desc()).limit(limit).offset(offset)
        )
        items = (await self.session.execute(query)).scalars().all()
        return items, total_items

    async def verify_chain(
        self,
        *,
        limit: int = 1000,
        start_sequence: int = 1,
    ) -> dict[str, Any]:
        """Verify the integrity of the audit chain consecutively from start_sequence."""
        query = (
            select(SecurityAuditEvent)
            .where(SecurityAuditEvent.sequence_number >= start_sequence)
            .order_by(SecurityAuditEvent.sequence_number.asc())
            .limit(limit)
        )
        events = (await self.session.execute(query)).scalars().all()

        now = datetime.now(UTC)
        if not events:
            return {
                "status": "empty",
                "chain_valid": True,
                "total_events_verified": 0,
                "first_sequence_number": None,
                "last_sequence_number": None,
                "tampered_event_ids": [],
                "tampered_sequence_numbers": [],
                "errors": [],
                "disclaimer": AUDIT_DISCLAIMER,
                "verified_at": now,
            }

        tampered_ids: list[UUID] = []
        tampered_seqs: list[int] = []
        errors: list[str] = []
        expected_prev_hash: str | None = None

        # If starting from sequence > 1, look up the predecessor's hash
        if events[0].sequence_number > 1:
            pred_query = select(SecurityAuditEvent).where(
                SecurityAuditEvent.sequence_number == events[0].sequence_number - 1
            )
            predecessor = (await self.session.execute(pred_query)).scalars().first()
            if predecessor:
                expected_prev_hash = predecessor.event_hash

        for idx, event in enumerate(events):
            # Check previous_event_hash link
            if idx == 0 and event.sequence_number == 1:
                if event.previous_event_hash is not None:
                    tampered_ids.append(event.id)
                    tampered_seqs.append(event.sequence_number)
                    errors.append(
                        f"Event seq {event.sequence_number}: Genesis event must have null previous_event_hash."
                    )
            elif expected_prev_hash is not None and event.previous_event_hash != expected_prev_hash:
                tampered_ids.append(event.id)
                tampered_seqs.append(event.sequence_number)
                errors.append(
                    f"Event seq {event.sequence_number}: previous_event_hash '{event.previous_event_hash}' "
                    f"does not match expected predecessor hash '{expected_prev_hash}'."
                )

            # Recompute event_hash
            details_dict = None
            if event.details:
                try:
                    details_dict = json.loads(event.details)
                except Exception:
                    details_dict = {"raw": event.details}

            computed_hash = compute_security_audit_event_hash(
                sequence_number=event.sequence_number,
                action=event.action,
                actor_id=event.actor_id,
                department_id=event.department_id,
                target_type=event.target_type,
                target_id=event.target_id,
                outcome=event.outcome,
                created_at=event.created_at,
                previous_event_hash=event.previous_event_hash,
                details=details_dict,
            )

            if computed_hash != event.event_hash:
                if event.id not in tampered_ids:
                    tampered_ids.append(event.id)
                    tampered_seqs.append(event.sequence_number)
                errors.append(
                    f"Event seq {event.sequence_number}: Computed hash '{computed_hash}' "
                    f"does not match recorded event_hash '{event.event_hash}'."
                )

            expected_prev_hash = event.event_hash

        is_valid = len(tampered_ids) == 0
        return {
            "status": "verified" if is_valid else "compromised",
            "chain_valid": is_valid,
            "total_events_verified": len(events),
            "first_sequence_number": events[0].sequence_number,
            "last_sequence_number": events[-1].sequence_number,
            "tampered_event_ids": tampered_ids,
            "tampered_sequence_numbers": tampered_seqs,
            "errors": errors,
            "disclaimer": AUDIT_DISCLAIMER,
            "verified_at": now,
        }

    async def create_evidence_export(self, export: EvidenceExport) -> EvidenceExport:
        """Persist a new evidence export audit record."""
        self.session.add(export)
        await self.session.flush()
        return export

    async def get_evidence_export_by_id(self, export_id: UUID) -> EvidenceExport | None:
        """Retrieve an evidence export record by ID."""
        result = await self.session.execute(
            select(EvidenceExport).where(EvidenceExport.id == export_id)
        )
        return result.scalars().first()

    async def list_evidence_exports_paginated(
        self,
        *,
        department_id: UUID | None = None,
        incident_id: UUID | None = None,
        exported_by_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[EvidenceExport], int]:
        """List evidence export records with filtering and pagination."""
        if limit > 100:
            limit = 100
        if limit < 1:
            limit = 1

        predicates = []
        if department_id is not None:
            predicates.append(EvidenceExport.department_id == department_id)
        if incident_id is not None:
            predicates.append(EvidenceExport.incident_id == incident_id)
        if exported_by_id is not None:
            predicates.append(EvidenceExport.exported_by_id == exported_by_id)

        count_stmt = select(func.count(EvidenceExport.id))
        if predicates:
            count_stmt = count_stmt.where(*predicates)
        total_items = (await self.session.execute(count_stmt)).scalar_one()

        if total_items == 0:
            return [], 0

        query = select(EvidenceExport)
        if predicates:
            query = query.where(*predicates)
        query = query.order_by(EvidenceExport.created_at.desc()).limit(limit).offset(offset)
        items = (await self.session.execute(query)).scalars().all()
        return items, total_items
