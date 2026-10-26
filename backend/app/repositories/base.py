"""Core repository structural protocols enforcing tenant isolation and immutability (Phase 07).

These protocols exist strictly where structural typing provides a concrete security
guarantee:
1. `TenantScopedRepositoryProtocol`: Mandates `department_id: UUID` on entity lookups
   to prevent cross-department data leakage (`SEC-002`).
2. `AppendOnlyLedgerRepositoryProtocol`: Restricts audit and custody ledgers to
   append and scoped-read operations, omitting `update` and `delete` (`AUD-001`).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeVar, runtime_checkable
from uuid import UUID

TEntity_co = TypeVar("TEntity_co", covariant=True)
TEntry = TypeVar("TEntry")


@runtime_checkable
class TenantScopedRepositoryProtocol(Protocol[TEntity_co]):
    """Protocol requiring explicit ``department_id`` scoping on multi-tenant reads."""

    async def get_by_id(
        self,
        entity_id: UUID,
        *,
        department_id: UUID,
    ) -> TEntity_co | None:
        """Retrieve a single entity strictly scoped to ``department_id``."""

    async def list_for_department(
        self,
        *,
        department_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[TEntity_co]:
        """List entities strictly scoped to ``department_id``."""


@runtime_checkable
class AppendOnlyLedgerRepositoryProtocol(Protocol[TEntry]):
    """Protocol for immutable audit and chain-of-custody repositories (no update/delete)."""

    async def append(self, entry: TEntry) -> TEntry:
        """Persist a new immutable ledger entry."""

    async def list_by_department(
        self,
        *,
        department_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[TEntry]:
        """Retrieve ledger entries scoped to ``department_id``."""
