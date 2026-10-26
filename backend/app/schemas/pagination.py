"""Standardized pagination, sorting, and filtering request/response schemas (Phase 25).

Provides uniform pagination parameters and response envelopes for list endpoints:
- 1-indexed page numbering (`page >= 1`).
- Bounded page sizes (`1 <= page_size <= 100`, default 20).
- Deterministic pagination metadata calculation (`total_items`, `total_pages`, `has_next`, `has_prev`).
- Generic paginated response envelope `PaginatedResponse[ItemT]`.
"""

from __future__ import annotations

import math
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SortOrder(StrEnum):
    """Sort direction enumeration for list query parameters."""

    ASC = "asc"
    DESC = "desc"


class PaginationParams(BaseModel):
    """Standardized query parameters for paginated collection endpoints."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "page": 1,
                "page_size": 20,
            }
        },
    )

    page: int = Field(
        default=1,
        ge=1,
        description="1-indexed page number.",
    )
    page_size: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of items per page (bounded 1-100, default 20).",
    )

    @property
    def offset(self) -> int:
        """Calculate zero-indexed SQL offset."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """SQL limit matching page_size."""
        return self.page_size


class PaginationMetadata(BaseModel):
    """Standard pagination envelope metadata for client consumption."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "example": {
                "page": 1,
                "page_size": 20,
                "total_items": 42,
                "total_pages": 3,
                "has_next": True,
                "has_prev": False,
            }
        },
    )

    page: int = Field(..., ge=1, description="Current 1-indexed page number.")
    page_size: int = Field(..., ge=1, le=100, description="Items per page requested.")
    total_items: int = Field(..., ge=0, description="Total matching items across all pages.")
    total_pages: int = Field(..., ge=0, description="Total number of available pages.")
    has_next: bool = Field(..., description="Whether a subsequent page exists.")
    has_prev: bool = Field(..., description="Whether a preceding page exists.")

    @classmethod
    def from_counts(
        cls,
        *,
        page: int,
        page_size: int,
        total_items: int,
    ) -> PaginationMetadata:
        """Compute pagination metadata from current page, size, and total record count."""
        total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0
        has_next = page < total_pages
        has_prev = page > 1 and total_items > 0
        return cls(
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_next=has_next,
            has_prev=has_prev,
        )


class PaginatedResponse[ItemT](BaseModel):
    """Generic envelope schema for paginated resource collections."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "items": [],
                "pagination": {
                    "page": 1,
                    "page_size": 20,
                    "total_items": 0,
                    "total_pages": 0,
                    "has_next": False,
                    "has_prev": False,
                },
            }
        },
    )

    items: list[ItemT] = Field(..., description="Collection of items for the requested page.")
    pagination: PaginationMetadata = Field(..., description="Pagination metadata.")
