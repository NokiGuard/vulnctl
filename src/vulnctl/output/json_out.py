"""Machine-readable JSON output (SPEC.md FR-14).

Emits the complete run under a top-level ``schema_version`` so consumers can
pin to a shape: every finding, its full enrichment (each source field is
either the data object or an ``{"reason": ...}`` :class:`Unavailable` marker),
the verdict with its entire decision path, and run metadata.

The output is one :class:`JsonReport` — using a Pydantic model for the
envelope means the same definition serializes the report and generates the
JSON Schema documented in ``docs/schema.md`` (see ``schema()``), so the two
cannot drift.

Discriminating a present value from an unavailable one: an ``Unavailable``
marker is the only enrichment shape carrying a ``reason`` key. No data model
has that field, so ``"reason" in value`` is a reliable test.
"""

from __future__ import annotations

from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict

from vulnctl.models import RankedResult, RunMetadata
from vulnctl.output import result_sort_key

SCHEMA_VERSION: Final = "1"


class JsonReport(BaseModel):
    """Top-level JSON document: schema version, run metadata, ranked results."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    schema_version: Literal["1"] = SCHEMA_VERSION
    run: RunMetadata
    results: list[RankedResult]


def build_report(results: list[RankedResult], metadata: RunMetadata) -> JsonReport:
    """Assemble the report envelope with results in canonical rank order."""
    return JsonReport(run=metadata, results=sorted(results, key=result_sort_key))


def render_json(results: list[RankedResult], metadata: RunMetadata) -> str:
    """Serialize the ranked results to a stable, indented JSON string."""
    return build_report(results, metadata).model_dump_json(indent=2) + "\n"


def schema() -> dict[str, Any]:
    """JSON Schema for :class:`JsonReport` — the source of truth for docs/schema.md."""
    return JsonReport.model_json_schema()
