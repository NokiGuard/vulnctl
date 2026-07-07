"""Output layer: every formatter consumes the same enriched results + run metadata.

All formatters rank findings with :func:`result_sort_key` so the table, JSON,
SARIF, and Markdown outputs agree on order (FRAMEWORK.md §3.6): decision
severity desc → EPSS desc → CVSS desc, with unavailable scores sorting last.
"""

from __future__ import annotations

from vulnctl.models import CvssData, Decision, EpssData, RankedResult

__all__ = ["gate_exit_code", "result_sort_key"]


def result_sort_key(result: RankedResult) -> tuple[int, float, float]:
    """Sort key: most urgent decision first, tie-broken by EPSS then CVSS."""
    epss = result.enrichment.epss
    cvss = result.enrichment.cvss
    return (
        -result.verdict.decision.rank,
        -(epss.score if isinstance(epss, EpssData) else -1.0),
        -(cvss.base_score if isinstance(cvss, CvssData) else -1.0),
    )


def gate_exit_code(results: list[RankedResult], threshold: Decision | None) -> int:
    """CI-gate exit code (SPEC.md FR-17): 2 if any finding's decision meets or
    exceeds ``threshold``, else 0. ``None`` disables the gate (always 0)."""
    if threshold is None:
        return 0
    tripped = any(result.verdict.decision.rank >= threshold.rank for result in results)
    return 2 if tripped else 0
