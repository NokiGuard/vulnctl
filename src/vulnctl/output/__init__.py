"""Output layer: every formatter consumes the same enriched results + run metadata.

All formatters rank findings with :func:`result_sort_key` so the table, JSON,
SARIF, and Markdown outputs agree on order (FRAMEWORK.md §3.6): decision
severity desc → EPSS desc → CVSS desc, with unavailable scores sorting last.
"""

from __future__ import annotations

import re

from vulnctl.models import (
    CvssData,
    Decision,
    EpssData,
    KevData,
    PackageRef,
    RankedResult,
    VersionData,
)

__all__ = [
    "DECISION_STYLE",
    "FIX_DISPLAY_CAP",
    "SEVERITY_STYLE",
    "degradation_groups",
    "display_fixes",
    "filter_results",
    "gate_exit_code",
    "result_sort_key",
    "short_purl",
]

#: Rich styles shared by the table and explain renderers.
DECISION_STYLE = {
    Decision.ACT: "bold red",
    Decision.ATTEND: "yellow",
    Decision.TRACK_STAR: "cyan",
    Decision.TRACK: "dim",
}
SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

#: The pipeline's per-finding degradation shape: "{source}: {id} unavailable ({reason})".
_DEGRADATION_RE = re.compile(r"^(?P<source>[a-z]+): \S+ unavailable \((?P<reason>[^)]+)\)$")

FIX_DISPLAY_CAP = 3
"""Fix entries shown inline in table/report cells; the rest fold into '+N more'."""


def result_sort_key(result: RankedResult) -> tuple[int, float, float]:
    """Sort key: most urgent decision first, tie-broken by EPSS then CVSS."""
    epss = result.enrichment.epss
    cvss = result.enrichment.cvss
    return (
        -result.verdict.decision.rank,
        -(epss.score if isinstance(epss, EpssData) else -1.0),
        -(cvss.base_score if isinstance(cvss, CvssData) else -1.0),
    )


def short_purl(package: PackageRef) -> str:
    """Compact display form of a purl: no ``pkg:`` prefix, qualifiers, or subpath.

    ``pkg:npm/lodash@4.17.20?arch=x64`` → ``npm/lodash@4.17.20``. The explicit
    ``version`` is appended when the purl itself doesn't already carry it.
    Returns plain text — each formatter applies its own escaping.
    """
    base = package.purl.split("#", 1)[0].split("?", 1)[0].removeprefix("pkg:")
    if package.version and not base.endswith(f"@{package.version}"):
        base = f"{base}@{package.version}"
    return base


def display_fixes(result: RankedResult) -> list[str]:
    """Fix versions for display, scoped to the finding and shortened.

    OSV fix entries read ``"<purl-or-name> <version>"``, one per affected
    sibling package (lodash, lodash-es, …). When the finding names its own
    package, that package's entries win and render as the bare version —
    the "upgrade to X" answer. Otherwise every entry is kept with the
    redundant ``pkg:`` scheme dropped. Deduplicated, order preserved.
    """
    versions = result.enrichment.versions
    if not isinstance(versions, VersionData):
        return []
    entries = [entry.removeprefix("pkg:") for entry in versions.fixed]
    if result.finding.package is not None:
        short = short_purl(result.finding.package)
        head, sep, tail = short.rpartition("@")
        base = head if sep and tail and "/" not in tail and head else short
        own = [e.removeprefix(f"{base} ") for e in entries if e.startswith(f"{base} ")]
        if own:
            entries = own
    return list(dict.fromkeys(entries))


def filter_results(
    results: list[RankedResult],
    *,
    min_decision: Decision | None = None,
    only_kev: bool = False,
    limit: int | None = None,
) -> list[RankedResult]:
    """Display filter shared by every output format: rank, threshold, cap.

    This shapes *output only* — ``--fail-on`` gating and the summary line's
    decision counts always see the unfiltered results, so filtering can never
    silently hide that an Act exists.
    """
    ranked = sorted(results, key=result_sort_key)
    if min_decision is not None:
        ranked = [r for r in ranked if r.verdict.decision.rank >= min_decision.rank]
    if only_kev:
        ranked = [
            r for r in ranked if isinstance(r.enrichment.kev, KevData) and r.enrichment.kev.listed
        ]
    if limit is not None:
        ranked = ranked[:limit]
    return ranked


def degradation_groups(degradations: list[str]) -> tuple[dict[tuple[str, str], int], list[str]]:
    """Group per-finding degradation strings for display.

    The pipeline emits one ``"{source}: {id} unavailable ({reason})"`` string
    per finding per source — thousands on a large offline run. Returns
    ``(groups, passthrough)``: counts keyed by ``(source, reason)`` for
    strings in that shape, and every other string (resolution notes, ingest
    warnings) verbatim in original order. JSON keeps the full flat list;
    only the human formats aggregate.
    """
    groups: dict[tuple[str, str], int] = {}
    passthrough: list[str] = []
    for entry in degradations:
        match = _DEGRADATION_RE.match(entry)
        if match is None:
            passthrough.append(entry)
        else:
            key = (match["source"], match["reason"])
            groups[key] = groups.get(key, 0) + 1
    return groups, passthrough


def gate_exit_code(results: list[RankedResult], threshold: Decision | None) -> int:
    """CI-gate exit code (SPEC.md FR-17): 2 if any finding's decision meets or
    exceeds ``threshold``, else 0. ``None`` disables the gate (always 0)."""
    if threshold is None:
        return 0
    tripped = any(result.verdict.decision.rank >= threshold.rank for result in results)
    return 2 if tripped else 0
