"""Rich terminal table for ranked findings.

Degraded data must be visibly degraded: ``Unavailable`` values render as a
dim ``n/a (reason)`` cell, never as a blank. Sort per FRAMEWORK.md §3.6:
decision severity desc → EPSS desc → CVSS desc; unavailable scores sort
below real ones within a tie. ``build_paths`` renders each finding's full
decision path (``--show-path``).
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from vulnctl.models import (
    CvssData,
    Decision,
    EpssData,
    KevData,
    RankedResult,
    RunMetadata,
    Unavailable,
)

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

_DECISION_STYLE = {
    Decision.ACT: "bold red",
    Decision.ATTEND: "yellow",
    Decision.TRACK_STAR: "cyan",
    Decision.TRACK: "dim",
}


def _na(value: Unavailable) -> str:
    return f"[dim]n/a ({value.reason.value.replace('_', ' ')})[/dim]"


def _decision_cell(decision: Decision) -> str:
    style = _DECISION_STYLE[decision]
    return f"[{style}]{decision.value.upper()}[/{style}]"


def _cvss_cell(cvss: CvssData | Unavailable) -> str:
    if isinstance(cvss, Unavailable):
        return _na(cvss)
    style = _SEVERITY_STYLE.get(cvss.severity.upper(), "default")
    return f"{cvss.base_score:.1f} [{style}]{cvss.severity}[/{style}]"


def _epss_cell(epss: EpssData | Unavailable) -> str:
    if isinstance(epss, Unavailable):
        return _na(epss)
    return f"{epss.score:.3f} (p{epss.percentile * 100:.1f})"


def _kev_cell(kev: KevData | Unavailable) -> str:
    if isinstance(kev, Unavailable):
        return _na(kev)
    if not kev.listed:
        return "no"
    added = f" {kev.date_added.isoformat()}" if kev.date_added is not None else ""
    ransomware = " [bold red]ransomware[/bold red]" if kev.ransomware else ""
    return f"[red]yes[/red]{added}{ransomware}"


def _sort_key(result: RankedResult) -> tuple[int, float, float]:
    epss = result.enrichment.epss
    cvss = result.enrichment.cvss
    return (
        -result.verdict.decision.rank,
        -(epss.score if isinstance(epss, EpssData) else -1.0),
        -(cvss.base_score if isinstance(cvss, CvssData) else -1.0),
    )


def _caption(metadata: RunMetadata) -> str:
    hits = ", ".join(
        f"{source} {rate:.0%}" for source, rate in sorted(metadata.cache_hit_rate.items())
    )
    parts = [f"sources: {', '.join(metadata.sources)}", f"cache hits: {hits}"]
    if metadata.degradations:
        parts.append(f"{len(metadata.degradations)} degraded field(s)")
    if metadata.offline:
        parts.append("offline mode")
    return " · ".join(parts)


def build_table(results: list[RankedResult], metadata: RunMetadata) -> Table:
    """Render ranked findings as a rich Table, most urgent decision first."""
    table = Table(title="vulnctl enrichment", caption=_caption(metadata))
    table.add_column("CVE", no_wrap=True)
    table.add_column("Decision", no_wrap=True)
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Exploits")

    for result in sorted(results, key=_sort_key):
        enrichment = result.enrichment
        table.add_row(
            result.finding.cve_id,
            _decision_cell(result.verdict.decision),
            _cvss_cell(enrichment.cvss),
            _epss_cell(enrichment.epss),
            _kev_cell(enrichment.kev),
            "[dim]—[/dim]",  # exploit-presence adapter arrives in M5
        )
    return table


def build_paths(results: list[RankedResult]) -> RenderableType:
    """Full decision path per finding (``--show-path``), in table order."""
    blocks: list[RenderableType] = [Text()]
    for result in sorted(results, key=_sort_key):
        verdict = result.verdict
        header = Text(result.finding.cve_id, style="bold")
        header.append(" → ")
        header.append(verdict.decision.value.upper(), style=_DECISION_STYLE[verdict.decision])
        header.append(f"  (tree {verdict.tree_id})", style="dim")
        if verdict.inputs_degraded:
            header.append("  [degraded: defaults applied]", style="yellow")
        blocks.append(header)
        width = max((len(step.node) for step in verdict.path.steps), default=0)
        for i, step in enumerate(verdict.path.steps, start=1):
            line = Text(f"  {i}. {step.node.ljust(width)} = {step.value}")
            style = "yellow" if step.value_source == "default" else "dim"
            line.append(f"  [{step.value_source}]", style=style)
            blocks.append(line)
    return Group(*blocks)
