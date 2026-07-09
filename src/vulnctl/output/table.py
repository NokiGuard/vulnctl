"""Rich terminal table for ranked findings.

Degraded data must be visibly degraded: ``Unavailable`` values render as a
dim ``n/a (reason)`` cell, never as a blank. Sort per FRAMEWORK.md §3.6:
decision severity desc → EPSS desc → CVSS desc; unavailable scores sort
below real ones within a tie. ``build_paths`` renders each finding's full
decision path (``--show-path``).

Strings that originate outside vulnctl — vulnerability IDs and purls from
scanner/SBOM files, severity labels from NVD — are rich-markup-escaped
before rendering: a hostile input file must not be able to restyle or
visually camouflage a row (e.g. dim an ACT verdict).
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from vulnctl.models import (
    CvssData,
    Decision,
    EpssData,
    ExploitData,
    KevData,
    PackageRef,
    RankedResult,
    RunMetadata,
    Unavailable,
)
from vulnctl.output import result_sort_key

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
    return f"{cvss.base_score:.1f} [{style}]{escape(cvss.severity)}[/{style}]"


def _epss_cell(epss: EpssData | Unavailable) -> str:
    if isinstance(epss, Unavailable):
        return _na(epss)
    return f"{epss.score:.3f} (p{epss.percentile * 100:.1f})"


def _package_cell(package: PackageRef | None) -> str:
    if package is None:
        return "[dim]—[/dim]"
    if package.version and not package.purl.endswith(f"@{package.version}"):
        return escape(f"{package.purl}@{package.version}")
    return escape(package.purl)


def _exploits_cell(exploits: ExploitData | Unavailable) -> str:
    if isinstance(exploits, Unavailable):
        return _na(exploits)
    counts = {
        "EDB": len(exploits.edb_ids),
        "MSF": len(exploits.msf_modules),
        "nuclei": len(exploits.nuclei_templates),
    }
    present = [f"{label}·{n}" for label, n in counts.items() if n]
    if not present:
        return "[dim]none[/dim]"
    return f"[red]{' '.join(present)}[/red]"


def _kev_cell(kev: KevData | Unavailable) -> str:
    if isinstance(kev, Unavailable):
        return _na(kev)
    if not kev.listed:
        return "no"
    added = f" {kev.date_added.isoformat()}" if kev.date_added is not None else ""
    ransomware = " [bold red]ransomware[/bold red]" if kev.ransomware else ""
    return f"[red]yes[/red]{added}{ransomware}"


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
    """Render ranked findings as a rich Table, most urgent decision first.

    A Package column appears only when a finding carries one (SBOM/scanner
    paths) — the CVE-list path stays as compact as before.
    """
    with_packages = any(result.finding.package is not None for result in results)
    table = Table(title="vulnctl enrichment", caption=_caption(metadata))
    table.add_column("CVE", no_wrap=True)
    if with_packages:
        table.add_column("Package", overflow="fold")
    table.add_column("Decision", no_wrap=True)
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Exploits")

    for result in sorted(results, key=result_sort_key):
        enrichment = result.enrichment
        row = [
            escape(result.finding.cve_id),
            _decision_cell(result.verdict.decision),
            _cvss_cell(enrichment.cvss),
            _epss_cell(enrichment.epss),
            _kev_cell(enrichment.kev),
            _exploits_cell(enrichment.exploits),
        ]
        if with_packages:
            row.insert(1, _package_cell(result.finding.package))
        table.add_row(*row)
    return table


def build_paths(results: list[RankedResult]) -> RenderableType:
    """Full decision path per finding (``--show-path``), in table order."""
    blocks: list[RenderableType] = [Text()]
    for result in sorted(results, key=result_sort_key):
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
