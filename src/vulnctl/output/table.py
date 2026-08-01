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

from collections import Counter

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from vulnctl.models import (
    CvssData,
    Decision,
    EpssData,
    ExploitData,
    GhsaData,
    KevData,
    PackageRef,
    RankedResult,
    RunMetadata,
    Unavailable,
)
from vulnctl.output import (
    DECISION_STYLE as _DECISION_STYLE,
)
from vulnctl.output import (
    FIX_DISPLAY_CAP,
    degradation_groups,
    display_fixes,
    result_sort_key,
    short_purl,
)
from vulnctl.output import (
    SEVERITY_STYLE as _SEVERITY_STYLE,
)


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
    return escape(short_purl(package))


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
    # The date-added detail lives in JSON/`--show-path`; the cell stays narrow.
    if isinstance(kev, Unavailable):
        return _na(kev)
    if not kev.listed:
        return "no"
    ransomware = " [bold red]ransomware[/bold red]" if kev.ransomware else ""
    return f"[red]yes[/red]{ransomware}"


def _fix_cell(result: RankedResult) -> str:
    versions = result.enrichment.versions
    if isinstance(versions, Unavailable):
        return _na(versions)
    fixes = display_fixes(result)
    if not fixes:
        return "[dim]—[/dim]"
    shown = f"[green]{escape(', '.join(fixes[:FIX_DISPLAY_CAP]))}[/green]"
    extra = len(fixes) - FIX_DISPLAY_CAP
    return f"{shown} [dim]+{extra} more[/dim]" if extra > 0 else shown


def _summary_cell(advisory: GhsaData | Unavailable) -> str:
    if isinstance(advisory, Unavailable):
        return _na(advisory)
    return escape(advisory.summary)


def _caption(metadata: RunMetadata) -> str:
    # Per-source hit rates stay in JSON; the caption carries one aggregate.
    parts = [f"sources: {', '.join(metadata.sources)}"]
    if metadata.cache_hit_rate:
        avg = sum(metadata.cache_hit_rate.values()) / len(metadata.cache_hit_rate)
        parts.append(f"cache hits: {avg:.0%} avg")
    if metadata.degradations:
        parts.append(_degraded_part(metadata.degradations))
    if metadata.offline:
        parts.append("offline mode")
    return " · ".join(parts)


def _degraded_part(degradations: list[str]) -> str:
    """Grouped one-part degradation summary: 3 000 strings must not become
    3 000 caption characters. Full detail stays in JSON."""
    groups, other = degradation_groups(degradations)
    entries = [
        f"{source} {count} ({reason.replace('_', ' ')})"
        for (source, reason), count in sorted(groups.items())
    ]
    if other:
        entries.append(f"{len(other)} note(s)")
    shown = entries[:3]
    if len(entries) > 3:
        shown.append(f"+{len(entries) - 3} more")
    return f"degraded: {', '.join(shown)}"


def build_summary(results: list[RankedResult], *, shown: int | None = None) -> Text:
    """One-line verdict rollup — the run's headline, printed last so it lands
    next to the prompt: counts per decision (zeros omitted) plus KEV exposure.

    Counts always cover the *unfiltered* results; ``shown`` (when it differs)
    marks how many rows the display filters let through — a hidden Act must
    still appear in this line.
    """
    counts = Counter(result.verdict.decision for result in results)
    line = Text(f"{len(results)} finding(s)")
    if shown is not None and shown != len(results):
        line.append(f" (showing {shown})", style="dim")
    for decision in (Decision.ACT, Decision.ATTEND, Decision.TRACK_STAR, Decision.TRACK):
        if counts[decision]:
            line.append(" · ")
            line.append(
                f"{counts[decision]} {decision.value.upper()}", style=_DECISION_STYLE[decision]
            )
    kev_listed = sum(
        1
        for result in results
        if isinstance(result.enrichment.kev, KevData) and result.enrichment.kev.listed
    )
    if kev_listed:
        line.append(" · ")
        line.append(f"{kev_listed} KEV-listed", style="red")
    return line


def build_table(results: list[RankedResult], metadata: RunMetadata) -> Table:
    """Render ranked findings as a rich Table, most urgent decision first.

    Package, Fix, and Summary columns appear only when some finding has the
    data (SBOM/scanner paths, OSV/GHSA answers) — a bare CVE-list or offline
    run stays as compact as before.
    """
    with_packages = any(result.finding.package is not None for result in results)
    with_fixes = any(display_fixes(result) for result in results)
    with_summaries = any(isinstance(result.enrichment.advisory, GhsaData) for result in results)
    table = Table(title="vulnctl enrichment", caption=_caption(metadata))
    table.add_column("CVE", no_wrap=True)
    if with_packages:
        table.add_column("Package", overflow="fold")
    table.add_column("Decision", no_wrap=True)
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Exploits")
    if with_fixes:
        table.add_column("Fix", overflow="fold")
    if with_summaries:
        table.add_column("Summary", max_width=48)

    previous: Decision | None = None
    for result in sorted(results, key=result_sort_key):
        if previous is not None and result.verdict.decision is not previous:
            table.add_section()  # visual break between decision tiers
        previous = result.verdict.decision
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
        if with_fixes:
            row.append(_fix_cell(result))
        if with_summaries:
            row.append(_summary_cell(enrichment.advisory))
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
