"""Rich terminal table for enriched findings.

Degraded data must be visibly degraded: ``Unavailable`` values render as a
dim ``n/a (reason)`` cell, never as a blank. Sorted by EPSS score descending
(decision-severity sort arrives with verdicts in M3); rows with no EPSS sink
to the bottom.
"""

from __future__ import annotations

from rich.table import Table

from vulnctl.models import (
    CvssData,
    EnrichedFinding,
    EpssData,
    KevData,
    RunMetadata,
    Unavailable,
)

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _na(value: Unavailable) -> str:
    return f"[dim]n/a ({value.reason.value.replace('_', ' ')})[/dim]"


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


def _sort_key(result: EnrichedFinding) -> tuple[int, float]:
    epss = result.enrichment.epss
    if isinstance(epss, EpssData):
        return (0, -epss.score)
    return (1, 0.0)


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


def build_table(results: list[EnrichedFinding], metadata: RunMetadata) -> Table:
    """Render enriched findings as a rich Table, highest EPSS first."""
    table = Table(title="vulnctl enrichment", caption=_caption(metadata))
    table.add_column("CVE", no_wrap=True)
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Exploits")

    for result in sorted(results, key=_sort_key):
        enrichment = result.enrichment
        table.add_row(
            result.finding.cve_id,
            _cvss_cell(enrichment.cvss),
            _epss_cell(enrichment.epss),
            _kev_cell(enrichment.kev),
            "[dim]—[/dim]",  # exploit-presence adapter arrives in M5
        )
    return table
