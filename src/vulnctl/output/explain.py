"""Deep-dive renderer for one finding (``vulnctl explain``).

Everything the table format elides is shown here in full: every source's
answer with its provenance (fetched-at, cache hit), complete affected/fixed
version lists, CWEs, exploit artifact identifiers, the decision path, and
the counterfactuals — which single input changes would alter the verdict.

Strings that originate outside vulnctl (IDs, purls, advisory text, exploit
identifiers) are rich-markup-escaped, same rule as the table renderer.
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from vulnctl.models import (
    Counterfactual,
    CvssData,
    Enrichment,
    EpssData,
    ExploitData,
    GhsaData,
    KevData,
    RankedResult,
    RunMetadata,
    Unavailable,
    Verdict,
    VersionData,
)
from vulnctl.output import DECISION_STYLE, SEVERITY_STYLE, short_purl


def build_explain(
    result: RankedResult, metadata: RunMetadata, flips: list[Counterfactual]
) -> RenderableType:
    """One finding, in full: identity, verdict path, evidence, what-ifs."""
    blocks: list[RenderableType] = [_header(result), Text()]
    blocks.append(_verdict_block(result.verdict))
    blocks.extend((Text(), _evidence_table(result.enrichment)))
    blocks.extend((Text(), _counterfactual_block(result.verdict, flips)))
    footer = f"sources: {', '.join(metadata.sources)}"
    if metadata.offline:
        footer += " · offline mode"
    blocks.extend((Text(), Text(footer, style="dim")))
    return Group(*blocks)


def _header(result: RankedResult) -> RenderableType:
    finding = result.finding
    lines = [Text(finding.cve_id, style="bold")]
    if finding.aliases:
        lines.append(Text(f"also known as: {', '.join(finding.aliases)}", style="dim"))
    if finding.package is not None:
        lines.append(Text(f"package: {short_purl(finding.package)}", style="dim"))
    advisory = result.enrichment.advisory
    if isinstance(advisory, GhsaData) and advisory.summary:
        lines.append(Text(advisory.summary, style="italic"))
    return Group(*lines)


def _verdict_block(verdict: Verdict) -> RenderableType:
    header = Text("verdict: ")
    header.append(verdict.decision.value.upper(), style=DECISION_STYLE[verdict.decision])
    header.append(f"  (tree {verdict.tree_id})", style="dim")
    if verdict.inputs_degraded:
        header.append("  [degraded: defaults applied]", style="yellow")
    lines: list[RenderableType] = [header]
    width = max((len(step.node) for step in verdict.path.steps), default=0)
    for i, step in enumerate(verdict.path.steps, start=1):
        line = Text(f"  {i}. {step.node.ljust(width)} = {step.value}")
        style = "yellow" if step.value_source == "default" else "dim"
        line.append(f"  [{step.value_source}]", style=style)
        lines.append(line)
    return Group(*lines)


def _evidence_table(enrichment: Enrichment) -> Table:
    table = Table(title="evidence", title_justify="left", show_edge=False, pad_edge=False)
    table.add_column("Source", no_wrap=True)
    table.add_column("Answer", overflow="fold")
    table.add_column("Fetched", no_wrap=True)
    table.add_column("Cache", no_wrap=True)
    rows = {
        "epss": _epss_answer(enrichment.epss),
        "kev": _kev_answer(enrichment.kev),
        "nvd": _nvd_answer(enrichment.cvss, enrichment.cwes),
        "osv": _versions_answer(enrichment.versions),
        "ghsa": _advisory_answer(enrichment.advisory),
        "exploits": _exploits_answer(enrichment.exploits),
    }
    for source, answer in rows.items():
        meta = enrichment.provenance.get(source)
        fetched = meta.fetched_at.strftime("%Y-%m-%d %H:%M") if meta else "—"
        cache = ("hit" if meta.cache_hit else "miss") if meta else "—"
        table.add_row(source, answer, f"[dim]{fetched}[/dim]", f"[dim]{cache}[/dim]")
    return table


def _na(value: Unavailable) -> str:
    detail = f": {escape(value.detail)}" if value.detail else ""
    return f"[dim]n/a ({value.reason.value.replace('_', ' ')}{detail})[/dim]"


def _epss_answer(epss: EpssData | Unavailable) -> str:
    if isinstance(epss, Unavailable):
        return _na(epss)
    return f"{epss.score:.3f} (p{epss.percentile * 100:.1f}), scored {epss.date.isoformat()}"


def _kev_answer(kev: KevData | Unavailable) -> str:
    if isinstance(kev, Unavailable):
        return _na(kev)
    if not kev.listed:
        return "not listed"
    added = f", added {kev.date_added.isoformat()}" if kev.date_added else ""
    ransomware = " · [bold red]known ransomware use[/bold red]" if kev.ransomware else ""
    return f"[red]listed[/red]{added}{ransomware}"


def _nvd_answer(cvss: CvssData | Unavailable, cwes: list[str]) -> str:
    if isinstance(cvss, Unavailable):
        answer = _na(cvss)
    else:
        style = SEVERITY_STYLE.get(cvss.severity.upper(), "default")
        answer = f"{cvss.base_score:.1f} [{style}]{escape(cvss.severity)}[/{style}]"
        answer += f" — {escape(cvss.vector)}"
    if cwes:
        answer += f"\n{escape(', '.join(cwes))}"
    return answer


def _versions_answer(versions: VersionData | Unavailable) -> str:
    if isinstance(versions, Unavailable):
        return _na(versions)
    lines = []
    if versions.affected:
        lines.append(f"affected: {escape(', '.join(versions.affected))}")
    if versions.fixed:
        lines.append(f"fixed: [green]{escape(', '.join(versions.fixed))}[/green]")
    return "\n".join(lines) if lines else "no version ranges published"


def _advisory_answer(advisory: GhsaData | Unavailable) -> str:
    if isinstance(advisory, Unavailable):
        return _na(advisory)
    return f"{escape(advisory.ghsa_id)} (severity: {escape(advisory.severity)})"


def _exploits_answer(exploits: ExploitData | Unavailable) -> str:
    if isinstance(exploits, Unavailable):
        return _na(exploits)
    lines = []
    if exploits.edb_ids:
        lines.append(f"Exploit-DB: {escape(', '.join(exploits.edb_ids))}")
    if exploits.msf_modules:
        lines.append(f"Metasploit: {escape(', '.join(exploits.msf_modules))}")
    if exploits.nuclei_templates:
        lines.append(f"nuclei: {escape(', '.join(exploits.nuclei_templates))}")
    return "\n".join(lines) if lines else "none known"


def _counterfactual_block(verdict: Verdict, flips: list[Counterfactual]) -> RenderableType:
    title = Text("what would change this verdict (one input at a time):", style="bold")
    if not flips:
        return Group(title, Text("  no single input change alters this verdict", style="dim"))
    lines: list[RenderableType] = [title]
    width = max(len(f"{flip.node} = {flip.value}") for flip in flips)
    for flip in flips:
        line = Text(f"  {f'{flip.node} = {flip.value}'.ljust(width)}  → ")
        line.append(flip.decision.value.upper(), style=DECISION_STYLE[flip.decision])
        lines.append(line)
    return Group(*lines)
