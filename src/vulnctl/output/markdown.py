"""Stakeholder-facing Markdown report (SPEC.md FR-16).

Plain language up top — decision counts, KEV exposure, a degraded-input note —
then a top-10 table, then a per-finding appendix carrying the full decision
path for anyone who needs to audit a verdict. No timestamps or provenance
noise: the report is written to be read by a person, and to be diffable/golden
so tests can pin it to bundled-snapshot data.
"""

from __future__ import annotations

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

_DECISION_LABEL = {
    Decision.ACT: "Act",
    Decision.ATTEND: "Attend",
    Decision.TRACK_STAR: "Track*",
    Decision.TRACK: "Track",
}
_TOP_N = 10


def _na(value: Unavailable) -> str:
    return f"n/a ({value.reason.value.replace('_', ' ')})"


def _cvss(cvss: CvssData | Unavailable) -> str:
    return _na(cvss) if isinstance(cvss, Unavailable) else f"{cvss.base_score:.1f} {cvss.severity}"


def _epss(epss: EpssData | Unavailable) -> str:
    return _na(epss) if isinstance(epss, Unavailable) else f"{epss.score:.3f}"


def _kev(kev: KevData | Unavailable) -> str:
    if isinstance(kev, Unavailable):
        return _na(kev)
    if not kev.listed:
        return "no"
    return "yes (ransomware)" if kev.ransomware else "yes"


def _exploits(exploits: ExploitData | Unavailable) -> str:
    if isinstance(exploits, Unavailable):
        return _na(exploits)
    counts = {"EDB": len(exploits.edb_ids), "MSF": len(exploits.msf_modules)}
    counts["nuclei"] = len(exploits.nuclei_templates)
    present = [f"{k}·{n}" for k, n in counts.items() if n]
    return " ".join(present) if present else "none"


def _package(package: PackageRef | None) -> str:
    if package is None:
        return "—"
    if package.version and not package.purl.endswith(f"@{package.version}"):
        return f"{package.purl}@{package.version}"
    return package.purl


def _summary(ranked: list[RankedResult], metadata: RunMetadata) -> list[str]:
    counts: dict[Decision, int] = dict.fromkeys(Decision, 0)
    kev_count = 0
    degraded = 0
    for result in ranked:
        counts[result.verdict.decision] += 1
        if isinstance(result.enrichment.kev, KevData) and result.enrichment.kev.listed:
            kev_count += 1
        if result.verdict.inputs_degraded:
            degraded += 1

    breakdown = ", ".join(
        f"{counts[d]} {_DECISION_LABEL[d].lower()}"
        for d in (Decision.ACT, Decision.ATTEND, Decision.TRACK_STAR, Decision.TRACK)
    )
    lines = [
        f"- **{len(ranked)} finding(s):** {breakdown}",
        f"- **KEV exposure:** {kev_count} finding(s) on CISA's Known Exploited "
        "Vulnerabilities catalog",
    ]
    if degraded:
        lines.append(
            f"- **Degraded inputs:** {degraded} verdict(s) fell back to a tree default; "
            "see the appendix for which step and why."
        )
    if metadata.offline:
        lines.append(
            "- _Generated in offline mode: some sources answered from cache/snapshot only._"
        )
    return lines


def _highlights(ranked: list[RankedResult]) -> list[str]:
    """The findings a stakeholder should look at first: Act, or KEV-listed."""
    lines: list[str] = []
    for result in ranked:
        kev = result.enrichment.kev
        kev_listed = isinstance(kev, KevData) and kev.listed
        if result.verdict.decision is not Decision.ACT and not kev_listed:
            continue
        flags = [_DECISION_LABEL[result.verdict.decision]]
        if isinstance(kev, KevData) and kev.listed:
            flags.append("KEV-listed (ransomware)" if kev.ransomware else "KEV-listed")
        epss = result.enrichment.epss
        if isinstance(epss, EpssData):
            flags.append(f"EPSS {epss.score:.3f}")
        where = f" — {_package(result.finding.package)}" if result.finding.package else ""
        lines.append(f"- **{result.finding.cve_id}** — {', '.join(flags)}{where}")
    return lines


def _table(ranked: list[RankedResult]) -> list[str]:
    with_pkg = any(r.finding.package is not None for r in ranked)
    header = ["#", "CVE", "Decision", "CVSS", "EPSS", "KEV", "Exploits"]
    if with_pkg:
        header.append("Package")
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for i, result in enumerate(ranked[:_TOP_N], start=1):
        e = result.enrichment
        row = [
            str(i),
            result.finding.cve_id,
            _DECISION_LABEL[result.verdict.decision],
            _cvss(e.cvss),
            _epss(e.epss),
            _kev(e.kev),
            _exploits(e.exploits),
        ]
        if with_pkg:
            row.append(_package(result.finding.package))
        lines.append("| " + " | ".join(row) + " |")
    return lines


def _appendix(ranked: list[RankedResult]) -> list[str]:
    lines: list[str] = []
    for result in ranked:
        verdict = result.verdict
        degraded = "  _(degraded: defaults applied)_" if verdict.inputs_degraded else ""
        lines.append(
            f"### {result.finding.cve_id} → {_DECISION_LABEL[verdict.decision]}"
            f"  (tree `{verdict.tree_id}`){degraded}"
        )
        if result.finding.package is not None:
            lines.append(f"- package: `{_package(result.finding.package)}`")
        lines.append("- decision path:")
        for step in verdict.path.steps:
            lines.append(f"  - `{step.node}` = `{step.value}` _({step.value_source})_")
        lines.append("")
    return lines


def render_markdown(results: list[RankedResult], metadata: RunMetadata) -> str:
    """Render ranked results as a stakeholder Markdown report."""
    ranked = sorted(results, key=result_sort_key)
    parts: list[str] = ["# vulnctl report", ""]
    parts += ["## Summary", "", *_summary(ranked, metadata), ""]

    highlights = _highlights(ranked)
    parts += ["## Highlights", ""]
    parts += highlights if highlights else ["_No Act verdicts or KEV-listed findings._"]
    parts += [""]

    top_heading = f"## Top {min(_TOP_N, len(ranked))} findings by priority"
    parts += [top_heading, "", *_table(ranked), ""]
    parts += ["## Appendix — all findings", "", *_appendix(ranked)]
    return "\n".join(parts).rstrip() + "\n"
