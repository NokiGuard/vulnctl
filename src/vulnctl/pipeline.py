"""Enrichment pipeline: fan out to every registered adapter (FRAMEWORK.md §3.3).

Adapters run concurrently via ``asyncio.gather`` with per-adapter exception
capture: an adapter that *raises* (a bug — adapters are supposed to degrade
internally) turns into ``Unavailable(source_down)`` for every CVE rather than
failing the run (CLAUDE.md architecture rule 3).

Sources with no adapter yet (exploits in M5) are filled with
``Unavailable(not_found, "no adapter for this source yet")`` so the decision
path can still show why the field is empty.

OSV/GHSA keep-both policy: both sources' answers are first-class —
``Enrichment.versions`` carries OSV's ranges and ``Enrichment.advisory``
carries GHSA's complete answer verbatim. The only merged value is the
*canonical* ``versions`` view: OSV's data when it has any ranges, else
GHSA's, else whatever degradation OSV reported. When both sources produced
ranges and they disagree, OSV is used and the disagreement is recorded in
``RunMetadata.degradations`` — never resolved silently.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import httpx

import vulnctl.adapters  # noqa: F401  (imports register every bundled adapter)
from vulnctl import __version__
from vulnctl.adapters.base import SourceAdapter, SourceResult, all_adapters
from vulnctl.adapters.osv import OsvAdapter
from vulnctl.cache import Cache
from vulnctl.context import OrgContext
from vulnctl.ingest.cyclonedx import parse_sbom, resolve_findings
from vulnctl.ingest.grype import load_grype
from vulnctl.models import (
    CvssData,
    EnrichedFinding,
    Enrichment,
    EpssData,
    Finding,
    GhsaData,
    KevData,
    NvdData,
    RankedResult,
    RunMetadata,
    SourceMeta,
    Unavailable,
    UnavailableReason,
    VersionData,
)
from vulnctl.ssvc.engine import evaluate
from vulnctl.ssvc.tree import DecisionTree

_NO_ADAPTER = Unavailable(
    reason=UnavailableReason.NOT_FOUND, detail="no adapter for this source yet"
)


def _default_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(30.0), headers={"User-Agent": f"vulnctl/{__version__}"}
    )


async def enrich_findings(
    findings: list[Finding],
    *,
    cache: Cache,
    client: httpx.AsyncClient | None = None,
    offline: bool = False,
    extra_degradations: Iterable[str] = (),
) -> tuple[list[EnrichedFinding], RunMetadata]:
    """Enrich every finding from all registered adapters; never raises for a source.

    ``extra_degradations`` lets callers (the SBOM path) surface ingest-time
    warnings in the run metadata alongside per-source degradations.
    """
    cve_ids = list(dict.fromkeys(finding.cve_id for finding in findings))

    own_client = client is None
    if client is None:
        client = _default_client()
    try:
        adapters = [cls(client, cache, offline=offline) for cls in all_adapters()]
        raw = await asyncio.gather(
            *(adapter.fetch(cve_ids) for adapter in adapters), return_exceptions=True
        )
    finally:
        if own_client:
            await client.aclose()

    by_source: dict[str, dict[str, SourceResult]] = {}
    for adapter, outcome in zip(adapters, raw, strict=True):
        if isinstance(outcome, BaseException):
            by_source[adapter.name] = _adapter_crashed(adapter, cve_ids, outcome)
        else:
            by_source[adapter.name] = outcome

    results: list[EnrichedFinding] = []
    conflicts: dict[str, None] = {}  # ordered dedupe: duplicate findings, one note
    for finding in findings:
        enrichment, conflict = _assemble(finding.cve_id, by_source)
        if conflict is not None:
            conflicts.setdefault(conflict)
        results.append(EnrichedFinding(finding=finding, enrichment=enrichment))
    metadata = _run_metadata(
        by_source,
        cve_ids,
        offline=offline,
        extra_degradations=[*extra_degradations, *conflicts],
    )
    return results, metadata


async def enrich_sbom(
    sbom_path: Path,
    *,
    cache: Cache,
    client: httpx.AsyncClient | None = None,
    offline: bool = False,
) -> tuple[list[EnrichedFinding], RunMetadata]:
    """SBOM → packages → findings (OSV discovery) → enrichment, one client throughout.

    Raises:
        IngestError: on a malformed SBOM (fail loud on input); discovery and
            enrichment degradations surface in the run metadata instead.
    """
    packages, warnings = parse_sbom(sbom_path)
    own_client = client is None
    if client is None:
        client = _default_client()
    try:
        adapter = OsvAdapter(client, cache, offline=offline)
        findings, discovery_warnings = await resolve_findings(packages, adapter)
        return await enrich_findings(
            findings,
            cache=cache,
            client=client,
            offline=offline,
            extra_degradations=[*warnings, *discovery_warnings],
        )
    finally:
        if own_client:
            await client.aclose()


async def enrich_grype(
    source: str,
    *,
    cache: Cache,
    client: httpx.AsyncClient | None = None,
    offline: bool = False,
) -> tuple[list[EnrichedFinding], RunMetadata]:
    """Grype JSON (file path, or ``-`` for stdin) → findings → enrichment.

    Raises:
        IngestError: on malformed scanner output (fail loud on input).
    """
    findings, warnings = load_grype(source)
    return await enrich_findings(
        findings, cache=cache, client=client, offline=offline, extra_degradations=warnings
    )


def apply_tree(
    results: list[EnrichedFinding], context: OrgContext, tree: DecisionTree
) -> list[RankedResult]:
    """Evaluate every enrichment against the tree — pure glue around the engine."""
    return [
        RankedResult(
            finding=result.finding,
            enrichment=result.enrichment,
            verdict=evaluate(result.enrichment, context, tree),
        )
        for result in results
    ]


def _adapter_crashed(
    adapter: SourceAdapter, cve_ids: list[str], exc: BaseException
) -> dict[str, SourceResult]:
    failure = SourceResult(
        data=Unavailable(reason=UnavailableReason.SOURCE_DOWN, detail=f"adapter raised: {exc!r}"),
        meta=SourceMeta(source=adapter.name, fetched_at=datetime.now(UTC), cache_hit=False),
    )
    return dict.fromkeys(cve_ids, failure)


def _result_for(
    by_source: dict[str, dict[str, SourceResult]], source: str, cve_id: str
) -> SourceResult:
    """The adapter's answer, tolerating an adapter that omitted a CVE (a bug)."""
    result = by_source.get(source, {}).get(cve_id)
    if result is not None:
        return result
    return SourceResult(
        data=Unavailable(reason=UnavailableReason.SOURCE_DOWN, detail="adapter returned no answer"),
        meta=SourceMeta(source=source, fetched_at=datetime.now(UTC), cache_hit=False),
    )


def _assemble(
    cve_id: str, by_source: dict[str, dict[str, SourceResult]]
) -> tuple[Enrichment, str | None]:
    """Fuse one CVE's source answers; also returns an OSV/GHSA conflict note, if any."""
    epss = _result_for(by_source, "epss", cve_id)
    kev = _result_for(by_source, "kev", cve_id)
    nvd = _result_for(by_source, "nvd", cve_id)
    osv = _result_for(by_source, "osv", cve_id)
    ghsa = _result_for(by_source, "ghsa", cve_id)

    if isinstance(nvd.data, NvdData):
        cvss: CvssData | Unavailable = nvd.data.cvss
        cwes = nvd.data.cwes
    else:
        cvss = nvd.data if isinstance(nvd.data, Unavailable) else _NO_ADAPTER
        cwes = []

    advisory = ghsa.data if isinstance(ghsa.data, GhsaData | Unavailable) else _NO_ADAPTER
    osv_versions = osv.data if isinstance(osv.data, VersionData | Unavailable) else _NO_ADAPTER
    versions, conflict = _merge_versions(cve_id, osv_versions, advisory)

    enrichment = Enrichment(
        epss=epss.data if isinstance(epss.data, EpssData | Unavailable) else _NO_ADAPTER,
        kev=kev.data if isinstance(kev.data, KevData | Unavailable) else _NO_ADAPTER,
        cvss=cvss,
        cwes=cwes,
        versions=versions,
        advisory=advisory,
        exploits=_NO_ADAPTER,  # exploit-presence adapter arrives in M5
        provenance={
            "epss": epss.meta,
            "kev": kev.meta,
            "nvd": nvd.meta,
            "osv": osv.meta,
            "ghsa": ghsa.meta,
        },
    )
    return enrichment, conflict


def _has_ranges(data: VersionData | Unavailable) -> bool:
    return isinstance(data, VersionData) and bool(data.affected or data.fixed)


def _merge_versions(
    cve_id: str, osv_data: VersionData | Unavailable, advisory: GhsaData | Unavailable
) -> tuple[VersionData | Unavailable, str | None]:
    """Canonical ``versions`` per the keep-both policy (module docstring)."""
    ghsa_versions = advisory.versions if isinstance(advisory, GhsaData) else None
    if _has_ranges(osv_data):
        assert isinstance(osv_data, VersionData)
        if (
            ghsa_versions is not None
            and _has_ranges(ghsa_versions)
            and (set(ghsa_versions.affected), set(ghsa_versions.fixed))
            != (set(osv_data.affected), set(osv_data.fixed))
        ):
            return osv_data, f"ghsa: {cve_id} version ranges differ from osv (osv used)"
        return osv_data, None
    if ghsa_versions is not None and _has_ranges(ghsa_versions):
        return ghsa_versions, None
    return osv_data, None


def _run_metadata(
    by_source: dict[str, dict[str, SourceResult]],
    cve_ids: list[str],
    *,
    offline: bool,
    extra_degradations: Iterable[str] = (),
) -> RunMetadata:
    hit_rates: dict[str, float] = {}
    degradations: list[str] = list(extra_degradations)
    for source, answers in by_source.items():
        hits = sum(1 for r in answers.values() if r.meta.cache_hit)
        hit_rates[source] = hits / len(cve_ids) if cve_ids else 0.0
        for cve_id in cve_ids:
            data = answers[cve_id].data if cve_id in answers else None
            if isinstance(data, Unavailable) or data is None:
                reason = data.reason.value if isinstance(data, Unavailable) else "missing"
                degradations.append(f"{source}: {cve_id} unavailable ({reason})")
    return RunMetadata(
        sources=sorted(by_source),
        offline=offline,
        cache_hit_rate=hit_rates,
        degradations=sorted(degradations),
    )
