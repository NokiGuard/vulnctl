"""Enrichment pipeline: fan out to every registered adapter (FRAMEWORK.md §3.3).

Adapters run concurrently via ``asyncio.gather`` with per-adapter exception
capture: an adapter that *raises* (a bug — adapters are supposed to degrade
internally) turns into ``Unavailable(source_down)`` for every CVE rather than
failing the run (CLAUDE.md architecture rule 3).

Sources with no adapter yet (versions in M4, exploits in M5) are filled with
``Unavailable(not_found, "no adapter for this source yet")`` so the decision
path can still show why the field is empty.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx

import vulnctl.adapters  # noqa: F401  (imports register every bundled adapter)
from vulnctl import __version__
from vulnctl.adapters.base import SourceAdapter, SourceResult, all_adapters
from vulnctl.cache import Cache
from vulnctl.models import (
    CvssData,
    EnrichedFinding,
    Enrichment,
    EpssData,
    Finding,
    KevData,
    NvdData,
    RunMetadata,
    SourceMeta,
    Unavailable,
    UnavailableReason,
)

_NO_ADAPTER = Unavailable(
    reason=UnavailableReason.NOT_FOUND, detail="no adapter for this source yet"
)


async def enrich_findings(
    findings: list[Finding],
    *,
    cache: Cache,
    client: httpx.AsyncClient | None = None,
    offline: bool = False,
) -> tuple[list[EnrichedFinding], RunMetadata]:
    """Enrich every finding from all registered adapters; never raises for a source."""
    cve_ids = list(dict.fromkeys(finding.cve_id for finding in findings))

    own_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0), headers={"User-Agent": f"vulnctl/{__version__}"}
        )
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

    results = [
        EnrichedFinding(finding=finding, enrichment=_assemble(finding.cve_id, by_source))
        for finding in findings
    ]
    return results, _run_metadata(by_source, cve_ids, offline=offline)


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


def _assemble(cve_id: str, by_source: dict[str, dict[str, SourceResult]]) -> Enrichment:
    epss = _result_for(by_source, "epss", cve_id)
    kev = _result_for(by_source, "kev", cve_id)
    nvd = _result_for(by_source, "nvd", cve_id)

    if isinstance(nvd.data, NvdData):
        cvss: CvssData | Unavailable = nvd.data.cvss
        cwes = nvd.data.cwes
    else:
        cvss = nvd.data if isinstance(nvd.data, Unavailable) else _NO_ADAPTER
        cwes = []

    return Enrichment(
        epss=epss.data if isinstance(epss.data, EpssData | Unavailable) else _NO_ADAPTER,
        kev=kev.data if isinstance(kev.data, KevData | Unavailable) else _NO_ADAPTER,
        cvss=cvss,
        cwes=cwes,
        versions=_NO_ADAPTER,  # OSV/GHSA adapters arrive in M4
        exploits=_NO_ADAPTER,  # exploit-presence adapter arrives in M5
        provenance={"epss": epss.meta, "kev": kev.meta, "nvd": nvd.meta},
    )


def _run_metadata(
    by_source: dict[str, dict[str, SourceResult]], cve_ids: list[str], *, offline: bool
) -> RunMetadata:
    hit_rates: dict[str, float] = {}
    degradations: list[str] = []
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
