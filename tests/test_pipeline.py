"""Pipeline integration tests: CVEs through all three adapters, fixtures only."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from conftest import LoadFixture, MakeClient
from vulnctl.adapters import base
from vulnctl.adapters.base import SourceAdapter, SourceResult
from vulnctl.cache import Cache
from vulnctl.models import (
    CvssData,
    EpssData,
    Finding,
    IngestSource,
    KevData,
    Unavailable,
    UnavailableReason,
)
from vulnctl.pipeline import enrich_findings


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


def _finding(cve_id: str) -> Finding:
    return Finding(cve_id=cve_id, source=IngestSource.CLI)


def _live_router(load_fixture: LoadFixture) -> callable[[httpx.Request], httpx.Response]:
    nvd_fixtures = {
        "CVE-2021-44228": "cve-2021-44228.json",
        "CVE-2023-4863": "multiple-cvss.json",
        "CVE-1999-0095": "v2-only.json",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "api.first.org":
            return httpx.Response(200, text=load_fixture("epss", "batch.json"))
        if host == "www.cisa.gov":
            return httpx.Response(200, text=load_fixture("kev", "catalog.json"))
        if host == "services.nvd.nist.gov":
            name = nvd_fixtures[request.url.params["cveId"]]
            return httpx.Response(200, text=load_fixture("nvd", name))
        raise AssertionError(f"unexpected host {host!r}")

    return handler


async def test_three_cves_through_all_three_adapters(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    findings = [_finding("CVE-2021-44228"), _finding("CVE-2023-4863"), _finding("CVE-1999-0095")]
    async with fixture_client(_live_router(load_fixture)) as client:
        results, metadata = await enrich_findings(findings, cache=cache, client=client)

    assert [r.finding.cve_id for r in results] == [f.cve_id for f in findings]

    log4shell = results[0].enrichment
    assert isinstance(log4shell.epss, EpssData) and log4shell.epss.score == 0.99999
    assert isinstance(log4shell.kev, KevData) and log4shell.kev.ransomware is True
    assert isinstance(log4shell.cvss, CvssData) and log4shell.cvss.severity == "CRITICAL"
    assert log4shell.cwes == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]
    assert set(log4shell.provenance) == {"epss", "kev", "nvd"}
    # Sources without adapters yet are explicitly degraded, not silently empty.
    assert isinstance(log4shell.versions, Unavailable)
    assert isinstance(log4shell.exploits, Unavailable)

    webp = results[1].enrichment
    assert isinstance(webp.kev, KevData) and webp.kev.listed and not webp.kev.ransomware
    assert isinstance(webp.cvss, CvssData) and webp.cvss.base_score == 8.8

    sendmail = results[2].enrichment
    # Heterogeneous degradation: no EPSS row, not in KEV, v2-only CVSS.
    assert isinstance(sendmail.epss, Unavailable)
    assert sendmail.epss.reason is UnavailableReason.NOT_FOUND
    assert isinstance(sendmail.kev, KevData) and sendmail.kev.listed is False
    assert isinstance(sendmail.cvss, CvssData) and sendmail.cvss.base_score == 10.0

    assert metadata.sources == ["epss", "kev", "nvd"]
    assert metadata.offline is False
    assert metadata.cache_hit_rate == {"epss": 0.0, "kev": 0.0, "nvd": 0.0}
    assert any("epss: CVE-1999-0095" in d for d in metadata.degradations)


async def test_second_run_hits_cache(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    findings = [_finding("CVE-2021-44228")]
    async with fixture_client(_live_router(load_fixture)) as client:
        await enrich_findings(findings, cache=cache, client=client)
        _, metadata = await enrich_findings(findings, cache=cache, client=client)

    assert metadata.cache_hit_rate == {"epss": 1.0, "kev": 1.0, "nvd": 1.0}


async def test_adapter_exception_degrades_never_crashes(
    cache: Cache, fixture_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class CrashingAdapter(SourceAdapter):
        name = "epss"
        ttl = timedelta(hours=1)
        supports_offline = False

        async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
            raise RuntimeError("adapter bug")

    monkeypatch.setattr(base, "_REGISTRY", {"epss": CrashingAdapter})

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no adapter should reach the network")

    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            [_finding("CVE-2021-44228")], cache=cache, client=client
        )

    epss = results[0].enrichment.epss
    assert isinstance(epss, Unavailable)
    assert epss.reason is UnavailableReason.SOURCE_DOWN
    assert epss.detail is not None and "adapter raised" in epss.detail
    assert metadata.sources == ["epss"]
    assert len(metadata.degradations) == 1


async def test_offline_end_to_end_from_snapshots(cache: Cache, fixture_client: MakeClient) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline run must never touch the network")

    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            [_finding("CVE-2021-44228")], cache=cache, client=client, offline=True
        )

    enrichment = results[0].enrichment
    assert isinstance(enrichment.epss, EpssData)  # bundled CSV snapshot
    assert isinstance(enrichment.kev, KevData) and enrichment.kev.listed  # bundled catalog
    assert isinstance(enrichment.cvss, Unavailable)  # NVD: cache-only, cold cache
    assert enrichment.cvss.reason is UnavailableReason.OFFLINE
    assert metadata.offline is True


async def test_duplicate_findings_fetch_once_but_answer_each(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    findings = [_finding("CVE-2021-44228"), _finding("CVE-2021-44228")]
    async with fixture_client(_live_router(load_fixture)) as client:
        results, _ = await enrich_findings(findings, cache=cache, client=client)

    assert len(results) == 2
    assert results[0].enrichment == results[1].enrichment
