"""Pipeline integration tests: CVEs through all registered adapters, fixtures only."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from conftest import FIXTURES_DIR, LoadFixture, MakeClient
from vulnctl.adapters import base
from vulnctl.adapters.base import SourceAdapter, SourceResult
from vulnctl.cache import Cache
from vulnctl.context import OrgContext
from vulnctl.ingest import IngestError
from vulnctl.models import (
    CvssData,
    EpssData,
    ExploitData,
    Finding,
    GhsaData,
    IngestSource,
    KevData,
    Unavailable,
    UnavailableReason,
    VersionData,
)
from vulnctl.pipeline import _merge_versions, apply_tree, enrich_findings, enrich_sbom
from vulnctl.ssvc.tree import load_bundled_tree


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
        if host == "api.osv.dev":
            if request.url.path == "/v1/vulns/CVE-2021-44228":
                return httpx.Response(200, text=load_fixture("osv", "cve-2021-44228.json"))
            return httpx.Response(404, text=load_fixture("osv", "not-found.json"))
        if host == "api.github.com":
            if request.url.params.get("cve_id") == "CVE-2021-23337":
                return httpx.Response(200, text=load_fixture("ghsa", "advisory-by-cve.json"))
            return httpx.Response(200, text=load_fixture("ghsa", "not-found-empty-list.json"))
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
    assert set(log4shell.provenance) == {"epss", "ghsa", "kev", "nvd", "osv", "exploits"}
    assert isinstance(log4shell.versions, VersionData)
    # Exploit index (bundled) knows Log4Shell — real ExploitData, not degraded.
    assert isinstance(log4shell.exploits, ExploitData) and log4shell.exploits.msf_modules

    webp = results[1].enrichment
    assert isinstance(webp.kev, KevData) and webp.kev.listed and not webp.kev.ransomware
    assert isinstance(webp.cvss, CvssData) and webp.cvss.base_score == 8.8

    sendmail = results[2].enrichment
    # Heterogeneous degradation: no EPSS row, not in KEV, v2-only CVSS, no OSV record.
    assert isinstance(sendmail.epss, Unavailable)
    assert sendmail.epss.reason is UnavailableReason.NOT_FOUND
    assert isinstance(sendmail.kev, KevData) and sendmail.kev.listed is False
    assert isinstance(sendmail.cvss, CvssData) and sendmail.cvss.base_score == 10.0
    assert isinstance(sendmail.versions, Unavailable)
    assert sendmail.versions.reason is UnavailableReason.NOT_FOUND

    assert metadata.sources == ["epss", "exploits", "ghsa", "kev", "nvd", "osv"]
    assert metadata.offline is False
    assert metadata.cache_hit_rate == {
        "epss": 0.0,
        "exploits": 0.0,
        "ghsa": 0.0,
        "kev": 0.0,
        "nvd": 0.0,
        "osv": 0.0,
    }
    assert any("epss: CVE-1999-0095" in d for d in metadata.degradations)


async def test_second_run_hits_cache(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    findings = [_finding("CVE-2021-44228")]
    async with fixture_client(_live_router(load_fixture)) as client:
        await enrich_findings(findings, cache=cache, client=client)
        _, metadata = await enrich_findings(findings, cache=cache, client=client)

    assert metadata.cache_hit_rate == {
        "epss": 1.0,
        "exploits": 0.0,  # snapshot-only: never counts as a cache hit
        "ghsa": 0.0,
        "kev": 1.0,
        "nvd": 1.0,
        "osv": 1.0,
    }


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
    assert isinstance(enrichment.versions, Unavailable)  # OSV: cache-only, cold cache
    assert enrichment.versions.reason is UnavailableReason.OFFLINE
    assert isinstance(enrichment.advisory, Unavailable)  # GHSA: cache-only, cold cache
    assert enrichment.advisory.reason is UnavailableReason.OFFLINE
    # Exploit index is bundled, so it answers offline with real data.
    assert isinstance(enrichment.exploits, ExploitData) and enrichment.exploits.edb_ids
    assert metadata.offline is True


async def test_offline_poc_from_bundled_exploit_index(
    cache: Cache, fixture_client: MakeClient
) -> None:
    """CVE-2010-0017 is in the bundled exploit index but not KEV: offline, the
    resolver derives exploitation=poc from real ExploitData end-to-end."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline run must never touch the network")

    async with fixture_client(handler) as client:
        results, _ = await enrich_findings(
            [_finding("CVE-2010-0017")], cache=cache, client=client, offline=True
        )
        ranked = apply_tree(results, OrgContext(), load_bundled_tree())

    enrichment = results[0].enrichment
    assert isinstance(enrichment.kev, KevData) and enrichment.kev.listed is False
    assert isinstance(enrichment.exploits, ExploitData) and enrichment.exploits.msf_modules
    exploitation = ranked[0].verdict.path.steps[0]
    assert (exploitation.value, exploitation.value_source) == ("poc", "exploits")


def _sbom_router(load_fixture: LoadFixture) -> callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "api.osv.dev":
            if request.url.path == "/v1/querybatch":
                return httpx.Response(200, text=load_fixture("osv", "querybatch-npm-app.json"))
            if request.url.path == "/v1/vulns/GHSA-35jh-r3h4-6jhm":
                return httpx.Response(200, text=load_fixture("osv", "vuln-ghsa-with-cve.json"))
            return httpx.Response(404, text=load_fixture("osv", "not-found.json"))
        if host == "api.first.org":
            return httpx.Response(200, text=load_fixture("epss", "batch.json"))
        if host == "www.cisa.gov":
            return httpx.Response(200, text=load_fixture("kev", "catalog.json"))
        if host == "services.nvd.nist.gov":
            return httpx.Response(200, text=load_fixture("nvd", "not-found.json"))
        if host == "api.github.com":
            return httpx.Response(200, text=load_fixture("ghsa", "advisory-by-cve.json"))
        raise AssertionError(f"unexpected host {host!r}")

    return handler


async def test_sbom_end_to_end(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    sbom = FIXTURES_DIR / "sbom" / "npm-app.cdx.json"
    async with fixture_client(_sbom_router(load_fixture)) as client:
        results, metadata = await enrich_sbom(sbom, cache=cache, client=client)

    (result,) = results  # left-pad and the app itself are vuln-free
    finding = result.finding
    assert finding.cve_id == "CVE-2021-23337"
    assert finding.source is IngestSource.CYCLONEDX
    assert finding.package is not None
    assert finding.package.purl == "pkg:npm/lodash@4.17.20"
    assert "GHSA-35jh-r3h4-6jhm" in finding.aliases

    versions = result.enrichment.versions
    assert isinstance(versions, VersionData)
    assert "pkg:npm/lodash 4.17.21" in versions.fixed
    # Discovery already parsed and cached the record under the CVE key:
    # the enrichment fan-out's OSV call must be a cache hit, not a refetch.
    assert result.enrichment.provenance["osv"].cache_hit is True

    assert "sbom: skipped 1 component(s) without a purl" in metadata.degradations

    ranked = apply_tree(results, OrgContext(), load_bundled_tree())
    verdict = ranked[0].verdict
    assert verdict.tree_id == "cisa-deployer-v1"
    # Not KEV-listed and exploit data has no adapter yet: exploitation
    # falls to its default, so the verdict is visibly degraded.
    assert verdict.inputs_degraded is True


# --- OSV/GHSA keep-both merge -------------------------------------------------


_OSV_RANGES = VersionData(affected=["pkg:npm/lodash <4.17.21"], fixed=["pkg:npm/lodash 4.17.21"])
_GHSA_SAME = GhsaData(
    ghsa_id="GHSA-35jh-r3h4-6jhm", severity="high", summary="s", versions=_OSV_RANGES
)
_GHSA_DIFFERENT = GhsaData(
    ghsa_id="GHSA-35jh-r3h4-6jhm",
    severity="high",
    summary="s",
    versions=VersionData(affected=["pkg:npm/lodash <4.17.22"], fixed=["pkg:npm/lodash 4.17.22"]),
)
_EMPTY = VersionData()
_DOWN = Unavailable(reason=UnavailableReason.SOURCE_DOWN)


def test_merge_versions_osv_wins_and_agreement_is_silent() -> None:
    assert _merge_versions("CVE-1", _OSV_RANGES, _GHSA_SAME) == (_OSV_RANGES, None)


def test_merge_versions_disagreement_uses_osv_and_notes_it() -> None:
    versions, note = _merge_versions("CVE-2021-23337", _OSV_RANGES, _GHSA_DIFFERENT)
    assert versions == _OSV_RANGES
    assert note == "ghsa: CVE-2021-23337 version ranges differ from osv (osv used)"


def test_merge_versions_ghsa_fills_when_osv_empty_or_unavailable() -> None:
    assert _merge_versions("CVE-1", _EMPTY, _GHSA_DIFFERENT) == (
        _GHSA_DIFFERENT.versions,
        None,
    )
    assert _merge_versions("CVE-1", _DOWN, _GHSA_DIFFERENT) == (_GHSA_DIFFERENT.versions, None)


def test_merge_versions_nothing_available_keeps_osv_degradation() -> None:
    assert _merge_versions("CVE-1", _DOWN, _DOWN) == (_DOWN, None)
    assert _merge_versions("CVE-1", _EMPTY, _DOWN) == (_EMPTY, None)


async def test_ghsa_fills_canonical_versions_when_osv_has_only_git_ranges(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "api.osv.dev":
            # The CVE-native OSV record: GIT commit ranges only → empty VersionData.
            return httpx.Response(200, text=load_fixture("osv", "vuln-cve-record.json"))
        if host == "api.github.com":
            return httpx.Response(200, text=load_fixture("ghsa", "advisory-by-cve.json"))
        if host == "api.first.org":
            return httpx.Response(200, text=load_fixture("epss", "batch.json"))
        if host == "www.cisa.gov":
            return httpx.Response(200, text=load_fixture("kev", "catalog.json"))
        return httpx.Response(200, text=load_fixture("nvd", "not-found.json"))

    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            [_finding("CVE-2021-23337")], cache=cache, client=client
        )

    enrichment = results[0].enrichment
    assert isinstance(enrichment.versions, VersionData)
    assert "pkg:npm/lodash <4.17.21" in enrichment.versions.affected  # GHSA's ranges
    assert isinstance(enrichment.advisory, GhsaData)
    assert enrichment.advisory.summary == "Command Injection in lodash"
    assert not any("version ranges differ" in d for d in metadata.degradations)


async def test_osv_ghsa_disagreement_is_recorded_not_silent(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    import json

    # The recorded advisory, with one patched version altered so the two
    # sources genuinely disagree — exercises the conflict-note plumbing.
    tweaked = json.loads(load_fixture("ghsa", "advisory-by-cve.json"))
    tweaked[0]["vulnerabilities"][0]["first_patched_version"] = "4.17.22"
    tweaked[0]["vulnerabilities"][0]["vulnerable_version_range"] = "< 4.17.22"

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "api.osv.dev":
            # The GHSA-flavored OSV record: full SEMVER/ECOSYSTEM ranges.
            return httpx.Response(200, text=load_fixture("osv", "vuln-ghsa-with-cve.json"))
        if host == "api.github.com":
            return httpx.Response(200, text=json.dumps(tweaked))
        if host == "api.first.org":
            return httpx.Response(200, text=load_fixture("epss", "batch.json"))
        if host == "www.cisa.gov":
            return httpx.Response(200, text=load_fixture("kev", "catalog.json"))
        return httpx.Response(200, text=load_fixture("nvd", "not-found.json"))

    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            [_finding("CVE-2021-23337")], cache=cache, client=client
        )

    enrichment = results[0].enrichment
    assert isinstance(enrichment.versions, VersionData)
    assert "pkg:npm/lodash 4.17.21" in enrichment.versions.fixed  # OSV used
    assert isinstance(enrichment.advisory, GhsaData)
    assert "pkg:npm/lodash 4.17.22" in enrichment.advisory.versions.fixed  # GHSA kept
    assert "ghsa: CVE-2021-23337 version ranges differ from osv (osv used)" in metadata.degradations


async def test_sbom_malformed_is_hard_error(cache: Cache, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(IngestError, match="not valid JSON"):
        await enrich_sbom(bad, cache=cache)


async def test_duplicate_findings_fetch_once_but_answer_each(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    findings = [_finding("CVE-2021-44228"), _finding("CVE-2021-44228")]
    async with fixture_client(_live_router(load_fixture)) as client:
        results, _ = await enrich_findings(findings, cache=cache, client=client)

    assert len(results) == 2
    assert results[0].enrichment == results[1].enrichment
