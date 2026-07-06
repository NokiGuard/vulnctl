"""OSV adapter tests, driven entirely by recorded fixtures.

The querybatch fixture was recorded for the five packages in ``PACKAGES``
below (in that order) and trimmed to one vulnerability per package so each
detail record has its own fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from conftest import LoadFixture, MakeClient
from vulnctl.adapters.osv import (
    OsvAdapter,
    _canonical_id,
    _parse_versions,
    _split_purl,
)
from vulnctl.cache import Cache
from vulnctl.models import PackageRef, Unavailable, UnavailableReason, VersionData

# Order matches the recorded querybatch fixture.
PACKAGES = [
    PackageRef(purl="pkg:npm/lodash", version="4.17.20"),
    PackageRef(purl="pkg:pypi/jinja2", version="2.4.1"),
    PackageRef(purl="pkg:golang/github.com/gin-gonic/gin", version="1.5.0"),
    PackageRef(purl="pkg:npm/left-pad", version="1.3.0"),
    PackageRef(purl="pkg:npm/event-stream", version="3.3.6"),
]

_VULN_FIXTURES = {
    "GHSA-35jh-r3h4-6jhm": "vuln-ghsa-with-cve.json",  # lodash; alias CVE-2021-23337
    "PYSEC-2021-66": "vuln-pypi.json",  # jinja2; alias CVE-2020-28493
    "GHSA-h395-qcrw-5vmq": "vuln-go.json",  # gin; alias CVE-2020-28483
    "GHSA-mh6f-8j2x-4483": "vuln-ghsa-no-cve.json",  # event-stream; no CVE alias
    "CVE-2021-23337": "vuln-cve-record.json",  # CVE-native record, GIT ranges only
}


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


class Router:
    """Route querybatch POSTs and per-vuln GETs to recorded fixtures."""

    def __init__(self, load_fixture: LoadFixture, *, detail_status: int = 200) -> None:
        self._load = load_fixture
        self._detail_status = detail_status
        self.querybatch_calls = 0
        self.detail_calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.osv.dev"
        if request.url.path == "/v1/querybatch":
            self.querybatch_calls += 1
            return httpx.Response(200, text=self._load("osv", "querybatch.json"))
        if request.url.path.startswith("/v1/vulns/"):
            self.detail_calls += 1
            if self._detail_status != 200:
                return httpx.Response(self._detail_status)
            vuln_id = request.url.path.rsplit("/", 1)[1]
            name = _VULN_FIXTURES.get(vuln_id)
            if name is None:
                return httpx.Response(404, text=self._load("osv", "not-found.json"))
            return httpx.Response(200, text=self._load("osv", name))
        raise AssertionError(f"unexpected path {request.url.path!r}")


# --- fetch(): the standard enrichment contract ---------------------------------


async def test_fetch_returns_version_ranges(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["GHSA-35jh-r3h4-6jhm"])

    data = results["GHSA-35jh-r3h4-6jhm"].data
    assert isinstance(data, VersionData)
    assert "pkg:npm/lodash <4.17.21" in data.affected
    assert "pkg:npm/lodash 4.17.21" in data.fixed


async def test_fetch_cve_native_record_with_only_git_ranges_is_empty_not_unavailable(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    # The CVE-native record publishes only GIT commit ranges, which are
    # skipped: an empty VersionData is a real answer, distinct from Unavailable.
    async with fixture_client(Router(load_fixture)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, VersionData)
    assert data.affected == []
    assert data.fixed == []


async def test_fetch_unknown_id_is_not_found(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["CVE-9999-99999"])

    data = results["CVE-9999-99999"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.NOT_FOUND


async def test_fetch_caches(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    router = Router(load_fixture)
    async with fixture_client(router) as client:
        adapter = OsvAdapter(client, cache)
        first = await adapter.fetch(["GHSA-35jh-r3h4-6jhm"])
        second = await adapter.fetch(["GHSA-35jh-r3h4-6jhm"])

    assert router.detail_calls == 1
    assert first["GHSA-35jh-r3h4-6jhm"].meta.cache_hit is False
    assert second["GHSA-35jh-r3h4-6jhm"].meta.cache_hit is True
    assert second["GHSA-35jh-r3h4-6jhm"].data == first["GHSA-35jh-r3h4-6jhm"].data


async def test_fetch_offline_cold_cache_degrades(cache: Cache, fixture_client: MakeClient) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = OsvAdapter(client, cache, offline=True)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.OFFLINE


async def test_fetch_rate_limited(cache: Cache, fixture_client: MakeClient) -> None:
    async with fixture_client(lambda request: httpx.Response(429)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.RATE_LIMITED


async def test_fetch_server_error_degrades_to_source_down(
    cache: Cache, fixture_client: MakeClient
) -> None:
    async with fixture_client(lambda request: httpx.Response(503)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_fetch_malformed_response_degrades(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("osv", "malformed.json")
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_fetch_oversized_response_degrades(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnctl.adapters import base

    monkeypatch.setattr(base, "MAX_RESPONSE_BYTES", 16)
    async with fixture_client(Router(load_fixture)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.fetch(["GHSA-35jh-r3h4-6jhm"])

    data = results["GHSA-35jh-r3h4-6jhm"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


# --- query_packages(): the SBOM discovery path ----------------------------------


async def test_query_packages_across_ecosystems(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.query_packages(PACKAGES)

    assert [r.package for r in results] == PACKAGES

    lodash = results[0]
    assert lodash.unavailable is None
    (vuln,) = lodash.vulns
    assert vuln.canonical_id == "CVE-2021-23337"
    assert vuln.native_id == "GHSA-35jh-r3h4-6jhm"
    assert "GHSA-35jh-r3h4-6jhm" in vuln.aliases
    assert isinstance(vuln.versions, VersionData)
    assert "pkg:npm/lodash 4.17.21" in vuln.versions.fixed

    jinja2 = results[1]
    (vuln,) = jinja2.vulns
    assert vuln.canonical_id == "CVE-2020-28493"
    assert vuln.native_id == "PYSEC-2021-66"
    assert "GHSA-g3rq-g295-4j3m" in vuln.aliases

    gin = results[2]
    (vuln,) = gin.vulns
    assert vuln.canonical_id == "CVE-2020-28483"
    assert isinstance(vuln.versions, VersionData)

    left_pad = results[3]
    assert left_pad.vulns == []  # zero vulns is a real answer, not a degradation
    assert left_pad.unavailable is None

    event_stream = results[4]
    (vuln,) = event_stream.vulns
    # No CVE alias exists: the native GHSA ID is kept as canonical.
    assert vuln.canonical_id == "GHSA-mh6f-8j2x-4483"
    assert vuln.native_id == "GHSA-mh6f-8j2x-4483"
    assert vuln.aliases == []


async def test_query_packages_caches_through_to_fetch(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    router = Router(load_fixture)
    async with fixture_client(router) as client:
        adapter = OsvAdapter(client, cache)
        await adapter.query_packages(PACKAGES)
        detail_calls = router.detail_calls
        # The discovery pass already parsed and cached version data under the
        # canonical CVE ID — the pipeline's fetch() must not refetch it.
        results = await adapter.fetch(["CVE-2021-23337"])

    assert router.detail_calls == detail_calls
    assert results["CVE-2021-23337"].meta.cache_hit is True
    data = results["CVE-2021-23337"].data
    assert isinstance(data, VersionData)
    assert "pkg:npm/lodash 4.17.21" in data.fixed


async def test_query_packages_second_run_is_fully_cached(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    router = Router(load_fixture)
    async with fixture_client(router) as client:
        adapter = OsvAdapter(client, cache)
        first = await adapter.query_packages(PACKAGES)
        querybatch_calls, detail_calls = router.querybatch_calls, router.detail_calls
        second = await adapter.query_packages(PACKAGES)

    assert (router.querybatch_calls, router.detail_calls) == (querybatch_calls, detail_calls)
    assert second == first


async def test_query_packages_offline_cold_cache_degrades(
    cache: Cache, fixture_client: MakeClient
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = OsvAdapter(client, cache, offline=True)
        results = await adapter.query_packages(PACKAGES)

    for result in results:
        assert result.vulns == []
        assert isinstance(result.unavailable, Unavailable)
        assert result.unavailable.reason is UnavailableReason.OFFLINE


async def test_query_packages_offline_warm_cache_answers(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = OsvAdapter(client, cache)
        online = await adapter.query_packages(PACKAGES)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = OsvAdapter(client, cache, offline=True)
        offline = await adapter.query_packages(PACKAGES)

    assert offline == online


async def test_query_packages_querybatch_down_degrades_every_package(
    cache: Cache, fixture_client: MakeClient
) -> None:
    async with fixture_client(lambda request: httpx.Response(503)) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.query_packages(PACKAGES)

    for result in results:
        assert isinstance(result.unavailable, Unavailable)
        assert result.unavailable.reason is UnavailableReason.SOURCE_DOWN


async def test_query_packages_detail_failure_keeps_vuln_degraded(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    router = Router(load_fixture, detail_status=503)
    async with fixture_client(router) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.query_packages(PACKAGES)

    (vuln,) = results[0].vulns
    # Without the detail record no alias is known — the native ID stands in.
    assert vuln.canonical_id == "GHSA-35jh-r3h4-6jhm"
    assert isinstance(vuln.versions, Unavailable)
    assert vuln.versions.reason is UnavailableReason.SOURCE_DOWN


async def test_query_packages_versionless_package_is_not_found(
    cache: Cache, fixture_client: MakeClient
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("a versionless package must not be queried")

    async with fixture_client(handler) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.query_packages([PackageRef(purl="pkg:npm/lodash")])

    assert isinstance(results[0].unavailable, Unavailable)
    assert results[0].unavailable.reason is UnavailableReason.NOT_FOUND


async def test_query_packages_version_embedded_in_purl(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    embedded = [PackageRef(purl=f"{p.purl}@{p.version}") for p in PACKAGES]
    router = Router(load_fixture)

    def routed(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            assert queries == [
                {"package": {"purl": p.purl}, "version": p.version} for p in PACKAGES
            ]
        return router(request)

    async with fixture_client(routed) as client:
        adapter = OsvAdapter(client, cache)
        results = await adapter.query_packages(embedded)

    assert results[0].vulns[0].canonical_id == "CVE-2021-23337"


# --- pure helpers ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("package", "expected"),
    [
        (PackageRef(purl="pkg:npm/lodash", version="4.17.20"), ("pkg:npm/lodash", "4.17.20")),
        (PackageRef(purl="pkg:npm/lodash@4.17.20"), ("pkg:npm/lodash", "4.17.20")),
        # An explicit version wins over one embedded in the purl.
        (PackageRef(purl="pkg:npm/lodash@1.0.0", version="4.17.20"), ("pkg:npm/lodash", "4.17.20")),
        # Unencoded npm scope: the @ is not a version separator.
        (PackageRef(purl="pkg:npm/@angular/core"), ("pkg:npm/@angular/core", None)),
        (PackageRef(purl="pkg:npm/@angular/core@1.2.3"), ("pkg:npm/@angular/core", "1.2.3")),
        # Qualifiers and subpaths are stripped before the version split.
        (
            PackageRef(purl="pkg:deb/debian/curl@7.50.3-1?arch=i386"),
            ("pkg:deb/debian/curl", "7.50.3-1"),
        ),
        (PackageRef(purl="pkg:npm/lodash"), ("pkg:npm/lodash", None)),
    ],
)
def test_split_purl(package: PackageRef, expected: tuple[str, str | None]) -> None:
    assert _split_purl(package) == expected


@pytest.mark.parametrize(
    ("native_id", "aliases", "expected"),
    [
        ("CVE-2021-23337", ["GHSA-35jh-r3h4-6jhm"], "CVE-2021-23337"),
        ("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"], "CVE-2021-23337"),
        # Multiple CVE aliases: pick the lexically first for determinism.
        ("GHSA-x", ["CVE-2021-2222", "CVE-2021-1111"], "CVE-2021-1111"),
        ("GHSA-mh6f-8j2x-4483", [], "GHSA-mh6f-8j2x-4483"),
        ("PYSEC-2021-66", ["SNYK-PYTHON-JINJA2-1012994"], "PYSEC-2021-66"),
        ("cve-2021-23337", [], "CVE-2021-23337"),  # normalized to uppercase
    ],
)
def test_canonical_id(native_id: str, aliases: list[str], expected: str) -> None:
    assert _canonical_id(native_id, aliases) == expected


def test_parse_versions_open_ended_and_last_affected_ranges() -> None:
    record = {
        "affected": [
            {
                "package": {"name": "demo", "purl": "pkg:pypi/demo"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}]},
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"last_affected": "1.9"}],
                    },
                    {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
                ],
            }
        ]
    }
    data = _parse_versions(record)
    assert data.affected == ["pkg:pypi/demo >=2.0", "pkg:pypi/demo <=1.9"]
    assert data.fixed == []  # GIT ranges are skipped; no ecosystem fix published


def test_parse_versions_all_versions_when_no_bound() -> None:
    record = {"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert _parse_versions(record).affected == ["all versions"]


def test_parse_versions_tolerates_garbage() -> None:
    record = {
        "affected": [
            42,
            {"package": [], "ranges": {"type": "ECOSYSTEM"}},
            {"ranges": [{"type": "ECOSYSTEM", "events": ["nope", {"introduced": "1"}]}]},
        ]
    }
    assert _parse_versions(record) == VersionData(affected=[">=1"], fixed=[])
