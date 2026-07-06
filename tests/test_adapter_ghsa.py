"""GHSA adapter tests, driven entirely by recorded fixtures.

``rate-limited.json`` and ``malformed.json`` are hand-crafted (GitHub's
rate-limit body shape is stable and public); everything else is recorded
from the live REST Global Advisories API.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from conftest import LoadFixture, MakeClient
from vulnctl.adapters.ghsa import (
    TOKEN_ENV,
    GhsaAdapter,
    _normalize_range,
    _purl_label,
)
from vulnctl.cache import Cache
from vulnctl.models import GhsaData, Unavailable, UnavailableReason


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


@pytest.fixture(autouse=True)
def anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests run anonymous unless they set the token themselves."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)


class Router:
    """Route CVE queries and GHSA-ID lookups to recorded fixtures."""

    def __init__(self, load_fixture: LoadFixture) -> None:
        self._load = load_fixture
        self.calls = 0
        self.last_request: httpx.Request | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.github.com"
        self.calls += 1
        self.last_request = request
        if request.url.path == "/advisories":
            if request.url.params["cve_id"] == "CVE-2021-23337":
                return httpx.Response(200, text=self._load("ghsa", "advisory-by-cve.json"))
            return httpx.Response(200, text=self._load("ghsa", "not-found-empty-list.json"))
        if request.url.path == "/advisories/GHSA-mh6f-8j2x-4483":
            return httpx.Response(200, text=self._load("ghsa", "advisory-by-ghsa-id.json"))
        return httpx.Response(404)


async def test_cve_lookup_parses_severity_summary_and_ranges(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, GhsaData)
    assert data.ghsa_id == "GHSA-35jh-r3h4-6jhm"
    assert data.severity == "high"
    assert data.summary == "Command Injection in lodash"
    # Ranges normalized to the OSV adapter's format so the merge can compare.
    assert "pkg:npm/lodash <4.17.21" in data.versions.affected
    assert "pkg:npm/lodash 4.17.21" in data.versions.fixed
    assert "pkg:gem/lodash-rails <4.17.21" in data.versions.affected
    # first_patched_version: null → no fixed entry for that package.
    assert not any("lodash.template" in fix for fix in data.versions.fixed)


async def test_ghsa_id_lookup_for_alias_path_findings(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["GHSA-mh6f-8j2x-4483"])

    data = results["GHSA-mh6f-8j2x-4483"].data
    assert isinstance(data, GhsaData)
    assert data.severity == "critical"
    assert "event-stream" in data.summary


async def test_non_github_id_is_not_found_without_a_request(
    cache: Cache, fixture_client: MakeClient
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("PYSEC IDs must not be sent to GitHub")

    async with fixture_client(handler) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["PYSEC-2021-66"])

    data = results["PYSEC-2021-66"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.NOT_FOUND


async def test_empty_list_answer_is_not_found(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(Router(load_fixture)) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["CVE-2020-99999"])

    data = results["CVE-2020-99999"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.NOT_FOUND


@pytest.mark.parametrize("status", [403, 429])
async def test_rate_limit_degrades_without_retry(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient, status: int
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, text=load_fixture("ghsa", "rate-limited.json"))

    async with fixture_client(handler) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    assert calls == 1  # no retry storm against an exhausted quota
    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.RATE_LIMITED


async def test_server_error_degrades_to_source_down(
    cache: Cache, fixture_client: MakeClient
) -> None:
    async with fixture_client(lambda request: httpx.Response(503)) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_malformed_response_degrades(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("ghsa", "malformed.json")
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_oversized_response_degrades(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnctl.adapters import base

    monkeypatch.setattr(base, "MAX_RESPONSE_BYTES", 16)
    async with fixture_client(Router(load_fixture)) as client:
        adapter = GhsaAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_caches_and_tolerates_corrupt_rows(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    router = Router(load_fixture)
    async with fixture_client(router) as client:
        adapter = GhsaAdapter(client, cache)
        first = await adapter.fetch(["CVE-2021-23337"])
        second = await adapter.fetch(["CVE-2021-23337"])
        assert router.calls == 1
        assert first["CVE-2021-23337"].meta.cache_hit is False
        assert second["CVE-2021-23337"].meta.cache_hit is True

        cache.set("ghsa", "CVE-2021-23337", '{"unexpected": "schema"}')
        third = await adapter.fetch(["CVE-2021-23337"])  # corrupt row → refetch

    assert router.calls == 2
    assert isinstance(third["CVE-2021-23337"].data, GhsaData)


async def test_offline_cold_cache_degrades(cache: Cache, fixture_client: MakeClient) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = GhsaAdapter(client, cache, offline=True)
        results = await adapter.fetch(["CVE-2021-23337"])

    data = results["CVE-2021-23337"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.OFFLINE


async def test_token_header_only_when_env_set(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router = Router(load_fixture)
    async with fixture_client(router) as client:
        await GhsaAdapter(client, cache).fetch(["CVE-2021-23337"])
        assert router.last_request is not None
        assert "Authorization" not in router.last_request.headers

        monkeypatch.setenv(TOKEN_ENV, "ghp_test-token")
        keyed = GhsaAdapter(client, cache)
        cache.purge("ghsa")
        await keyed.fetch(["CVE-2021-23337"])
        assert router.last_request.headers["Authorization"] == "Bearer ghp_test-token"


# --- pure helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (">= 3.0.0, < 3.9.2", ">=3.0.0 <3.9.2"),
        ("< 4.17.21", "<4.17.21"),
        ("<= 1.0.0", "<=1.0.0"),
        ("= 2.0.0", "=2.0.0"),
    ],
)
def test_normalize_range(raw: str, expected: str) -> None:
    assert _normalize_range(raw) == expected


@pytest.mark.parametrize(
    ("package", "expected"),
    [
        ({"ecosystem": "npm", "name": "lodash"}, "pkg:npm/lodash"),
        ({"ecosystem": "pip", "name": "jinja2"}, "pkg:pypi/jinja2"),
        ({"ecosystem": "rubygems", "name": "lodash-rails"}, "pkg:gem/lodash-rails"),
        (
            {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
            "pkg:maven/org.apache.logging.log4j/log4j-core",
        ),
        (
            {"ecosystem": "go", "name": "github.com/gin-gonic/gin"},
            "pkg:golang/github.com/gin-gonic/gin",
        ),
        ({"ecosystem": "somethingnew", "name": "x"}, "pkg:somethingnew/x"),
        ({"name": "x"}, "pkg:generic/x"),
        ({"ecosystem": "npm"}, None),
        ("not-a-dict", None),
    ],
)
def test_purl_label(package: object, expected: str | None) -> None:
    assert _purl_label(package) == expected
