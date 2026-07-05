"""NVD adapter tests, driven entirely by recorded fixtures."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from conftest import LoadFixture, MakeClient
from vulnctl.adapters.nvd import API_KEY_ENV, NvdAdapter
from vulnctl.cache import Cache
from vulnctl.models import CvssData, NvdData, Unavailable, UnavailableReason


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


@pytest.fixture(autouse=True)
def no_api_key_and_no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    monkeypatch.setattr(NvdAdapter, "_backoff_base", 0.0)


def _fixture_router(load_fixture: LoadFixture) -> Callable[[httpx.Request], httpx.Response]:
    """Route by cveId param to the matching recorded fixture."""
    by_cve = {
        "CVE-2021-44228": "cve-2021-44228.json",
        "CVE-2023-4863": "multiple-cvss.json",
        "CVE-1999-0095": "v2-only.json",
        "CVE-2023-4128": "rejected.json",
        "CVE-1999-99999": "not-found.json",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        name = by_cve[request.url.params["cveId"]]
        return httpx.Response(200, text=load_fixture("nvd", name))

    return handler


async def test_happy_path_v31_primary_with_cwes(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, NvdData)
    assert isinstance(data.cvss, CvssData)
    # v3.1 Primary (10.0) chosen over the v2 metric (9.3) in the same record.
    assert data.cvss.vector.startswith("CVSS:3.1/")
    assert data.cvss.base_score == 10.0
    assert data.cvss.severity == "CRITICAL"
    assert data.cwes == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]


async def test_multiple_v31_entries_resolve_to_primary(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2023-4863"])

    data = results["CVE-2023-4863"].data
    assert isinstance(data, NvdData)
    assert isinstance(data.cvss, CvssData)
    assert data.cvss.base_score == 8.8
    assert data.cvss.severity == "HIGH"
    assert data.cwes == ["CWE-787"]


async def test_v2_only_cve_records_available_data(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-1999-0095"])

    data = results["CVE-1999-0095"].data
    assert isinstance(data, NvdData)
    assert isinstance(data.cvss, CvssData)
    # v2 vector: no CVSS:3.1/ prefix, severity from the metric level.
    assert not data.cvss.vector.startswith("CVSS:")
    assert data.cvss.base_score == 10.0
    assert data.cvss.severity == "HIGH"
    assert data.cwes == []  # NVD-CWE-Other placeholder is filtered out


async def test_rejected_cve_is_not_found(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2023-4128"])

    data = results["CVE-2023-4128"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.NOT_FOUND
    assert data.detail is not None and "rejected" in data.detail


async def test_unknown_cve_is_not_found(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-1999-99999"])

    data = results["CVE-1999-99999"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.NOT_FOUND


async def test_503_retries_then_succeeds(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("nvd", "cve-2021-44228.json")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503) if calls == 1 else httpx.Response(200, text=body)

    async with fixture_client(handler) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    assert calls == 2
    assert isinstance(results["CVE-2021-44228"].data, NvdData)


async def test_persistent_503_gives_up_as_source_down(
    cache: Cache, fixture_client: MakeClient
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async with fixture_client(handler) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    assert calls == NvdAdapter._MAX_ATTEMPTS
    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_persistent_403_gives_up_as_rate_limited(
    cache: Cache, fixture_client: MakeClient
) -> None:
    async with fixture_client(lambda request: httpx.Response(403)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.RATE_LIMITED


async def test_api_key_header_and_keyed_rate_limit(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(API_KEY_ENV, "test-key-not-real")
    seen_headers: list[str | None] = []
    body = load_fixture("nvd", "cve-2021-44228.json")

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers.get("apiKey"))
        return httpx.Response(200, text=body)

    async with fixture_client(handler) as client:
        adapter = NvdAdapter(client, cache)
        assert adapter.rate_limit.requests == 40
        await adapter.fetch(["CVE-2021-44228"])

    assert seen_headers == ["test-key-not-real"]


async def test_unkeyed_rate_limit_and_no_header(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    seen_headers: list[str | None] = []
    body = load_fixture("nvd", "cve-2021-44228.json")

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers.get("apiKey"))
        return httpx.Response(200, text=body)

    async with fixture_client(handler) as client:
        adapter = NvdAdapter(client, cache)
        assert adapter.rate_limit.requests == 4
        await adapter.fetch(["CVE-2021-44228"])

    assert seen_headers == [None]


async def test_cache_hit_skips_network(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    calls = 0
    body = load_fixture("nvd", "cve-2021-44228.json")

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text=body)

    async with fixture_client(handler) as client:
        adapter = NvdAdapter(client, cache)
        first = await adapter.fetch(["CVE-2021-44228"])
        second = await adapter.fetch(["CVE-2021-44228"])

    assert calls == 1
    assert second["CVE-2021-44228"].meta.cache_hit is True
    assert second["CVE-2021-44228"].data == first["CVE-2021-44228"].data


async def test_corrupt_cache_row_is_refetched_not_fatal(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    cache.set("nvd", "CVE-2021-44228", '{"schema": "from-an-old-version"}')
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    assert isinstance(results["CVE-2021-44228"].data, NvdData)
    assert results["CVE-2021-44228"].meta.cache_hit is False  # treated as a miss


async def test_oversized_response_degrades_to_source_down(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnctl.adapters import base

    monkeypatch.setattr(base, "MAX_RESPONSE_BYTES", 16)
    async with fixture_client(_fixture_router(load_fixture)) as client:
        adapter = NvdAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN
    assert data.detail == "response exceeds size limit"


async def test_offline_answers_from_cache_only(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    # Warm the cache online first.
    async with fixture_client(_fixture_router(load_fixture)) as client:
        await NvdAdapter(client, cache).fetch(["CVE-2021-44228"])

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = NvdAdapter(client, cache, offline=True)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-2023-4863"])

    assert isinstance(results["CVE-2021-44228"].data, NvdData)  # from cache
    cold = results["CVE-2023-4863"].data
    assert isinstance(cold, Unavailable)
    assert cold.reason is UnavailableReason.OFFLINE
