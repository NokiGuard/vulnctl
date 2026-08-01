"""KEV adapter tests, driven entirely by recorded fixtures."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import httpx
import pytest

from conftest import LoadFixture, MakeClient
from vulnctl.adapters.kev import KevAdapter
from vulnctl.cache import Cache
from vulnctl.models import KevData, Unavailable, UnavailableReason


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


async def test_listed_cve_with_ransomware(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("kev", "catalog.json")
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = KevAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-2023-4863"])

    log4shell = results["CVE-2021-44228"].data
    assert isinstance(log4shell, KevData)
    assert log4shell.listed is True
    assert log4shell.date_added == date(2021, 12, 10)
    assert log4shell.ransomware is True

    webp = results["CVE-2023-4863"].data
    assert isinstance(webp, KevData)
    assert webp.listed is True
    assert webp.ransomware is False  # feed says "Unknown"


async def test_unlisted_cve_is_a_real_answer_not_unavailable(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("kev", "catalog.json")
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = KevAdapter(client, cache)
        results = await adapter.fetch(["CVE-2014-0160"])

    heartbleed = results["CVE-2014-0160"].data
    assert isinstance(heartbleed, KevData)
    assert heartbleed.listed is False
    assert heartbleed.date_added is None


async def test_feed_unreachable_degrades_to_source_down(
    cache: Cache, fixture_client: MakeClient
) -> None:
    async with fixture_client(lambda request: httpx.Response(503)) as client:
        adapter = KevAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_single_fetch_serves_all_cves_and_caches(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("kev", "catalog.json")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text=body)

    async with fixture_client(handler) as client:
        adapter = KevAdapter(client, cache)
        first = await adapter.fetch(["CVE-2021-44228", "CVE-2023-4863", "CVE-2014-0160"])
        second = await adapter.fetch(["CVE-2019-0708"])

    assert calls == 1  # one feed download for both runs (second is a cache hit)
    assert first["CVE-2021-44228"].meta.cache_hit is False
    assert second["CVE-2019-0708"].meta.cache_hit is True
    assert isinstance(second["CVE-2019-0708"].data, KevData)
    assert second["CVE-2019-0708"].data.listed is True


async def test_oversized_feed_degrades_to_source_down(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnctl.adapters import base

    monkeypatch.setattr(base, "MAX_RESPONSE_BYTES", 16)
    body = load_fixture("kev", "catalog.json")
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = KevAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_offline_uses_bundled_snapshot(cache: Cache, fixture_client: MakeClient) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = KevAdapter(client, cache, offline=True)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-1999-99999"])

    log4shell = results["CVE-2021-44228"].data
    assert isinstance(log4shell, KevData)
    assert log4shell.listed is True
    assert log4shell.ransomware is True
    # Not in the catalog: still a real listed=False answer, even offline.
    unknown = results["CVE-1999-99999"].data
    assert isinstance(unknown, KevData)
    assert unknown.listed is False


# --- non-CVE ID guard -----------------------------------------------------------


async def test_non_cve_ids_are_not_found_without_catalog_fetch(
    cache: Cache, fixture_client: MakeClient
) -> None:
    # A GHSA ID can never appear in the CVE-keyed catalog: an honest
    # not_found, never a false listed=False — and a CVE-free run skips the
    # catalog fetch entirely.
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("a CVE-free fetch must not touch the catalog")

    async with fixture_client(handler) as client:
        adapter = KevAdapter(client, cache)
        results = await adapter.fetch(["GHSA-mh6f-8j2x-4483"])

    data = results["GHSA-mh6f-8j2x-4483"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.NOT_FOUND


async def test_mixed_ids_answer_cves_and_degrade_ghsa(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("kev", "catalog.json")
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = KevAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228", "GHSA-mh6f-8j2x-4483"])

    listed = results["CVE-2021-44228"].data
    assert isinstance(listed, KevData) and listed.listed
    assert isinstance(results["GHSA-mh6f-8j2x-4483"].data, Unavailable)


async def test_progress_advances_sum_to_requested_ids(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("kev", "catalog.json")
    calls: list[int] = []
    async with fixture_client(lambda request: httpx.Response(200, text=body)) as client:
        adapter = KevAdapter(client, cache)
        adapter.progress = calls.append
        await adapter.fetch(["CVE-2021-44228", "GHSA-mh6f-8j2x-4483"])
    assert sum(calls) == 2
