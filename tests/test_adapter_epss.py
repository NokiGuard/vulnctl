"""EPSS adapter tests, driven entirely by recorded fixtures."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest

from conftest import LoadFixture, MakeClient
from vulnctl.adapters.epss import EpssAdapter
from vulnctl.cache import Cache
from vulnctl.models import EpssData, Unavailable, UnavailableReason


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


def _fixture_handler(body: str) -> httpx.Response:
    return httpx.Response(200, text=body)


async def test_happy_path_batch(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("epss", "batch.json")
    async with fixture_client(lambda request: _fixture_handler(body)) as client:
        adapter = EpssAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-2023-4863", "CVE-2014-0160"])

    log4shell = results["CVE-2021-44228"]
    assert isinstance(log4shell.data, EpssData)
    assert log4shell.data.score == 0.99999
    assert log4shell.data.percentile == 1.0
    assert log4shell.data.date == date(2026, 7, 4)
    assert log4shell.meta.source == "epss"
    assert log4shell.meta.cache_hit is False
    assert isinstance(results["CVE-2023-4863"].data, EpssData)
    assert isinstance(results["CVE-2014-0160"].data, EpssData)


async def test_missing_cve_is_not_found(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("epss", "missing.json")
    async with fixture_client(lambda request: _fixture_handler(body)) as client:
        adapter = EpssAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-1999-99999"])

    assert isinstance(results["CVE-2021-44228"].data, EpssData)
    missing = results["CVE-1999-99999"].data
    assert isinstance(missing, Unavailable)
    assert missing.reason is UnavailableReason.NOT_FOUND


async def test_malformed_rows_degrade_without_crashing(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("epss", "malformed.json")
    async with fixture_client(lambda request: _fixture_handler(body)) as client:
        adapter = EpssAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-2023-4863", "CVE-2014-0160"])

    # Non-numeric epss and a missing percentile are both skipped -> not_found.
    for degraded in ("CVE-2021-44228", "CVE-2023-4863"):
        data = results[degraded].data
        assert isinstance(data, Unavailable)
        assert data.reason is UnavailableReason.NOT_FOUND
    # The intact row in the same response still parses.
    assert isinstance(results["CVE-2014-0160"].data, EpssData)


async def test_source_down_degrades_whole_batch(cache: Cache, fixture_client: MakeClient) -> None:
    async with fixture_client(lambda request: httpx.Response(503)) as client:
        adapter = EpssAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN


async def test_cache_hit_skips_network(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    body = load_fixture("epss", "batch.json")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _fixture_handler(body)

    async with fixture_client(handler) as client:
        adapter = EpssAdapter(client, cache)
        first = await adapter.fetch(["CVE-2021-44228"])
        second = await adapter.fetch(["CVE-2021-44228"])

    assert calls == 1
    assert first["CVE-2021-44228"].meta.cache_hit is False
    assert second["CVE-2021-44228"].meta.cache_hit is True
    assert second["CVE-2021-44228"].data == first["CVE-2021-44228"].data


async def test_corrupt_cache_row_is_refetched_not_fatal(
    cache: Cache, load_fixture: LoadFixture, fixture_client: MakeClient
) -> None:
    cache.set("epss", "CVE-2021-44228", "not json {")
    body = load_fixture("epss", "batch.json")
    async with fixture_client(lambda request: _fixture_handler(body)) as client:
        adapter = EpssAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    assert isinstance(results["CVE-2021-44228"].data, EpssData)
    assert results["CVE-2021-44228"].meta.cache_hit is False  # treated as a miss


async def test_oversized_response_degrades_to_source_down(
    cache: Cache,
    load_fixture: LoadFixture,
    fixture_client: MakeClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnctl.adapters import base

    monkeypatch.setattr(base, "MAX_RESPONSE_BYTES", 16)
    body = load_fixture("epss", "batch.json")
    async with fixture_client(lambda request: _fixture_handler(body)) as client:
        adapter = EpssAdapter(client, cache)
        results = await adapter.fetch(["CVE-2021-44228"])

    data = results["CVE-2021-44228"].data
    assert isinstance(data, Unavailable)
    assert data.reason is UnavailableReason.SOURCE_DOWN
    assert data.detail == "response exceeds size limit"


async def test_offline_uses_bundled_snapshot(cache: Cache, fixture_client: MakeClient) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = EpssAdapter(client, cache, offline=True)
        results = await adapter.fetch(["CVE-2021-44228", "CVE-1999-99999"])

    snap = results["CVE-2021-44228"].data
    assert isinstance(snap, EpssData)
    assert 0.0 <= snap.score <= 1.0
    unknown = results["CVE-1999-99999"].data
    assert isinstance(unknown, Unavailable)
    assert unknown.reason is UnavailableReason.OFFLINE


async def test_offline_prefers_cache_even_when_stale(
    cache: Cache, fixture_client: MakeClient
) -> None:
    cached = EpssData(score=0.5, percentile=0.5, date=date(2020, 1, 1))
    cache.set("epss", "CVE-2021-44228", cached.model_dump_json())

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode must never touch the network")

    async with fixture_client(handler) as client:
        adapter = EpssAdapter(client, cache, offline=True)
        # Far beyond the 24h TTL, but offline mode accepts any cached row.
        assert adapter.ttl == timedelta(hours=24)
        results = await adapter.fetch(["CVE-2021-44228"])

    assert results["CVE-2021-44228"].data == cached
    assert results["CVE-2021-44228"].meta.cache_hit is True
