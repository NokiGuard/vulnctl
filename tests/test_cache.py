"""Cache tests. All paths come from tmp_path — never the real cache dir."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnctl.cache import Cache, default_cache_path

TTL = timedelta(hours=24)


@pytest.fixture
def cache(tmp_path: Path) -> Iterator[Cache]:
    with Cache(path=tmp_path / "cache.db") as c:
        yield c


def test_get_missing_returns_none(cache: Cache) -> None:
    assert cache.get("epss", "CVE-2021-44228", TTL) is None


def test_set_then_get(cache: Cache) -> None:
    cache.set("epss", "CVE-2021-44228", '{"score": 0.97}')
    assert cache.get("epss", "CVE-2021-44228", TTL) == '{"score": 0.97}'


def test_set_overwrites(cache: Cache) -> None:
    cache.set("epss", "CVE-2021-44228", "old")
    cache.set("epss", "CVE-2021-44228", "new")
    assert cache.get("epss", "CVE-2021-44228", TTL) == "new"


def test_sources_are_namespaced(cache: Cache) -> None:
    cache.set("epss", "CVE-2021-44228", "epss-payload")
    cache.set("kev", "CVE-2021-44228", "kev-payload")
    assert cache.get("epss", "CVE-2021-44228", TTL) == "epss-payload"
    assert cache.get("kev", "CVE-2021-44228", TTL) == "kev-payload"


def test_ttl_enforced_at_read(cache: Cache) -> None:
    cache.set("epss", "CVE-2021-44228", "payload")
    stale = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    with sqlite3.connect(cache.path) as conn:
        conn.execute("UPDATE cache SET fetched_at = ?", (stale,))
    assert cache.get("epss", "CVE-2021-44228", TTL) is None
    # A caller with a longer TTL still sees the same row as fresh.
    assert cache.get("epss", "CVE-2021-44228", timedelta(days=7)) == "payload"


def test_purge_single_source(cache: Cache) -> None:
    cache.set("epss", "CVE-1", "a")
    cache.set("epss", "CVE-2", "b")
    cache.set("kev", "CVE-1", "c")
    assert cache.purge("epss") == 2
    assert cache.get("epss", "CVE-1", TTL) is None
    assert cache.get("kev", "CVE-1", TTL) == "c"


def test_purge_all(cache: Cache) -> None:
    cache.set("epss", "CVE-1", "a")
    cache.set("kev", "CVE-1", "b")
    assert cache.purge() == 2
    assert cache.stats().total_entries == 0


def test_stats(cache: Cache) -> None:
    cache.set("epss", "CVE-1", "a")
    cache.set("epss", "CVE-2", "b")
    cache.set("kev", "CVE-1", "c")
    stats = cache.stats()
    assert stats.total_entries == 3
    assert stats.entries_by_source == {"epss": 2, "kev": 1}
    assert stats.path == str(cache.path)
    assert stats.size_bytes > 0


def test_wal_mode_enabled(cache: Cache) -> None:
    (mode,) = sqlite3.connect(cache.path).execute("PRAGMA journal_mode").fetchone()
    assert mode == "wal"


def test_default_path_honors_xdg_cache_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_path() == tmp_path / "xdg" / "vulnctl" / "cache.db"


def test_default_path_falls_back_to_home_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    assert default_cache_path() == Path.home() / ".cache" / "vulnctl" / "cache.db"


def test_parent_dirs_created(tmp_path: Path) -> None:
    with Cache(path=tmp_path / "deep" / "nested" / "cache.db") as c:
        c.set("epss", "CVE-1", "a")
        assert c.get("epss", "CVE-1", TTL) == "a"
