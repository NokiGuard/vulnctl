"""SQLite-backed response cache with per-source TTL (FRAMEWORK.md §4).

One file, WAL mode, keyed by ``(source, key)``. TTL is enforced at read time:
each adapter passes its own TTL to :meth:`Cache.get`, so a single stored row
can be fresh for one caller and stale for another.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

from pydantic import BaseModel, ConfigDict

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS cache (
    source TEXT NOT NULL,
    key TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (source, key)
)
"""


class CacheEntry(BaseModel):
    """A fresh cache row: the payload plus when it was originally fetched."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    payload: str
    fetched_at: datetime


class CacheStats(BaseModel):
    """Snapshot of cache contents for ``vulnctl cache stats``."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    path: str
    size_bytes: int
    total_entries: int
    entries_by_source: dict[str, int]


def default_cache_path() -> Path:
    """Return ``$XDG_CACHE_HOME/vulnctl/cache.db``, defaulting to ``~/.cache``."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "vulnctl" / "cache.db"


class Cache:
    """SQLite cache; pass ``path`` explicitly in tests (never the real dir)."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else default_cache_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._conn:
            self._conn.execute(_SCHEMA)

    def get(self, source: str, key: str, ttl: timedelta) -> str | None:
        """Return the cached payload, or None if absent or older than ``ttl``."""
        entry = self.get_entry(source, key, ttl)
        return entry.payload if entry is not None else None

    def get_entry(self, source: str, key: str, ttl: timedelta) -> CacheEntry | None:
        """Like :meth:`get`, but also returns the row's original fetch time.

        Adapters use ``fetched_at`` to build provenance (``SourceMeta``).
        """
        row = self._conn.execute(
            "SELECT fetched_at, payload FROM cache WHERE source = ? AND key = ?",
            (source, key),
        ).fetchone()
        if row is None:
            return None
        fetched_at = datetime.fromisoformat(row[0])
        if datetime.now(UTC) - fetched_at > ttl:
            return None
        return CacheEntry(payload=str(row[1]), fetched_at=fetched_at)

    def set(self, source: str, key: str, payload: str) -> None:
        """Insert or refresh a payload, stamping it with the current UTC time."""
        with self._conn:
            self._conn.execute(
                "INSERT INTO cache (source, key, fetched_at, payload) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (source, key) DO UPDATE SET "
                "fetched_at = excluded.fetched_at, payload = excluded.payload",
                (source, key, datetime.now(UTC).isoformat(), payload),
            )

    def purge(self, source: str | None = None) -> int:
        """Delete entries for ``source``, or everything if None. Returns rows removed."""
        with self._conn:
            if source is None:
                cursor = self._conn.execute("DELETE FROM cache")
            else:
                cursor = self._conn.execute("DELETE FROM cache WHERE source = ?", (source,))
        return cursor.rowcount

    def stats(self) -> CacheStats:
        """Summarize entry counts per source and on-disk size."""
        rows = self._conn.execute(
            "SELECT source, COUNT(*) FROM cache GROUP BY source ORDER BY source"
        ).fetchall()
        by_source = {str(source): int(count) for source, count in rows}
        return CacheStats(
            path=str(self.path),
            size_bytes=self.path.stat().st_size if self.path.exists() else 0,
            total_entries=sum(by_source.values()),
            entries_by_source=by_source,
        )

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def __enter__(self) -> Cache:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
