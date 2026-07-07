"""Source-adapter contract, registry, and shared fetch helpers (FRAMEWORK.md §3.2).

Isolation rule (CLAUDE.md architecture rule 1): adapter modules may import
only from here, ``vulnctl.cache``, and ``vulnctl.models`` — never each other,
never the SSVC engine.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Awaitable, Iterable
from datetime import timedelta
from typing import ClassVar, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict

from vulnctl.cache import Cache
from vulnctl.models import (
    EpssData,
    ExploitData,
    GhsaData,
    KevData,
    NvdData,
    SourceMeta,
    Unavailable,
    VersionData,
)

T = TypeVar("T")

#: Passed as TTL when running --offline: any cached row beats no data at all.
OFFLINE_TTL = timedelta(days=36500)

#: Refuse to parse response bodies larger than this — a compromised or
#: misbehaving feed must not be able to exhaust memory during JSON parsing.
#: (Largest legitimate body today is the ~3 MiB KEV catalog.)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def body_too_large(response: httpx.Response) -> bool:
    """True if the response body exceeds :data:`MAX_RESPONSE_BYTES`."""
    return len(response.content) > MAX_RESPONSE_BYTES


AdapterData = EpssData | ExploitData | GhsaData | KevData | NvdData | VersionData


class SourceResult(BaseModel):
    """One adapter's answer for one CVE: the payload (or why it's missing) plus provenance."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    data: AdapterData | Unavailable
    meta: SourceMeta


class SourceAdapter(ABC):
    """Base class for intel-source adapters.

    Lifecycle per FRAMEWORK.md §3.2: check cache → fetch misses (bounded
    concurrency, per-source rate limit) → validate strictly → write cache.
    The ``httpx.AsyncClient`` is injected, never created per call.
    """

    name: ClassVar[str]
    ttl: ClassVar[timedelta]
    supports_offline: ClassVar[bool]

    def __init__(self, client: httpx.AsyncClient, cache: Cache, *, offline: bool = False) -> None:
        self._client = client
        self._cache = cache
        self._offline = offline

    @abstractmethod
    async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
        """Return a :class:`SourceResult` for every requested CVE ID."""

    def _cache_ttl(self) -> timedelta:
        return OFFLINE_TTL if self._offline else self.ttl


_REGISTRY: dict[str, type[SourceAdapter]] = {}


def register(cls: type[SourceAdapter]) -> type[SourceAdapter]:
    """Class decorator adding an adapter to the registry (keyed by ``name``)."""
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate adapter name {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def get_adapter(name: str) -> type[SourceAdapter]:
    """Look up a registered adapter class by name."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"no adapter registered under {name!r}") from None


def all_adapters() -> list[type[SourceAdapter]]:
    """All registered adapter classes, in registration order."""
    return list(_REGISTRY.values())


class RateLimit(BaseModel):
    """At most ``requests`` calls per sliding ``window_seconds`` window."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    requests: int
    window_seconds: float


class RateLimiter:
    """Async sliding-window rate limiter shared by an adapter's in-flight requests."""

    def __init__(self, limit: RateLimit) -> None:
        self._limit = limit
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a request slot is available inside the window."""
        while True:
            async with self._lock:
                now = time.monotonic()
                window = self._limit.window_seconds
                while self._timestamps and now - self._timestamps[0] >= window:
                    self._timestamps.popleft()
                if len(self._timestamps) < self._limit.requests:
                    self._timestamps.append(now)
                    return
                wait = window - (now - self._timestamps[0])
            await asyncio.sleep(wait)


async def bounded_gather(coros: Iterable[Awaitable[T]], *, limit: int) -> list[T]:
    """``asyncio.gather`` capped at ``limit`` concurrent awaitables, order preserved."""
    semaphore = asyncio.Semaphore(limit)

    async def _run(coro: Awaitable[T]) -> T:
        async with semaphore:
            return await coro

    return await asyncio.gather(*(_run(c) for c in coros))
