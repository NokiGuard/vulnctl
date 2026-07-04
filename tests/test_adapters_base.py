"""Tests for the adapter ABC, registry, and shared fetch helpers."""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta

import pytest

from vulnctl.adapters import base
from vulnctl.adapters.base import (
    RateLimit,
    RateLimiter,
    SourceAdapter,
    SourceResult,
    all_adapters,
    bounded_gather,
    get_adapter,
    register,
)


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give each test a fresh registry so dummies never leak into other tests."""
    monkeypatch.setattr(base, "_REGISTRY", {})


def _dummy_adapter(adapter_name: str) -> type[SourceAdapter]:
    class Dummy(SourceAdapter):
        name = adapter_name
        ttl = timedelta(hours=1)
        supports_offline = False

        async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
            return {}

    return Dummy


def test_register_and_lookup() -> None:
    cls = register(_dummy_adapter("dummy"))
    assert get_adapter("dummy") is cls
    assert all_adapters() == [cls]


def test_register_duplicate_name_rejected() -> None:
    register(_dummy_adapter("dummy"))
    with pytest.raises(ValueError, match="duplicate adapter name 'dummy'"):
        register(_dummy_adapter("dummy"))


def test_get_unknown_adapter_raises() -> None:
    with pytest.raises(KeyError, match="no adapter registered under 'nope'"):
        get_adapter("nope")


def test_registration_order_preserved() -> None:
    first = register(_dummy_adapter("first"))
    second = register(_dummy_adapter("second"))
    assert all_adapters() == [first, second]


async def test_bounded_gather_caps_concurrency() -> None:
    active = 0
    peak = 0

    async def work(i: int) -> int:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return i

    results = await bounded_gather((work(i) for i in range(10)), limit=3)
    assert results == list(range(10))
    assert peak <= 3


async def test_rate_limiter_delays_over_limit() -> None:
    limiter = RateLimiter(RateLimit(requests=2, window_seconds=0.2))
    start = time.monotonic()
    await limiter.acquire()
    await limiter.acquire()
    fast = time.monotonic() - start
    await limiter.acquire()  # third call must wait for the window to slide
    elapsed = time.monotonic() - start
    assert fast < 0.1
    assert elapsed >= 0.15


async def test_rate_limiter_within_limit_is_immediate() -> None:
    limiter = RateLimiter(RateLimit(requests=5, window_seconds=1.0))
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire()
    assert time.monotonic() - start < 0.1
