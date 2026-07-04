"""Shared test helpers.

All httpx mocking flows through :func:`fixture_client` + recorded fixtures in
``tests/fixtures/<source>/`` — never mock httpx inline in a test (CLAUDE.md rule).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

Handler = Callable[[httpx.Request], httpx.Response]
LoadFixture = Callable[[str, str], str]
MakeClient = Callable[[Handler], httpx.AsyncClient]


@pytest.fixture
def load_fixture() -> LoadFixture:
    """Load a recorded API response from tests/fixtures/<source>/<name>."""

    def _load(source: str, name: str) -> str:
        return (FIXTURES_DIR / source / name).read_text()

    return _load


@pytest.fixture
def fixture_client() -> MakeClient:
    """Build an httpx.AsyncClient whose transport is a MockTransport handler."""

    def _make(handler: Handler) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return _make
