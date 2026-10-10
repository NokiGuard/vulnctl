"""Shared test helpers.

All httpx mocking flows through :func:`fixture_client` + recorded fixtures in
``tests/fixtures/<source>/`` — never mock httpx inline in a test (CLAUDE.md rule).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class MemoryKeyring(KeyringBackend):
    """In-process keychain so no test ever reads or writes the real OS keychain."""

    priority = 1
    name = "test keyring"

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if self.store.pop((service, username), None) is None:
            raise PasswordDeleteError("not found")


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[MemoryKeyring]:
    """Every test gets an empty in-memory keychain and a throwaway config dir.

    Autouse because any CLI run resolves the NVD key: without this, the suite
    would read the developer's real keychain and write prompt markers into
    their real ``~/.config``.
    """
    backend = MemoryKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    yield backend
    keyring.set_keyring(previous)


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
