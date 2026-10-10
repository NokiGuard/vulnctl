"""Credential resolution and storage — always against the in-memory test keychain."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import MemoryKeyring
from vulnctl import credentials
from vulnctl.adapters.nvd import API_KEY_ENV
from vulnctl.credentials import (
    KEYRING_SERVICE,
    NVD_KEY_ENV,
    NVD_KEYRING_ACCOUNT,
    CredentialError,
    KeySource,
    delete_nvd_key,
    dismiss_prompt,
    mask,
    prompt_dismissed,
    resolve_nvd_key,
    save_nvd_key,
)


@pytest.fixture(autouse=True)
def no_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(NVD_KEY_ENV, raising=False)


class _BrokenKeyring(MemoryKeyring):
    """A keychain whose every operation fails, like a locked or absent backend."""

    def get_password(self, service: str, username: str) -> str | None:
        raise RuntimeError("keychain locked")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise RuntimeError("keychain locked")


def test_env_var_name_matches_the_adapter_fallback() -> None:
    # Duplicated on purpose (adapters may not import the CLI layer); must agree.
    assert NVD_KEY_ENV == API_KEY_ENV


def test_no_key_anywhere() -> None:
    resolved = resolve_nvd_key()
    assert resolved.key is None
    assert resolved.source is KeySource.NONE
    assert resolved.note is None


def test_saved_key_resolves_from_keychain(memory_keyring: MemoryKeyring) -> None:
    save_nvd_key("saved-key-1234")
    assert memory_keyring.store == {(KEYRING_SERVICE, NVD_KEYRING_ACCOUNT): "saved-key-1234"}
    resolved = resolve_nvd_key()
    assert (resolved.key, resolved.source) == ("saved-key-1234", KeySource.KEYCHAIN)


def test_env_var_wins_over_saved_key(monkeypatch: pytest.MonkeyPatch) -> None:
    save_nvd_key("saved-key-1234")
    monkeypatch.setenv(NVD_KEY_ENV, "  env-key-5678 \n")
    resolved = resolve_nvd_key()
    assert (resolved.key, resolved.source) == ("env-key-5678", KeySource.ENV)


def test_blank_env_var_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    save_nvd_key("saved-key-1234")
    monkeypatch.setenv(NVD_KEY_ENV, "   ")
    assert resolve_nvd_key().source is KeySource.KEYCHAIN


def test_env_var_skips_the_keychain_entirely(monkeypatch: pytest.MonkeyPatch) -> None:
    # CI sets the env var; a broken or absent keychain there must not matter.
    import keyring

    keyring.set_keyring(_BrokenKeyring())
    monkeypatch.setenv(NVD_KEY_ENV, "env-key-5678")
    assert resolve_nvd_key().key == "env-key-5678"


def test_unreadable_keychain_fails_open_with_a_note() -> None:
    import keyring

    keyring.set_keyring(_BrokenKeyring())
    resolved = resolve_nvd_key()
    assert resolved.key is None
    assert resolved.note is not None and "keychain locked" in resolved.note


def test_save_failure_is_loud() -> None:
    import keyring

    keyring.set_keyring(_BrokenKeyring())
    with pytest.raises(CredentialError, match="could not save"):
        save_nvd_key("saved-key-1234")


def test_delete_round_trip() -> None:
    assert delete_nvd_key() is False
    save_nvd_key("saved-key-1234")
    assert delete_nvd_key() is True
    assert resolve_nvd_key().key is None
    assert delete_nvd_key() is False


def test_delete_failure_is_loud() -> None:
    import keyring

    keyring.set_keyring(_BrokenKeyring())
    with pytest.raises(CredentialError, match="could not remove"):
        delete_nvd_key()


def test_dismissal_marker_lives_in_the_config_dir(tmp_path: Path) -> None:
    assert prompt_dismissed() is False
    dismiss_prompt()
    assert prompt_dismissed() is True
    marker = tmp_path / "config" / "vulnctl" / "nvd-key-prompt-dismissed"
    assert marker.is_file()
    assert marker.read_text() == ""  # a marker only — never holds a secret


def test_dismissal_survives_an_unwritable_config_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    monkeypatch.setattr(credentials, "config_dir", lambda: blocker / "vulnctl")
    dismiss_prompt()  # must not raise
    assert prompt_dismissed() is False


def test_mask_shows_only_the_tail() -> None:
    assert mask("0123456789abcdef") == "…cdef"
    assert mask("short") == "…"
