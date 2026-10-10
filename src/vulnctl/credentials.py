"""Optional API credentials: where the NVD key comes from, and where it is saved.

Resolution order (CLAUDE.md rule 6): the ``VULNCTL_NVD_API_KEY`` environment
variable, then the OS keychain (macOS Keychain, Linux Secret Service, Windows
Credential Locker — via ``keyring``). Never a config file, never a CLI flag,
never the cache.

Only the CLI layer calls into this module. The pipeline and adapters receive
the resolved key as a plain string, so library callers and the test suite
never touch a real keychain. ``keyring`` is imported lazily: a run with the
env var set never loads a keychain backend at all.

Keychain failures on *read* fail open — no key, with a note for
``vulnctl auth status`` — because a missing optional credential must never
break a run. Failures on *write* raise :class:`CredentialError` so the user
hears that their key was not saved.
"""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

NVD_KEY_ENV = "VULNCTL_NVD_API_KEY"
KEYRING_SERVICE = "vulnctl"
NVD_KEYRING_ACCOUNT = "nvd-api-key"
_DISMISSED_MARKER = "nvd-key-prompt-dismissed"


class CredentialError(Exception):
    """The keychain refused a write or delete; the message says why."""


class KeySource(StrEnum):
    """Where a resolved key came from."""

    ENV = "env"
    KEYCHAIN = "keychain"
    NONE = "none"


class ResolvedKey(BaseModel):
    """A key (or its absence) plus where it came from.

    ``note`` explains a keychain that could not be read, so ``auth status``
    can say why no saved key was found.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    key: str | None
    source: KeySource
    note: str | None = None


def resolve_nvd_key() -> ResolvedKey:
    """The NVD key to use: env var first, then the keychain, else none."""
    env_key = os.environ.get(NVD_KEY_ENV, "").strip()
    if env_key:
        return ResolvedKey(key=env_key, source=KeySource.ENV)
    try:
        import keyring

        saved = keyring.get_password(KEYRING_SERVICE, NVD_KEYRING_ACCOUNT)
    except Exception as exc:  # any backend failure: fail open, explain in status
        return ResolvedKey(key=None, source=KeySource.NONE, note=f"keychain unreadable: {exc}")
    if saved:
        return ResolvedKey(key=saved, source=KeySource.KEYCHAIN)
    return ResolvedKey(key=None, source=KeySource.NONE)


def keychain_name() -> str:
    """Human-readable name of the active keychain backend, e.g. ``macOS Keyring``."""
    try:
        import keyring

        return str(getattr(keyring.get_keyring(), "name", "system keychain"))
    except Exception:
        return "system keychain"


def save_nvd_key(key: str) -> None:
    """Store ``key`` in the OS keychain, replacing any saved key.

    Raises:
        CredentialError: if no usable keychain exists or it refused the write.
    """
    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, NVD_KEYRING_ACCOUNT, key)
    except Exception as exc:
        raise CredentialError(f"could not save to {keychain_name()}: {exc}") from exc


def delete_nvd_key() -> bool:
    """Remove the saved key. Returns False when none was saved.

    Raises:
        CredentialError: if the keychain could not be read or refused the delete.
    """
    try:
        import keyring
        from keyring.errors import PasswordDeleteError

        if keyring.get_password(KEYRING_SERVICE, NVD_KEYRING_ACCOUNT) is None:
            return False
        try:
            keyring.delete_password(KEYRING_SERVICE, NVD_KEYRING_ACCOUNT)
        except PasswordDeleteError:
            return False
    except Exception as exc:
        raise CredentialError(f"could not remove from {keychain_name()}: {exc}") from exc
    return True


def mask(key: str) -> str:
    """Display form of a key: only its last four characters."""
    return f"…{key[-4:]}" if len(key) > 8 else "…"


def config_dir() -> Path:
    """``$XDG_CONFIG_HOME/vulnctl``, defaulting to ``~/.config/vulnctl``."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "vulnctl"


def prompt_dismissed() -> bool:
    """True once the user has skipped the first-run key prompt."""
    return (config_dir() / _DISMISSED_MARKER).exists()


def dismiss_prompt() -> None:
    """Remember that the user skipped the prompt (holds no secret — a marker file)."""
    try:
        directory = config_dir()
        directory.mkdir(parents=True, exist_ok=True)
        (directory / _DISMISSED_MARKER).touch()
    except OSError:
        pass  # worst case the prompt shows again next run; never fail a run over it
