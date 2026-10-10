"""First-run NVD key prompt and ``vulnctl auth`` commands.

The terminal is simulated: ``_interactive`` and ``_read_secret`` are patched,
and ``_verify`` stands in for the NVD probe (``check_api_key`` itself is
tested against mocked HTTP in ``test_adapter_nvd.py``). The autouse
``memory_keyring`` fixture keeps every write off the real keychain.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import MemoryKeyring
from vulnctl import auth
from vulnctl.adapters.nvd import KeyCheck
from vulnctl.cli import app
from vulnctl.credentials import (
    KEYRING_SERVICE,
    NVD_KEY_ENV,
    NVD_KEYRING_ACCOUNT,
    prompt_dismissed,
    save_nvd_key,
)

runner = CliRunner()
_SLOT = (KEYRING_SERVICE, NVD_KEYRING_ACCOUNT)
GOOD = "11111111-2222-3333-4444-555555555555"
BAD = "99999999-8888-7777-6666-555555555555"


class Terminal:
    """Scripted keystrokes for the hidden prompt, plus what NVD says per key."""

    def __init__(self) -> None:
        self.inputs: list[str] = []
        self.prompts: list[str] = []
        self.verdicts: dict[str, tuple[KeyCheck, str]] = {
            GOOD: (KeyCheck.VALID, "accepted by NVD"),
            BAD: (KeyCheck.INVALID, "NVD rejected the API key (Invalid apiKey)"),
        }
        self.probed: list[str] = []

    def read(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.inputs:
            raise AssertionError("prompted more times than the test scripted")
        return self.inputs.pop(0)

    def verify(self, key: str) -> tuple[KeyCheck, str]:
        self.probed.append(key)
        return self.verdicts.get(key, (KeyCheck.UNVERIFIED, "could not reach NVD (timeout)"))


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Terminal]:
    term = Terminal()
    monkeypatch.delenv(NVD_KEY_ENV, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(auth, "_interactive", lambda: True)
    monkeypatch.setattr(auth, "_read_secret", term.read)
    monkeypatch.setattr(auth, "_verify", term.verify)
    yield term


def _no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "_interactive", lambda: False)


# --- run_credentials: when the first-run prompt may appear ---------------------


def test_valid_key_is_verified_saved_and_used(
    terminal: Terminal, memory_keyring: MemoryKeyring
) -> None:
    terminal.inputs = [f"  {GOOD}\n"]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": GOOD}
    assert terminal.probed == [GOOD]
    assert memory_keyring.store[_SLOT] == GOOD
    assert "Enter to skip" in terminal.prompts[0]


def test_saved_key_is_used_without_prompting(terminal: Terminal) -> None:
    save_nvd_key(GOOD)
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": GOOD}
    assert terminal.prompts == []


def test_env_key_is_used_without_prompting(
    terminal: Terminal, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(NVD_KEY_ENV, GOOD)
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": GOOD}
    assert terminal.prompts == []


def test_skip_is_remembered_and_never_asks_again(
    terminal: Terminal, memory_keyring: MemoryKeyring
) -> None:
    terminal.inputs = [""]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {}
    assert prompt_dismissed()
    assert memory_keyring.store == {}
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {}
    assert len(terminal.prompts) == 1


@pytest.mark.parametrize(
    ("offline", "stdin_is_data"),
    [(True, False), (False, True)],
    ids=["offline", "grype-from-stdin"],
)
def test_no_prompt_when_it_could_not_help_or_would_break_input(
    terminal: Terminal, offline: bool, stdin_is_data: bool
) -> None:
    assert auth.run_credentials(offline=offline, stdin_is_data=stdin_is_data) == {}
    assert terminal.prompts == []
    assert not prompt_dismissed()


def test_offline_ignores_even_a_saved_key(terminal: Terminal) -> None:
    save_nvd_key(GOOD)  # offline never talks to NVD, so it never needs the key
    assert auth.run_credentials(offline=True, stdin_is_data=False) == {}


def test_no_prompt_without_a_terminal(terminal: Terminal, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_terminal(monkeypatch)
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {}
    assert terminal.prompts == []
    assert not prompt_dismissed()  # a script didn't decline — a human might still


def test_ci_env_counts_as_non_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    assert auth._interactive() is False


def test_rejected_key_is_re_asked(terminal: Terminal, memory_keyring: MemoryKeyring) -> None:
    terminal.inputs = [BAD, GOOD]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": GOOD}
    assert terminal.probed == [BAD, GOOD]
    assert memory_keyring.store[_SLOT] == GOOD


def test_malformed_input_is_re_asked_without_a_probe(terminal: Terminal) -> None:
    terminal.inputs = ["has spaces in it", "x", GOOD]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": GOOD}
    assert terminal.probed == [GOOD]


def test_three_bad_keys_give_up_without_silencing_the_prompt(
    terminal: Terminal, memory_keyring: MemoryKeyring
) -> None:
    terminal.inputs = [BAD, BAD, BAD]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {}
    assert memory_keyring.store == {}
    assert not prompt_dismissed()  # a typo streak is not a "no thanks"


def test_unverifiable_key_is_saved_anyway(
    terminal: Terminal, memory_keyring: MemoryKeyring
) -> None:
    unreachable = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    terminal.inputs = [unreachable]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": unreachable}
    assert memory_keyring.store[_SLOT] == unreachable


def test_keychain_refusal_still_uses_the_key_for_this_run(
    terminal: Terminal, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ReadOnly(MemoryKeyring):
        def set_password(self, service: str, username: str, password: str) -> None:
            raise RuntimeError("write denied")

    import keyring

    keyring.set_keyring(ReadOnly())
    terminal.inputs = [GOOD]
    assert auth.run_credentials(offline=False, stdin_is_data=False) == {"nvd": GOOD}


# --- the enrich command wires it in --------------------------------------------


def test_enrich_offline_never_prompts(terminal: Terminal) -> None:
    result = runner.invoke(app, ["enrich", "CVE-2021-44228", "--offline", "-f", "json"])
    assert result.exit_code == 0, result.output
    assert terminal.prompts == []


def test_enrich_passes_the_saved_key_to_the_pipeline(
    terminal: Terminal, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    async def fake_run_enrichment(**kwargs: object) -> tuple[list[object], object]:
        seen.append(kwargs["credentials"])
        raise SystemExit(0)  # stop before any network: only the hand-off matters

    monkeypatch.setattr("vulnctl.commands.run_enrichment", fake_run_enrichment)
    save_nvd_key(GOOD)
    runner.invoke(app, ["enrich", "CVE-2021-44228"])
    assert seen == [{"nvd": GOOD}]


def test_input_errors_surface_before_the_prompt(terminal: Terminal) -> None:
    result = runner.invoke(app, ["enrich", "not-a-cve"])
    assert result.exit_code == 1
    assert terminal.prompts == []  # never ask for a key on a run that can't start


# --- vulnctl auth -------------------------------------------------------------


def _invoke(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["auth", *args])
    return result.exit_code, result.stderr


def test_auth_nvd_saves_a_verified_key(terminal: Terminal, memory_keyring: MemoryKeyring) -> None:
    terminal.inputs = [GOOD]
    code, err = _invoke("nvd")
    assert code == 0
    assert memory_keyring.store[_SLOT] == GOOD
    assert "Verified and saved" in err
    assert "Enter to cancel" in terminal.prompts[0]


def test_auth_nvd_replaces_an_existing_key(
    terminal: Terminal, memory_keyring: MemoryKeyring
) -> None:
    save_nvd_key(BAD)
    terminal.inputs = [GOOD]
    assert _invoke("nvd")[0] == 0
    assert memory_keyring.store[_SLOT] == GOOD


def test_auth_nvd_cancel_exits_1_and_does_not_dismiss(terminal: Terminal) -> None:
    terminal.inputs = [""]
    assert _invoke("nvd")[0] == 1
    assert not prompt_dismissed()


def test_auth_nvd_needs_a_terminal(terminal: Terminal, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_terminal(monkeypatch)
    code, err = _invoke("nvd")
    assert code == 1
    assert NVD_KEY_ENV in err
    assert terminal.prompts == []


def test_auth_nvd_warns_when_the_env_var_will_override(
    terminal: Terminal, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(NVD_KEY_ENV, BAD)
    terminal.inputs = [GOOD]
    code, err = _invoke("nvd")
    assert code == 0
    assert "overrides the saved key" in err


def test_auth_status_none() -> None:
    code, err = _invoke("status")
    assert code == 0
    assert "none" in err and "vulnctl auth nvd" in err


def test_auth_status_masks_a_saved_key() -> None:
    save_nvd_key(GOOD)
    code, err = _invoke("status")
    assert code == 0
    assert "…5555" in err and "test keyring" in err
    assert GOOD not in err  # never print the whole key


def test_auth_status_names_the_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(NVD_KEY_ENV, GOOD)
    code, err = _invoke("status")
    assert code == 0
    assert NVD_KEY_ENV in err and GOOD not in err


def test_auth_remove(memory_keyring: MemoryKeyring) -> None:
    save_nvd_key(GOOD)
    code, err = _invoke("remove", "nvd")
    assert code == 0 and "Removed" in err
    assert memory_keyring.store == {}
    code, err = _invoke("remove", "nvd")
    assert code == 0 and "No saved" in err


def test_auth_remove_notes_a_lingering_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(NVD_KEY_ENV, GOOD)
    assert "still set" in _invoke("remove", "nvd")[1]


def test_auth_remove_rejects_unknown_services() -> None:
    assert runner.invoke(app, ["auth", "remove", "github"]).exit_code == 2


def test_auth_remove_reports_a_keychain_failure() -> None:
    class Locked(MemoryKeyring):
        def get_password(self, service: str, username: str) -> str | None:
            raise RuntimeError("keychain locked")

    import keyring

    keyring.set_keyring(Locked())
    code, err = _invoke("remove", "nvd")
    assert code == 1
    assert "keychain locked" in err
