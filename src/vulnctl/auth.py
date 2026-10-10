"""``vulnctl auth`` commands and the first-run NVD key prompt.

Without a key NVD allows ~7 lookups a minute, which is most of a large run's
wall time; a free key makes it ~10x faster. So the first interactive online
``enrich``/``explain`` with no key configured offers to save one — once. A
skipped prompt is remembered (a marker file, no secret) and never repeats;
``vulnctl auth nvd`` sets or replaces the key at any time.

The prompt never appears where it could break a pipeline or a script: when
stdin or stderr is not a terminal, under CI, with ``--offline``, or when stdin
carries the scan (``--grype -``). It writes to stderr and reads with
``getpass`` (no echo), so ``-f json > out.json`` stays byte-clean.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import re
import sys
from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console

from vulnctl.adapters.nvd import KeyCheck, check_api_key
from vulnctl.credentials import (
    NVD_KEY_ENV,
    CredentialError,
    KeySource,
    delete_nvd_key,
    dismiss_prompt,
    keychain_name,
    mask,
    prompt_dismissed,
    resolve_nvd_key,
    save_nvd_key,
)
from vulnctl.pipeline import default_client

KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"
_MAX_ATTEMPTS = 3
#: Keys go into an HTTP header: printable ASCII, no whitespace, bounded.
_KEY_SHAPE = re.compile(r"[\x21-\x7e]{8,256}")

err = Console(stderr=True, highlight=False)

auth_app = typer.Typer(
    help="Manage the optional NVD API key (saved in your OS keychain).", no_args_is_help=True
)


class Service(StrEnum):
    """Services whose credentials ``vulnctl auth`` manages."""

    NVD = "nvd"


def run_credentials(*, offline: bool, stdin_is_data: bool) -> dict[str, str]:
    """Credentials for one enrichment run, keyed by adapter name.

    Resolves the NVD key (env var, then keychain) and, when none exists and
    the session is interactive, offers the one-time prompt. Offline runs
    never touch NVD, so they never resolve or prompt.
    """
    if offline:
        return {}
    resolved = resolve_nvd_key()
    if resolved.key is not None:
        return {"nvd": resolved.key}
    if stdin_is_data or not _interactive() or prompt_dismissed():
        return {}
    err.print(
        "[bold]No NVD API key found.[/bold] Without one NVD allows about 7 lookups a "
        "minute;\na free key makes enrichment ~10x faster: "
        f"[link={KEY_URL}]{KEY_URL}[/link]"
    )
    key = _ask_for_key(allow_skip=True)
    return {"nvd": key} if key is not None else {}


@auth_app.command("nvd")
def set_nvd() -> None:
    """Save or replace your NVD API key (hidden input, verified against NVD).

    The key is stored in your OS keychain. VULNCTL_NVD_API_KEY, when set,
    takes precedence over the saved key (useful in CI).
    """
    if not _interactive():
        err.print(
            "[red]error:[/red] `vulnctl auth nvd` needs a terminal to read the key; "
            f"in scripts and CI set {NVD_KEY_ENV} instead."
        )
        raise typer.Exit(1)
    if _ask_for_key(allow_skip=False) is None:
        raise typer.Exit(1)
    if os.environ.get(NVD_KEY_ENV, "").strip():
        err.print(f"[yellow]note:[/yellow] {NVD_KEY_ENV} is set and overrides the saved key.")


@auth_app.command("status")
def status() -> None:
    """Show which NVD API key vulnctl will use, and where it comes from."""
    resolved = resolve_nvd_key()
    if resolved.key is None:
        detail = f" ({resolved.note})" if resolved.note else ""
        err.print(f"NVD API key: [yellow]none[/yellow]{detail} — add one with `vulnctl auth nvd`")
        return
    where = (
        f"environment variable {NVD_KEY_ENV}"
        if resolved.source is KeySource.ENV
        else keychain_name()
    )
    err.print(f"NVD API key: [green]{mask(resolved.key)}[/green] from {where}")


@auth_app.command("remove")
def remove(
    service: Annotated[Service, typer.Argument(help="Which credential to remove.")],
) -> None:
    """Delete a saved key from the OS keychain (environment variables are untouched)."""
    try:
        removed = delete_nvd_key()
    except CredentialError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    if removed:
        err.print(f"Removed the saved {service.value.upper()} API key from {keychain_name()}.")
    else:
        err.print(f"No saved {service.value.upper()} API key to remove.")
    if os.environ.get(NVD_KEY_ENV, "").strip():
        err.print(f"[yellow]note:[/yellow] {NVD_KEY_ENV} is still set and will be used.")


def _ask_for_key(*, allow_skip: bool) -> str | None:
    """Read, verify, and save a key; None if skipped or every attempt failed.

    Only an explicit skip (Enter on the first-run prompt) is remembered —
    running out of attempts on a mistyped key must not silence the prompt
    for good. A key NVD rejects is re-asked (up to three tries). A key that cannot be
    verified because NVD is unreachable is saved anyway with a warning — an
    outage must not stop you saving a good key. A keychain that refuses the
    write still lets this run use the key.
    """
    hint = "Enter to skip" if allow_skip else "Enter to cancel"
    for _ in range(_MAX_ATTEMPTS):
        key = _read_secret(f"NVD API key (input hidden; {hint}): ").strip()
        if not key:
            if allow_skip:
                dismiss_prompt()
                err.print("Skipped — vulnctl won't ask again. Add one any time: `vulnctl auth nvd`")
            return None
        if not _KEY_SHAPE.fullmatch(key):
            err.print("[red]That doesn't look like an API key[/red] (8-256 printable characters).")
            continue
        outcome, detail = _verify(key)
        if outcome is KeyCheck.INVALID:
            err.print(f"[red]{detail}.[/red] Check the key and try again.")
            continue
        if outcome is KeyCheck.UNVERIFIED:
            err.print(f"[yellow]Couldn't verify the key[/yellow] — {detail}; saving it anyway.")
        try:
            save_nvd_key(key)
        except CredentialError as exc:
            err.print(
                f"[yellow]warning:[/yellow] {exc}. Using the key for this run only; "
                f"set {NVD_KEY_ENV} to keep it."
            )
            return key
        verified = "Verified and saved" if outcome is KeyCheck.VALID else "Saved"
        err.print(f"[green]{verified}[/green] to {keychain_name()}.")
        return key
    err.print("No key saved. Try again any time with `vulnctl auth nvd`.")
    return None


def _verify(key: str) -> tuple[KeyCheck, str]:
    async def _probe() -> tuple[KeyCheck, str]:
        async with default_client() as client:
            return await check_api_key(client, key)

    return asyncio.run(_probe())


def _read_secret(prompt: str) -> str:
    """Hidden input on the terminal (``getpass`` uses /dev/tty, never stdout)."""
    return getpass.getpass(prompt, stream=sys.stderr)


def _interactive() -> bool:
    """A human at a terminal: stdin and stderr are TTYs and this is not CI."""
    return sys.stdin.isatty() and sys.stderr.isatty() and not os.environ.get("CI")
