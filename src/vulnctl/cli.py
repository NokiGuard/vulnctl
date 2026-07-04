"""Typer CLI entry point. Thin by design — no business logic lives here."""

from __future__ import annotations

import re
from importlib.metadata import version as _pkg_version
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulnctl.cache import Cache

app = typer.Typer(
    name="vulnctl",
    help="Auditable, SSVC-based vulnerability prioritization.",
    no_args_is_help=True,
)
cache_app = typer.Typer(help="Inspect and manage the local response cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")

console = Console()

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"vulnctl {_pkg_version('vulnctl')}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Not another score. A defensible decision."""


def _validate_cve_id(value: str) -> str:
    if not _CVE_ID_RE.fullmatch(value):
        raise typer.BadParameter(f"{value!r} is not a CVE ID (expected CVE-YYYY-NNNN...)")
    return value.upper()


@app.command()
def enrich(
    cve_ids: Annotated[
        list[str],
        typer.Argument(
            metavar="CVE_ID...",
            callback=lambda ids: [_validate_cve_id(i) for i in ids],
            help="One or more CVE IDs, e.g. CVE-2021-44228.",
        ),
    ],
) -> None:
    """Enrich CVE IDs with threat intelligence and rank them (not yet implemented)."""
    console.print(
        f"[yellow]Enrichment is not yet implemented[/yellow] — "
        f"parsed {len(cve_ids)} CVE ID(s): {', '.join(cve_ids)}.\n"
        "Source adapters arrive in milestone M2 (see ROADMAP.md)."
    )


@cache_app.command()
def stats() -> None:
    """Show cache location, size, and entry counts per source."""
    with Cache() as cache:
        s = cache.stats()
    table = Table(title=f"vulnctl cache — {s.path} ({s.size_bytes:,} bytes)")
    table.add_column("Source")
    table.add_column("Entries", justify="right")
    for source, count in s.entries_by_source.items():
        table.add_row(source, str(count))
    table.add_row("[bold]total[/bold]", f"[bold]{s.total_entries}[/bold]")
    console.print(table)


@cache_app.command()
def purge(
    source: Annotated[
        str | None,
        typer.Option("--source", help="Purge only this source's entries (default: all)."),
    ] = None,
) -> None:
    """Delete cached entries, optionally scoped to one source."""
    with Cache() as cache:
        removed = cache.purge(source)
    scope = f"source {source!r}" if source else "all sources"
    console.print(f"Purged {removed} entrie(s) for {scope}.")
