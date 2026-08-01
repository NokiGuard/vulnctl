"""Typer app wiring. Thin by design — command bodies live in ``commands.py``,
business logic below that in ``pipeline`` and ``output``."""

from __future__ import annotations

from importlib.metadata import version as _pkg_version
from typing import Annotated

import typer
from rich.table import Table

from vulnctl import commands
from vulnctl.cache import Cache
from vulnctl.cli_help import HelpfulGroup
from vulnctl.commands import console

app = typer.Typer(
    name="vulnctl",
    cls=HelpfulGroup,  # root --help also lists every command's flags + examples
    help="Auditable, SSVC-based vulnerability prioritization.",
    no_args_is_help=True,
)
cache_app = typer.Typer(help="Inspect and manage the local response cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")

app.command()(commands.enrich)
app.command()(commands.explain)


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
