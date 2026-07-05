"""Typer CLI entry point. Thin by design — no business logic lives here."""

from __future__ import annotations

import asyncio
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulnctl.cache import Cache
from vulnctl.context import ContextError, load_context
from vulnctl.ingest.cve_list import parse_cve_ids
from vulnctl.output.table import build_paths, build_table
from vulnctl.pipeline import apply_tree, enrich_findings
from vulnctl.ssvc.engine import EvaluationError
from vulnctl.ssvc.tree import TreeError, load_bundled_tree, load_tree

app = typer.Typer(
    name="vulnctl",
    help="Auditable, SSVC-based vulnerability prioritization.",
    no_args_is_help=True,
)
cache_app = typer.Typer(help="Inspect and manage the local response cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")

console = Console()


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


@app.command()
def enrich(
    cve_ids: Annotated[
        list[str],
        typer.Argument(metavar="CVE_ID...", help="One or more CVE IDs, e.g. CVE-2021-44228."),
    ],
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Use only cached data and bundled snapshots; never touch the network.",
        ),
    ] = False,
    context_path: Annotated[
        Path | None,
        typer.Option("--context", help="Org context YAML (default: conservative defaults)."),
    ] = None,
    tree_path: Annotated[
        Path | None,
        typer.Option("--tree", help="Decision-tree YAML (default: bundled cisa-deployer-v1)."),
    ] = None,
    show_path: Annotated[
        bool,
        typer.Option("--show-path", help="Print each finding's full decision path."),
    ] = False,
) -> None:
    """Enrich CVE IDs with threat intel and rank them with SSVC verdicts."""
    try:
        findings = parse_cve_ids(cve_ids)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    try:
        org_context = load_context(context_path)
        tree = load_tree(tree_path) if tree_path is not None else load_bundled_tree()
        with Cache() as cache:
            results, metadata = asyncio.run(enrich_findings(findings, cache=cache, offline=offline))
        ranked = apply_tree(results, org_context, tree)
    except (ContextError, TreeError, EvaluationError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(build_table(ranked, metadata))
    if show_path:
        console.print(build_paths(ranked))


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
