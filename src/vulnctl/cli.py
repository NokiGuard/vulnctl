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
from vulnctl.ingest import IngestError
from vulnctl.models import Decision
from vulnctl.output import gate_exit_code
from vulnctl.output.render import OutputFormat, render_output
from vulnctl.pipeline import apply_tree, resolve_inputs, run_enrichment
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
        list[str] | None,
        typer.Argument(
            metavar="[CVE_ID...]",
            help="CVE IDs, e.g. CVE-2021-44228 (omit when using --sbom).",
        ),
    ] = None,
    sbom_path: Annotated[
        Path | None,
        typer.Option("--sbom", help="CycloneDX 1.4/1.5 JSON SBOM; components resolve via OSV."),
    ] = None,
    grype_source: Annotated[
        str | None,
        typer.Option("--grype", help="Grype JSON output file, or '-' to read stdin."),
    ] = None,
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
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.TABLE,
    fail_on: Annotated[
        Decision | None,
        typer.Option("--fail-on", help="Exit 2 if any finding's decision meets/exceeds this."),
    ] = None,
    show_path: Annotated[
        bool,
        typer.Option("--show-path", help="Print each finding's decision path (table format)."),
    ] = False,
) -> None:
    """Enrich CVE IDs, an SBOM, or a Grype scan with intel and rank with SSVC verdicts.

    Exit codes: 0 success, 1 input/config error, 2 --fail-on threshold met.
    """
    try:
        findings = resolve_inputs(cve_ids, sbom_path, grype_source)
        org_context = load_context(context_path)
        tree = load_tree(tree_path) if tree_path is not None else load_bundled_tree()
        with Cache() as cache:
            results, metadata = asyncio.run(
                run_enrichment(
                    findings=findings,
                    sbom_path=sbom_path,
                    grype_source=grype_source,
                    cache=cache,
                    offline=offline,
                )
            )
        ranked = apply_tree(results, org_context, tree)
    except (IngestError, ContextError, TreeError, EvaluationError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    artifact_uri = str(sbom_path) if sbom_path is not None else grype_source
    render_output(
        ranked,
        metadata,
        fmt=output_format,
        show_path=show_path,
        console=console,
        artifact_uri=artifact_uri if artifact_uri != "-" else None,
    )
    raise typer.Exit(gate_exit_code(ranked, fail_on))


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
