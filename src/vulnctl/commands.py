"""Data commands (``enrich``; ``explain`` lands with it) — thin by design.

These are Typer signatures plus dispatch only: parsing, enrichment, tree
evaluation, and rendering all live in ``pipeline`` and ``output``. Split out
of ``cli.py`` so the app-wiring module stays under its ~150-line budget
(CLAUDE.md style notes); ``cli.py`` registers these on the app.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vulnctl.cache import Cache
from vulnctl.context import ContextError, load_context
from vulnctl.ingest import IngestError
from vulnctl.models import Decision
from vulnctl.output import gate_exit_code
from vulnctl.output.render import OutputFormat, render_output
from vulnctl.pipeline import apply_tree, resolve_inputs, run_enrichment
from vulnctl.ssvc.engine import EvaluationError
from vulnctl.ssvc.tree import TreeError, load_bundled_tree, load_tree

console = Console()

_INPUT_ERRORS = (IngestError, ContextError, TreeError, EvaluationError)


def enrich(
    vuln_ids: Annotated[
        list[str] | None,
        typer.Argument(
            metavar="[VULN_ID...]",
            help="CVE or GHSA IDs, e.g. CVE-2021-44228 (omit when using --sbom or --grype).",
        ),
    ] = None,
    sbom_path: Annotated[
        Path | None,
        typer.Option("--sbom", help="CycloneDX 1.4-1.6 JSON SBOM; components resolve via OSV."),
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
    """Enrich CVE/GHSA IDs, an SBOM, or a Grype scan with intel and rank with SSVC verdicts.

    Exit codes: 0 success, 1 input/config error, 2 --fail-on threshold met.
    """
    try:
        findings = resolve_inputs(vuln_ids, sbom_path, grype_source)
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
    except _INPUT_ERRORS as exc:
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
