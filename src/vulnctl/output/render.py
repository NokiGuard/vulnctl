"""Output-format dispatch — the one place the CLI picks a renderer.

Keeps ``cli.py`` thin: the command builds ``ranked`` results and hands them
here with the chosen :class:`OutputFormat`. New formats (SARIF, Markdown)
plug in as they land in M5 without touching the CLI.

Machine formats are written straight to ``console.file`` (the underlying
stream) rather than ``console.print`` so rich never wraps or styles them —
piped JSON/SARIF must stay byte-for-byte valid.
"""

from __future__ import annotations

from enum import StrEnum

from rich.console import Console

from vulnctl.models import RankedResult, RunMetadata
from vulnctl.output.json_out import render_json
from vulnctl.output.markdown import render_markdown
from vulnctl.output.sarif import render_sarif
from vulnctl.output.table import build_paths, build_table


class OutputFormat(StrEnum):
    """User-selectable ``--format`` value."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"
    MD = "md"


def render_output(
    ranked: list[RankedResult],
    metadata: RunMetadata,
    *,
    fmt: OutputFormat,
    show_path: bool,
    console: Console,
    artifact_uri: str | None = None,
) -> None:
    """Render ``ranked`` in the chosen format to ``console``'s stream.

    ``artifact_uri`` is the SBOM/scanner input path, used by SARIF to point
    results at the scanned artifact (ignored by the other formats).
    """
    if fmt is OutputFormat.JSON:
        console.file.write(render_json(ranked, metadata))
        return
    if fmt is OutputFormat.SARIF:
        console.file.write(render_sarif(ranked, metadata, artifact_uri=artifact_uri))
        return
    if fmt is OutputFormat.MD:
        console.file.write(render_markdown(ranked, metadata))
        return
    console.print(build_table(ranked, metadata))
    if show_path:
        console.print(build_paths(ranked))
