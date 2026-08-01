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

from vulnctl.models import Decision, RankedResult, RunMetadata
from vulnctl.output import filter_results
from vulnctl.output.json_out import render_json
from vulnctl.output.markdown import render_markdown
from vulnctl.output.sarif import render_sarif
from vulnctl.output.table import build_paths, build_summary, build_table


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
    min_decision: Decision | None = None,
    only_kev: bool = False,
    limit: int | None = None,
) -> None:
    """Render ``ranked`` in the chosen format to ``console``'s stream.

    The display filters (``min_decision``/``only_kev``/``limit``) shape every
    format's result list identically; the table's summary line still counts
    the full set so a filtered-out Act stays visible. ``artifact_uri`` is the
    SBOM/scanner input path, used by SARIF to point results at the scanned
    artifact (ignored by the other formats).
    """
    shown = filter_results(ranked, min_decision=min_decision, only_kev=only_kev, limit=limit)
    if fmt is OutputFormat.JSON:
        console.file.write(render_json(shown, metadata))
        return
    if fmt is OutputFormat.SARIF:
        console.file.write(render_sarif(shown, metadata, artifact_uri=artifact_uri))
        return
    if fmt is OutputFormat.MD:
        console.file.write(render_markdown(shown, metadata))
        return
    console.print(build_table(shown, metadata))
    if show_path:
        console.print(build_paths(shown))
    console.print(build_summary(ranked, shown=len(shown)))
