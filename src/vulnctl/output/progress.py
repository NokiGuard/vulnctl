"""Live enrichment progress on stderr (rich), off unless stderr is a real TTY.

The gate is plain ``sys.stderr.isatty()`` — deliberately not rich's
``Console.is_terminal``, which honors FORCE_COLOR: under Typer's CliRunner
(which merges stderr into the captured output) a forced-on display would
corrupt every CLI test assertion. When disabled, no rich objects are
constructed at all — rich's ``Live.stop()`` prints a final frame even to
non-terminal consoles, and the safest frame is the one never rendered.

stdout is never touched: machine formats (``-f json | jq``) stay byte-clean
while the display runs. Columns show elapsed time, not ETA — NVD's
burst-then-wait rate limiting makes ETAs lie.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from types import TracebackType
from typing import Protocol

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)


def _no_advance(count: int) -> None:
    """Advance callback handed out while the display is disabled."""


class ProgressReporter(Protocol):
    """What the pipeline needs from a progress display: named, advanceable phases."""

    def add_phase(self, name: str, total: int | None) -> Callable[[int], None]:
        """Register a phase (``total=None`` renders indeterminate); returns advance(n)."""
        ...


class EnrichmentProgress:
    """Context-managed rich ``Progress`` on stderr; completely inert when disabled."""

    def __init__(self, *, console: Console | None = None, enabled: bool | None = None) -> None:
        if enabled is None:
            enabled = sys.stderr.isatty()
        self._progress: Progress | None = None
        if enabled:
            self._progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console if console is not None else Console(stderr=True),
                transient=True,
            )

    def __enter__(self) -> EnrichmentProgress:
        if self._progress is not None:
            self._progress.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.stop()

    def add_phase(self, name: str, total: int | None) -> Callable[[int], None]:
        if self._progress is None:
            return _no_advance
        progress = self._progress
        task_id = progress.add_task(name, total=total)

        def advance(count: int) -> None:
            progress.advance(task_id, count)

        return advance
