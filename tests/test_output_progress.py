"""Progress display: inert when disabled, stderr-only when enabled."""

from __future__ import annotations

import sys
from io import StringIO

import pytest
from rich.console import Console

from vulnctl.output.progress import EnrichmentProgress, _no_advance


def test_disabled_reporter_is_inert() -> None:
    reporter = EnrichmentProgress(enabled=False)
    with reporter:
        advance = reporter.add_phase("epss", 10)
        advance(10)  # harmless no-op
    assert reporter._progress is None  # no rich objects were ever constructed
    assert advance is _no_advance


def test_auto_gate_resolves_disabled_under_pytest() -> None:
    # Captured stderr is not a TTY; the default gate must land False even if
    # a dev shell exports FORCE_COLOR (the gate reads isatty, not rich).
    assert not sys.stderr.isatty()
    assert EnrichmentProgress()._progress is None


def test_enabled_reporter_advances_to_totals_without_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True, width=80)
    reporter = EnrichmentProgress(console=console, enabled=True)
    with reporter:
        fixed = reporter.add_phase("nvd", 3)
        indeterminate = reporter.add_phase("osv discovery", None)
        fixed(1)
        fixed(2)
        indeterminate(5)
    assert "nvd" in buffer.getvalue()  # rendered to the injected console…
    assert capsys.readouterr().out == ""  # …never to stdout
