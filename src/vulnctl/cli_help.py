"""Extra panels for the root ``vulnctl --help``.

Typer's root help lists the commands but none of their flags, so a first-time
user has to run ``--help`` once per command before they know what the tool can
do. :class:`HelpfulGroup` appends two panels to the root help only: every
command's parameters — walked from the registered Click objects, so the
summary cannot drift from the real signatures — and worked examples of the
common workflows.

Per-command ``--help`` is untouched; it remains the place for defaults,
required-ness, and env vars.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from rich import box
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup

# Mirror Typer's help palette (typer.rich_utils) so the extra panels read as
# part of the same page rather than as something bolted on.
_STYLE_OPTION = "bold cyan"
_STYLE_SWITCH = "bold green"
_STYLE_TYPES = "bold yellow"
_STYLE_BORDER = "dim"

# One example per workflow the tool is built around: ad-hoc IDs, SBOM triage,
# CI gating, filtering, and single-finding forensics.
_EXAMPLES: tuple[tuple[str, str], ...] = (
    (
        "Rank two CVEs with no network, showing the path behind each verdict",
        "vulnctl enrich CVE-2021-44228 CVE-2019-0708 --offline --show-path",
    ),
    (
        "Rank an SBOM against your org context, as JSON for jq",
        "vulnctl enrich --sbom app.cdx.json --context context.yaml -f json",
    ),
    (
        "Gate CI on a Grype scan: exit 2 if anything lands on Attend or worse",
        "grype my-image:latest -o json | vulnctl enrich --grype - --fail-on attend",
    ),
    (
        "Triage the top of the pile: KEV-listed findings only",
        "vulnctl enrich --sbom app.cdx.json --only-kev --limit 10",
    ),
    (
        "Ask why one finding got its verdict, and what would change it",
        "vulnctl explain CVE-2021-44228",
    ),
)


def _value_hint(param: Any) -> str:
    """Render what an option takes: ``PATH``, ``[a|b]``, or "" for a switch."""
    if getattr(param, "is_flag", False):
        return ""
    if param.metavar:
        return str(param.metavar)
    choices = getattr(param.type, "choices", None)
    if choices:
        return "[" + "|".join(str(choice) for choice in choices) + "]"
    return str(param.type.name).upper()


def _arg_name(param: Any) -> str:
    """The metavar an argument is documented under, e.g. ``[VULN_ID...]``."""
    return str(param.metavar or str(param.name).upper())


def _visible_params(cmd: Any, kind: str) -> list[Any]:
    return [
        param
        for param in cmd.params
        if param.param_type_name == kind and not getattr(param, "hidden", False)
    ]


def _usage(path: str, cmd: Any) -> str:
    """The one-line invocation shape, e.g. ``vulnctl enrich [OPTIONS] [VULN_ID...]``."""
    parts = [path]
    if _visible_params(cmd, "option"):
        parts.append("[OPTIONS]")
    parts.extend(_arg_name(param) for param in _visible_params(cmd, "argument"))
    return " ".join(parts)


def _param_rows(cmd: Any) -> Iterator[tuple[Text, Text, str]]:
    """Yield ``(name, value hint, help)`` for one command's arguments and options."""
    for param in _visible_params(cmd, "argument"):
        yield (
            Text(f"  {_arg_name(param)}", style=_STYLE_OPTION),
            Text(str(param.type.name).upper(), style=_STYLE_TYPES),
            str(getattr(param, "help", "") or ""),
        )
    for param in _visible_params(cmd, "option"):
        switch = bool(getattr(param, "is_flag", False))
        yield (
            Text("  " + " ".join(param.opts), style=_STYLE_SWITCH if switch else _STYLE_OPTION),
            Text(_value_hint(param), style=_STYLE_TYPES),
            str(getattr(param, "help", "") or ""),
        )


def _leaf_commands(group: Any, prefix: str) -> Iterator[tuple[str, str, Any]]:
    """Walk the command tree depth-first, yielding ``(label, invocation, command)``.

    ``label`` is the command as the user types it after the program name
    (``enrich``, ``cache purge``); ``invocation`` includes the program name.
    Subgroups recurse so nested commands are listed rather than hidden behind
    another ``--help``.
    """
    for name, cmd in group.commands.items():
        if getattr(cmd, "hidden", False):
            continue
        label = f"{prefix} {name}".strip()
        subcommands = getattr(cmd, "commands", None)
        if subcommands:
            yield from _leaf_commands(cmd, label)
        else:
            yield label, name, cmd


def _flags_panel(group: Any, prog: str) -> Panel:
    """Every command's parameters, generated from the registered Click objects."""
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    table.add_column(no_wrap=True)  # command / flag
    table.add_column(overflow="fold")  # what it takes
    table.add_column()  # help

    for index, (label, _name, cmd) in enumerate(_leaf_commands(group, "")):
        if index:
            table.add_row("", "", "")
        table.add_row(
            Text(label, style="bold"),
            "",
            Text(_usage(f"{prog} {label}", cmd), style="dim"),
        )
        for name, hint, help_text in _param_rows(cmd):
            table.add_row(name, hint, help_text)

    return Panel(
        table,
        title="Options by command",
        title_align="left",
        border_style=_STYLE_BORDER,
        box=box.ROUNDED,
    )


def _examples_panel() -> Panel:
    """Worked invocations, one per supported workflow."""
    lines: list[RenderableType] = []
    for comment, command in _EXAMPLES:
        if lines:
            lines.append(Text(""))
        lines.append(Text(f"# {comment}", style="dim"))
        lines.append(Text(command, style=_STYLE_OPTION))
    return Panel(
        Group(*lines),
        title="Examples",
        title_align="left",
        border_style=_STYLE_BORDER,
        box=box.ROUNDED,
    )


class HelpfulGroup(TyperGroup):
    """Root group whose ``--help`` also lists every command's flags and examples."""

    def format_help(self, ctx: Any, formatter: Any) -> None:
        super().format_help(ctx, formatter)
        prog = str(ctx.find_root().info_name or "vulnctl")
        console = Console()
        console.print(_flags_panel(self, prog))
        console.print(_examples_panel())
        console.print(
            Padding(
                Text.assemble(
                    ("Run ", "dim"),
                    (f"{prog} COMMAND --help", "bold"),
                    (" for one command in full: defaults, value ranges, exit codes.", "dim"),
                ),
                (0, 1),
            )
        )
