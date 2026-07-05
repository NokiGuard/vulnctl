"""SSVC decision-tree format: schema, strict loader, and derived-value resolvers.

A tree YAML document has four top-level keys (FRAMEWORK.md §3.4):

    id: cisa-deployer-v1
    decision_points:
      exploitation:
        from: derived          # value computed from Enrichment by a resolver
        rule: exploitation     # resolver name — a typed function, not a DSL
        values: [none, poc, active]
      exposure:
        from: context          # value supplied by OrgContext
        key: exposure
        values: [small, controlled, open]
    tree:                      # nested {point: {value: subtree-or-decision}}
      exploitation:
        none: track
        ...
    defaults:                  # applied when a derived input is Unavailable
      exploitation: none

Validation is strict and loud (FRAMEWORK.md §5: a broken tree must never
silently mis-decide). Load-time hard errors: unknown top-level keys, unknown
decision-point references, branch sets that don't exactly match a point's
declared values (missing or extra), a point repeated along one path (its
other branches would be unreachable), declared points never used in the
tree, defaults referencing unknown points or values, unknown resolver
names, and derived points without a default (a degraded enrichment must
always have a recorded fallback rather than a mid-run crash).

YAML 1.1 tools sometimes emit ``none``/``yes``/``no`` as null/booleans;
scalar keys and values are normalized back to those strings before
validation so hand-edited trees behave identically everywhere.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from vulnctl.models import CvssData, Decision, Enrichment, ExploitData, KevData

_TOP_LEVEL_KEYS = {"id", "decision_points", "tree", "defaults"}
_MODEL_CONFIG = ConfigDict(strict=True, frozen=True, extra="forbid")


class TreeError(Exception):
    """A tree document failed validation; the message says exactly where and why."""


def _norm(value: Any) -> Any:
    """Undo YAML-1.1-style coercion of bare none/yes/no scalars."""
    if value is None:
        return "none"
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return value


# --- Derived-value resolvers -------------------------------------------------
#
# A resolver maps an Enrichment to (value, source_label) for one decision
# point, or None when its inputs are Unavailable — the engine then applies the
# tree's default and records value_source="default".

Resolution = tuple[str, str]
Resolver = Callable[[Enrichment], Resolution | None]


def _resolve_exploitation(enrichment: Enrichment) -> Resolution | None:
    """Exploitation status: active > poc > none, degrading only when unknowable.

    - KEV listed → ``active`` (source ``kev``): a positive signal wins even if
      exploit-presence data is unavailable.
    - Any public exploit artifact (EDB, Metasploit, nuclei) → ``poc``
      (source ``exploits``).
    - Both sources answered and both negative → ``none`` (source
      ``kev+exploits``).
    - Otherwise (either source Unavailable with no positive signal) → None:
      ``none`` cannot be asserted from partial data, so the tree default
      applies and the verdict is flagged degraded. Until the M5 exploit
      adapter lands, exploits is always Unavailable, so unlisted CVEs flow
      through the default by design.
    """
    kev = enrichment.kev
    exploits = enrichment.exploits
    if isinstance(kev, KevData) and kev.listed:
        return ("active", "kev")
    if isinstance(exploits, ExploitData):
        if exploits.edb_ids or exploits.msf_modules or exploits.nuclei_templates:
            return ("poc", "exploits")
        if isinstance(kev, KevData):
            return ("none", "kev+exploits")
    return None


def _resolve_automatable(enrichment: Enrichment) -> Resolution | None:
    """Automatable: can an attacker reliably automate steps 1-4 of the kill chain?

    Heuristic (documented tradeoff, overridable via context ``overrides``):
    a CVSS v3.x vector with AV:N (network), AC:L (low complexity), PR:N (no
    privileges), and UI:N (no user interaction) → ``yes``; any v3.x vector
    missing one of those → ``no``. CVSS v2 vectors and Unavailable CVSS →
    None (tree default applies; the verdict is flagged degraded).
    """
    cvss = enrichment.cvss
    if not isinstance(cvss, CvssData) or not cvss.vector.startswith("CVSS:3"):
        return None
    metrics = dict(part.split(":", 1) for part in cvss.vector.split("/")[1:] if ":" in part)
    automatable = (
        metrics.get("AV") == "N"
        and metrics.get("AC") == "L"
        and metrics.get("PR") == "N"
        and metrics.get("UI") == "N"
    )
    return ("yes" if automatable else "no", "cvss")


RESOLVERS: dict[str, Resolver] = {
    "exploitation": _resolve_exploitation,
    "automatable": _resolve_automatable,
}


# --- Schema -------------------------------------------------------------------


class DecisionPointSpec(BaseModel):
    """One decision point: where its value comes from and its allowed values."""

    model_config = _MODEL_CONFIG

    source: Literal["derived", "context"] = Field(alias="from")
    rule: str | None = None
    key: str | None = None
    values: list[str] = Field(min_length=2)


class TreeNode(BaseModel):
    """An internal node: which point to read and a branch per declared value."""

    model_config = _MODEL_CONFIG

    point: str
    branches: dict[str, TreeNode | Decision]


class DecisionTree(BaseModel):
    """A fully validated decision tree; construct via :meth:`from_raw` or ``load_tree``."""

    model_config = _MODEL_CONFIG

    id: str
    decision_points: dict[str, DecisionPointSpec]
    root: TreeNode
    defaults: dict[str, str]

    @classmethod
    def from_raw(cls, raw: Any) -> DecisionTree:
        """Validate a parsed YAML document into a DecisionTree; TreeError on any defect."""
        if not isinstance(raw, dict):
            raise TreeError("tree document must be a mapping")
        unknown = set(raw) - _TOP_LEVEL_KEYS
        if unknown:
            raise TreeError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
        missing = {"id", "decision_points", "tree"} - set(raw)
        if missing:
            raise TreeError(f"missing required top-level key(s): {', '.join(sorted(missing))}")

        tree_id = raw["id"]
        if not isinstance(tree_id, str) or not tree_id:
            raise TreeError("'id' must be a non-empty string")

        points = _parse_points(raw["decision_points"])
        used: set[str] = set()
        root = _parse_node(raw["tree"], points, on_path=frozenset(), used=used, where="tree")
        if isinstance(root, Decision):
            raise TreeError("'tree' must be a decision node, not a bare decision")
        unused = set(points) - used
        if unused:
            raise TreeError(
                f"decision point(s) declared but never used in the tree: "
                f"{', '.join(sorted(unused))}"
            )
        defaults = _parse_defaults(raw.get("defaults", {}), points)
        return cls(id=tree_id, decision_points=points, root=root, defaults=defaults)


def _parse_points(raw: Any) -> dict[str, DecisionPointSpec]:
    if not isinstance(raw, dict) or not raw:
        raise TreeError("'decision_points' must be a non-empty mapping")
    points: dict[str, DecisionPointSpec] = {}
    for raw_name, raw_spec in raw.items():
        name = str(_norm(raw_name))
        if not isinstance(raw_spec, dict):
            raise TreeError(f"decision point {name!r}: spec must be a mapping")
        normalized = dict(raw_spec)
        if isinstance(normalized.get("values"), list):
            normalized["values"] = [str(_norm(v)) for v in normalized["values"]]
        try:
            spec = DecisionPointSpec.model_validate(normalized)
        except ValidationError as exc:
            raise TreeError(f"decision point {name!r}: {exc}") from exc
        if len(set(spec.values)) != len(spec.values):
            raise TreeError(f"decision point {name!r}: duplicate values")
        if spec.source == "derived":
            if spec.rule is None or spec.key is not None:
                raise TreeError(f"decision point {name!r}: from=derived requires 'rule' only")
            if spec.rule not in RESOLVERS:
                raise TreeError(
                    f"decision point {name!r}: unknown rule {spec.rule!r} "
                    f"(known: {', '.join(sorted(RESOLVERS))})"
                )
        else:
            if spec.key is None or spec.rule is not None:
                raise TreeError(f"decision point {name!r}: from=context requires 'key' only")
        points[name] = spec
    return points


def _parse_node(
    raw: Any,
    points: dict[str, DecisionPointSpec],
    *,
    on_path: frozenset[str],
    used: set[str],
    where: str,
) -> TreeNode | Decision:
    normalized = _norm(raw)
    if isinstance(normalized, str):
        try:
            return Decision(normalized)
        except ValueError:
            raise TreeError(
                f"{where}: invalid decision {normalized!r} "
                f"(expected one of: {', '.join(d.value for d in Decision)})"
            ) from None
    if not isinstance(raw, dict):
        raise TreeError(f"{where}: node must be a mapping or a decision string")
    if len(raw) != 1:
        raise TreeError(
            f"{where}: node must reference exactly one decision point, "
            f"got {len(raw)}: {', '.join(str(_norm(k)) for k in raw)}"
        )
    raw_point, raw_branches = next(iter(raw.items()))
    point = str(_norm(raw_point))
    if point not in points:
        raise TreeError(f"{where}: unknown decision point {point!r}")
    if point in on_path:
        raise TreeError(
            f"{where}: decision point {point!r} repeated along one path — "
            "its earlier value is already fixed, so these branches are unreachable"
        )
    used.add(point)
    if not isinstance(raw_branches, dict):
        raise TreeError(f"{where}.{point}: branches must be a mapping of value to subtree")

    branches_raw = {str(_norm(value)): subtree for value, subtree in raw_branches.items()}
    declared = set(points[point].values)
    missing = declared - set(branches_raw)
    if missing:
        raise TreeError(
            f"{where}.{point}: missing branch(es) for value(s): "
            f"{', '.join(sorted(missing))} — every declared value needs a path"
        )
    extra = set(branches_raw) - declared
    if extra:
        raise TreeError(
            f"{where}.{point}: branch(es) for undeclared value(s): {', '.join(sorted(extra))}"
        )
    branches = {
        value: _parse_node(
            subtree, points, on_path=on_path | {point}, used=used, where=f"{where}.{point}.{value}"
        )
        for value, subtree in branches_raw.items()
    }
    return TreeNode(point=point, branches=branches)


def _parse_defaults(raw: Any, points: dict[str, DecisionPointSpec]) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise TreeError("'defaults' must be a mapping of decision point to value")
    defaults: dict[str, str] = {}
    for raw_point, raw_value in raw.items():
        point = str(_norm(raw_point))
        if point not in points:
            raise TreeError(f"defaults: unknown decision point {point!r}")
        value = str(_norm(raw_value))
        if value not in points[point].values:
            raise TreeError(
                f"defaults: {value!r} is not a declared value of {point!r} "
                f"(declared: {', '.join(points[point].values)})"
            )
        defaults[point] = value
    for name, spec in points.items():
        if spec.source == "derived" and name not in defaults:
            raise TreeError(
                f"derived decision point {name!r} has no default — required so a "
                "degraded enrichment falls back audibly instead of crashing mid-run"
            )
    return defaults


def load_tree(path: Path) -> DecisionTree:
    """Load and validate a tree YAML file; TreeError with an actionable message."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TreeError(f"cannot read tree file {path}: {exc}") from exc
    try:
        raw = YAML(typ="safe").load(text)
    except YAMLError as exc:
        raise TreeError(f"tree file {path} is not valid YAML: {exc}") from exc
    return DecisionTree.from_raw(raw)
