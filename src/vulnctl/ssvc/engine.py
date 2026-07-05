"""Pure SSVC tree walker (CLAUDE.md architecture rule 2: the engine is pure).

``evaluate`` performs no I/O, touches no network or cache, and is fully
deterministic: identical ``(Enrichment, OrgContext, DecisionTree)`` inputs
always yield the identical ``Verdict``.

Every node visit is recorded as a ``DecisionPathStep`` whose ``value_source``
is one of:

- ``"override"`` — forced via ``OrgContext.overrides`` (not a degradation)
- ``"context"`` — supplied by a ``from: context`` decision point
- a source label from a resolver (e.g. ``"kev"``, ``"exploits"``, ``"cvss"``)
- ``"default"`` — the tree's default applied because the derived input was
  Unavailable; this sets ``inputs_degraded=True`` on the verdict

A tree/context mismatch (override or context value outside a point's declared
values, unknown context key) is a hard ``EvaluationError`` — a broken
configuration must never silently mis-decide (FRAMEWORK.md §5).
"""

from __future__ import annotations

from vulnctl.context import OrgContext
from vulnctl.models import Decision, DecisionPath, DecisionPathStep, Enrichment, Verdict
from vulnctl.ssvc.tree import RESOLVERS, DecisionPointSpec, DecisionTree, TreeNode

_DEFAULT = "default"


class EvaluationError(Exception):
    """Tree, context, and enrichment cannot be combined coherently."""


def evaluate(enrichment: Enrichment, context: OrgContext, tree: DecisionTree) -> Verdict:
    """Walk ``tree`` for one enrichment, returning the verdict with its audit trail."""
    steps: list[DecisionPathStep] = []
    degraded = False
    node: TreeNode | Decision = tree.root
    while isinstance(node, TreeNode):
        spec = tree.decision_points[node.point]
        value, source = _resolve_value(node.point, spec, enrichment, context, tree)
        if source == _DEFAULT:
            degraded = True
        steps.append(DecisionPathStep(node=node.point, value=value, value_source=source))
        node = node.branches[value]
    return Verdict(
        decision=node,
        path=DecisionPath(steps=steps),
        tree_id=tree.id,
        inputs_degraded=degraded,
    )


def _resolve_value(
    point: str,
    spec: DecisionPointSpec,
    enrichment: Enrichment,
    context: OrgContext,
    tree: DecisionTree,
) -> tuple[str, str]:
    override = context.overrides.get(point)
    if override is not None:
        if override not in spec.values:
            raise EvaluationError(
                f"override for {point!r}: {override!r} is not a declared value "
                f"(declared: {', '.join(spec.values)})"
            )
        return override, "override"

    if spec.source == "context":
        if spec.key is None:  # unreachable: loader enforces key on context points
            raise EvaluationError(f"decision point {point!r} has no context key")
        try:
            value = context.decision_value(spec.key)
        except KeyError:
            raise EvaluationError(
                f"decision point {point!r} reads unknown context key {spec.key!r}"
            ) from None
        if value not in spec.values:
            raise EvaluationError(
                f"context value {value!r} for {point!r} is not a declared value "
                f"(declared: {', '.join(spec.values)})"
            )
        return value, "context"

    if spec.rule is None:  # unreachable: loader enforces rule on derived points
        raise EvaluationError(f"decision point {point!r} has no resolver rule")
    resolution = RESOLVERS[spec.rule](enrichment)
    if resolution is not None:
        value, source = resolution
        if value not in spec.values:
            raise EvaluationError(
                f"resolver {spec.rule!r} produced {value!r}, not a declared value of "
                f"{point!r} (declared: {', '.join(spec.values)})"
            )
        return value, source
    default = tree.defaults.get(point)
    if default is None:  # unreachable: loader requires defaults for derived points
        raise EvaluationError(f"input for {point!r} unavailable and no default declared")
    return default, _DEFAULT
