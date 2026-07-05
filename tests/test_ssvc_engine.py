"""Engine tests: walking, value sources, degradation flag, determinism."""

from __future__ import annotations

import itertools

import pytest

from conftest import FIXTURES_DIR
from test_ssvc_tree import (
    _AUTOMATABLE_CVSS,
    _NO_EXPLOITS,
    _SOME_EXPLOITS,
    _UNAVAILABLE,
    _V2_CVSS,
    enrichment,
)
from vulnctl.context import Exposure, MissionImpact, OrgContext
from vulnctl.models import CvssData, Decision, ExploitData, KevData, Unavailable
from vulnctl.ssvc.engine import EvaluationError, evaluate
from vulnctl.ssvc.tree import DecisionTree, load_tree

TOY = load_tree(FIXTURES_DIR / "trees" / "toy.yaml")


def test_walk_records_every_hop_with_sources() -> None:
    verdict = evaluate(
        enrichment(kev=KevData(listed=True)),
        OrgContext(exposure=Exposure.INTERNET),
        TOY,
    )
    assert verdict.decision is Decision.ACT
    assert verdict.tree_id == "toy-v1"
    assert verdict.inputs_degraded is False
    assert [(s.node, s.value, s.value_source) for s in verdict.path.steps] == [
        ("exploitation", "active", "kev"),
        ("exposure", "open", "context"),
    ]


def test_default_applied_on_unavailable_flags_degraded() -> None:
    verdict = evaluate(enrichment(), OrgContext(), TOY)
    assert verdict.decision is Decision.TRACK
    assert verdict.inputs_degraded is True
    assert verdict.path.steps[0].value == "none"
    assert verdict.path.steps[0].value_source == "default"


def test_override_forces_value_and_is_not_degraded() -> None:
    verdict = evaluate(
        enrichment(),  # exploitation would degrade to the default without the override
        OrgContext(exposure=Exposure.INTERNAL, overrides={"exploitation": "poc"}),
        TOY,
    )
    assert verdict.decision is Decision.TRACK_STAR
    assert verdict.inputs_degraded is False
    assert verdict.path.steps[0].value_source == "override"


def test_invalid_override_value_is_hard_error() -> None:
    with pytest.raises(EvaluationError, match="override for 'exploitation'"):
        evaluate(enrichment(), OrgContext(overrides={"exploitation": "sideways"}), TOY)


def test_exposure_mapping_isolated_becomes_small() -> None:
    verdict = evaluate(
        enrichment(kev=KevData(listed=True)),
        OrgContext(exposure=Exposure.ISOLATED),
        TOY,
    )
    assert verdict.decision is Decision.TRACK_STAR
    assert verdict.path.steps[1].value == "small"


def test_unknown_context_key_is_hard_error() -> None:
    tree = DecisionTree.from_raw(
        {
            "id": "badkey-v1",
            "decision_points": {
                "exploitation": {
                    "from": "derived",
                    "rule": "exploitation",
                    "values": ["none", "poc", "active"],
                },
                "weather": {"from": "context", "key": "weather", "values": ["sunny", "rainy"]},
            },
            "tree": {
                "exploitation": {
                    "none": "track",
                    "poc": {"weather": {"sunny": "track", "rainy": "attend"}},
                    "active": {"weather": {"sunny": "attend", "rainy": "act"}},
                }
            },
            "defaults": {"exploitation": "active"},
        }
    )
    with pytest.raises(EvaluationError, match="unknown context key 'weather'"):
        evaluate(enrichment(), OrgContext(), tree)


def test_determinism_across_input_grid() -> None:
    """Identical inputs must always produce the identical verdict."""
    kev_variants: list[KevData | Unavailable] = [
        KevData(listed=True),
        KevData(listed=False),
        _UNAVAILABLE,
    ]
    exploit_variants: list[ExploitData | Unavailable] = [
        _SOME_EXPLOITS,
        _NO_EXPLOITS,
        _UNAVAILABLE,
    ]
    cvss_variants: list[CvssData | Unavailable] = [_AUTOMATABLE_CVSS, _V2_CVSS, _UNAVAILABLE]
    contexts = [
        OrgContext(exposure=exposure, mission_impact=impact)
        for exposure, impact in itertools.product(Exposure, MissionImpact)
    ] + [OrgContext(overrides={"exploitation": "active"})]

    checked = 0
    for kev, exploits, cvss, context in itertools.product(
        kev_variants, exploit_variants, cvss_variants, contexts
    ):
        e = enrichment(kev=kev, exploits=exploits, cvss=cvss)
        first = evaluate(e, context, TOY)
        second = evaluate(e, context, TOY)
        assert first == second
        assert len(first.path.steps) >= 1
        checked += 1
    assert checked == 3 * 3 * 3 * 13


def _hand_built_tree(point_spec: dict[str, object], defaults: dict[str, str]) -> DecisionTree:
    """Bypass from_raw's cross-checks to reach the engine's defensive errors."""
    from vulnctl.models import Decision
    from vulnctl.ssvc.tree import DecisionPointSpec, TreeNode

    spec = DecisionPointSpec.model_validate({"values": ["a", "b"], **point_spec})
    return DecisionTree(
        id="handmade-v1",
        decision_points={"p": spec},
        root=TreeNode(point="p", branches={"a": Decision.TRACK, "b": Decision.ACT}),
        defaults=defaults,
    )


def test_context_point_without_key_is_hard_error() -> None:
    tree = _hand_built_tree({"from": "context"}, defaults={})
    with pytest.raises(EvaluationError, match="has no context key"):
        evaluate(enrichment(), OrgContext(), tree)


def test_context_value_outside_declared_values_is_hard_error() -> None:
    tree = _hand_built_tree({"from": "context", "key": "exposure"}, defaults={})
    with pytest.raises(EvaluationError, match="not a declared value"):
        evaluate(enrichment(), OrgContext(), tree)  # exposure maps to "open", not in [a, b]


def test_derived_point_without_rule_is_hard_error() -> None:
    tree = _hand_built_tree({"from": "derived"}, defaults={"p": "a"})
    with pytest.raises(EvaluationError, match="has no resolver rule"):
        evaluate(enrichment(), OrgContext(), tree)


def test_resolver_returning_undeclared_value_is_hard_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnctl.ssvc import tree as tree_module

    monkeypatch.setitem(tree_module.RESOLVERS, "exploitation", lambda e: ("sideways", "kev"))
    with pytest.raises(EvaluationError, match="resolver 'exploitation' produced 'sideways'"):
        evaluate(enrichment(), OrgContext(), TOY)


def test_unavailable_input_without_default_is_hard_error() -> None:
    tree = _hand_built_tree({"from": "derived", "rule": "exploitation"}, defaults={})
    with pytest.raises(EvaluationError, match="unavailable and no default"):
        evaluate(enrichment(), OrgContext(), tree)


def test_degraded_only_when_default_used() -> None:
    # Fully resolvable: KEV answered no, exploits answered empty.
    verdict = evaluate(
        enrichment(kev=KevData(listed=False), exploits=_NO_EXPLOITS), OrgContext(), TOY
    )
    assert verdict.inputs_degraded is False
    assert verdict.path.steps[0].value_source == "kev+exploits"
