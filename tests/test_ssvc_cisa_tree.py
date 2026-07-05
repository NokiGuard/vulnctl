"""Bundled CISA deployer tree: every one of the 72 paths, plus end-to-end cases.

EXPECTED below is an independent transcription of the CERT/CC deployer table
(fetched 2026-07-04, outcomes renamed defer→track, scheduled→track*,
out-of-cycle→attend, immediate→act). The bundled YAML was generated
separately; these tests catch any divergence between the two.
"""

from __future__ import annotations

import pytest

from test_ssvc_tree import _AUTOMATABLE_CVSS, enrichment
from vulnctl.context import Exposure, MissionImpact, OrgContext
from vulnctl.models import Decision, KevData
from vulnctl.ssvc.engine import evaluate
from vulnctl.ssvc.tree import load_bundled_tree

TREE = load_bundled_tree()

T = Decision.TRACK
TS = Decision.TRACK_STAR
A = Decision.ATTEND
ACT = Decision.ACT

HUMAN_IMPACT = ("low", "medium", "high", "very_high")

# (exploitation, exposure, automatable) -> decisions for human_impact low..very_high
EXPECTED: dict[tuple[str, str, str], tuple[Decision, Decision, Decision, Decision]] = {
    ("none", "small", "no"): (T, T, TS, TS),
    ("none", "small", "yes"): (T, TS, TS, TS),
    ("none", "controlled", "no"): (T, TS, TS, TS),
    ("none", "controlled", "yes"): (TS, TS, TS, TS),
    ("none", "open", "no"): (T, TS, TS, TS),
    ("none", "open", "yes"): (TS, TS, TS, A),
    ("poc", "small", "no"): (T, TS, TS, TS),
    ("poc", "small", "yes"): (TS, TS, TS, TS),
    ("poc", "controlled", "no"): (T, TS, TS, TS),
    ("poc", "controlled", "yes"): (TS, TS, TS, A),
    ("poc", "open", "no"): (TS, TS, TS, A),
    ("poc", "open", "yes"): (TS, TS, A, A),
    ("active", "small", "no"): (TS, TS, A, A),
    ("active", "small", "yes"): (TS, A, A, A),
    ("active", "controlled", "no"): (TS, TS, A, A),
    ("active", "controlled", "yes"): (A, A, A, A),
    ("active", "open", "no"): (TS, A, A, ACT),
    ("active", "open", "yes"): (A, A, ACT, ACT),
}

ALL_PATHS = [
    (expl, expo, auto, hi, decisions[i])
    for (expl, expo, auto), decisions in EXPECTED.items()
    for i, hi in enumerate(HUMAN_IMPACT)
]
assert len(ALL_PATHS) == 72


@pytest.mark.parametrize(
    ("exploitation", "exposure", "automatable", "human_impact", "expected"),
    ALL_PATHS,
    ids=lambda v: v.value if isinstance(v, Decision) else str(v),
)
def test_every_path_through_the_tree(
    exploitation: str, exposure: str, automatable: str, human_impact: str, expected: Decision
) -> None:
    context = OrgContext(
        overrides={
            "exploitation": exploitation,
            "exposure": exposure,
            "automatable": automatable,
            "human_impact": human_impact,
        }
    )
    verdict = evaluate(enrichment(), context, TREE)
    assert verdict.decision is expected
    assert verdict.tree_id == "cisa-deployer-v1"
    assert verdict.inputs_degraded is False
    assert [s.value_source for s in verdict.path.steps] == ["override"] * 4
    assert [s.node for s in verdict.path.steps] == [
        "exploitation",
        "exposure",
        "automatable",
        "human_impact",
    ]


def test_tree_shape() -> None:
    assert TREE.id == "cisa-deployer-v1"
    assert list(TREE.decision_points) == ["exploitation", "exposure", "automatable", "human_impact"]
    assert TREE.defaults == {"exploitation": "none", "automatable": "yes"}


def test_log4shell_style_finding_is_act() -> None:
    """KEV-listed + wormable CVSS on an internet-facing, high-impact estate → Act."""
    verdict = evaluate(
        enrichment(kev=KevData(listed=True), cvss=_AUTOMATABLE_CVSS),
        OrgContext(exposure=Exposure.INTERNET, mission_impact=MissionImpact.HIGH),
        TREE,
    )
    assert verdict.decision is Decision.ACT
    assert verdict.inputs_degraded is False
    assert [(s.node, s.value, s.value_source) for s in verdict.path.steps] == [
        ("exploitation", "active", "kev"),
        ("exposure", "open", "context"),
        ("automatable", "yes", "cvss"),
        ("human_impact", "high", "context"),
    ]


def test_unlisted_cve_with_missing_data_flows_through_defaults() -> None:
    """KEV says unlisted, exploits+CVSS unavailable: both derived points default,
    the path records it, and the verdict is flagged degraded (M2 reality until
    the exploit adapter lands in M5)."""
    verdict = evaluate(
        enrichment(kev=KevData(listed=False)),
        OrgContext(exposure=Exposure.INTERNET, mission_impact=MissionImpact.HIGH),
        TREE,
    )
    # none/open/yes/high → track* per the table.
    assert verdict.decision is Decision.TRACK_STAR
    assert verdict.inputs_degraded is True
    assert [(s.node, s.value, s.value_source) for s in verdict.path.steps] == [
        ("exploitation", "none", "default"),
        ("exposure", "open", "context"),
        ("automatable", "yes", "default"),
        ("human_impact", "high", "context"),
    ]


def test_isolated_low_impact_estate_tracks_even_when_active() -> None:
    verdict = evaluate(
        enrichment(kev=KevData(listed=True), cvss=_AUTOMATABLE_CVSS),
        OrgContext(exposure=Exposure.ISOLATED, mission_impact=MissionImpact.LOW),
        TREE,
    )
    # active/small/yes/low → track* per the table.
    assert verdict.decision is Decision.TRACK_STAR
