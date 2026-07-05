"""Tree schema, loader validation, and derived-value resolver tests."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from conftest import FIXTURES_DIR
from vulnctl.models import (
    CvssData,
    Decision,
    Enrichment,
    EpssData,
    ExploitData,
    KevData,
    Unavailable,
    UnavailableReason,
)
from vulnctl.ssvc.tree import (
    DecisionTree,
    TreeError,
    TreeNode,
    _resolve_automatable,
    _resolve_exploitation,
    load_tree,
)

TOY = FIXTURES_DIR / "trees" / "toy.yaml"

_UNAVAILABLE = Unavailable(reason=UnavailableReason.SOURCE_DOWN)
_NO_EXPLOITS = ExploitData()
_SOME_EXPLOITS = ExploitData(edb_ids=["50592"])
_EPSS = EpssData(score=0.5, percentile=0.5, date=date(2026, 7, 4))
_AUTOMATABLE_CVSS = CvssData(
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=10.0, severity="CRITICAL"
)
_MANUAL_CVSS = CvssData(
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", base_score=8.8, severity="HIGH"
)
_V2_CVSS = CvssData(vector="AV:N/AC:L/Au:N/C:C/I:C/A:C", base_score=10.0, severity="HIGH")


def enrichment(
    *,
    kev: KevData | Unavailable = _UNAVAILABLE,
    exploits: ExploitData | Unavailable = _UNAVAILABLE,
    cvss: CvssData | Unavailable = _UNAVAILABLE,
) -> Enrichment:
    return Enrichment(
        epss=_EPSS, kev=kev, cvss=cvss, versions=_UNAVAILABLE, exploits=exploits, provenance={}
    )


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "tree.yaml"
    path.write_text(text)
    return path


# --- Loader: valid document ---------------------------------------------------


def test_toy_tree_loads() -> None:
    tree = load_tree(TOY)
    assert tree.id == "toy-v1"
    assert set(tree.decision_points) == {"exploitation", "exposure"}
    assert tree.decision_points["exploitation"].source == "derived"
    assert tree.decision_points["exposure"].key == "exposure"
    assert tree.defaults == {"exploitation": "none"}
    assert tree.root.point == "exploitation"
    assert tree.root.branches["none"] is Decision.TRACK
    poc = tree.root.branches["poc"]
    assert isinstance(poc, TreeNode)
    assert poc.branches["open"] is Decision.ATTEND


def test_yaml_11_scalars_normalized(tmp_path: Path) -> None:
    # `none:` parses as null and `no`/`yes` as booleans under YAML 1.1 rules;
    # the loader must treat them as the strings SSVC uses.
    path = _write(
        tmp_path,
        """
id: norm-v1
decision_points:
  exploitation:
    from: derived
    rule: exploitation
    values: [none, poc, active]
  automatable:
    from: derived
    rule: automatable
    values: [no, yes]
tree:
  exploitation:
    none: track
    poc:
      automatable:
        no: track
        yes: attend
    active:
      automatable:
        no: attend
        yes: act
defaults:
  exploitation: none
  automatable: yes
""",
    )
    tree = load_tree(path)
    assert tree.decision_points["automatable"].values == ["no", "yes"]
    assert tree.defaults["automatable"] == "yes"
    active = tree.root.branches["active"]
    assert isinstance(active, TreeNode)
    assert active.branches["yes"] is Decision.ACT


# --- Loader: hard errors ------------------------------------------------------


def _toy_text() -> str:
    return TOY.read_text()


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda t: t.replace("        small: track\n", ""), "missing branch"),
        (
            lambda t: t.replace("tree:\n  exploitation:", "tree:\n  mystery:"),
            "unknown decision point",
        ),
        (
            lambda t: t.replace("defaults:\n  exploitation: none", "defaults:\n  mystery: none"),
            "defaults: unknown decision point",
        ),
        (
            lambda t: t.replace(
                "defaults:\n  exploitation: none", "defaults:\n  exploitation: sideways"
            ),
            "not a declared value",
        ),
        (lambda t: t.replace("rule: exploitation", "rule: horoscope"), "unknown rule"),
        (lambda t: t + "\nfooter: 1\n", "unknown top-level"),
        (lambda t: t.replace("        open: attend", "        open: escalate"), "invalid decision"),
        (lambda t: t.replace("defaults:\n  exploitation: none", "defaults: {}"), "no default"),
    ],
)
def test_broken_trees_fail_loudly(
    tmp_path: Path, mutation: callable[[str], str], match: str
) -> None:
    path = _write(tmp_path, mutation(_toy_text()))
    with pytest.raises(TreeError, match=match):
        load_tree(path)


def test_repeated_point_along_path_is_unreachable(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
id: loop-v1
decision_points:
  exploitation:
    from: derived
    rule: exploitation
    values: [none, poc, active]
tree:
  exploitation:
    none: track
    poc:
      exploitation:
        none: track
        poc: attend
        active: act
    active: act
defaults:
  exploitation: none
""",
    )
    with pytest.raises(TreeError, match="repeated along one path"):
        load_tree(path)


def test_declared_but_unused_point_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
id: unused-v1
decision_points:
  exploitation:
    from: derived
    rule: exploitation
    values: [none, poc, active]
  exposure:
    from: context
    key: exposure
    values: [small, controlled, open]
tree:
  exploitation:
    none: track
    poc: attend
    active: act
defaults:
  exploitation: none
""",
    )
    with pytest.raises(TreeError, match="never used"):
        load_tree(path)


def test_derived_point_requires_rule_and_context_requires_key(tmp_path: Path) -> None:
    with pytest.raises(TreeError, match="from=derived requires 'rule'"):
        load_tree(_write(tmp_path, _toy_text().replace("rule: exploitation", "key: exploitation")))
    with pytest.raises(TreeError, match="from=context requires 'key'"):
        load_tree(_write(tmp_path, _toy_text().replace("key: exposure", "rule: exploitation")))


def test_invalid_yaml_and_missing_file_are_tree_errors(tmp_path: Path) -> None:
    with pytest.raises(TreeError, match="not valid YAML"):
        load_tree(_write(tmp_path, "id: [unclosed"))
    with pytest.raises(TreeError, match="cannot read"):
        load_tree(tmp_path / "absent.yaml")


def test_bare_decision_document_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
id: bare-v1
decision_points:
  exploitation:
    from: derived
    rule: exploitation
    values: [none, poc, active]
tree: track
defaults:
  exploitation: none
""",
    )
    with pytest.raises(TreeError, match="bare decision"):
        load_tree(path)


# --- Resolvers ----------------------------------------------------------------


def test_exploitation_kev_listed_wins_even_if_exploits_unavailable() -> None:
    result = _resolve_exploitation(enrichment(kev=KevData(listed=True)))
    assert result == ("active", "kev")


def test_exploitation_exploits_present_is_poc() -> None:
    result = _resolve_exploitation(enrichment(kev=KevData(listed=False), exploits=_SOME_EXPLOITS))
    assert result == ("poc", "exploits")


def test_exploitation_both_negative_is_none() -> None:
    result = _resolve_exploitation(enrichment(kev=KevData(listed=False), exploits=_NO_EXPLOITS))
    assert result == ("none", "kev+exploits")


def test_exploitation_partial_data_degrades() -> None:
    # KEV says unlisted but exploit presence is unknown: "none" cannot be
    # asserted, so the resolver abstains and the tree default applies.
    assert _resolve_exploitation(enrichment(kev=KevData(listed=False))) is None
    assert _resolve_exploitation(enrichment(exploits=_NO_EXPLOITS)) is None
    assert _resolve_exploitation(enrichment()) is None


def test_automatable_from_cvss_vector() -> None:
    assert _resolve_automatable(enrichment(cvss=_AUTOMATABLE_CVSS)) == ("yes", "cvss")
    assert _resolve_automatable(enrichment(cvss=_MANUAL_CVSS)) == ("no", "cvss")


def test_automatable_v2_or_unavailable_degrades() -> None:
    assert _resolve_automatable(enrichment(cvss=_V2_CVSS)) is None
    assert _resolve_automatable(enrichment()) is None


# --- from_raw direct ----------------------------------------------------------


def test_non_mapping_document_rejected() -> None:
    with pytest.raises(TreeError, match="must be a mapping"):
        DecisionTree.from_raw(["not", "a", "tree"])
