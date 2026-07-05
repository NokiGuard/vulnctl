"""Org context loading and validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnctl.context import (
    AssetTier,
    ContextError,
    Exposure,
    MissionImpact,
    OrgContext,
    load_context,
)

EXAMPLE = Path(__file__).parent.parent / "examples" / "context.yaml"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "context.yaml"
    path.write_text(text)
    return path


def test_no_file_gives_conservative_defaults() -> None:
    context = load_context(None)
    assert context.exposure is Exposure.INTERNET
    assert context.mission_impact is MissionImpact.HIGH
    assert context.asset_tier is AssetTier.STANDARD
    assert context.overrides == {}


def test_committed_example_loads_and_matches_defaults() -> None:
    context = load_context(EXAMPLE)
    assert context == OrgContext()  # the example documents the defaults


def test_valid_file(tmp_path: Path) -> None:
    context = load_context(
        _write(
            tmp_path,
            "exposure: isolated\nmission_impact: very_high\nasset_tier: crown_jewel\n"
            "overrides:\n  exploitation: active\n",
        )
    )
    assert context.exposure is Exposure.ISOLATED
    assert context.mission_impact is MissionImpact.VERY_HIGH
    assert context.asset_tier is AssetTier.CROWN_JEWEL
    assert context.overrides == {"exploitation": "active"}


def test_unknown_key_is_hard_error_naming_the_key(tmp_path: Path) -> None:
    with pytest.raises(ContextError, match="exposrue"):
        load_context(_write(tmp_path, "exposrue: internet\n"))


def test_invalid_enum_value_is_hard_error(tmp_path: Path) -> None:
    with pytest.raises(ContextError, match="mission_impact"):
        load_context(_write(tmp_path, "mission_impact: apocalyptic\n"))


def test_null_overrides_are_dropped_and_bools_normalized(tmp_path: Path) -> None:
    context = load_context(
        _write(
            tmp_path,
            "overrides:\n  automatable: null\n  exploitation: active\n",
        )
    )
    assert context.overrides == {"exploitation": "active"}


def test_yaml11_bool_override_normalized(tmp_path: Path) -> None:
    # A YAML 1.1 tool may serialize automatable: yes as a boolean.
    context = load_context(_write(tmp_path, "overrides:\n  automatable: true\n"))
    assert context.overrides == {"automatable": "yes"}
    context = load_context(_write(tmp_path, "overrides:\n  automatable: false\n"))
    assert context.overrides == {"automatable": "no"}


def test_empty_file_gives_defaults(tmp_path: Path) -> None:
    assert load_context(_write(tmp_path, "# only comments\n")) == OrgContext()


def test_non_mapping_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ContextError, match="must be a mapping"):
        load_context(_write(tmp_path, "- a\n- list\n"))


def test_invalid_yaml_and_missing_file_are_context_errors(tmp_path: Path) -> None:
    with pytest.raises(ContextError, match="not valid YAML"):
        load_context(_write(tmp_path, "exposure: [unclosed"))
    with pytest.raises(ContextError, match="cannot read"):
        load_context(tmp_path / "absent.yaml")
