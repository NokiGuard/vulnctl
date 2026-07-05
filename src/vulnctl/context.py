"""Organizational risk context feeding SSVC decision points (FRAMEWORK.md §3.5).

Defaults when no context file is given are conservative — when in doubt,
higher severity — but not maximal:

- ``exposure: internet``: assume the worst network position; an internet-
  facing assumption can only over-prioritize, never hide a verdict.
- ``mission_impact: high``: SSVC reserves ``very_high`` for effects like
  danger to life or mission failure; defaulting there would push nearly
  every exploited CVE to Act and destroy the ranking signal, so ``high`` is
  the highest honest default.
- ``asset_tier: standard``: carried for the v0.2 per-asset registry; the v1
  tree does not read it, so the default has no verdict effect.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

_EXPOSURE_TO_TREE = {"internet": "open", "internal": "controlled", "isolated": "small"}


class Exposure(StrEnum):
    """Network position of the affected estate."""

    INTERNET = "internet"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class MissionImpact(StrEnum):
    """Impact on the organization's mission if the vulnerability is exploited."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class AssetTier(StrEnum):
    """Criticality tier; unused by the v1 tree (v0.2 asset registry groundwork)."""

    CROWN_JEWEL = "crown_jewel"
    IMPORTANT = "important"
    STANDARD = "standard"


class OrgContext(BaseModel):
    """Validated organizational context; see module docstring for the defaults."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    exposure: Exposure = Exposure.INTERNET
    mission_impact: MissionImpact = MissionImpact.HIGH
    asset_tier: AssetTier = AssetTier.STANDARD
    overrides: dict[str, str] = {}

    def decision_value(self, key: str) -> str:
        """Tree-vocabulary value for a ``from: context`` decision point.

        ``exposure`` maps to SSVC System Exposure terms (internet → open,
        internal → controlled, isolated → small); ``mission_impact`` values
        are already tree vocabulary.

        Raises:
            KeyError: if the tree references a context key that does not exist.
        """
        if key == "exposure":
            return _EXPOSURE_TO_TREE[self.exposure.value]
        if key == "mission_impact":
            return self.mission_impact.value
        raise KeyError(key)
