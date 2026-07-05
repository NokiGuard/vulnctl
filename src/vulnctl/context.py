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
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

_EXPOSURE_TO_TREE = {"internet": "open", "internal": "controlled", "isolated": "small"}


class ContextError(Exception):
    """A context file failed validation; the message says exactly what to fix."""


#: Context files are a few lines; refuse absurd inputs before YAML parsing.
MAX_CONTEXT_FILE_BYTES = 64 * 1024


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


def load_context(path: Path | None) -> OrgContext:
    """Load and validate ``context.yaml``; documented defaults when ``path`` is None.

    Unknown keys are hard errors — they are almost always typos, and a typoed
    key silently reverting to a default would change verdicts (FRAMEWORK.md
    §3.5). Override entries set to null are treated as "no override" and
    dropped; bare YAML booleans in override values are normalized back to the
    ``yes``/``no`` strings the trees use.
    """
    if path is None:
        return OrgContext()
    try:
        size = path.stat().st_size
        if size > MAX_CONTEXT_FILE_BYTES:
            raise ContextError(
                f"context file {path} is {size} bytes; limit is "
                f"{MAX_CONTEXT_FILE_BYTES} (context files are a few lines of YAML)"
            )
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContextError(f"cannot read context file {path}: {exc}") from exc
    try:
        raw = YAML(typ="safe").load(text)
    except YAMLError as exc:
        raise ContextError(f"context file {path} is not valid YAML: {exc}") from exc
    if raw is None:
        return OrgContext()
    if not isinstance(raw, dict):
        raise ContextError(f"context file {path} must be a mapping of settings")

    overrides = raw.get("overrides")
    if isinstance(overrides, dict):
        raw = dict(raw)
        raw["overrides"] = {
            str(point): _norm_override(value)
            for point, value in overrides.items()
            if value is not None
        }
    try:
        # strict=False: YAML scalars arrive as plain strings and must coerce
        # into the enum fields; extra="forbid" still rejects unknown keys.
        return OrgContext.model_validate(raw, strict=False)
    except ValidationError as exc:
        raise ContextError(f"context file {path} is invalid: {exc}") from exc


def _norm_override(value: Any) -> Any:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return value
