"""Core data models.

Every data structure crossing a module boundary is a Pydantic v2 model in
strict mode (no type coercion from Python values) and frozen (value objects).
``Unavailable`` is a first-class value, not ``None``: it carries *why* a piece
of enrichment data is missing and flows into the decision path so degraded
verdicts are visibly degraded (FRAMEWORK.md §2).
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

_MODEL_CONFIG = ConfigDict(strict=True, frozen=True, extra="forbid")


class IngestSource(StrEnum):
    """How a finding entered the pipeline (SPEC.md §4.1, v0.1 inputs)."""

    CLI = "cli"
    CYCLONEDX = "cyclonedx"
    GRYPE = "grype"


class UnavailableReason(StrEnum):
    """Why an enrichment field could not be populated."""

    SOURCE_DOWN = "source_down"
    OFFLINE = "offline"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"


class Unavailable(BaseModel):
    """Marker value for enrichment data that could not be fetched."""

    model_config = _MODEL_CONFIG

    reason: UnavailableReason
    detail: str | None = None


class PackageRef(BaseModel):
    """A package identified by purl, present on SBOM/scanner ingest paths."""

    model_config = _MODEL_CONFIG

    purl: str
    version: str | None = None


class Finding(BaseModel):
    """Normalized unit of work produced by the ingest layer.

    ``cve_id`` holds the canonical vulnerability ID: a CVE ID where one
    exists, else the native OSV/GHSA ID (SBOM path — alias resolution
    happens in the OSV adapter). ``aliases`` records the other IDs the same
    vulnerability is known by, preserving the audit trail of that
    resolution (e.g. the GHSA ID that resolved to this CVE).

    ``scanner_severity`` is the ingesting scanner's own severity label,
    carried as informational metadata only — it never feeds the SSVC
    engine. ``locations`` lists the file paths a scanner reported for this
    finding (several when layer dedup merged repeated matches).
    """

    model_config = _MODEL_CONFIG

    cve_id: str
    source: IngestSource
    package: PackageRef | None = None
    asset_hint: str | None = None
    aliases: list[str] = []
    scanner_severity: str | None = None
    locations: list[str] = []


class EpssData(BaseModel):
    """FIRST EPSS exploitation-probability data for one CVE."""

    model_config = _MODEL_CONFIG

    score: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    date: date


class KevData(BaseModel):
    """CISA Known Exploited Vulnerabilities catalog membership."""

    model_config = _MODEL_CONFIG

    listed: bool
    date_added: date | None = None
    ransomware: bool = False


class CvssData(BaseModel):
    """CVSS scoring data (NVD)."""

    model_config = _MODEL_CONFIG

    vector: str
    base_score: float = Field(ge=0.0, le=10.0)
    severity: str


class NvdData(BaseModel):
    """Combined NVD answer for one CVE: CVSS scoring plus CWE classification.

    The NVD adapter is the single source for both ``Enrichment.cvss`` and
    ``Enrichment.cwes``; the pipeline unpacks this into those two fields.
    """

    model_config = _MODEL_CONFIG

    cvss: CvssData | Unavailable
    cwes: list[str] = []


class VersionData(BaseModel):
    """Affected / fixed version ranges (OSV/GHSA)."""

    model_config = _MODEL_CONFIG

    affected: list[str] = []
    fixed: list[str] = []


class GhsaData(BaseModel):
    """GitHub Security Advisory detail for one vulnerability.

    ``severity`` is GitHub's label, informational only — it never feeds the
    SSVC engine. ``versions`` holds GHSA's own ranges verbatim; they are kept
    here even when OSV's data fills the canonical ``Enrichment.versions``
    (keep-both policy, see pipeline module docstring).
    """

    model_config = _MODEL_CONFIG

    ghsa_id: str
    severity: str
    summary: str
    versions: VersionData


class ExploitData(BaseModel):
    """Public exploit presence indicators."""

    model_config = _MODEL_CONFIG

    edb_ids: list[str] = []
    msf_modules: list[str] = []
    nuclei_templates: list[str] = []


class SourceMeta(BaseModel):
    """Provenance for one source's contribution to an enrichment."""

    model_config = _MODEL_CONFIG

    source: str
    fetched_at: datetime
    cache_hit: bool


class Enrichment(BaseModel):
    """Fused intelligence for one finding, produced by the pipeline.

    Each source-backed field is either its data model or ``Unavailable`` —
    a source outage degrades the field, never the run (SPEC.md FR-8).
    """

    model_config = _MODEL_CONFIG

    epss: EpssData | Unavailable
    kev: KevData | Unavailable
    cvss: CvssData | Unavailable
    cwes: list[str] = []
    versions: VersionData | Unavailable
    advisory: GhsaData | Unavailable
    exploits: ExploitData | Unavailable
    provenance: dict[str, SourceMeta] = {}


class EnrichedFinding(BaseModel):
    """A finding paired with its enrichment — what the output layer consumes.

    Extended to ``RankedResult`` (adding a ``Verdict``) in M3.
    """

    model_config = _MODEL_CONFIG

    finding: Finding
    enrichment: Enrichment


class RunMetadata(BaseModel):
    """Run-level facts the pipeline emits alongside results (FRAMEWORK.md §3.3)."""

    model_config = _MODEL_CONFIG

    sources: list[str]
    offline: bool
    cache_hit_rate: dict[str, float]
    degradations: list[str] = []


class Decision(StrEnum):
    """SSVC outcome, in ascending priority order. Compare via :attr:`rank`."""

    TRACK = "track"
    TRACK_STAR = "track*"
    ATTEND = "attend"
    ACT = "act"

    @property
    def rank(self) -> int:
        """Ascending priority: TRACK=0, TRACK_STAR=1, ATTEND=2, ACT=3."""
        order = (Decision.TRACK, Decision.TRACK_STAR, Decision.ATTEND, Decision.ACT)
        return order.index(self)


class DecisionPathStep(BaseModel):
    """One tree-node visit: which input was read, its value, and its origin."""

    model_config = _MODEL_CONFIG

    node: str
    value: str
    value_source: str


class DecisionPath(BaseModel):
    """Ordered record of every node visited en route to a decision."""

    model_config = _MODEL_CONFIG

    steps: list[DecisionPathStep] = []


class Verdict(BaseModel):
    """SSVC engine output: the decision plus the audit trail behind it."""

    model_config = _MODEL_CONFIG

    decision: Decision
    path: DecisionPath
    tree_id: str
    inputs_degraded: bool


class RankedResult(BaseModel):
    """Finding + Enrichment + Verdict — the unit every formatter consumes (§3.6)."""

    model_config = _MODEL_CONFIG

    finding: Finding
    enrichment: Enrichment
    verdict: Verdict
