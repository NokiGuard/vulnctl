"""Round-trip (model -> JSON -> model) tests for every core model."""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from pydantic import BaseModel, ValidationError

from vulnctl.models import (
    CvssData,
    Decision,
    DecisionPath,
    DecisionPathStep,
    Enrichment,
    EpssData,
    ExploitData,
    Finding,
    IngestSource,
    KevData,
    PackageRef,
    SourceMeta,
    Unavailable,
    UnavailableReason,
    Verdict,
    VersionData,
)

EPSS = EpssData(score=0.9754, percentile=0.9999, date=date(2026, 7, 1))
KEV = KevData(listed=True, date_added=date(2021, 12, 10), ransomware=True)
CVSS = CvssData(
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=10.0, severity="CRITICAL"
)
VERSIONS = VersionData(affected=[">=2.0.0,<2.15.0"], fixed=["2.15.0"])
EXPLOITS = ExploitData(
    edb_ids=["50592"],
    msf_modules=["exploit/multi/http/log4shell"],
    nuclei_templates=["CVE-2021-44228"],
)
META = SourceMeta(source="epss", fetched_at=datetime(2026, 7, 1, 12, 0, tzinfo=UTC), cache_hit=True)
UNAVAILABLE = Unavailable(reason=UnavailableReason.SOURCE_DOWN, detail="HTTP 503")
PACKAGE = PackageRef(purl="pkg:maven/org.apache.logging.log4j/log4j-core", version="2.14.1")
FINDING = Finding(
    cve_id="CVE-2021-44228",
    source=IngestSource.CYCLONEDX,
    package=PACKAGE,
    asset_hint="payments-api",
)
ENRICHMENT = Enrichment(
    epss=EPSS,
    kev=KEV,
    cvss=CVSS,
    cwes=["CWE-502", "CWE-917"],
    versions=VERSIONS,
    exploits=EXPLOITS,
    provenance={"epss": META},
)
DEGRADED_ENRICHMENT = Enrichment(
    epss=Unavailable(reason=UnavailableReason.OFFLINE),
    kev=UNAVAILABLE,
    cvss=Unavailable(reason=UnavailableReason.NOT_FOUND),
    versions=Unavailable(reason=UnavailableReason.RATE_LIMITED),
    exploits=UNAVAILABLE,
)
PATH = DecisionPath(
    steps=[
        DecisionPathStep(node="exploitation", value="active", value_source="derived:kev"),
        DecisionPathStep(node="exposure", value="internet", value_source="context"),
        DecisionPathStep(node="human_impact", value="high", value_source="default"),
    ]
)
VERDICT = Verdict(
    decision=Decision.ACT, path=PATH, tree_id="cisa-deployer-v1", inputs_degraded=True
)

ALL_MODELS = [
    EPSS,
    KEV,
    CVSS,
    VERSIONS,
    EXPLOITS,
    META,
    UNAVAILABLE,
    PACKAGE,
    FINDING,
    ENRICHMENT,
    DEGRADED_ENRICHMENT,
    PATH,
    VERDICT,
]


@pytest.mark.parametrize("model", ALL_MODELS, ids=lambda m: type(m).__name__)
def test_round_trip(model: BaseModel) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model


def test_unavailable_survives_union_round_trip() -> None:
    restored = Enrichment.model_validate_json(DEGRADED_ENRICHMENT.model_dump_json())
    assert isinstance(restored.epss, Unavailable)
    assert restored.epss.reason is UnavailableReason.OFFLINE
    assert isinstance(restored.kev, Unavailable)
    assert restored.kev.detail == "HTTP 503"


def test_data_survives_union_round_trip() -> None:
    restored = Enrichment.model_validate_json(ENRICHMENT.model_dump_json())
    assert isinstance(restored.epss, EpssData)
    assert isinstance(restored.kev, KevData)
    assert isinstance(restored.cvss, CvssData)
    assert isinstance(restored.versions, VersionData)
    assert isinstance(restored.exploits, ExploitData)


def test_models_are_frozen() -> None:
    with pytest.raises(ValidationError):
        FINDING.cve_id = "CVE-2000-0001"  # type: ignore[misc]


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        KevData.model_validate({"listed": True, "surprise": 1})


def test_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        EpssData(score=1.5, percentile=0.5, date=date(2026, 7, 1))
    with pytest.raises(ValidationError):
        CvssData(vector="CVSS:3.1/...", base_score=11.0, severity="CRITICAL")
