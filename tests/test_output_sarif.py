"""SARIF 2.1.0 output: official-schema validation + structural invariants.

The schema is vendored at ``tests/fixtures/sarif/sarif-schema-2.1.0.json``
(the OASIS canonical schema) so CI validates output offline, catching any
drift from the spec.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import jsonschema
import pytest

from conftest import FIXTURES_DIR, MakeClient
from test_output_table import _cvss, _epss, _result
from vulnctl.cache import Cache
from vulnctl.context import OrgContext
from vulnctl.models import (
    Decision,
    DecisionPath,
    DecisionPathStep,
    Enrichment,
    ExploitData,
    Finding,
    IngestSource,
    PackageRef,
    RankedResult,
    RunMetadata,
    Unavailable,
    UnavailableReason,
    Verdict,
)
from vulnctl.output.sarif import build_sarif, render_sarif
from vulnctl.pipeline import apply_tree, enrich_findings
from vulnctl.ssvc.tree import load_bundled_tree

SARIF_SCHEMA = json.loads((FIXTURES_DIR / "sarif" / "sarif-schema-2.1.0.json").read_text())
_META = RunMetadata(sources=["kev"], offline=False, cache_hit_rate={"kev": 1.0})
_DOWN = Unavailable(reason=UnavailableReason.NOT_FOUND)


def _validate(doc: dict[str, Any]) -> None:
    jsonschema.validate(doc, SARIF_SCHEMA)


def _ranked(
    cve_id: str,
    *,
    decision: Decision,
    source: IngestSource = IngestSource.CLI,
    package: PackageRef | None = None,
    locations: list[str] | None = None,
) -> RankedResult:
    return RankedResult(
        finding=Finding(cve_id=cve_id, source=source, package=package, locations=locations or []),
        enrichment=Enrichment(
            epss=_DOWN, kev=_DOWN, cvss=_DOWN, versions=_DOWN, advisory=_DOWN, exploits=_DOWN
        ),
        verdict=Verdict(
            decision=decision,
            path=DecisionPath(
                steps=[DecisionPathStep(node="exploitation", value="active", value_source="kev")]
            ),
            tree_id="cisa-deployer-v1",
            inputs_degraded=False,
        ),
    )


# --- schema validation --------------------------------------------------------


def test_cve_list_output_validates() -> None:
    rows = [_result("CVE-2021-44228", decision=Decision.ACT, epss=_epss(0.9), cvss=_cvss(10.0))]
    _validate(build_sarif(rows, _META))


def test_sbom_and_grype_output_validates() -> None:
    pkg = PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20")
    rows = [
        _ranked(
            "CVE-2021-23337", decision=Decision.ATTEND, source=IngestSource.CYCLONEDX, package=pkg
        ),
        _ranked(
            "CVE-2020-28500",
            decision=Decision.TRACK,
            source=IngestSource.GRYPE,
            package=pkg,
            locations=["/package-lock.json"],
        ),
    ]
    _validate(build_sarif(rows, _META, artifact_uri="examples/app.cdx.json"))


async def test_real_offline_pipeline_output_validates(
    tmp_path: Path, fixture_client: MakeClient
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline run must never touch the network")

    findings = [
        Finding(cve_id=c, source=IngestSource.CLI) for c in ("CVE-2021-44228", "CVE-2010-0017")
    ]
    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            findings, cache=Cache(path=tmp_path / "c.db"), client=client, offline=True
        )
    ranked = apply_tree(results, OrgContext(), load_bundled_tree())
    doc = json.loads(render_sarif(ranked, metadata))
    _validate(doc)


# --- structural invariants ----------------------------------------------------


@pytest.mark.parametrize(
    ("decision", "level"),
    [
        (Decision.ACT, "error"),
        (Decision.ATTEND, "warning"),
        (Decision.TRACK_STAR, "note"),
        (Decision.TRACK, "none"),
    ],
)
def test_level_mapping(decision: Decision, level: str) -> None:
    doc = build_sarif([_ranked("CVE-2020-0001", decision=decision)], _META)
    assert doc["runs"][0]["results"][0]["level"] == level


def test_cve_list_result_has_no_locations_but_rule_has_nvd_help() -> None:
    doc = build_sarif([_ranked("CVE-2021-44228", decision=Decision.ACT)], _META)
    result = doc["runs"][0]["results"][0]
    assert "locations" not in result  # no artifact for a bare CVE
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CVE-2021-44228"
    assert rule["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_grype_result_points_at_component() -> None:
    pkg = PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20")
    doc = build_sarif(
        [
            _ranked(
                "CVE-2021-23337",
                decision=Decision.ATTEND,
                source=IngestSource.GRYPE,
                package=pkg,
                locations=["/app/package-lock.json"],
            )
        ],
        _META,
    )
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "/app/package-lock.json"
    assert loc["logicalLocations"][0]["fullyQualifiedName"] == "pkg:npm/lodash@4.17.20"


def test_sbom_result_points_at_sbom_file() -> None:
    pkg = PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20")
    doc = build_sarif(
        [
            _ranked(
                "CVE-2021-23337",
                decision=Decision.ATTEND,
                source=IngestSource.CYCLONEDX,
                package=pkg,
            )
        ],
        _META,
        artifact_uri="examples/app.cdx.json",
    )
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "examples/app.cdx.json"


def test_same_cve_two_packages_share_one_rule() -> None:
    a = PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20")
    b = PackageRef(purl="pkg:npm/lodash-es@4.17.20", version="4.17.20")
    rows = [
        _ranked(
            "CVE-2021-23337",
            decision=Decision.ATTEND,
            source=IngestSource.GRYPE,
            package=a,
            locations=["/a"],
        ),
        _ranked(
            "CVE-2021-23337",
            decision=Decision.ATTEND,
            source=IngestSource.GRYPE,
            package=b,
            locations=["/b"],
        ),
    ]
    doc = build_sarif(rows, _META)
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1  # deduped by CVE
    assert len(doc["runs"][0]["results"]) == 2
    assert all(r["ruleIndex"] == 0 for r in doc["runs"][0]["results"])


def test_decision_path_in_message_markdown_and_properties() -> None:
    doc = build_sarif([_ranked("CVE-2020-0001", decision=Decision.ACT)], _META)
    result = doc["runs"][0]["results"][0]
    assert "SSVC decision: ACT" in result["message"]["markdown"]
    assert "`exploitation` = `active`" in result["message"]["markdown"]
    assert result["properties"]["decision"] == "act"
    assert result["properties"]["treeId"] == "cisa-deployer-v1"


def test_results_ordered_by_rank() -> None:
    rows = [
        _ranked("CVE-2020-1111", decision=Decision.TRACK),
        _ranked("CVE-2020-2222", decision=Decision.ACT),
    ]
    doc = build_sarif(rows, _META)
    assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["CVE-2020-2222", "CVE-2020-1111"]


def test_properties_carry_exploit_presence() -> None:
    row = _ranked("CVE-2020-0001", decision=Decision.ACT)
    row = row.model_copy(
        update={
            "enrichment": row.enrichment.model_copy(update={"exploits": ExploitData(edb_ids=["1"])})
        }
    )
    doc = build_sarif([row], _META)
    assert doc["runs"][0]["results"][0]["properties"]["exploitPresent"] is True
