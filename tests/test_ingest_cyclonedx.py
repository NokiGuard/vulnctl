"""CycloneDX SBOM parsing and OSV-discovery→Finding mapping tests.

The two real SBOM fixtures were generated with Syft from small demo projects
(``syft dir:… -o cyclonedx-json@1.5`` / ``@1.4``); both naturally include a
purl-less component, exercising the skip-and-warn path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import FIXTURES_DIR
from vulnctl.adapters.osv import PackageVulns, ResolvedVuln
from vulnctl.ingest import IngestError
from vulnctl.ingest.cyclonedx import MAX_SBOM_FILE_BYTES, findings_from_package_vulns, parse_sbom
from vulnctl.models import (
    IngestSource,
    PackageRef,
    Unavailable,
    UnavailableReason,
    VersionData,
)

NPM_SBOM = FIXTURES_DIR / "sbom" / "npm-app.cdx.json"
PY_SBOM = FIXTURES_DIR / "sbom" / "py-app.cdx.json"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "sbom.json"
    path.write_text(text)
    return path


def _minimal(**patches: object) -> str:
    import json

    raw: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"purl": "pkg:npm/lodash@4.17.20", "version": "4.17.20"}],
    }
    raw.update(patches)
    return json.dumps(raw)


# --- parse_sbom: real Syft fixtures ---------------------------------------------


def test_parse_syft_15_sbom() -> None:
    packages, warnings = parse_sbom(NPM_SBOM)
    assert PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20") in packages
    assert PackageRef(purl="pkg:npm/left-pad@1.3.0", version="1.3.0") in packages
    assert warnings == ["sbom: skipped 1 component(s) without a purl"]


def test_parse_syft_14_sbom() -> None:
    packages, warnings = parse_sbom(PY_SBOM)
    assert PackageRef(purl="pkg:pypi/jinja2@2.4.1", version="2.4.1") in packages
    assert warnings == ["sbom: skipped 1 component(s) without a purl"]


def test_parse_syft_16_sbom() -> None:
    # Modern Syft defaults to CycloneDX 1.6; it must parse like 1.4/1.5.
    packages, warnings = parse_sbom(FIXTURES_DIR / "sbom" / "npm-app-1.6.cdx.json")
    assert PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20") in packages
    assert warnings == ["sbom: skipped 1 component(s) without a purl"]


# --- parse_sbom: hard errors (fail loud on input) --------------------------------


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("{not json", "not valid JSON"),
        ('["a", "list"]', "root must be a JSON object"),
        (_minimal(bomFormat="SPDX"), "not a CycloneDX SBOM"),
        (_minimal(specVersion="1.3"), "unsupported specVersion '1.3'"),  # too old
        (_minimal(specVersion="2.0"), "unsupported specVersion '2.0'"),  # doesn't exist yet
        (_minimal(components="lots"), "'components' must be a list"),
        (_minimal(components=["not-an-object"]), r"components\[0\] must be an object"),
        (_minimal(components=[{"purl": 42}]), r"components\[0\].purl must be a string"),
        (
            _minimal(components=[{"purl": "pkg:npm/x", "version": 1.0}]),
            r"components\[0\].version must be a string",
        ),
    ],
)
def test_malformed_sboms_fail_loudly(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(IngestError, match=match):
        parse_sbom(_write(tmp_path, text))


def test_missing_file_is_ingest_error(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="cannot read SBOM"):
        parse_sbom(tmp_path / "absent.json")


def test_oversized_sbom_rejected_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_text("x" * (MAX_SBOM_FILE_BYTES + 1))
    with pytest.raises(IngestError, match="limit is"):
        parse_sbom(path)


# --- parse_sbom: edge behavior ----------------------------------------------------


def test_empty_components_is_valid_but_warned(tmp_path: Path) -> None:
    packages, warnings = parse_sbom(_write(tmp_path, _minimal(components=[])))
    assert packages == []
    assert warnings == ["sbom: no components found"]


def test_duplicate_components_deduped(tmp_path: Path) -> None:
    component = {"purl": "pkg:npm/lodash@4.17.20", "version": "4.17.20"}
    packages, _ = parse_sbom(_write(tmp_path, _minimal(components=[component, component])))
    assert packages == [PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20")]


def test_component_without_version_field(tmp_path: Path) -> None:
    packages, _ = parse_sbom(_write(tmp_path, _minimal(components=[{"purl": "pkg:npm/x"}])))
    assert packages == [PackageRef(purl="pkg:npm/x", version=None)]


# --- findings_from_package_vulns ---------------------------------------------------


_LODASH = PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20")
_VERSIONS = VersionData(affected=["pkg:npm/lodash <4.17.21"], fixed=["pkg:npm/lodash 4.17.21"])


def _vuln(canonical_id: str, native_id: str, aliases: list[str]) -> ResolvedVuln:
    return ResolvedVuln(
        canonical_id=canonical_id, native_id=native_id, aliases=aliases, versions=_VERSIONS
    )


def test_findings_carry_package_source_and_aliases() -> None:
    package_vulns = [
        PackageVulns(
            package=_LODASH,
            vulns=[_vuln("CVE-2021-23337", "GHSA-35jh-r3h4-6jhm", ["GHSA-35jh-r3h4-6jhm"])],
        )
    ]
    findings, warnings = findings_from_package_vulns(package_vulns)
    assert warnings == []
    (finding,) = findings
    assert finding.cve_id == "CVE-2021-23337"
    assert finding.source is IngestSource.CYCLONEDX
    assert finding.package == _LODASH
    assert finding.aliases == ["GHSA-35jh-r3h4-6jhm"]


def test_native_records_aliasing_same_cve_merge_into_one_finding() -> None:
    # jinja2's CVE-2020-28493 is served by both a PYSEC and a GHSA record.
    package_vulns = [
        PackageVulns(
            package=PackageRef(purl="pkg:pypi/jinja2", version="2.4.1"),
            vulns=[
                _vuln("CVE-2020-28493", "PYSEC-2021-66", ["PYSEC-2021-66", "GHSA-g3rq-g295-4j3m"]),
                _vuln("CVE-2020-28493", "GHSA-g3rq-g295-4j3m", ["GHSA-g3rq-g295-4j3m"]),
            ],
        )
    ]
    findings, _ = findings_from_package_vulns(package_vulns)
    (finding,) = findings
    assert finding.cve_id == "CVE-2020-28493"
    assert finding.aliases == ["PYSEC-2021-66", "GHSA-g3rq-g295-4j3m"]


def test_ghsa_only_vuln_keeps_native_id() -> None:
    package_vulns = [
        PackageVulns(
            package=PackageRef(purl="pkg:npm/event-stream", version="3.3.6"),
            vulns=[_vuln("GHSA-mh6f-8j2x-4483", "GHSA-mh6f-8j2x-4483", [])],
        )
    ]
    findings, _ = findings_from_package_vulns(package_vulns)
    assert findings[0].cve_id == "GHSA-mh6f-8j2x-4483"


def test_same_cve_on_two_packages_stays_two_findings() -> None:
    other = PackageRef(purl="pkg:npm/lodash-es@4.17.20", version="4.17.20")
    package_vulns = [
        PackageVulns(package=_LODASH, vulns=[_vuln("CVE-2021-23337", "GHSA-x", ["GHSA-x"])]),
        PackageVulns(package=other, vulns=[_vuln("CVE-2021-23337", "GHSA-x", ["GHSA-x"])]),
    ]
    findings, _ = findings_from_package_vulns(package_vulns)
    assert [f.package for f in findings] == [_LODASH, other]  # different remediations


def test_failed_discovery_becomes_warning_not_silent_gap() -> None:
    package_vulns = [
        PackageVulns(
            package=_LODASH,
            unavailable=Unavailable(reason=UnavailableReason.OFFLINE, detail="not in cache"),
        )
    ]
    findings, warnings = findings_from_package_vulns(package_vulns)
    assert findings == []
    assert warnings == ["sbom: pkg:npm/lodash@4.17.20: OSV discovery unavailable (offline)"]
