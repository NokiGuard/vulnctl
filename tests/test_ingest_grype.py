"""Grype ingestion tests.

``npm-app.json`` is real ``grype sbom:… -o json`` output for the demo npm
project (lodash 4.17.20). ``duplicate-layers.json`` is derived from it by
duplicating one match with a second location, simulating the same package
found in two image layers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FIXTURES_DIR
from vulnctl.ingest import IngestError
from vulnctl.ingest.grype import MAX_GRYPE_FILE_BYTES, load_grype, parse_grype_json
from vulnctl.models import IngestSource, PackageRef

NPM_SCAN = FIXTURES_DIR / "grype" / "npm-app.json"
DUPLICATES = FIXTURES_DIR / "grype" / "duplicate-layers.json"


def _minimal(**patches: object) -> str:
    raw: dict[str, object] = {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-35jh-r3h4-6jhm", "severity": "High"},
                "relatedVulnerabilities": [{"id": "CVE-2021-23337"}],
                "artifact": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                    "locations": [{"path": "/package-lock.json"}],
                },
            }
        ]
    }
    raw.update(patches)
    return json.dumps(raw)


# --- real scan output -------------------------------------------------------------


def test_parse_real_scan() -> None:
    findings, warnings = load_grype(str(NPM_SCAN))
    assert warnings == []
    assert len(findings) == 5
    by_id = {finding.cve_id: finding for finding in findings}

    lodash_cmd_injection = by_id["CVE-2021-23337"]
    assert lodash_cmd_injection.source is IngestSource.GRYPE
    assert lodash_cmd_injection.package == PackageRef(
        purl="pkg:npm/lodash@4.17.20", version="4.17.20"
    )
    assert "GHSA-35jh-r3h4-6jhm" in lodash_cmd_injection.aliases
    assert lodash_cmd_injection.scanner_severity == "High"  # informational only
    assert lodash_cmd_injection.locations == ["/package-lock.json"]


def test_duplicate_matches_across_layers_merge_locations() -> None:
    findings, _ = load_grype(str(DUPLICATES))
    (finding,) = findings
    assert finding.cve_id == "CVE-2021-23337"
    assert finding.locations == [
        "/package-lock.json",
        "/usr/lib/node_modules/lodash/package.json",
    ]


# --- canonical-ID and structure edge cases ----------------------------------------


def test_cve_native_match_stays_canonical() -> None:
    text = _minimal(
        matches=[
            {
                "vulnerability": {"id": "cve-2021-23337", "severity": "High"},
                "artifact": {"name": "lodash", "version": "4.17.20"},
            }
        ]
    )
    findings, _ = parse_grype_json(text, origin="test")
    assert findings[0].cve_id == "CVE-2021-23337"  # normalized to uppercase
    assert findings[0].aliases == []
    assert findings[0].package is None  # purl-less artifact: no PackageRef


def test_ghsa_without_related_cve_keeps_native_id() -> None:
    text = _minimal(
        matches=[
            {
                "vulnerability": {"id": "GHSA-mh6f-8j2x-4483"},
                "artifact": {"name": "event-stream", "version": "3.3.6"},
            }
        ]
    )
    findings, _ = parse_grype_json(text, origin="test")
    assert findings[0].cve_id == "GHSA-mh6f-8j2x-4483"
    assert findings[0].scanner_severity is None


def test_same_cve_on_two_packages_stays_two_findings() -> None:
    match = json.loads(_minimal())["matches"][0]
    other = json.loads(_minimal())["matches"][0]
    other["artifact"]["purl"] = "pkg:npm/lodash-es@4.17.20"
    findings, _ = parse_grype_json(json.dumps({"matches": [match, other]}), origin="test")
    assert len(findings) == 2


def test_empty_scan_is_valid_but_warned() -> None:
    findings, warnings = parse_grype_json('{"matches": []}', origin="test")
    assert findings == []
    assert warnings == ["grype: no matches in scan output"]


# --- hard errors (fail loud on input) ----------------------------------------------


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("{nope", "not valid JSON"),
        ('["a", "list"]', "root must be a JSON object"),
        ('{"vulnerabilities": []}', "no 'matches' key"),
        ('{"matches": "many"}', "'matches' must be a list"),
        ('{"matches": ["not-an-object"]}', r"matches\[0\] must be an object"),
        ('{"matches": [{"artifact": {}}]}', r"matches\[0\].vulnerability.id is missing"),
        (
            '{"matches": [{"vulnerability": {"id": "CVE-2021-1", "severity": 9}, "artifact": {}}]}',
            r"matches\[0\].vulnerability.severity must be a string",
        ),
        (
            '{"matches": [{"vulnerability": {"id": "CVE-2021-1"}}]}',
            r"matches\[0\].artifact is missing",
        ),
        (
            _minimal(matches=[{"vulnerability": {"id": "CVE-2021-1"}, "artifact": {"purl": 42}}]),
            r"matches\[0\].artifact.purl must be a string",
        ),
        (
            _minimal(
                matches=[{"vulnerability": {"id": "CVE-2021-1"}, "artifact": {"version": 4.2}}]
            ),
            r"matches\[0\].artifact.version must be a string",
        ),
    ],
)
def test_malformed_scans_fail_loudly(text: str, match: str) -> None:
    with pytest.raises(IngestError, match=match):
        parse_grype_json(text, origin="test")


# --- load_grype: file and stdin handling --------------------------------------------


def test_missing_file_is_ingest_error(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="cannot read Grype output"):
        load_grype(str(tmp_path / "absent.json"))


def test_oversized_file_rejected_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_text("x" * (MAX_GRYPE_FILE_BYTES + 1))
    with pytest.raises(IngestError, match="limit is"):
        load_grype(str(path))


def test_stdin_via_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(_minimal()))
    findings, _ = load_grype("-")
    assert findings[0].cve_id == "CVE-2021-23337"
