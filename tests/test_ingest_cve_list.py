"""CVE/GHSA-ID-list ingestion tests."""

from __future__ import annotations

import pytest

from vulnctl.ingest.cve_list import parse_vuln_ids
from vulnctl.models import IngestSource


def test_valid_ids_become_findings() -> None:
    findings = parse_vuln_ids(["CVE-2021-44228", "cve-2023-4863"])
    assert [f.cve_id for f in findings] == ["CVE-2021-44228", "CVE-2023-4863"]
    assert all(f.source is IngestSource.CLI for f in findings)
    assert all(f.package is None for f in findings)


def test_duplicates_removed_order_preserved() -> None:
    findings = parse_vuln_ids(["CVE-2023-4863", "cve-2023-4863", "CVE-2021-44228"])
    assert [f.cve_id for f in findings] == ["CVE-2023-4863", "CVE-2021-44228"]


def test_ghsa_ids_accepted_and_case_normalized() -> None:
    # OSV's URL path and the cache are case-sensitive: suffix must go lowercase,
    # matching the form scanners emit, whatever case the user typed.
    findings = parse_vuln_ids(["ghsa-35JH-R3H4-6JHM", "CVE-2021-44228"])
    assert [f.cve_id for f in findings] == ["GHSA-35jh-r3h4-6jhm", "CVE-2021-44228"]


def test_ghsa_duplicates_collapse_across_case_forms() -> None:
    findings = parse_vuln_ids(["GHSA-35jh-r3h4-6jhm", "ghsa-35JH-r3h4-6jhm"])
    assert [f.cve_id for f in findings] == ["GHSA-35jh-r3h4-6jhm"]


def test_invalid_id_is_hard_error_naming_offenders() -> None:
    with pytest.raises(ValueError, match=r"'NOPE-123'.*CVE-YYYY-NNNN.*GHSA-xxxx"):
        parse_vuln_ids(["CVE-2021-44228", "NOPE-123"])


def test_ghsa_outside_alphabet_rejected() -> None:
    # 0, 1, and most letters are not in GitHub's GHSA alphabet.
    with pytest.raises(ValueError, match=r"GHSA-1111-1111-1111"):
        parse_vuln_ids(["GHSA-1111-1111-1111"])


def test_short_sequence_number_rejected() -> None:
    with pytest.raises(ValueError):
        parse_vuln_ids(["CVE-2021-123"])
