"""CVE-list ingestion tests."""

from __future__ import annotations

import pytest

from vulnctl.ingest.cve_list import parse_cve_ids
from vulnctl.models import IngestSource


def test_valid_ids_become_findings() -> None:
    findings = parse_cve_ids(["CVE-2021-44228", "cve-2023-4863"])
    assert [f.cve_id for f in findings] == ["CVE-2021-44228", "CVE-2023-4863"]
    assert all(f.source is IngestSource.CLI for f in findings)
    assert all(f.package is None for f in findings)


def test_duplicates_removed_order_preserved() -> None:
    findings = parse_cve_ids(["CVE-2023-4863", "cve-2023-4863", "CVE-2021-44228"])
    assert [f.cve_id for f in findings] == ["CVE-2023-4863", "CVE-2021-44228"]


def test_invalid_id_is_hard_error_naming_offenders() -> None:
    with pytest.raises(ValueError, match=r"'GHSA-jfh8-c2jp-5v3q'.*CVE-YYYY-NNNN"):
        parse_cve_ids(["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"])


def test_short_sequence_number_rejected() -> None:
    with pytest.raises(ValueError):
        parse_cve_ids(["CVE-2021-123"])
