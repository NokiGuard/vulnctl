"""Markdown report: hermetic golden-file test + structural assertions.

The report carries no timestamps or provenance, so a fully-offline run is
deterministic from bundled snapshots — no normalization needed, unlike the
JSON golden.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from conftest import FIXTURES_DIR, MakeClient
from vulnctl.cache import Cache
from vulnctl.context import OrgContext
from vulnctl.models import (
    Decision,
    DecisionPath,
    Enrichment,
    Finding,
    GhsaData,
    IngestSource,
    KevData,
    PackageRef,
    RankedResult,
    RunMetadata,
    Unavailable,
    UnavailableReason,
    Verdict,
    VersionData,
)
from vulnctl.output.markdown import render_markdown
from vulnctl.pipeline import apply_tree, enrich_findings
from vulnctl.ssvc.tree import load_bundled_tree

GOLDEN = FIXTURES_DIR / "golden" / "enrich.md"
GOLDEN_CVES = ["CVE-2021-44228", "CVE-2010-0017"]


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


async def _offline_md(cache: Cache, fixture_client: MakeClient) -> str:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("golden run must never touch the network")

    findings = [Finding(cve_id=c, source=IngestSource.CLI) for c in GOLDEN_CVES]
    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            findings, cache=cache, client=client, offline=True
        )
    ranked = apply_tree(results, OrgContext(), load_bundled_tree())
    return render_markdown(ranked, metadata)


async def test_markdown_matches_golden(cache: Cache, fixture_client: MakeClient) -> None:
    assert await _offline_md(cache, fixture_client) == GOLDEN.read_text()


def test_untrusted_strings_cannot_splice_markdown_into_the_report() -> None:
    # IDs and purls arrive verbatim from scanner files; a hostile value must
    # not break table rows, close code spans, inject headings, or smuggle
    # raw HTML into a rendered report.
    na = Unavailable(reason=UnavailableReason.OFFLINE)
    hostile = RankedResult(
        finding=Finding(
            cve_id="CVE-2020-0001`<img src=x>`\n# fake heading",
            source=IngestSource.GRYPE,
            package=PackageRef(purl="pkg:npm/evil|Act|9.9"),
        ),
        enrichment=Enrichment(epss=na, kev=na, cvss=na, versions=na, advisory=na, exploits=na),
        verdict=Verdict(
            decision=Decision.ACT,
            path=DecisionPath(steps=[]),
            tree_id="toy-v1",
            inputs_degraded=False,
        ),
    )
    metadata = RunMetadata(sources=["kev"], offline=True, cache_hit_rate={"kev": 0.0})
    report = render_markdown([hostile], metadata)
    assert "\n# fake heading" not in report  # newlines collapsed: no injected headings
    assert "npm/evil\\|Act\\|9.9" in report  # pipes escaped: table cells hold
    assert "`<img" not in report and "<img" not in report  # code spans + HTML neutralized


def test_fix_and_description_render_in_report() -> None:
    na = Unavailable(reason=UnavailableReason.OFFLINE)
    result = RankedResult(
        finding=Finding(
            cve_id="CVE-2021-23337",
            source=IngestSource.GRYPE,
            package=PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20"),
        ),
        enrichment=Enrichment(
            epss=na,
            kev=KevData(listed=True),
            cvss=na,
            versions=VersionData(affected=["npm <4.17.21"], fixed=["npm 4.17.21"]),
            advisory=GhsaData(
                ghsa_id="GHSA-35jh-r3h4-6jhm",
                severity="high",
                summary="Command injection in lodash",
                versions=VersionData(),
            ),
            exploits=na,
        ),
        verdict=Verdict(
            decision=Decision.ACT,
            path=DecisionPath(steps=[]),
            tree_id="toy-v1",
            inputs_degraded=False,
        ),
    )
    metadata = RunMetadata(sources=["kev"], offline=False, cache_hit_rate={"kev": 1.0})
    report = render_markdown([result], metadata)
    assert "| Fix |" in report  # column appears when a fix is known
    assert "| npm 4.17.21 |" in report
    assert "fix: npm 4.17.21" in report  # highlights carry the remediation
    assert "_Command injection in lodash_" in report  # highlights carry the description
    assert "- summary: Command injection in lodash" in report  # appendix detail
    assert "npm/lodash@4.17.20" in report
    assert "pkg:npm" not in report  # purls are shortened for display


async def test_markdown_structure(cache: Cache, fixture_client: MakeClient) -> None:
    report = await _offline_md(cache, fixture_client)
    assert report.startswith("# vulnctl report")
    assert "**2 finding(s):** 1 act, 1 attend" in report
    assert "**KEV exposure:** 1 finding(s)" in report
    # The KEV-listed Act finding is surfaced in Highlights; the Attend one is not.
    highlights = report.split("## Highlights")[1].split("## Top")[0]
    assert "CVE-2021-44228" in highlights and "KEV-listed (ransomware)" in highlights
    assert "CVE-2010-0017" not in highlights
    # The appendix carries the sourced decision path.
    assert "`exploitation` = `active` _(kev)_" in report
    assert "`exploitation` = `poc` _(exploits)_" in report
