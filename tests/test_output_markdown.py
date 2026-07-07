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
from vulnctl.models import Finding, IngestSource
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
