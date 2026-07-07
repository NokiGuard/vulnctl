"""Live-smoke tests: the ONE sanctioned exception to fixture-only CI.

These hit real upstream APIs and are skipped unless ``VULNCTL_LIVE`` is set, so
``uv run pytest`` locally and in normal CI never touches the network. The
weekly ``live-smoke`` workflow sets ``VULNCTL_LIVE=1`` and runs only this file.

Drift detection: every adapter parses upstream responses through strict
Pydantic models, so an upstream schema change makes the adapter *degrade* to
``Unavailable`` rather than crash. Each test therefore asserts that a
known-good CVE yields *real data* — a returned ``Unavailable`` means the
upstream schema drifted (or the source is down), and the run fails so the
workflow opens an issue.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import jsonschema
import pytest

from vulnctl.adapters.epss import EpssAdapter
from vulnctl.adapters.exploits import ExploitsAdapter
from vulnctl.adapters.ghsa import GhsaAdapter
from vulnctl.adapters.kev import KevAdapter
from vulnctl.adapters.nvd import NvdAdapter
from vulnctl.adapters.osv import OsvAdapter
from vulnctl.cache import Cache
from vulnctl.context import OrgContext
from vulnctl.models import (
    CvssData,
    Decision,
    EpssData,
    ExploitData,
    Finding,
    GhsaData,
    IngestSource,
    KevData,
    NvdData,
    VersionData,
)
from vulnctl.output.sarif import build_sarif
from vulnctl.pipeline import apply_tree, enrich_findings
from vulnctl.ssvc.tree import load_bundled_tree

pytestmark = pytest.mark.skipif(
    not os.environ.get("VULNCTL_LIVE"), reason="live smoke only (set VULNCTL_LIVE=1)"
)

# A CVE that every source has an answer for (KEV-listed, scored, exploited).
CVE = "CVE-2021-44228"
_SCHEMA_DIR = Path(__file__).parent.parent / "fixtures" / "sarif"


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0), headers={"User-Agent": "vulnctl-live-smoke"}
    ) as c:
        yield c


async def test_epss_live(client: httpx.AsyncClient, cache: Cache) -> None:
    data = (await EpssAdapter(client, cache).fetch([CVE]))[CVE].data
    assert isinstance(data, EpssData), data


async def test_kev_live(client: httpx.AsyncClient, cache: Cache) -> None:
    data = (await KevAdapter(client, cache).fetch([CVE]))[CVE].data
    assert isinstance(data, KevData) and data.listed, data


async def test_nvd_live(client: httpx.AsyncClient, cache: Cache) -> None:
    data = (await NvdAdapter(client, cache).fetch([CVE]))[CVE].data
    assert isinstance(data, NvdData), data


async def test_osv_live(client: httpx.AsyncClient, cache: Cache) -> None:
    data = (await OsvAdapter(client, cache).fetch([CVE]))[CVE].data
    assert isinstance(data, VersionData), data  # a record exists (ranges may be empty)


async def test_ghsa_live(client: httpx.AsyncClient, cache: Cache) -> None:
    data = (await GhsaAdapter(client, cache).fetch([CVE]))[CVE].data
    assert isinstance(data, GhsaData), data


async def test_exploits_live(client: httpx.AsyncClient, cache: Cache) -> None:
    data = (await ExploitsAdapter(client, cache).fetch([CVE]))[CVE].data
    assert isinstance(data, ExploitData) and data.edb_ids, data


async def test_pipeline_end_to_end_live(client: httpx.AsyncClient, cache: Cache) -> None:
    """Full fan-out: every core source real, verdict ACT, SARIF still schema-valid."""
    findings = [Finding(cve_id=CVE, source=IngestSource.CLI)]
    results, metadata = await enrich_findings(findings, cache=cache, client=client)
    enrichment = results[0].enrichment
    assert isinstance(enrichment.epss, EpssData)
    assert isinstance(enrichment.kev, KevData) and enrichment.kev.listed
    assert isinstance(enrichment.cvss, CvssData)
    assert not metadata.degradations, metadata.degradations  # every source answered

    ranked = apply_tree(results, OrgContext(), load_bundled_tree())
    assert ranked[0].verdict.decision is Decision.ACT

    schema = json.loads((_SCHEMA_DIR / "sarif-schema-2.1.0.json").read_text())
    jsonschema.validate(build_sarif(ranked, metadata), schema)
