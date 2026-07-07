"""JSON output: hermetic golden-file test + envelope invariants.

The golden run is fully offline (bundled snapshots only, zero network), so the
only volatile field is each source's ``fetched_at`` timestamp — normalized to
``<ts>`` before comparison. Regenerate the golden with::

    (see the generator block at the bottom of this file's git history)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from conftest import FIXTURES_DIR, MakeClient
from vulnctl.cache import Cache
from vulnctl.context import OrgContext
from vulnctl.models import Finding, IngestSource
from vulnctl.output.json_out import JsonReport, build_report, render_json, schema
from vulnctl.pipeline import apply_tree, enrich_findings
from vulnctl.ssvc.tree import load_bundled_tree

GOLDEN = FIXTURES_DIR / "golden" / "enrich.json"
GOLDEN_CVES = ["CVE-2021-44228", "CVE-2010-0017"]

_TS_RE = re.compile(r'"fetched_at": "[^"]*"')


def _normalize(rendered: str) -> str:
    return _TS_RE.sub('"fetched_at": "<ts>"', rendered)


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "cache.db")


async def _offline_json(cache: Cache, fixture_client: MakeClient) -> str:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("golden run must never touch the network")

    findings = [Finding(cve_id=c, source=IngestSource.CLI) for c in GOLDEN_CVES]
    async with fixture_client(handler) as client:
        results, metadata = await enrich_findings(
            findings, cache=cache, client=client, offline=True
        )
    ranked = apply_tree(results, OrgContext(), load_bundled_tree())
    return render_json(ranked, metadata)


async def test_json_matches_golden(cache: Cache, fixture_client: MakeClient) -> None:
    rendered = await _offline_json(cache, fixture_client)
    assert _normalize(rendered) == GOLDEN.read_text()


async def test_json_is_valid_and_versioned(cache: Cache, fixture_client: MakeClient) -> None:
    payload = json.loads(await _offline_json(cache, fixture_client))
    assert payload["schema_version"] == "1"
    assert [r["finding"]["cve_id"] for r in payload["results"]] == GOLDEN_CVES  # act before attend
    # Unavailable markers are discriminated by their `reason` key.
    log4shell = payload["results"][0]["enrichment"]
    assert "reason" in log4shell["cvss"] and log4shell["cvss"]["reason"] == "offline"
    assert "reason" not in log4shell["kev"]  # present data has no reason key


async def test_report_round_trips(cache: Cache, fixture_client: MakeClient) -> None:
    rendered = await _offline_json(cache, fixture_client)
    # The envelope validates its own serialized form (strict, extra=forbid).
    assert JsonReport.model_validate_json(rendered).schema_version == "1"


def test_schema_describes_the_envelope() -> None:
    doc = schema()
    assert doc["properties"]["schema_version"]["const"] == "1"
    assert {"schema_version", "run", "results"} <= set(doc["properties"])


def test_committed_schema_json_is_current() -> None:
    """docs/schema.json is generated from the models — regenerate it if this fails:
    uv run python -c 'import json;from vulnctl.output.json_out import schema;
    open("docs/schema.json","w").write(json.dumps(schema(),indent=2)+chr(10))'."""
    committed = (Path(__file__).parent.parent / "docs" / "schema.json").read_text()
    assert committed == json.dumps(schema(), indent=2) + "\n"


def test_build_report_orders_by_rank() -> None:
    from test_output_table import _cvss, _epss, _result
    from vulnctl.models import Decision, RunMetadata

    meta = RunMetadata(sources=[], offline=True, cache_hit_rate={})
    rows = [
        _result("CVE-2020-1111", decision=Decision.TRACK, epss=_epss(0.9)),
        _result("CVE-2020-2222", decision=Decision.ACT, epss=_epss(0.1), cvss=_cvss(9.8)),
    ]
    report = build_report(rows, meta)
    assert [r.finding.cve_id for r in report.results] == ["CVE-2020-2222", "CVE-2020-1111"]
