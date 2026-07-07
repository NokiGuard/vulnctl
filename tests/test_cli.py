"""CLI smoke tests via Typer's test runner."""

from __future__ import annotations

import json
from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnctl.cache import Cache
from vulnctl.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Isolate the cache under tmp_path and widen the terminal so cells don't wrap."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setenv("COLUMNS", "200")


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"vulnctl {pkg_version('vulnctl')}" in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_enrich_offline_renders_table_from_snapshots() -> None:
    """End-to-end offline run: bundled snapshots only, zero network."""
    result = runner.invoke(app, ["enrich", "--offline", "cve-2021-44228", "CVE-2019-0708"])
    assert result.exit_code == 0
    # IDs normalized to uppercase; both CVEs are in the bundled snapshots.
    assert "CVE-2021-44228" in result.output
    assert "CVE-2019-0708" in result.output
    assert "ransomware" in result.output  # both are KEV ransomware entries
    assert "n/a (offline)" in result.output  # NVD has no snapshot -> visibly degraded
    assert "offline mode" in result.output
    assert "ACT" in result.output  # KEV-listed + defaults on internet/high context


def test_enrich_offline_with_context_and_show_path() -> None:
    """DoD flow: verdict with complete decision path, defaults visibly sourced."""
    result = runner.invoke(
        app,
        [
            "enrich",
            "--offline",
            "--context",
            str(Path(__file__).parent.parent / "examples" / "context.yaml"),
            "--show-path",
            "CVE-2021-44228",
        ],
    )
    assert result.exit_code == 0
    # KEV snapshot marks it active; NVD is offline so automatable falls to
    # the tree default and must be visible as such in the path.
    assert "exploitation = active" in result.output
    assert "[kev]" in result.output
    assert "automatable" in result.output
    assert "[default]" in result.output
    assert "[context]" in result.output
    assert "degraded: defaults applied" in result.output
    assert "cisa-deployer-v1" in result.output


def test_enrich_bad_context_file_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "context.yaml"
    bad.write_text("exposrue: internet\n")
    result = runner.invoke(app, ["enrich", "--offline", "--context", str(bad), "CVE-2021-44228"])
    assert result.exit_code == 1
    assert "error" in result.output


def test_enrich_bad_tree_file_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "tree.yaml"
    bad.write_text("id: broken\n")
    result = runner.invoke(app, ["enrich", "--offline", "--tree", str(bad), "CVE-2021-44228"])
    assert result.exit_code == 1
    assert "error" in result.output


def test_enrich_invalid_cve_rejected() -> None:
    result = runner.invoke(app, ["enrich", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"])
    assert result.exit_code == 1  # input error, not a usage (2) or gate (2) code
    assert "GHSA-jfh8-c2jp-5v3q" in result.output


NPM_SBOM = Path(__file__).parent / "fixtures" / "sbom" / "npm-app.cdx.json"
NPM_SCAN = Path(__file__).parent / "fixtures" / "grype" / "npm-app.json"


def test_enrich_requires_exactly_one_input_mode() -> None:
    for args in (
        ["enrich", "CVE-2021-44228", "--sbom", str(NPM_SBOM)],
        ["enrich", "--sbom", str(NPM_SBOM), "--grype", str(NPM_SCAN)],
        ["enrich"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 1
        assert "exactly one input" in result.output


def test_enrich_sbom_offline_cold_cache_degrades_but_succeeds() -> None:
    """Offline with an empty cache: discovery degrades to warnings, run still exits 0."""
    result = runner.invoke(app, ["enrich", "--offline", "--sbom", str(NPM_SBOM)])
    assert result.exit_code == 0
    assert "vulnctl enrichment" in result.output
    assert "degraded" in result.output  # skipped component + offline discovery


def test_enrich_sbom_malformed_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "app.cdx.json"
    bad.write_text('{"bomFormat": "SPDX"}')
    result = runner.invoke(app, ["enrich", "--sbom", str(bad)])
    assert result.exit_code == 1
    assert "not a CycloneDX SBOM" in result.output


def test_enrich_grype_offline_renders_findings() -> None:
    result = runner.invoke(app, ["enrich", "--offline", "--grype", str(NPM_SCAN)])
    assert result.exit_code == 0
    assert "CVE-2021-23337" in result.output
    assert "pkg:npm/lodash@4.17.20" in result.output  # Package column on scanner runs


def test_enrich_grype_reads_stdin_via_dash() -> None:
    result = runner.invoke(app, ["enrich", "--offline", "--grype", "-"], input=NPM_SCAN.read_text())
    assert result.exit_code == 0
    assert "CVE-2021-23337" in result.output


def test_enrich_grype_malformed_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "scan.json"
    bad.write_text('{"vulnerabilities": []}')
    result = runner.invoke(app, ["enrich", "--grype", str(bad)])
    assert result.exit_code == 1
    assert "no 'matches' key" in result.output


def test_enrich_json_format_is_valid() -> None:
    result = runner.invoke(app, ["enrich", "--offline", "-f", "json", "CVE-2021-44228"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"


def test_enrich_markdown_format() -> None:
    result = runner.invoke(app, ["enrich", "--offline", "-f", "md", "CVE-2021-44228"])
    assert result.exit_code == 0
    assert result.output.startswith("# vulnctl report")
    assert "## Summary" in result.output


# --- exit-code contract (SPEC FR-17): 0 ok, 1 input/config, 2 gate ------------


def test_fail_on_act_trips_on_act_verdict() -> None:
    # CVE-2021-44228 is KEV-listed → ACT on the default internet/high context.
    result = runner.invoke(app, ["enrich", "--offline", "--fail-on", "act", "CVE-2021-44228"])
    assert result.exit_code == 2
    assert "CVE-2021-44228" in result.output  # output is still emitted before the gate


def test_fail_on_act_passes_when_below_threshold() -> None:
    # CVE-2010-0017 has a public exploit but is not KEV-listed → ATTEND, below ACT.
    result = runner.invoke(app, ["enrich", "--offline", "--fail-on", "act", "CVE-2010-0017"])
    assert result.exit_code == 0


def test_fail_on_attend_trips_on_attend_verdict() -> None:
    result = runner.invoke(app, ["enrich", "--offline", "--fail-on", "attend", "CVE-2010-0017"])
    assert result.exit_code == 2


def test_no_gate_exits_zero_even_on_act() -> None:
    result = runner.invoke(app, ["enrich", "--offline", "CVE-2021-44228"])
    assert result.exit_code == 0


def test_input_error_beats_gate_exit_code() -> None:
    # A bad CVE must exit 1 (input), never 2 — even with --fail-on set.
    result = runner.invoke(app, ["enrich", "--offline", "--fail-on", "act", "NOPE"])
    assert result.exit_code == 1


def test_cache_stats_renders_counts(tmp_path: Path) -> None:
    with Cache() as cache:
        cache.set("epss", "CVE-2021-44228", "{}")
        cache.set("kev", "CVE-2021-44228", "{}")
    result = runner.invoke(app, ["cache", "stats"])
    assert result.exit_code == 0
    assert "epss" in result.output
    assert "kev" in result.output


def test_cache_purge_all() -> None:
    with Cache() as cache:
        cache.set("epss", "CVE-1", "{}")
        cache.set("kev", "CVE-1", "{}")
    result = runner.invoke(app, ["cache", "purge"])
    assert result.exit_code == 0
    assert "Purged 2" in result.output
    with Cache() as cache:
        assert cache.stats().total_entries == 0


def test_cache_purge_single_source() -> None:
    with Cache() as cache:
        cache.set("epss", "CVE-1", "{}")
        cache.set("kev", "CVE-1", "{}")
    result = runner.invoke(app, ["cache", "purge", "--source", "epss"])
    assert result.exit_code == 0
    assert "Purged 1" in result.output
    with Cache() as cache:
        assert cache.stats().entries_by_source == {"kev": 1}
