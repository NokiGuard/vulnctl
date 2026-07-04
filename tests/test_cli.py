"""CLI smoke tests via Typer's test runner."""

from __future__ import annotations

from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnctl.cache import Cache
from vulnctl.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point XDG_CACHE_HOME at tmp_path so no test touches the real cache."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))


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


def test_enrich_invalid_cve_rejected() -> None:
    result = runner.invoke(app, ["enrich", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"])
    assert result.exit_code != 0
    assert "GHSA-jfh8-c2jp-5v3q" in result.output


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
