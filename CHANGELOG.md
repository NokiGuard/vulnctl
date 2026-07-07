# Changelog

All notable changes to vulnctl are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-07

First public release. `vulnctl` turns CVE lists, SBOMs, and scanner output into
auditable, SSVC-based remediation verdicts — each with the full decision path
that produced it.

### Added

- **`enrich` command** accepting three input modes (exactly one per run): one or
  more CVE IDs, a CycloneDX 1.4–1.6 SBOM (`--sbom`, components resolved to CVEs
  via OSV), or Grype JSON (`--grype <file>` or `-` for stdin).
- **Fused enrichment** from six public intelligence sources: FIRST EPSS
  (exploit probability + percentile), CISA KEV (known-exploited + ransomware
  flag), NVD (CVSS vector/score, CWE), OSV and GHSA (affected/fixed versions,
  advisories), and exploit presence (Exploit-DB, Metasploit, nuclei).
- **SSVC decision engine**: a pure, deterministic tree-walker bundling the
  CISA-style deployer tree `cisa-deployer-v1`. Every verdict carries a full
  `DecisionPath` — each node visited, its value, and the source that supplied
  it — and flags when a degraded input fell back to a tree default. Bring your
  own tree with `--tree`.
- **Organizational context** via `--context context.yaml`: `exposure`,
  `mission_impact`, `asset_tier`, and per-decision-point `overrides`, with
  conservative defaults when absent and hard errors on unknown keys.
- **Offline mode** (`--offline`): runs from cached data and bundled EPSS/KEV/
  exploit snapshots with zero network access.
- **Output formats**: rich terminal table (with `--show-path`), machine-readable
  `--format json` (versioned, schema-documented), `--format sarif` (SARIF 2.1.0
  for GitHub code scanning), and `--format md` (stakeholder report).
- **CI gating**: `--fail-on track|track*|attend|act` exits `2` when any finding
  meets or exceeds the threshold; output is written before the gate is applied.
- **Response cache**: SQLite with per-source TTLs; `cache stats` and
  `cache purge` subcommands.
- **`--version`** sourced from installed package metadata (single source of
  truth in `pyproject.toml`).
- **Documentation**: README with quickstart, plus `docs/` references for the
  context file, tree format, JSON schema, exit codes, and the release runbook;
  a `vhs` demo tape; and an example CI gate under `examples/ci/`.

### Security

- All GitHub Actions pinned by full commit SHA; least-privilege token scopes per
  workflow.
- Strict Pydantic validation of every external JSON payload before it becomes a
  model; response- and file-size bounds on all inputs; no `eval`, no `pickle` of
  untrusted data, no shelling out to parse files.
- Signed release pipeline: build with `uv`, generate a CycloneDX SBOM (Syft),
  scan the artifact (Grype, dogfooded through vulnctl's own `--fail-on` gate),
  sign with keyless cosign (OIDC), and publish to PyPI via trusted publishing
  (no stored token).

[Unreleased]: https://github.com/NokiGuard/vulnctl/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NokiGuard/vulnctl/releases/tag/v0.1.0
