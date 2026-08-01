# Changelog

All notable changes to vulnctl are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-01

Makes the output actionable and readable, and accepts GHSA identifiers
everywhere CVE IDs are accepted. The JSON output shape and its
`schema_version` (`"1"`) are unchanged.

### Added

- **`explain` command**: `vulnctl explain <VULN_ID>` renders one finding in
  depth — every source's answer with provenance (fetched-at, cache hit/miss),
  the full affected/fixed version ranges, CWEs, exploit artifact identifiers,
  the complete decision path, and the **counterfactuals**: every single-input
  change that would produce a different decision. Accepts CVE and GHSA IDs and
  honors `--offline`, `--context`, and `--tree`.
- **GHSA identifiers as input**: `vulnctl enrich GHSA-xxxx-xxxx-xxxx` works
  alongside CVE IDs, and Grype scans whose matches are GHSA-native (no
  `relatedVulnerabilities`) alias-resolve to CVEs via OSV before enrichment,
  preserving the GHSA ID in `aliases`. An identifier with no CVE alias enriches
  under its native ID rather than being dropped.
- **Fix versions and advisory summaries in human output**: the table and
  Markdown report gain a `Fix` column (OSV fixed versions, scoped to the
  finding's own package on SBOM/scanner runs) and a `Summary` column (the GHSA
  one-line description). Both were already fetched but reachable only in JSON.
- **Verdict rollup line**: table runs close with
  `5 finding(s) · 1 ACT · 4 TRACK* · 1 KEV-listed`.
- **Display filters**: `--min-decision`, `--only-kev`, and `--limit` shape every
  output format. The rollup line still counts every finding and reports
  `(showing M)`, and `--fail-on` still evaluates the unfiltered set, so a
  filtered-out Act can neither disappear from the summary nor skip the gate.
- **Live progress display**: per-source progress bars on stderr during online
  runs — transient, shown only when stderr is a terminal, skipped for
  `--offline` — leaving piped stdout byte-clean for `-f json`.
- **Shell completion documentation**: `vulnctl --install-completion` enables
  completion for commands, flags, and enum values (`--format`, `--fail-on`).

### Changed

- **CVE-only sources now answer honestly for non-CVE identifiers.** KEV
  previously returned `listed: false` and the exploit index an empty result for
  a GHSA ID — facts neither CVE-keyed catalog can assert — which let the engine
  resolve `exploitation=none` with no degradation flag. EPSS, KEV, NVD, and the
  exploit index now return `unavailable (not_found)` for non-CVE identifiers
  without issuing a request, so the verdict falls to the tree default and is
  visibly degraded.
- **Slimmer table columns**: purls render without the `pkg:` scheme
  (`npm/lodash@4.17.20`); the KEV cell shows `yes ransomware` without the
  date added (still present in JSON); the caption reports one average cache-hit
  rate instead of six per-source figures; and rows are separated into sections
  per decision tier.
- **Grouped degradation reporting**: `degraded: nvd 340 (offline), …` in the
  table caption and a `Data gaps` bullet in the Markdown report, replacing one
  line per finding per source. JSON keeps the full per-finding list.
- The positional argument is now `VULN_ID...` (was `CVE_ID...`).

### Fixed

- NVD no longer spends its retry and backoff budget on requests for identifiers
  it cannot index.

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

[Unreleased]: https://github.com/NokiGuard/vulnctl/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/NokiGuard/vulnctl/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/NokiGuard/vulnctl/releases/tag/v0.1.0
