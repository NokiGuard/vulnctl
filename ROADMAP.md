# ROADMAP.md — vulnctl Week-by-Week Plan

10-week plan to v0.1. Each task is scoped to be one GitHub issue; checkboxes within a task are its acceptance criteria. Labels suggested: `m1`–`m6`, `adapter`, `engine`, `output`, `infra`, `docs`.

Weekly rhythm: **1 weekday evening** = Claude Code generates the next chunk + tests, you review. **Weekend block** = integration, fixtures, judgment-heavy work.

---

## Week 1 — M1: Skeleton

**#1 Repo bootstrap** `infra`
- [ ] Repo created; CLAUDE.md, SPEC.md, FRAMEWORK.md at root
- [ ] `pyproject.toml` (hatchling), `uv sync` works, Python 3.11+ pinned
- [ ] ruff + mypy --strict configured; pre-commit hook running all four checks
- [ ] MIT or Apache-2.0 license picked and committed

**#2 Core models** `engine`
- [ ] `models.py`: Finding, PackageRef, Enrichment (+ per-source data classes), Unavailable, Verdict, Decision enum, DecisionPath, SourceMeta
- [ ] Unavailable carries reason enum: `source_down | offline | not_found | rate_limited`
- [ ] Round-trip serialization tests (model → JSON → model)

**#3 SQLite cache** `infra`
- [ ] `cache.py`: get/set with per-source TTL, WAL mode, `~/.cache/vulnctl/cache.db` (XDG-aware)
- [ ] `vulnctl cache stats` and `vulnctl cache purge` subcommands
- [ ] Tests use tmp_path, never the real cache dir

**#4 CLI scaffold + CI** `infra`
- [ ] Typer app with `--version`, `enrich` stub, `cache` group
- [ ] GitHub Actions: lint + type + test on push/PR, actions pinned by SHA, least-privilege token
- [ ] TestPyPI publish workflow (manual trigger); `pipx install` from TestPyPI verified

**Exit demo:** `pipx install vulnctl` (TestPyPI) → `vulnctl --version` works. CI green.

---

## Week 2 — M2 part 1: Easy adapters

**#5 Adapter base + registry** `adapter`
- [ ] `SourceAdapter` ABC per FRAMEWORK §3.2; registry with name lookup
- [ ] Fixture-loading helper in `tests/conftest.py` (loads recorded JSON, patches transport)
- [ ] Bounded-concurrency fetch helper with per-source rate limit config

**#6 EPSS adapter** `adapter`
- [ ] Batch REST fetch, score + percentile + date; 24h TTL
- [ ] Bundled CSV snapshot loader for `--offline`
- [ ] Recorded fixtures + tests, including missing-CVE and malformed-row cases

**#7 KEV adapter** `adapter`
- [ ] Single-JSON fetch, membership + dateAdded + ransomware flag; 6h TTL
- [ ] Bundled JSON snapshot for offline
- [ ] Fixtures + tests

**Exit demo:** unit level only — adapters return validated models from fixtures.

---

## Week 3 — M2 part 2: NVD + first real output

**#8 NVD adapter** `adapter` *(the week's time sink — start it on the weekday evening)*
- [ ] CVE 2.0 API: CVSS v3.1 vector/base/severity, CWEs; 7d TTL
- [ ] `VULNCTL_NVD_API_KEY` support; polite rate limiting keyed vs unkeyed
- [ ] Handles: CVE with only v2 scores, multiple CVSS entries, rejected CVEs, 403/503 backoff
- [ ] Fixtures covering each edge case above

**#9 Enrichment pipeline** `engine`
- [ ] Fan-out across registered adapters, per-adapter exception capture → Unavailable
- [ ] Run metadata: sources used, cache hit rate, degradations
- [ ] Integration test: 3 CVEs through all 3 adapters from fixtures

**#10 Rich table output** `output`
- [ ] `vulnctl enrich CVE-…` renders table: CVE, CVSS, EPSS, KEV, exploit cols (exploit blank for now)
- [ ] `--offline` flag end-to-end

**Exit demo (screenshot-worthy):** `vulnctl enrich CVE-2021-44228 CVE-2023-4863` shows fused live intel. **→ Start dogfooding weekly from here.**

---

## Week 4 — M3 part 1: SSVC engine core

**#11 Tree format + loader** `engine`
- [ ] YAML tree schema per FRAMEWORK §3.4; strict validation, hard error on malformed trees
- [ ] Derived-value rules: kev_listed→active, exploits_present→poc, else→none (+ rule mini-DSL or explicit enum mapping — decide and document)
- [ ] `defaults:` block applied on Unavailable, flagged in path

**#12 Tree walker** `engine`
- [ ] Pure function `(Enrichment, OrgContext, DecisionTree) -> Verdict`; zero I/O
- [ ] DecisionPath records (node, value, value_source) per hop; `inputs_degraded` set correctly
- [ ] Determinism property test

**Exit demo:** unit tests pass on a toy tree.

---

## Week 5 — M3 part 2: CISA tree + context (schedule-risk week — protect the weekend)

**#13 Bundled CISA deployer tree** `engine`
- [ ] CISA SSVC deployer tree transcribed to YAML, versioned `cisa-deployer-v1`
- [ ] Table-driven tests enumerating **every** path; 100% branch coverage gate in CI
- [ ] Verdicts validated against CISA's published worked examples

**#14 Org context** `engine`
- [ ] `context.py`: load/validate `context.yaml`; unknown keys are errors
- [ ] `--context` wired into `enrich`; sensible documented defaults when absent
- [ ] Example `context.yaml` committed to `examples/`

**Exit demo (differentiator moment):** `vulnctl enrich CVE-2021-44228 --context examples/context.yaml` prints a verdict **with its full decision path**. Worth a short write-up/post even pre-release.

*Contingency: if #13 runs long, push #14 into week 6 and drop the exploit-presence adapter (#19) to v0.2.*

---

## Week 6 — M4 part 1: SBOM ingestion

**#15 OSV adapter** `adapter`
- [ ] querybatch endpoint: purl+version → vuln IDs; alias resolution to CVE IDs; affected/fixed ranges
- [ ] Dedup strategy across OSV/GHSA documented in code
- [ ] Fixtures: npm, PyPI, Go packages; a purl with no vulns; an alias-only (GHSA-…) result

**#16 CycloneDX ingestion** `adapter`
- [ ] Parse CDX 1.4/1.5 JSON → Findings with PackageRef; hard error w/ actionable message on malformed
- [ ] `--sbom` flag end-to-end through pipeline
- [ ] Test SBOMs in fixtures (generate with Syft from a sample container)

**Exit demo:** `vulnctl enrich --sbom examples/app.cdx.json --context …` → ranked verdicts.

---

## Week 7 — M4 part 2: Scanner input + GHSA

**#17 Grype ingestion** `adapter`
- [ ] Parse Grype JSON → Findings (CVE + package + severity passthrough)
- [ ] `--grype` flag end-to-end; dedup when Grype reports same CVE across layers

**#18 GHSA adapter** `adapter`
- [ ] GraphQL securityAdvisories: severity, summary, affected ranges; anonymous + token modes
- [ ] Merge policy with OSV data (who wins on conflict) documented + tested

**Exit demo:** full path — `grype <image> -o json | vulnctl enrich --grype - --context …`.

---

## Week 8 — M5 part 1: Machine outputs

**#19 Exploit-presence adapter** `adapter` *(first cut candidate if behind)*
- [ ] EDB CSV mirror index, Metasploit module list, nuclei template index; bundled snapshot
- [ ] Conservative matching (CVE-ID exact only for v0.1); fixtures + tests

**#20 JSON output** `output`
- [ ] `--format json`: full results incl. decision paths + run metadata; stable schema documented in `docs/schema.md`

**#21 SARIF output** `output` *(the tax — weekend item)*
- [ ] SARIF 2.1.0: ACT→error, ATTEND→warning, TRACK*→note, TRACK→none; path in message.markdown
- [ ] Schema-validation test in CI; renders correctly in GitHub code scanning on a test repo

**Exit demo:** SARIF uploaded to a demo repo's Security tab.

---

## Week 9 — M5 part 2: Gating + report

**#22 CI gate** `output`
- [ ] `--fail-on act|attend` → exit 2 on threshold; exit codes documented
- [ ] Demo workflow in `examples/ci/`: Syft → vulnctl → gate

**#23 Markdown report** `output`
- [ ] `--format md`: summary counts by decision, KEV highlights, top-10 table, per-finding appendix
- [ ] Golden-file test pinned to bundled snapshots

**#24 Weekly live smoke workflow** `infra`
- [ ] Scheduled action hitting live APIs (all adapters), alerting on schema drift; never blocks PR CI

**Exit demo:** a PR on the demo repo blocked by an ACT verdict, with the MD report as a PR comment artifact.

---

## Week 10 — M6: Release

**#25 Docs pass** `docs`
- [ ] README: value prop, install, 60-second demo GIF (vhs/asciinema), decision-path screenshot
- [ ] `docs/`: context.yaml reference, tree format reference, output schema

**#26 Release engineering** `infra`
- [ ] Release workflow: build → Syft SBOM → Grype scan (gate: KEV or critical-with-fix) → cosign keyless sign → PyPI publish
- [ ] v0.1.0 tagged, signed, published; install verified from clean machine

**#27 Announcement** `docs`
- [ ] Case study: CVSS-only vs vulnctl verdicts on one real Grype report (queue-size reduction)
- [ ] Post (blog/LinkedIn/r/netsec) + submit to relevant awesome-lists

**Exit demo:** `pipx install vulnctl` from PyPI, verified signature, README GIF live.

---

## Standing weekly habits

- Dogfood on a real CVE list or homelab scan (from week 3 onward); file issues for friction
- Keep commits small, one adapter/format per PR (CLAUDE.md style rules)
- Friday: 5-minute triage of open issues → pick next week's scope
