# SPEC.md — vulnctl Project Specification

**Version:** 0.1 draft · **Owner:** Brian · **Status:** Pre-development

---

## 1. Problem statement

CVSS base scores are a poor prioritization signal: they ignore exploitation likelihood, exploit availability, asset criticality, and organizational risk tolerance. Teams either drown remediating "criticals" that will never be exploited or miss medium-severity CVEs under active exploitation. Existing enrichment is scattered across EPSS, CISA KEV, OSV, GHSA, and exploit databases with no single tool that (a) fuses them, (b) applies a defensible decision framework (SSVC), and (c) shows its work.

## 2. Product vision

A CLI-first vulnerability prioritization engine that turns raw findings into **auditable remediation decisions**. Input a CVE list, SBOM, or scanner report; output a ranked set of Track / Track* / Attend / Act verdicts, each with the complete decision path and the intelligence that drove it. Designed for vulnerability management practitioners who must defend prioritization decisions to engineering and leadership.

**Tagline:** *Not another score. A defensible decision.*

## 3. Target users

| User | Need |
|---|---|
| Vuln management / product security engineer | Triage scanner output; negotiate remediation timelines with evidence |
| AppSec / DevSecOps engineer | Gate CI on risk-based policy, not raw CVSS |
| Security leadership | Posture summaries: KEV exposure, decision distribution, trending |

## 4. Functional requirements

### 4.1 Ingestion (v0.1)
- **FR-1:** Accept one or more CVE IDs as CLI arguments
- **FR-2:** Accept a CycloneDX 1.4/1.5 JSON SBOM (`--sbom`); resolve components → CVEs via OSV batch API
- **FR-3:** Accept Grype JSON output (`--grype`)
- **FR-4 (v0.2):** SPDX SBOMs, Trivy JSON

### 4.2 Enrichment (v0.1)
- **FR-5:** For each CVE, gather: EPSS score + percentile; CISA KEV membership (+ date added, ransomware flag); CVSS v3.1 vector and base score from NVD; CWE(s); affected/fixed versions from OSV/GHSA; exploit presence (Exploit-DB, Metasploit modules, nuclei templates)
- **FR-6:** All source fetches cached in SQLite with per-source TTL (EPSS 24h, KEV 6h, NVD 7d, OSV 24h)
- **FR-7:** `--offline` runs from cache + bundled snapshots only; missing data marked `unavailable`
- **FR-8:** Graceful degradation — a source outage never fails the run; it is recorded in output metadata and the decision path

### 4.3 Decision engine (v0.1)
- **FR-9:** Evaluate each enriched finding against an SSVC decision tree defined in YAML. Ship CISA's Stakeholder-Specific Vulnerability Categorization (coordinator/deployer) tree as the bundled default
- **FR-10:** Accept an org context file (`--context context.yaml`) supplying decision inputs the intel sources cannot: exposure (internet-facing / internal / isolated), mission impact, asset criticality tier, automatable-exploitation override
- **FR-11:** Every verdict includes a `DecisionPath`: ordered list of (node, input value, value source) tuples ending in the decision
- **FR-12:** Deterministic: identical inputs → identical verdicts

### 4.4 Output (v0.1)
- **FR-13:** Rich terminal table sorted by decision severity (Act → Attend → Track* → Track), tie-broken by EPSS
- **FR-14:** `--format json` — full machine-readable results including decision paths
- **FR-15:** `--format sarif` — SARIF 2.1.0 with verdict as level mapping and decision path in message; validates against schema
- **FR-16:** `--format md` — stakeholder-facing Markdown report: summary counts by decision, KEV exposure highlights, top-10 table, per-finding detail appendix
- **FR-17:** Exit codes for CI gating: `--fail-on act|attend` returns non-zero if any finding meets/exceeds the threshold

### 4.5 v0.2+ (roadmap, not MVP)
- **FR-18:** Asset-context model — per-service criticality tiers and exposure flags in a registry file; findings matched to assets; SSVC inputs resolved per-asset (directly targets asset-criticality-aware prioritization)
- **FR-19:** GCP asset inventory importer to seed the asset registry
- **FR-20:** KPI/posture mode: decision distribution over time, mean EPSS of open findings, KEV exposure count, remediation SLA burn-down (requires state file)
- **FR-21:** VEX consumption (OpenVEX) to suppress not-affected findings with justification carried into the decision path
- **FR-22:** Custom SSVC trees authored by users; tree linter/validator
- **FR-23:** Optional LLM-generated plain-English impact summaries per finding

## 5. Non-functional requirements

- **NFR-1:** Enrich 500 CVEs in < 60s warm-cache, < 5min cold (API rate limits permitting)
- **NFR-2:** Zero required credentials; NVD API key optional (higher rate limits) via env var
- **NFR-3:** Runs on Linux and macOS; Python 3.11+; installable via `pipx install vulnctl`
- **NFR-4:** Test coverage ≥ 85% on `ssvc/` and `adapters/`; SSVC engine at 100% branch coverage
- **NFR-5:** All third-party API schemas validated defensively; malformed upstream data degrades, never crashes
- **NFR-6:** Supply-chain hygiene on the repo itself: pinned actions, signed releases (Sigstore), SBOM published per release, SLSA provenance (v0.2)

## 6. Explicit non-goals (v0.x)

- Not a scanner — consumes scanner/SBOM output, never detects vulnerabilities itself
- No web UI, no daemon/service mode
- No ticketing integrations (Jira etc.)
- No proprietary intel feeds; public/free sources only
- Not a patch management tool

## 7. Data sources

| Source | Data | Access | Offline snapshot |
|---|---|---|---|
| FIRST EPSS | Exploitation probability, percentile | REST + daily bulk CSV | Yes (bundled CSV) |
| CISA KEV | Known exploited, ransomware use | Single JSON file | Yes |
| NVD 2.0 API | CVSS vectors, CWE, references | REST, keyed rate limits | Cache only |
| OSV.dev | Ecosystem package vulns, versions | Batch REST | Cache only |
| GitHub GSA | Advisory detail, severity | GraphQL | Cache only |
| Exploit presence | EDB IDs, MSF modules, nuclei templates | CSV mirror / repo listings | Yes (bundled index) |

## 8. Milestones

| Milestone | Scope | Definition of done |
|---|---|---|
| **M1 — Skeleton** | Repo, CI, models, cache, CLI scaffold | `vulnctl --version` ships via pipx from TestPyPI; CI green |
| **M2 — Enrich core** | EPSS + KEV + NVD adapters, CVE-list ingestion, rich table | `vulnctl enrich CVE-2021-44228` shows fused intel |
| **M3 — Decisions** | SSVC engine, bundled tree, context file, decision paths | Verdicts with full paths; 100% branch coverage on engine |
| **M4 — SBOM & scanner input** | CycloneDX + Grype ingestion, OSV/GHSA adapters | End-to-end: SBOM in → ranked verdicts out |
| **M5 — Outputs & gating** | JSON/SARIF/MD formats, exploit-presence adapter, `--fail-on` | SARIF validates; works as a CI gate on a demo repo |
| **M6 — v0.1 release** | Docs, README with demo GIF, signed release | Published to PyPI; announcement post |

## 9. Success metrics

- Dogfood: used weekly for real triage within 1 month of v0.1
- 100+ GitHub stars or one external contributor within 3 months
- One written case study: "CVSS-only vs vulnctl verdicts on the same Grype report" showing reduced Act-priority queue
- Basis for at least one internal product-feedback writeup (enrichment/prioritization gaps observed vs. commercial tooling)

## 10. Risks

| Risk | Mitigation |
|---|---|
| NVD API instability/rate limits | Aggressive caching, offline snapshots, OSV as partial fallback |
| SSVC tree modeling errors | Bundle CISA's published tree verbatim; 100% branch tests; tree files versioned |
| Scope creep toward "platform" | Non-goals section enforced; v0.2 items require closing v0.1 first |
| Source schema drift | Pydantic strict validation + recorded fixtures catch drift in CI |
