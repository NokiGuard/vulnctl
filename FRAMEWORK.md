# FRAMEWORK.md — vulnctl High-Level Architecture

**Companion to:** `SPEC.md` (what/why) · This document covers *how*.

---

## 1. System overview

```
                        ┌──────────────────────────────────────────────┐
                        │                 vulnctl CLI                  │
                        │                                              │
 CVE IDs ──────┐        │  ┌─────────┐   ┌────────────┐   ┌─────────┐  │
 SBOM ─────────┼──────▶ │  │ Ingest  │──▶│ Enrichment │──▶│  SSVC   │  │
 (CycloneDX)   │        │  │ layer   │   │ pipeline   │   │ engine  │  │
 Grype JSON ───┘        │  └─────────┘   └─────┬──────┘   └────┬────┘  │
                        │                      │               │       │
                        │                ┌─────▼──────┐        │       │
 context.yaml ──────────┼───────────────▶│  SQLite    │        │       │
 (org risk tolerance)   │                │  cache     │        ▼       │
                        │                └─────┬──────┘   ┌─────────┐  │
                        │                      │          │ Output  │  │
                        │     EPSS  KEV  NVD   │          │ layer   │  │
                        │     OSV  GHSA  EDB ◀─┘          └────┬────┘  │
                        │     (source adapters)                │       │
                        └──────────────────────────────────────┼───────┘
                                                               ▼
                                          table · JSON · SARIF · Markdown
                                                 exit code (CI gate)
```

Four layers, strictly ordered, data flows one direction:

**Ingest → Enrich → Decide → Output**

## 2. Core data model (Pydantic)

```
Finding            # normalized unit of work
├── cve_id: str
├── source: IngestSource            # cli | cyclonedx | grype
├── package: PackageRef | None      # purl, version (SBOM/scanner paths)
└── asset_hint: str | None          # v0.2: asset registry key

Enrichment         # produced by the pipeline, one per Finding
├── epss: EpssData | Unavailable            # score, percentile, date
├── kev: KevData | Unavailable              # listed, date_added, ransomware
├── cvss: CvssData | Unavailable            # vector, base, severity
├── cwes: list[str]
├── versions: VersionData | Unavailable     # affected, fixed
├── exploits: ExploitData | Unavailable     # edb_ids, msf_modules, nuclei
└── provenance: dict[str, SourceMeta]       # which source, fetched when, cache hit?

Verdict            # produced by the SSVC engine
├── decision: Decision              # TRACK | TRACK_STAR | ATTEND | ACT
├── path: DecisionPath              # ordered [(node, value, value_source)]
├── tree_id: str                    # which tree + version produced this
└── inputs_degraded: bool           # any Unavailable inputs defaulted?
```

**`Unavailable` is a first-class value**, not `None`. It carries *why* (source down, offline mode, not found) and flows into the decision path so degraded verdicts are visibly degraded.

## 3. Layer contracts

### 3.1 Ingest layer
- One parser module per input type; all return `list[Finding]`
- SBOM path additionally performs component→CVE resolution via the OSV batch endpoint (this is the one place ingest touches the network, via the OSV adapter)
- Hard-fails with actionable errors on malformed input files

### 3.2 Source adapters
```python
class SourceAdapter(ABC):
    name: str
    ttl: timedelta
    supports_offline: bool

    async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]: ...
```
- Registered in a simple registry (same pluggable pattern as composeguard's rule engine)
- Each adapter: check cache → batch-fetch misses (bounded concurrency, per-source rate limits) → validate against strict Pydantic schema → write cache → return
- Isolation rule: adapters import only `base`, `cache`, `models`. Adding a source touches exactly one new module + fixtures + registry line

### 3.3 Enrichment pipeline
- Fans out to all registered adapters concurrently (`asyncio.gather` with per-adapter exception capture)
- Assembles `Enrichment` per finding; any adapter failure → that field becomes `Unavailable(reason)`
- Emits run metadata: sources used, cache hit rates, degradations

### 3.4 SSVC engine (the crown jewel — keep it pure)
- **Pure function:** `(Enrichment, OrgContext, DecisionTree) -> Verdict`. No I/O. 100% branch coverage.
- Trees are declarative YAML:

```yaml
id: cisa-deployer-v1
decision_points:
  exploitation:            # derived from enrichment
    from: derived
    rule: kev_listed -> active | exploits_present -> poc | else -> none
  exposure:                # supplied by org context
    from: context
    key: exposure
  utility:                 # derived: automatable × value density
    from: derived
    rule: ...
  human_impact:
    from: context
    key: mission_impact
tree:
  exploitation:
    active:
      exposure:
        open: { utility: { ... : ACT } }
        controlled: { ... }
    poc: { ... }
    none: { ... }
defaults:                  # used when an input is Unavailable; recorded in path
  exploitation: none
```

- The walker records every node visit into `DecisionPath`. Defaults applied due to `Unavailable` inputs are flagged in the path — auditability is the product.
- Tree files are versioned; `tree_id` in every verdict pins which logic produced it.

### 3.5 Org context (`context.yaml`)
```yaml
# Organizational risk tolerance — feeds SSVC decision points
exposure: internet          # internet | internal | isolated
mission_impact: high        # low | medium | high | very_high
asset_tier: crown_jewel     # v0.2: replaced by per-asset registry
overrides:
  automatable: null         # force a decision-point value if you know better
```
Validated on load; unknown keys are errors (catch typos early).

### 3.6 Output layer
- All formatters consume the same `list[RankedResult]` (Finding + Enrichment + Verdict)
- Sort: decision severity desc → EPSS desc → CVSS desc
- SARIF mapping: ACT→error, ATTEND→warning, TRACK*→note, TRACK→none; decision path serialized into `message.markdown`
- `--fail-on` evaluated after formatting; exit 2 if threshold met (CI-gate contract)

## 4. Cache design

- Single SQLite file, WAL mode: `~/.cache/vulnctl/cache.db`
- Schema: `(source TEXT, key TEXT, fetched_at TEXT, payload JSON, PRIMARY KEY(source, key))`
- TTL enforced at read time per adapter; `vulnctl cache purge|stats` subcommands
- Bundled snapshots (EPSS CSV, KEV JSON, exploit index) ship in the wheel for offline cold-start

## 5. Error-handling philosophy

| Failure | Behavior |
|---|---|
| Malformed input file (SBOM/Grype/context) | Hard error, actionable message, exit 1 |
| Intel source down / rate-limited | Degrade: field = `Unavailable`, noted in path + run metadata, exit 0 |
| Unknown CVE ID | Included in output as `not_found`, doesn't abort the batch |
| Tree/schema validation failure | Hard error (a broken tree must never silently mis-decide) |

## 6. Testing strategy

- **Adapters:** recorded-fixture tests (real captured API responses, scrubbed). CI never hits live APIs. A separate weekly scheduled workflow runs live smoke tests to catch upstream schema drift.
- **SSVC engine:** table-driven tests enumerating every path through the bundled tree (100% branch); property test that identical inputs are deterministic.
- **End-to-end:** golden-file tests — sample SBOM in, expected JSON out — pinned to bundled snapshot data so they're hermetic.
- **SARIF:** schema validation test against SARIF 2.1.0 JSON schema.

## 7. Repo self-security (dogfooding the day job)

- GitHub Actions pinned by SHA; least-privilege `GITHUB_TOKEN`; harden-runner egress policy
- Release workflow: build → SBOM (Syft) → scan (Grype, gate on KEV/critical-with-fix) → sign (cosign keyless) → publish
- v0.2: SLSA provenance via slsa-github-generator

## 8. v0.2 asset-context extension (design sketch)

Replaces the single global `context.yaml` values with per-asset resolution:

```yaml
# assets.yaml — asset registry
assets:
  - key: payments-api
    tier: crown_jewel
    exposure: internet
    mission_impact: very_high
  - key: internal-wiki
    tier: standard
    exposure: internal
    mission_impact: low
```

- Findings carry an `asset_hint` (from scanner metadata, SBOM component group, or `--asset` flag); resolver maps hint → asset → SSVC context inputs
- Same finding can yield different verdicts on different assets — which is the entire point of risk-based prioritization
- GCP importer (`vulnctl assets import-gcp`) seeds the registry from Cloud Asset Inventory
- KPI mode aggregates verdicts across assets over time (state file) → posture reporting for leadership

## 9. Build order (maps to SPEC milestones)

1. `models.py` + `cache.py` + CLI scaffold → **M1**
2. `epss.py`, `kev.py`, `nvd.py` adapters + pipeline + table output → **M2**
3. `ssvc/engine.py` + bundled CISA tree + `context.py` → **M3**
4. `ingest/cyclonedx.py`, `ingest/grype.py`, `osv.py`, `ghsa.py` → **M4**
5. `output/{json,sarif,markdown}.py` + `exploits.py` + `--fail-on` → **M5**
6. Docs, packaging, signed release → **M6**
