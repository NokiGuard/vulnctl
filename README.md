# vulnctl

*Auditable decisions, not scores.*

CVSS base scores are a poor way to decide what to fix first: they ignore
exploitation likelihood, exploit availability, your asset exposure, and your
risk tolerance. Teams end up drowning in "criticals" that will never be
exploited while missing medium-severity CVEs under active attack. `vulnctl`
fuses the public intelligence that actually predicts risk — EPSS, CISA KEV,
NVD, OSV, GHSA, and public exploit feeds — evaluates each finding against a
declarative **SSVC** decision tree using *your* organizational context, and
emits a ranked set of **Track / Track\* / Attend / Act** verdicts. Every
verdict ships with its full decision path: which input, what value, and which
source supplied it. The audit trail is the product — you can defend each call
to engineering and leadership instead of hand-waving at a number.

## What it does

- **Ingest** a CVE list, a CycloneDX SBOM (1.4–1.6), or Grype scanner JSON.
- **Enrich** each finding from EPSS (exploit probability), CISA KEV (known
  exploited + ransomware), NVD (CVSS vector, CWE), OSV/GHSA (affected/fixed
  versions), and exploit presence (Exploit-DB, Metasploit, nuclei).
- **Decide** with a bundled CISA-style SSVC deployer tree — or bring your own
  with `--tree`.
- **Explain** every verdict with the full path that produced it; degraded
  inputs (a source down, or `--offline`) are visibly flagged, never hidden.
- **Output** a rich table, JSON, SARIF 2.1.0 (GitHub code scanning), or a
  stakeholder Markdown report — and gate CI with `--fail-on`.

## Install

```bash
pipx install vulnctl
vulnctl --version
```

Requires Python 3.11+ on Linux or macOS. No credentials are required; an NVD
API key (optional, for higher rate limits) is read from the
`VULNCTL_NVD_API_KEY` environment variable only.

## Quickstart (60 seconds)

**1. See a verdict and the decision path behind it.** This runs entirely from
bundled snapshots — no network, no API key:

```console
$ vulnctl enrich CVE-2021-44228 --offline --show-path
                                         vulnctl enrichment
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ CVE            ┃ Decision ┃ CVSS          ┃ EPSS           ┃ KEV              ┃ Exploits         ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ CVE-2021-44228 │ ACT      │ n/a (offline) │ 1.000 (p100.0) │ yes 2021-12-10   │ EDB·3 MSF·5      │
│                │          │               │                │ ransomware       │ nuclei·1         │
└────────────────┴──────────┴───────────────┴────────────────┴──────────────────┴──────────────────┘

CVE-2021-44228 → ACT  (tree cisa-deployer-v1)  [degraded: defaults applied]
  1. exploitation = active  [kev]
  2. exposure     = open  [context]
  3. automatable  = yes  [default]
  4. human_impact = high  [context]
```

The path is the point. This is `ACT` because CISA KEV lists it as actively
exploited (`exploitation = active`, from `kev`), it's treated as internet-exposed
(`exposure = open`, from the default org context), and mission impact is `high`.
`automatable` fell back to the tree **default** here because `--offline` has no
CVSS vector to derive it from — so the verdict is flagged *degraded*. Drop
`--offline` and the live CVSS vector resolves `automatable` from data
(`value_source = cvss`), clearing the flag.

**2. Feed it your context.** Exposure, mission impact, and overrides that no
intel source can know come from a small [`context.yaml`](examples/context.yaml):

```bash
vulnctl enrich CVE-2021-44228 --context examples/context.yaml --show-path
```

**3. Prioritize a whole SBOM or scanner report:**

```bash
# CycloneDX SBOM: components resolve to CVEs via OSV, then rank
vulnctl enrich --sbom app.cdx.json --context context.yaml

# Grype JSON straight off a scan (‘-’ reads stdin)
grype my-image:latest -o json | vulnctl enrich --grype - --context context.yaml
```

**4. Gate CI on risk, not raw CVSS.** Emit SARIF for code scanning, then fail
the build only when something crosses your threshold:

```bash
vulnctl enrich --sbom app.cdx.json --format sarif > vulnctl.sarif  # always written
vulnctl enrich --sbom app.cdx.json --fail-on act                   # exit 2 blocks the PR
```

A complete GitHub Actions gate lives in
[`examples/ci/vulnctl-gate.yml`](examples/ci/vulnctl-gate.yml).

## How it works

Four strictly-ordered layers, data flowing one way — **Ingest → Enrich →
Decide → Output**. Source adapters are isolated and fail *open* (a source
outage degrades one field, never the run); the SSVC engine is a pure,
deterministic tree-walker that records every node visit. Verdicts come from a
declarative SSVC tree (bundled: `cisa-deployer-v1`, the CERT/CC deployer model
with CISA's Track/Track\*/Attend/Act labels). See
[FRAMEWORK.md](FRAMEWORK.md) for the architecture.

## Documentation

| Doc | What's in it |
|---|---|
| [docs/context.md](docs/context.md) | Every `context.yaml` field, its values, and how each maps to an SSVC decision point |
| [docs/trees.md](docs/trees.md) | The YAML decision-tree format and how to author/validate a custom tree |
| [docs/schema.md](docs/schema.md) | The `--format json` output schema (machine-readable [`schema.json`](docs/schema.json)) |
| [docs/exit-codes.md](docs/exit-codes.md) | Exit codes and `--fail-on` semantics for CI gating |
| [docs/releasing.md](docs/releasing.md) | Cut-a-release runbook: build, sign, publish, verify |
| [SPEC.md](SPEC.md) · [FRAMEWORK.md](FRAMEWORK.md) · [CLAUDE.md](CLAUDE.md) | Product spec, architecture, and contributor conventions |

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
uv sync                       # install deps (incl. dev group)
uv run pytest                 # tests
uv run ruff check .           # lint
uv run ruff format --check .  # format check
uv run mypy src/              # type check
uv run vulnctl --help         # smoke-test the CLI
uv run pre-commit install     # wire the git hook
```

All four checks (pytest, ruff check, ruff format, mypy) must pass before any
commit. The SSVC engine holds a 100% branch-coverage gate in CI.

## Security posture

vulnctl is a security tool and holds itself to the bar it enforces: GitHub
Actions pinned by full commit SHA, least-privilege token scopes, a committed
lockfile, no `eval` and no `pickle` of untrusted data, and strict Pydantic
validation of every byte of external JSON before it becomes a model. Releases
are built with an SBOM (Syft), scanned (Grype, and dogfooded through vulnctl
itself), and signed with keyless [cosign](https://docs.sigstore.dev/) — see
[docs/releasing.md](docs/releasing.md).

## License

[Apache-2.0](LICENSE).
