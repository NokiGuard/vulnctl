# CLAUDE.md — vulnctl

## What this project is

`vulnctl` is a Python CLI that ingests CVE identifiers, SBOMs (CycloneDX/SPDX), or scanner output (Grype/Trivy JSON), enriches each finding from multiple threat-intelligence sources (EPSS, CISA KEV, NVD, OSV, GHSA, exploit-presence feeds), evaluates it against a declarative SSVC decision tree with user-supplied organizational context, and emits a prioritized, **auditable** ranking. The differentiator is that every verdict ships with its full decision path — not just a score.

Read `SPEC.md` for the product spec and `FRAMEWORK.md` for architecture before making structural changes.

## Tech stack & conventions

- **Python 3.11+**, packaged with `pyproject.toml` (hatchling or setuptools), managed with `uv`
- **CLI:** Typer. Entry point: `vulnctl` console script
- **HTTP:** `httpx` with async batching for source adapters; respect per-source rate limits
- **Models:** Pydantic v2 for ALL data structures crossing module boundaries. No bare dicts across interfaces.
- **Cache:** SQLite via `sqlite3` stdlib (no ORM), single file at `~/.cache/vulnctl/cache.db`, per-source TTLs
- **Terminal output:** `rich` tables
- **Config/trees:** YAML via `ruamel.yaml` (round-trip safe, preserves comments in user files)
- **Tests:** pytest + pytest-asyncio; adapters tested against recorded fixtures (JSON files in `tests/fixtures/`), never live APIs in CI
- **Lint/format:** ruff (lint + format), mypy --strict on `src/`
- **Line length 100. Google-style docstrings.**

## Commands

```bash
uv sync                       # install deps
uv run pytest                 # run tests
uv run pytest -k adapter      # adapter tests only
uv run ruff check --fix .     # lint
uv run ruff format .          # format
uv run mypy src/              # type check
uv run vulnctl --help         # smoke-test the CLI
```

All four (pytest, ruff check, ruff format, mypy) must pass before any commit.

## Repository layout

```
src/vulnctl/
├── cli.py               # Typer app; thin — no business logic here
├── models.py            # Pydantic: Finding, Enrichment, Verdict, DecisionPath
├── ingest/              # cve_list.py, cyclonedx.py, spdx.py, grype.py, trivy.py
├── adapters/            # one module per intel source; all implement SourceAdapter ABC
│   ├── base.py          # SourceAdapter ABC + registry
│   ├── epss.py, kev.py, nvd.py, osv.py, ghsa.py, exploits.py
├── cache.py             # SQLite cache: get/set with TTL, per-source namespacing
├── ssvc/                # engine.py (tree walker), trees/ (bundled YAML trees)
├── context.py           # org context loading + validation (context.yaml)
├── output/              # table.py, json_out.py, sarif.py, markdown.py
└── __init__.py
tests/
├── fixtures/            # recorded API responses, sample SBOMs, scanner JSON
└── ...mirrors src layout
```

## Architecture rules (do not violate without discussion)

1. **Adapters are isolated.** An adapter may import from `base.py`, `cache.py`, and `models.py` only. Adapters never import each other or the SSVC engine.
2. **The SSVC engine is pure.** `ssvc/engine.py` takes `(Enrichment, OrgContext, tree)` and returns a `Verdict` with a `DecisionPath`. No I/O, no network, no cache access. Fully deterministic and unit-testable.
3. **Fail open on enrichment, fail loud on input.** A source being down degrades the enrichment (mark the field `unavailable`, note it in the decision path) — it never crashes a run. Malformed SBOMs/scanner files are hard errors with actionable messages.
4. **Every verdict is explainable.** `DecisionPath` records each tree node visited, the input value used, and which source supplied it. If you add a scoring signal, you must thread it through `DecisionPath`.
5. **Offline mode is first-class.** `--offline` must work using only cached/bundled data (EPSS CSV snapshot, KEV JSON snapshot). Adapters declare whether they support offline.
6. **No secrets in code or fixtures.** NVD API key comes from `VULNCTL_NVD_API_KEY` env var only. Scrub any recorded fixtures of keys before committing.

## Security posture (this is a security tool — hold the bar)

- Pin all GitHub Actions by full SHA
- Dependabot/renovate on; lockfile committed
- No `eval`, no `pickle` for untrusted data, no shelling out to parse files
- Validate and bound all external JSON before model construction (Pydantic strict mode)
- SARIF output must validate against the 2.1.0 schema (test enforces this)

## Style notes for Claude Code

- Prefer small PRs/commits scoped to one adapter or one output format
- When adding a source adapter: implement ABC → add fixtures → add tests → register in `base.py` registry → update `SPEC.md` source table
- Never mock `httpx` inline in tests; use the fixture-loading helper in `tests/conftest.py`
- Update `FRAMEWORK.md` diagrams when module boundaries change
- Keep `cli.py` under ~150 lines; push logic down into modules
