# M1 Kickoff Prompt for Claude Code

Copy everything below the line into Claude Code from the repo root (with CLAUDE.md, SPEC.md, FRAMEWORK.md, ROADMAP.md already committed).

---

Read CLAUDE.md, SPEC.md, FRAMEWORK.md, and ROADMAP.md in full before writing any code.

We are implementing **Milestone M1 (Skeleton)** — ROADMAP.md Week 1, issues #1–#4 — and nothing beyond it. Do not implement any source adapters, the SSVC engine, or output formats other than the CLI stubs described below.

## Scope for this session

1. **Project bootstrap**
   - `pyproject.toml` using hatchling, package `vulnctl` under `src/` layout, Python `>=3.11`, console script `vulnctl = vulnctl.cli:app`
   - Dependencies: typer, pydantic (v2), httpx, rich, ruamel.yaml. Dev deps: pytest, pytest-asyncio, ruff, mypy, pre-commit
   - Configure ruff (lint + format, line length 100) and mypy strict on `src/` in pyproject
   - `.pre-commit-config.yaml` running ruff check, ruff format, mypy, pytest
   - `.gitignore` for Python/uv; Apache-2.0 LICENSE; minimal README stub (one paragraph from SPEC §2, install/dev instructions)

2. **Core models — `src/vulnctl/models.py`** (follow FRAMEWORK.md §2 exactly)
   - `Finding`, `PackageRef`, `IngestSource` enum
   - `Unavailable` with `reason: UnavailableReason` enum (`source_down | offline | not_found | rate_limited`) and optional detail string
   - Per-source data models: `EpssData`, `KevData`, `CvssData`, `VersionData`, `ExploitData`, `SourceMeta`
   - `Enrichment` composing the above, each field `X | Unavailable`, plus `provenance: dict[str, SourceMeta]`
   - `Decision` enum (`TRACK, TRACK_STAR, ATTEND, ACT`), `DecisionPathStep` (node, value, value_source), `DecisionPath`, `Verdict`
   - All models: Pydantic v2, strict mode, frozen where sensible. Round-trip (model → JSON → model) tests for every model.

3. **Cache — `src/vulnctl/cache.py`** (FRAMEWORK.md §4)
   - SQLite, WAL mode, schema `(source TEXT, key TEXT, fetched_at TEXT, payload TEXT, PRIMARY KEY(source, key))`
   - Default path `~/.cache/vulnctl/cache.db`, honoring `XDG_CACHE_HOME`; path injectable for tests
   - API: `get(source, key, ttl) -> str | None` (TTL enforced at read), `set(source, key, payload)`, `purge(source: str | None)`, `stats() -> CacheStats`
   - Tests use `tmp_path` exclusively — never touch the real cache directory

4. **CLI scaffold — `src/vulnctl/cli.py`** (keep under 150 lines, no business logic)
   - Typer app: `--version`; `enrich` command accepting CVE IDs (validate `CVE-\d{4}-\d{4,}` format, then print a "not yet implemented" notice via rich — no adapter work); `cache stats` and `cache purge` subcommands wired to cache.py
   - A smoke test invoking the CLI via Typer's test runner

5. **CI — `.github/workflows/ci.yml`**
   - Triggers: push to main, PRs. Jobs: ruff check, ruff format --check, mypy, pytest — using uv
   - All actions pinned by full commit SHA; top-level `permissions: contents: read`
   - Separate `publish-testpypi.yml` on `workflow_dispatch`: build with uv, publish to TestPyPI via PyPA's publish action with OIDC trusted publishing (no stored token), also SHA-pinned

## Working agreement for this session

- Work in this order: bootstrap → models → cache → CLI → CI. After each of the five parts, stop, run `uv run pytest && uv run ruff check . && uv run ruff format --check . && uv run mypy src/`, show me the results, and give a one-paragraph summary of decisions made before continuing.
- If anything in the specs is ambiguous, ask before implementing — do not invent requirements.
- Do not add dependencies beyond those listed without asking.
- Follow every rule in CLAUDE.md, especially the architecture rules and security posture sections.
- Definition of done for M1 (from ROADMAP.md): CI green on all four checks, `vulnctl --version` works after `uv run`, cache subcommands functional, TestPyPI workflow present and documented in README.

Start with part 1 (bootstrap) now.
