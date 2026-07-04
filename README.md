# vulnctl

*Not another score. A defensible decision.*

`vulnctl` is a CLI-first vulnerability prioritization engine that turns raw findings into **auditable remediation decisions**. Input a CVE list, SBOM, or scanner report; output a ranked set of Track / Track\* / Attend / Act verdicts, each with the complete decision path and the intelligence that drove it. Designed for vulnerability management practitioners who must defend prioritization decisions to engineering and leadership.

> **Status:** pre-alpha (M2 enrich core). EPSS, CISA KEV, and NVD enrichment with a rich-table view; the SSVC decision engine arrives in M3 — see [ROADMAP.md](ROADMAP.md).

## Usage

```bash
vulnctl enrich CVE-2021-44228 CVE-2023-4863   # fused intel table (EPSS, KEV, CVSS)
vulnctl enrich --offline CVE-2021-44228       # cached data + bundled snapshots only
vulnctl cache stats                            # cache location and entry counts
vulnctl cache purge --source epss              # drop one source's cached entries
```

An NVD API key (optional, higher rate limits) is read from the `VULNCTL_NVD_API_KEY` environment variable only.

## Install

Releases are published to TestPyPI during pre-alpha:

```bash
pipx install --index-url https://test.pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple/" vulnctl
vulnctl --version
```

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

All four checks (pytest, ruff check, ruff format, mypy) must pass before any commit. See [CLAUDE.md](CLAUDE.md) for conventions, [SPEC.md](SPEC.md) for the product spec, and [FRAMEWORK.md](FRAMEWORK.md) for architecture.

## Releasing to TestPyPI

The `Publish to TestPyPI` workflow (`.github/workflows/publish-testpypi.yml`) is triggered manually from the Actions tab (`workflow_dispatch`). It builds the sdist/wheel with `uv build` and publishes via [trusted publishing](https://docs.pypi.org/trusted-publishers/) (OIDC) — no stored API token. The TestPyPI project must have this repo configured as a trusted publisher.

## License

Apache-2.0
