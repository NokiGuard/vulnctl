# vulnctl CLI reference

Every command, argument, and option. `vulnctl --help` prints the same thing
from the installed version — an **Options by command** panel covering every
command's flags, plus worked **Examples** — and `--help` on a subcommand
prints that one command in full, including defaults and value ranges. The
root summary is generated from the registered parameters, so it cannot drift
from the real signatures.

```
vulnctl [OPTIONS] COMMAND [ARGS]...
```

## Global options

| Option | What it does |
|---|---|
| `--version` | Show the version and exit. |
| `--install-completion` | Install shell completion for the current shell. |
| `--show-completion` | Print the completion script to copy or customize. |
| `--help` | Show help and exit. |

## `vulnctl enrich`

Enrich CVE/GHSA IDs, an SBOM, or a Grype scan with intel and rank with SSVC
verdicts. Exactly one input mode per run: positional IDs, `--sbom`, or
`--grype`.

```
vulnctl enrich [OPTIONS] [VULN_ID...]
```

| Argument | What it does |
|---|---|
| `VULN_ID...` | One or more CVE or GHSA IDs, e.g. `CVE-2021-44228` or `GHSA-35jh-r3h4-6jhm`. GHSA IDs alias-resolve to their CVE via OSV where one exists; without a CVE alias the finding enriches under the GHSA ID and CVE-only sources show `n/a (not found)`. Omit when using `--sbom` or `--grype`. |

| Option | Value | What it does |
|---|---|---|
| `--sbom` | `PATH` | CycloneDX 1.4–1.6 JSON SBOM; components resolve to CVEs via OSV. |
| `--grype` | `TEXT` | Grype JSON output file, or `-` to read stdin. |
| `--offline` | flag | Use only cached data and bundled snapshots; never touch the network. |
| `--context` | `PATH` | Org context YAML (default: conservative defaults). See [context.md](context.md). |
| `--tree` | `PATH` | Decision-tree YAML (default: bundled `cisa-deployer-v1`). See [trees.md](trees.md). |
| `--format`, `-f` | `table\|json\|sarif\|md` | Output format (default: `table`). See [output.md](output.md) and [schema.md](schema.md). |
| `--fail-on` | `track\|track*\|attend\|act` | Exit 2 if any finding's decision meets/exceeds this. See [exit-codes.md](exit-codes.md). |
| `--show-path` | flag | Print each finding's decision path (table format). |
| `--min-decision` | `track\|track*\|attend\|act` | Show only findings at or above this decision. Display filter only — the summary line still counts every finding and `--fail-on` still evaluates all of them. |
| `--only-kev` | flag | Show only KEV-listed findings (display filter). |
| `--limit` | `N` | Show at most N findings, highest priority first (display filter). |

During online runs a live progress display (one bar per intel source, plus
an ID-resolution bar when GHSA IDs need resolving) renders on **stderr**, so
piped stdout — `-f json | jq` — stays byte-clean. It appears only when
stderr is a real terminal, clears itself when the run completes, and is
skipped entirely for `--offline` runs (they finish instantly).

Exit codes: `0` success, `1` input/config error, `2` `--fail-on` threshold
met — full semantics in [exit-codes.md](exit-codes.md).

### Examples

```bash
# One CVE, fully offline, with the decision path
vulnctl enrich CVE-2021-44228 --offline --show-path

# An SBOM with your org context, as JSON
vulnctl enrich --sbom app.cdx.json --context context.yaml --format json

# Grype scan from stdin, gate CI on Attend or worse
grype my-image:latest -o json | vulnctl enrich --grype - --fail-on attend
```

## `vulnctl explain`

```
vulnctl explain [OPTIONS] VULN_ID
```

One finding in depth: every source's answer with provenance (fetched-at,
cache hit), the full affected/fixed version lists, CWEs, exploit artifact
identifiers, the complete decision path, and — the part the table cannot
show — *what would change the verdict*: every single-input change that lands
on a different decision.

Takes one CVE or GHSA ID; GHSA IDs alias-resolve exactly as in `enrich`.
Supports `--offline`, `--context`, and `--tree` with the same semantics as
`enrich`. Exit codes: `0` success, `1` input/config error — there is no
`--fail-on` gate, since `explain` is for reading rather than CI.

```bash
vulnctl explain CVE-2021-44228 --offline
vulnctl explain GHSA-35jh-r3h4-6jhm --context context.yaml
```

## `vulnctl cache`

Inspect and manage the local response cache (SQLite at
`~/.cache/vulnctl/cache.db`, per-source TTLs).

```
vulnctl cache COMMAND [ARGS]...
```

| Command | What it does |
|---|---|
| `cache stats` | Show cache location, size, and entry counts per source. |
| `cache purge` | Delete all cached entries, or one source's with `--source <name>` (e.g. `--source epss`). |

## Shell completion

Typer ships tab completion for commands, flags, and enum values
(`--format <TAB>` offers `table json sarif md`; `--fail-on <TAB>` offers the
four decisions). Enable it once for your shell:

```bash
vulnctl --install-completion        # zsh: appends to ~/.zshrc — restart the shell after
vulnctl --show-completion           # print the script instead, to inspect or place manually
```

Two things to know:

- Completion re-invokes the `vulnctl` binary on every TAB, so it works only
  for installed entry points on `PATH` (`pipx install` / `uv tool install`),
  not for `uv run vulnctl`.
- In zsh, always quote the starred decision when typing it yourself:
  `--fail-on 'track*'`. Unquoted, zsh treats the `*` as a glob and aborts
  with "no matches found" before vulnctl even runs. (Accepting the tab
  completion inserts it correctly escaped as `track\*`.)
