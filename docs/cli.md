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

## Commands

| Command | What it does |
|---|---|
| [`enrich`](#vulnctl-enrich) | Enrich CVE/GHSA IDs, an SBOM, or a Grype scan and rank the findings with SSVC verdicts. |
| [`explain`](#vulnctl-explain) | One finding in depth: every source's answer, the decision path, and what would change the verdict. |
| [`auth nvd`](#vulnctl-auth) | Save or replace your NVD API key in the OS keychain (verified first). |
| [`auth status`](#vulnctl-auth) | Show which NVD key vulnctl will use and where it comes from (masked). |
| [`auth remove nvd`](#vulnctl-auth) | Delete the saved NVD key from the keychain. |
| [`cache stats`](#vulnctl-cache) | Show cache location, size, and entries per source. |
| [`cache purge`](#vulnctl-cache) | Delete cached entries, all or one source's. |

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

Online runs read the NVD API key from `VULNCTL_NVD_API_KEY` or the OS
keychain; with neither, the first interactive run offers to save one — see
[`vulnctl auth`](#vulnctl-auth).

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

# Bundled sample SBOMs of old, vulnerable packages (npm, PyPI, Maven, Go)
vulnctl enrich --sbom examples/medium-app.cdx.json --limit 25   # ~230 CVEs
vulnctl enrich --sbom examples/large-app.cdx.json -f json > large.json  # ~1,700 CVEs
```

The two sample SBOMs in `examples/` are sized for trying vulnctl on realistic
volume and for timing runs: with an NVD key, NVD lookups for the medium file
take about 3 minutes cold and the large one about 22 (roughly 10x longer
without a key). Repeat runs answer from the cache in seconds. CVE counts drift
as new advisories are published against these old versions.

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

## `vulnctl auth`

Manage the optional NVD API key. No credentials are ever required, but
without a key NVD allows about 7 lookups a minute — on a large SBOM that is
most of the run. A free key ([request one here](https://nvd.nist.gov/developers/request-an-api-key))
makes NVD lookups roughly 10x faster.

```
vulnctl auth COMMAND [ARGS]...
```

| Command | What it does |
|---|---|
| `auth nvd` | Prompt for your key (hidden input), verify it with one NVD request, and save it to your OS keychain. Re-run to replace it. |
| `auth status` | Show whether a key is configured and where it comes from; the key itself is masked to its last four characters. |
| `auth remove nvd` | Delete the saved key from the keychain. |

**Where the key lives.** In the OS keychain only — macOS Keychain, Linux
Secret Service (GNOME Keyring / KWallet), or Windows Credential Locker — never
a config file, the cache, or a command-line flag. The
`VULNCTL_NVD_API_KEY` environment variable, when set, takes precedence over
the saved key; use it in CI and anywhere without a keychain.

**First-run prompt.** The first time `enrich` or `explain` runs online with no
key configured, vulnctl offers to save one:

```
No NVD API key found. Without one NVD allows about 7 lookups a minute;
a free key makes enrichment ~10x faster: https://nvd.nist.gov/developers/request-an-api-key
NVD API key (input hidden; Enter to skip):
```

A key NVD rejects is asked for again (up to three tries); a key that can't be
verified because NVD is unreachable is saved anyway with a warning. Pressing
Enter skips, and vulnctl remembers that and never asks again
(`vulnctl auth nvd` still works any time). The marker is
`~/.config/vulnctl/nvd-key-prompt-dismissed` — delete it to see the prompt
again.

The prompt never appears where it could get in the way: when stdin or stderr
isn't a terminal (scripts, pipes, CI — or when `CI` is set), with `--offline`,
or with `--grype -` (stdin is the scan). It writes to stderr and reads from
the terminal, so `-f json > out.json` stays clean.

### Examples

```bash
vulnctl auth nvd              # paste your key (hidden); verified, then saved
vulnctl auth status           # NVD API key: …a1b2 from macOS Keyring
vulnctl auth remove nvd       # forget the saved key
```

## Environment variables

| Variable | What it does |
|---|---|
| `VULNCTL_NVD_API_KEY` | NVD API key; takes precedence over a key saved with `vulnctl auth nvd`. Use in CI. |
| `VULNCTL_GITHUB_TOKEN` | Optional GitHub token for advisory lookups (5,000 req/h instead of 60). |
| `XDG_CACHE_HOME` | Cache location: `$XDG_CACHE_HOME/vulnctl/cache.db` (default `~/.cache`). |
| `XDG_CONFIG_HOME` | Config location for the prompt-dismissed marker (default `~/.config`). |
| `CI` | When set, vulnctl never prompts. |

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
