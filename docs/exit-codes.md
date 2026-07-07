# vulnctl exit codes

`vulnctl enrich` uses exit codes so it can gate CI without parsing output.

| Code | Meaning | When |
|------|---------|------|
| `0`  | Success | The run completed. No `--fail-on` threshold was set, or no finding met it. |
| `1`  | Input / config error | Malformed CVE ID, no or multiple input modes, unreadable/invalid SBOM or Grype file, invalid `--context` or `--tree`, or a tree evaluation error. Nothing was gated — the run could not produce verdicts. |
| `2`  | Gate threshold met | `--fail-on <decision>` was set and at least one finding's decision met or exceeded it. Output (table/JSON/SARIF/Markdown) is still emitted before exiting. |

Codes `1` and `2` are kept distinct on purpose: a `2` always means "the tool ran
and found something at or above your threshold," never "you invoked it wrong."

## `--fail-on`

`--fail-on <decision>` fails the run when any finding's decision is at least as
severe as `<decision>`, using the SSVC severity order
`track < track* < attend < act`:

| `--fail-on` | Exits 2 on a finding decided… |
|-------------|-------------------------------|
| `act`       | `act` |
| `attend`    | `attend` or `act` |
| `track*`    | `track*`, `attend`, or `act` |
| `track`     | any finding (i.e. any result at all) |

The gate is evaluated **after** output is written, so a CI job can upload the
SARIF report and still fail the build:

```bash
vulnctl enrich --sbom app.cdx.json --format sarif > vulnctl.sarif   # always written
vulnctl enrich --sbom app.cdx.json --fail-on act                    # exit 2 blocks the PR
```
