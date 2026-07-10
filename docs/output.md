# Reading vulnctl's output

Every format — table, JSON, SARIF, Markdown — renders the same ranked
results: one **decision** per finding, the **decision path** that produced
it, and the **enrichment** it was decided from. This doc explains each of
those, using the quickstart run as the example:

```console
$ vulnctl enrich CVE-2021-44228 --offline --show-path
│ CVE-2021-44228 │ ACT │ n/a (offline) │ 1.000 (p100.0) │ yes 2021-12-10 ransomware │ EDB·3 MSF·5 nuclei·1 │

CVE-2021-44228 → ACT  (tree cisa-deployer-v1)  [degraded: defaults applied]
  1. exploitation = active  [kev]
  2. exposure     = open  [context]
  3. automatable  = yes  [default]
  4. human_impact = high  [context]
```

## The four decisions

Each verdict is an action with a timeline, not a score. The labels are
CISA's names for the CERT/CC deployer model's outcomes (`defer` → Track,
`scheduled` → Track\*, `out-of-cycle` → Attend, `immediate` → Act):

| Decision | Meaning | Timeline |
|---|---|---|
| **Track** | No action needed now. Remediate within standard update cadence. | Routine |
| **Track\*** | Track, with an asterisk: characteristics (a PoC, high potential impact) warrant closer monitoring for changes. | Routine, monitored |
| **Attend** | Needs attention from supervisors: out-of-cycle remediation, possibly internal notifications. | Sooner than routine |
| **Act** | Needs attention from leadership: immediate remediation or mitigation. | Immediately |

The same CVE can be **Act** on an internet-facing service and **Track\***
on an isolated one — that is the point: the verdict reflects *your* risk
(via [`context.yaml`](context.md)), not a universal number.

For CI gating the decisions are ordered `track < track* < attend < act`;
`--fail-on attend` trips on Attend *or* Act. See
[exit-codes.md](exit-codes.md).

## The decision path (`--show-path`)

The path lists every tree node visited, in order: the decision point, the
value it took, and — in brackets — **where that value came from**. The
bracket vocabulary:

| `[source]` | The value came from… | Degrades the verdict? |
|---|---|---|
| `kev` | CISA KEV catalog membership | no |
| `exploits` | a public exploit artifact (Exploit-DB, Metasploit, nuclei) | no |
| `kev+exploits` | both sources answering "no exploitation signal" | no |
| `cvss` | the NVD CVSS v3 vector | no |
| `context` | your [`context.yaml`](context.md) (or its documented defaults) | no |
| `override` | a forced value in `context.yaml`'s `overrides` | no |
| `default` | the tree's declared fallback — the real input was unavailable | **yes** |

Any `[default]` step flags the whole verdict **degraded** — shown as
`[degraded: defaults applied]` in the table, `inputs_degraded: true` in
JSON, and a note in SARIF and Markdown. A degraded Act is still an Act;
the flag tells you one input was assumed rather than observed. In the
example above, `--offline` left no CVSS vector to derive `automatable`
from, so the tree default (`yes`) applied. Re-running online resolves it
from data (`[cvss]`) and clears the flag.

How each decision point in the bundled tree resolves:

| Point | Resolution |
|---|---|
| `exploitation` | KEV-listed → `active`. Else any public exploit artifact → `poc`. Else, if both KEV and the exploit index answered, `none`. Partial data never asserts `none` — the default applies instead. |
| `exposure` | Your context's `exposure`, translated to SSVC terms (`internet` → `open`, `internal` → `controlled`, `isolated` → `small`). |
| `automatable` | `yes` iff the CVSS v3 vector has `AV:N`, `AC:L`, `PR:N`, `UI:N` — network-reachable, low complexity, no privileges, no user interaction. A heuristic; force it via `overrides` if you know better. |
| `human_impact` | Your context's `mission_impact`, verbatim. |

Custom trees can wire these differently — see [trees.md](trees.md).

## The enrichment columns

The table (and the equivalent fields in every other format) shows what
each source said about the finding:

| Column | Reading it |
|---|---|
| **CVSS** | NVD base score and severity label, e.g. `10.0 CRITICAL`. Technical severity only — it feeds `automatable`, never the verdict directly. |
| **EPSS** | FIRST's estimated probability of exploitation in the next 30 days, with percentile: `1.000 (p100.0)` means "more likely to be exploited than 100% of scored CVEs". Informational ranking tie-breaker. |
| **KEV** | `yes <date-added>` when CISA has cataloged in-the-wild exploitation, plus `ransomware` when it's known ransomware-campaign use. `no` is a real answer, not missing data. |
| **Exploits** | Public exploit artifact counts from the bundled index: `EDB·3 MSF·5 nuclei·1` = 3 Exploit-DB entries, 5 Metasploit modules, 1 nuclei template. `none` is a real answer as of the index's snapshot date. |
| **Package** | The affected purl (SBOM/scanner runs only). |

### `n/a (reason)` cells

A source that could not answer degrades that field — never the run. The
reason states why:

| Reason | Meaning |
|---|---|
| `n/a (offline)` | `--offline` run, and the value was in neither the cache nor a bundled snapshot |
| `n/a (source down)` | the source errored or was unreachable |
| `n/a (not found)` | the source answered and has no record for this ID |
| `n/a (rate limited)` | the source refused the request (HTTP 403/429); re-run later or set the API-key env var |

## Run metadata

The table caption (the `run` object in JSON, `properties` in SARIF)
summarizes the run itself: which sources were consulted, per-source cache
hit rates, how many fields degraded, and whether the run was offline. Use
it to judge how fresh and complete the evidence behind the verdicts is.

## Format-specific notes

- **JSON** (`--format json`) carries everything above machine-readably,
  under a pinned `schema_version` — see [schema.md](schema.md).
- **SARIF** (`--format sarif`) maps decisions to levels for code-scanning
  UIs: Act → `error`, Attend → `warning`, Track\* → `note`, Track →
  `none`; the full decision path rides in each result's Markdown message.
- **Markdown** (`--format md`) is the stakeholder report: summary,
  highlights (Act or KEV-listed findings), top-10 table, and a
  per-finding appendix with every decision path.
