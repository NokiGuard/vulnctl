# Organizational context (`context.yaml`)

Some SSVC decision points can't be answered by any intel feed — they depend on
*your* environment: how exposed the affected systems are, how much a compromise
would hurt, and cases where you know better than a derived signal. You supply
those with a context file:

```bash
vulnctl enrich CVE-2021-44228 --context context.yaml
```

Every field is optional. When `--context` is omitted, or a field is left out,
vulnctl uses conservative defaults (below). A starter file lives at
[`examples/context.yaml`](../examples/context.yaml).

## Fields at a glance

| Field | Values | Default | Feeds SSVC point | Read by `cisa-deployer-v1`? |
|---|---|---|---|---|
| `exposure` | `internet`, `internal`, `isolated` | `internet` | System Exposure | ✅ |
| `mission_impact` | `low`, `medium`, `high`, `very_high` | `high` | Human Impact | ✅ |
| `asset_tier` | `crown_jewel`, `important`, `standard` | `standard` | — (v0.2 groundwork) | ❌ |
| `overrides` | mapping of decision point → value | `{}` | any point, forced | ✅ |

Two other decision points in the bundled tree — `exploitation` and
`automatable` — are **derived from intelligence, not context**: KEV/exploit
feeds drive `exploitation`, and the CVSS vector drives `automatable`. You don't
set them here (though `overrides` can force them; see below).

## `exposure`

Network position of the estate these findings run on. Maps to the SSVC
**System Exposure** decision point, translating vulnctl's plain terms to SSVC's:

| `exposure` | SSVC System Exposure | Meaning |
|---|---|---|
| `internet` | `open` | Reachable from the public internet |
| `internal` | `controlled` | Reachable only behind access controls / VPN |
| `isolated` | `small` | Air-gapped or a highly restricted segment |

The default is `internet` (`open`) on purpose: assuming the worst network
position can only over-prioritize a finding, never hide one.

## `mission_impact`

Impact on your mission if a finding here is exploited. Maps directly to the
SSVC **Human Impact** decision point — these values *are* the tree vocabulary,
so no translation happens:

| `mission_impact` | Guidance |
|---|---|
| `low` | Degraded/nuisance; negligible mission effect |
| `medium` | Noticeable impairment of non-essential functions |
| `high` | Significant impairment of essential functions |
| `very_high` | Danger to life, or outright mission failure |

The default is `high`, not `very_high`: SSVC reserves `very_high` for effects
like danger to life. Defaulting there would push nearly every exploited CVE to
`Act` and destroy the ranking signal, so `high` is the highest *honest*
default.

## `asset_tier`

Criticality tier: `crown_jewel`, `important`, or `standard`. Validated on load
but **not read by the bundled v1 tree** — it's groundwork for the v0.2 per-asset
registry (FRAMEWORK.md §8), where the same finding can yield different verdicts
on different assets. Setting it today has no effect on the verdict.

## `overrides`

Force a decision point to a specific value when you know better than the
derived signal — e.g. your own testing proves exploitation, or you know
exploitation can't be automated in your environment:

```yaml
overrides:
  automatable: null       # null means "no override" (the entry is dropped)
  # exploitation: active  # force the exploitation point to `active`
```

Semantics — read these carefully:

- **Keys** are decision-point *names* from the active tree. For
  `cisa-deployer-v1` those are `exploitation`, `exposure`, `automatable`, and
  `human_impact`. An override for a name the tree never reads has **no effect**
  (it is silently ignored — the walker only consults overrides for points it
  actually visits).
- **Values** are the point's own declared values, in *tree* vocabulary — not
  the friendly `exposure` terms above. So to force System Exposure you write
  `exposure: open` (not `internet`); valid values per point:
  - `exploitation`: `none`, `poc`, `active`
  - `exposure`: `small`, `controlled`, `open`
  - `automatable`: `yes`, `no`
  - `human_impact`: `low`, `medium`, `high`, `very_high`
- A value **outside** the point's declared set is a hard error at evaluation
  time (a bad override must never silently mis-decide).
- Bare YAML booleans are normalized: `yes`/`no`/`true`/`false` become the
  `yes`/`no` strings the trees use (handy for `automatable`).
- A forced value appears in the decision path with `value_source = override`
  and **never** counts as a degraded input.

## Validation rules

- **Unknown keys are hard errors.** A typo like `expsoure:` fails loudly rather
  than silently reverting to a default and changing your verdicts.
- The file must be a YAML mapping and is capped at 64 KiB (context files are a
  few lines — anything larger is rejected before parsing).
- A missing file, unreadable file, or invalid YAML is an input error (exit 1)
  with an actionable message.

## Worked example

```yaml
# context.yaml — a public-facing service handling essential functions
exposure: internet        # SSVC System Exposure = open
mission_impact: high      # SSVC Human Impact = high
overrides:
  automatable: yes        # we've confirmed the exploit chain automates here
```

Running against a KEV-listed CVE, this yields `exploitation = active [kev]`,
`exposure = open [context]`, `automatable = yes [override]`,
`human_impact = high [context]` → **ACT**, with `automatable` shown as an
override (not degraded) in the path.

See [docs/trees.md](trees.md) for the decision-tree format these values feed.
