# Decision-tree format

vulnctl's verdicts come from a declarative SSVC decision tree in YAML. The
bundled default is [`cisa-deployer-v1`](../src/vulnctl/ssvc/trees/cisa-deployer-v1.yaml)
(the CERT/CC deployer model relabeled to CISA's Track/Track\*/Attend/Act). You
can supply your own with `--tree`:

```bash
vulnctl enrich CVE-2021-44228 --tree my-tree.yaml --context context.yaml
```

The engine that walks the tree is a pure, deterministic function — no I/O, same
inputs always produce the same verdict — and it records every node it visits
into the decision path. A broken tree is a **hard error at load**, never a
silent mis-decision.

## Document shape

A tree has four top-level keys (`defaults` is optional but required in practice
whenever any point is `derived`):

```yaml
id: my-tree-v1              # non-empty string; pinned into every verdict as tree_id
decision_points:           # declare each point once: where its value comes from
  exploitation:
    from: derived           # value computed from the Enrichment by a resolver
    rule: exploitation      # resolver name (a typed function, not a DSL)
    values: [none, poc, active]
  exposure:
    from: context           # value supplied by the OrgContext (context.yaml)
    key: exposure
    values: [small, controlled, open]
tree:                      # nested {point: {value: subtree-or-decision}}
  exploitation:
    none: track
    poc:
      exposure:
        small: track
        controlled: track*
        open: attend
    active:
      exposure:
        small: track*
        controlled: attend
        open: act
defaults:                  # value used when a derived input is Unavailable
  exploitation: none
```

That document above is a complete, valid tree (it's the test fixture
`toy-v1`). The four decision outcomes are `track`, `track*`, `attend`, `act`.

## `decision_points`

Each entry declares one point:

- **`from`** — `derived` or `context`.
  - `derived`: requires **`rule`** (a resolver name) and **no** `key`.
  - `context`: requires **`key`** (a context key) and **no** `rule`.
- **`values`** — the point's allowed values, at least two, all distinct. These
  are the only branch labels the tree may use for this point.

### Resolvers (`from: derived`)

Derived points read the fused `Enrichment` through a named resolver. Two ship
today; the value's origin is recorded as its `value_source` in the path:

| `rule` | Produces | Logic |
|---|---|---|
| `exploitation` | `active` / `poc` / `none` | KEV-listed → `active` (source `kev`); any public exploit artifact (EDB/Metasploit/nuclei) → `poc` (source `exploits`); both sources answered and negative → `none` (source `kev+exploits`); otherwise unresolved → tree default |
| `automatable` | `yes` / `no` | A CVSS v3.x vector with `AV:N/AC:L/PR:N/UI:N` → `yes` (source `cvss`); any other v3.x vector → `no`; CVSS v2 or no CVSS → unresolved → tree default |

When a resolver can't answer (its inputs are `Unavailable` — e.g. `--offline`
with no CVSS to derive `automatable`), the tree's **default** for that point is
used, the step is marked `value_source = default`, and the verdict is flagged
`inputs_degraded: true`.

### Context points (`from: context`)

Context points read a key from `context.yaml`. The bundled tree uses two:
`exposure` (key `exposure`) and `human_impact` (key `mission_impact`). See
[docs/context.md](context.md) for the keys and how their values map into tree
vocabulary. A `context` value outside the point's declared `values` is a hard
error.

## `tree`

A nested mapping. Each internal node is a single-key mapping `{point:
{value: …}}`; each leaf is a decision string. Rules:

- The **root must be a node**, not a bare decision.
- A node references **exactly one** declared decision point.
- Its branches must cover the point's declared `values` **exactly** — every
  value needs a branch, and no branch may use an undeclared value.
- A point may **not repeat along a single path** (its value is already fixed
  upstream, so the branches would be unreachable).
- Every declared point must be **used somewhere** in the tree.
- Leaves must be one of `track`, `track*`, `attend`, `act`.

## `defaults`

A mapping of decision point → fallback value, used when a *derived* input is
`Unavailable`. Requirements:

- Every point named must exist, and each value must be one of that point's
  declared `values`.
- **Every `derived` point must have a default** — so a degraded enrichment
  falls back audibly (flagged in the path) instead of crashing mid-run.
- Context points don't need defaults (a missing context value is a hard error,
  not a degradation).

## YAML gotcha: `none` / `yes` / `no`

YAML 1.1 tooling sometimes emits bare `none` as null and `yes`/`no` as booleans.
vulnctl normalizes these back to the strings the trees use, so
`exploitation: none` and `automatable: yes` behave identically whether quoted or
not. Quoting (`"none"`) is still the safest habit.

## Validating a custom tree

There's no separate lint subcommand yet (that's on the v0.2 roadmap). To
validate a tree, load it on any run — validation happens at load, before any
network, so an offline run against a throwaway CVE is enough:

```bash
vulnctl enrich CVE-0000-0000 --offline --tree my-tree.yaml
```

If the tree is malformed, vulnctl prints a specific `error:` message pointing at
the exact defect (unknown key, missing branch, undeclared value, a derived
point with no default, an unknown resolver, …) and exits `1`. If it loads, the
run proceeds and your tree is good. Files are capped at 1 MiB.

See [docs/context.md](context.md) for the org-context inputs and
[docs/schema.md](schema.md) for how a verdict and its path are serialized.
