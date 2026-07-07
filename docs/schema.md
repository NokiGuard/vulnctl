# vulnctl JSON output schema

`vulnctl enrich --format json` emits one JSON document. This page is the human
reference; the machine-readable JSON Schema is [`schema.json`](./schema.json),
generated from the Pydantic models (`JsonReport.model_json_schema()`) so it can
never drift from the code — a test fails if `schema.json` is stale.

## Versioning

The top-level `schema_version` is currently `"1"`. It changes only on a
breaking change to the shape below; additive, backward-compatible fields do
not bump it. Pin to the major version and tolerate unknown keys.

## Top level

```jsonc
{
  "schema_version": "1",
  "run":     { /* RunMetadata: sources, offline, cache_hit_rate, degradations */ },
  "results": [ /* one RankedResult per finding, most urgent first */ ]
}
```

Results are ordered by decision severity (ACT → ATTEND → TRACK\* → TRACK), then
EPSS, then CVSS — the same order as the table and other formats.

## `results[i]`

Each result is a `RankedResult`: `finding` + `enrichment` + `verdict`.

- **`finding`** — the normalized unit of work: `cve_id` (canonical ID: a CVE
  where one exists, else the native OSV/GHSA ID), `source`
  (`cli`|`cyclonedx`|`grype`), optional `package` (purl + version),
  `aliases`, `scanner_severity` (Grype's label, informational), `locations`.
- **`enrichment`** — fused intel. Each source-backed field
  (`epss`, `kev`, `cvss`, `versions`, `advisory`, `exploits`) is **either** its
  data object **or** an `Unavailable` marker; `cwes` is a list; `provenance`
  maps each source name to `{source, fetched_at, cache_hit}`.
- **`verdict`** — `decision` (`track`|`track*`|`attend`|`act`), `path` (the
  ordered decision steps, each `{node, value, value_source}`), `tree_id`, and
  `inputs_degraded` (true if any input fell back to a tree default).

## Telling data apart from `Unavailable`

An enrichment field is unavailable when — and only when — the object carries a
`reason` key (one of `source_down`, `offline`, `not_found`, `rate_limited`,
plus an optional `detail`). No data model has a `reason` field, so:

```python
value = result["enrichment"]["cvss"]
unavailable = "reason" in value          # reliable discriminator
```

A degraded verdict is visible two ways: `inputs_degraded: true` on the verdict,
and a `value_source` of `"default"` on the affected decision-path step.

## Example (abridged, offline run)

```jsonc
{
  "schema_version": "1",
  "run": { "sources": ["epss","exploits","ghsa","kev","nvd","osv"], "offline": true, "...": "..." },
  "results": [{
    "finding": { "cve_id": "CVE-2021-44228", "source": "cli", "package": null },
    "enrichment": {
      "kev":  { "listed": true, "date_added": "2021-12-10", "ransomware": true },
      "cvss": { "reason": "offline", "detail": "NVD has no bundled snapshot; cache miss" },
      "exploits": { "edb_ids": ["..."], "msf_modules": ["..."], "nuclei_templates": ["..."] }
    },
    "verdict": {
      "decision": "act",
      "path": [{ "node": "exploitation", "value": "active", "value_source": "kev" }, "..."],
      "tree_id": "cisa-deployer-v1",
      "inputs_degraded": true
    }
  }]
}
```
