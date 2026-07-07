# Case study: CVSS-only vs vulnctl on one real Grype report

> **Draft skeleton.** Replace every `{{PLACEHOLDER}}` and each `<!-- paste … -->`
> block with numbers produced by [`scripts/case_study_stats.py`](../scripts/case_study_stats.py)
> (see [Reproduce](#reproduce)). The tables are generated; you only write the prose.

## The setup

- **Target:** `{{image-or-repo}}`, scanned with Grype `{{grype-version}}` on
  `{{date}}` — `{{N}}` findings.
- **Two ways to prioritize the same report:**
  - **CVSS-only** — the common "remediate every Critical and High now" policy,
    using Grype's own severity labels.
  - **vulnctl** — `vulnctl enrich --grype … --context …` → an SSVC
    Act / Attend / Track\* / Track verdict per finding, each with a decision path.
- **Org context used:** exposure `{{internet}}`, mission impact `{{high}}`
  (`context.yaml`). Different context would give different verdicts — that's the
  point of risk-based prioritization.

## Headline: a smaller, better-aimed queue

<!-- paste: the "Queue size by policy" table from case_study_stats.py -->

Under a CVSS "Critical + High = fix now" policy, `{{cvss_now}}` findings land in
the urgent queue. vulnctl flags `{{act}}` for immediate action — a
**`{{reduction}}%` smaller queue** — without dropping the genuinely dangerous
ones (see the escalations below). The team works fewer items, and the *right*
fewer items.

## Where the two disagree

<!-- paste: the "CVSS severity vs vulnctl decision" cross-tab -->

Every off-diagonal cell is a disagreement between raw severity and a
risk-based decision. Two directions matter, and both show up here.

### A "Critical" you can actually schedule

> **`{{CVE-XXXX-YYYY}}` — CVSS `{{9.8 Critical}}` → vulnctl `{{TRACK*}}`.**
> Not KEV-listed, EPSS `{{0.00X}}`, no public exploit, exposure `{{controlled}}`.
> Decision path: `exploitation={{none}} → … → {{track*}}`.
>
> It's a real vulnerability, but nothing indicates it's being exploited and it
> isn't cheaply automatable in this environment — so it's tracked, not a
> fire drill. That's a defensible reason to *not* page someone tonight.

### A "Medium" that jumps to the front

> **`{{CVE-XXXX-YYYY}}` — CVSS `{{5.9 Medium}}` → vulnctl `ACT`.**
> KEV-listed (actively exploited), EPSS `{{0.9X}}`. Decision path:
> `exploitation=active [kev] → exposure=open [context] → … → act`.
>
> CVSS calls it medium; CISA's Known Exploited catalog and EPSS say attackers
> are using it right now. A severity-only queue buries this under the criticals.

<!-- optional third example: a High -> Track or Low -> Attend, if the report has one -->

Pull both examples straight from the script's *"de-prioritizes"* and
*"escalates"* lists — they already include the CVE, EPSS/KEV flags, and the
decision path.

## Why this holds up in a room

Every verdict carries its decision path: the exact inputs (KEV membership,
EPSS-driven exploitation, CVSS-derived automatability, and your exposure /
mission context) and which source supplied each one. When an engineer asks "why
is this Critical only *Track*?" or leadership asks "why is a *medium* our top
priority?", the answer is one line of evidence, not a hunch.

## Reproduce

```bash
# 1. Scan (or reuse an existing Grype report)
grype {{target}} -o json > report.json

# 2. vulnctl verdicts as JSON
vulnctl enrich --grype report.json --context context.yaml --format json > verdicts.json

# 3. Generate the tables + divergence lists in this doc
python scripts/case_study_stats.py verdicts.json

# 4. (Appendix) the human-readable report with every decision path
vulnctl enrich --grype report.json --context context.yaml --format md > report.md
```

## Method notes

- The **CVSS baseline is Grype's severity labels** (`scanner_severity`) — what a
  Grype-only team actually triages on — falling back to NVD's CVSS severity when
  Grype omits one.
- **vulnctl decisions** use the bundled `cisa-deployer-v1` tree and the org
  context above.
- Any **degraded inputs** (a source down, or an offline run) are flagged in the
  decision path and in run metadata — note them here rather than hiding them, so
  the comparison stays honest.
