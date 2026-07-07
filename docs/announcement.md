<!-- Announcement draft (~350 words). Fill {{...}} from the case study before posting.
     Targets: blog / LinkedIn / r/netsec. -->

# vulnctl v0.1: auditable vulnerability decisions, not scores

If you run vulnerability management, you know the CVSS trap. A scanner hands you
200 findings, 40 of them "Critical," and the base score can't tell you which of
those 40 will actually be exploited — or that the "Medium" three rows down is
under active attack right now. So teams burn weeks patching criticals that no
one will ever touch, and miss the ones that matter. The intelligence that would
fix this exists — EPSS, CISA's Known Exploited catalog, OSV, GHSA, public
exploit databases — but it's scattered across a half-dozen sources and nobody
has time to fuse it by hand.

**vulnctl** is a CLI that does the fusing, then makes a defensible decision. Give
it a CVE list, a CycloneDX SBOM, or Grype output; it enriches every finding from
those sources, evaluates it against an SSVC decision tree using *your*
organization's exposure and mission-impact context, and ranks the results as
**Track / Track\* / Attend / Act**.

The part I care about most: every verdict ships with its **decision path**. Not
a score — the actual chain of reasoning. `exploitation=active` (because it's
KEV-listed), `exposure=open` (from your context), `automatable=yes` (from the
CVSS vector) → **Act**. When an engineer asks "why is this Critical only
*Track*?" or leadership asks "why is a *medium* our #1?", you have one line of
evidence instead of a shrug.

On one real Grype report, a CVSS "fix all Critical + High" policy produced a
`{{cvss_now}}`-item urgent queue; vulnctl's Act queue was `{{act}}` — a
`{{reduction}}%` reduction — while still surfacing the KEV-listed medium that
severity alone buried. Full write-up here: `{{case-study-link}}`.

It's offline-capable (bundled EPSS/KEV/exploit snapshots), emits JSON / SARIF /
Markdown, and gates CI with `--fail-on`. Releases are signed (cosign keyless)
and ship an SBOM.

```bash
pipx install vulnctl
vulnctl enrich CVE-2021-44228 --show-path
```

- Repo: `{{github-link}}`
- Docs: `{{docs-link}}`
- PyPI: `{{pypi-link}}`

Feedback and issues very welcome — especially where a verdict surprised you.
