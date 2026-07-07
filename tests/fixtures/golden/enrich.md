# vulnctl report

## Summary

- **2 finding(s):** 1 act, 1 attend, 0 track*, 0 track
- **KEV exposure:** 1 finding(s) on CISA's Known Exploited Vulnerabilities catalog
- **Degraded inputs:** 2 verdict(s) fell back to a tree default; see the appendix for which step and why.
- _Generated in offline mode: some sources answered from cache/snapshot only._

## Highlights

- **CVE-2021-44228** — Act, KEV-listed (ransomware), EPSS 1.000

## Top 2 findings by priority

| # | CVE | Decision | CVSS | EPSS | KEV | Exploits |
|---|---|---|---|---|---|---|
| 1 | CVE-2021-44228 | Act | n/a (offline) | 1.000 | yes (ransomware) | EDB·3 MSF·5 nuclei·1 |
| 2 | CVE-2010-0017 | Attend | n/a (offline) | n/a (offline) | no | EDB·1 MSF·1 |

## Appendix — all findings

### CVE-2021-44228 → Act  (tree `cisa-deployer-v1`)  _(degraded: defaults applied)_
- decision path:
  - `exploitation` = `active` _(kev)_
  - `exposure` = `open` _(context)_
  - `automatable` = `yes` _(default)_
  - `human_impact` = `high` _(context)_

### CVE-2010-0017 → Attend  (tree `cisa-deployer-v1`)  _(degraded: defaults applied)_
- decision path:
  - `exploitation` = `poc` _(exploits)_
  - `exposure` = `open` _(context)_
  - `automatable` = `yes` _(default)_
  - `human_impact` = `high` _(context)_
