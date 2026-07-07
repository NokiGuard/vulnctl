#!/usr/bin/env python3
"""Compute the case-study comparison numbers from vulnctl's JSON output.

Feed it the output of:

    vulnctl enrich --grype <report>.json --context <context>.yaml --format json

It prints Markdown -- a queue-size table (CVSS-only vs vulnctl), a
severity-by-decision cross-tab, and the divergence lists (Critical/High that
vulnctl de-prioritizes, Low/Medium that it escalates) -- ready to paste into
docs/case-study.md. Everything comes from a single vulnctl JSON run: the CVSS
baseline is each finding's scanner severity (or NVD CVSS severity as a
fallback), and the vulnctl verdict is the SSVC decision.

Usage:
    vulnctl enrich --grype report.json --context ctx.yaml --format json \\
        | python scripts/case_study_stats.py -
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Any

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
DEC_ORDER = ["track", "track*", "attend", "act"]
DEC_LABEL = {"track": "Track", "track*": "Track*", "attend": "Attend", "act": "Act"}


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _unavailable(value: Any) -> bool:
    """An enrichment field is unavailable iff it carries a ``reason`` key."""
    return isinstance(value, dict) and "reason" in value


def severity_of(result: dict[str, Any]) -> str:
    """CVSS-baseline severity: scanner label first, then NVD CVSS, else Unknown."""
    sev = result["finding"].get("scanner_severity")
    if not sev:
        cvss = result["enrichment"].get("cvss")
        if isinstance(cvss, dict) and not _unavailable(cvss):
            sev = cvss.get("severity")
    return (sev or "Unknown").upper()


def _decision(result: dict[str, Any]) -> str:
    return str(result["verdict"]["decision"])


def _pct(part: int, whole: int) -> str:
    return f"{(100 * part / whole):.0f}%" if whole else "0%"


def _reduction(baseline: int, reduced: int) -> str:
    return f"{(100 * (baseline - reduced) / baseline):.0f}%" if baseline else "n/a"


def _divergence_line(result: dict[str, Any]) -> str:
    enrichment = result["enrichment"]
    verdict = result["verdict"]
    epss = enrichment.get("epss")
    epss_note = "" if _unavailable(epss) else f", EPSS {epss['score']:.3f}"
    kev = enrichment.get("kev")
    kev_note = " KEV-listed" if (not _unavailable(kev) and kev.get("listed")) else ""
    path = " -> ".join(f"{s['node']}={s['value']}" for s in verdict["path"]["steps"])
    return (
        f"- `{result['finding']['cve_id']}` {severity_of(result).title()} -> "
        f"**{DEC_LABEL[_decision(result)]}**{epss_note}{kev_note}\n  _{path}_"
    )


def render(doc: dict[str, Any]) -> str:
    results: list[dict[str, Any]] = doc["results"]
    total = len(results)
    xtab: Counter[tuple[str, str]] = Counter()
    for result in results:
        xtab[(severity_of(result), _decision(result))] += 1

    present_sevs = [s for s in SEV_ORDER if any(sv == s for sv, _ in xtab)] or ["UNKNOWN"]
    cvss_now = sum(n for (sv, _), n in xtab.items() if sv in ("CRITICAL", "HIGH"))
    act = sum(n for (_, d), n in xtab.items() if d == "act")
    act_attend = sum(n for (_, d), n in xtab.items() if d in ("act", "attend"))

    out: list[str] = [f"_Total findings: {total}_", ""]
    out += ["### Queue size by policy", ""]
    out += ['| Policy | "Fix now" set | Count | Share |', "|---|---|---:|---:|"]
    out += [f"| CVSS-only | Critical + High | {cvss_now} | {_pct(cvss_now, total)} |"]
    out += [f"| vulnctl | Act | {act} | {_pct(act, total)} |"]
    out += [f"| vulnctl | Act + Attend | {act_attend} | {_pct(act_attend, total)} |"]
    out += [
        "",
        f"**Immediate-action queue: {cvss_now} -> {act}, "
        f"a {_reduction(cvss_now, act)} reduction.**",
        "",
    ]

    out += ["### CVSS severity vs vulnctl decision", ""]
    out += ["| Severity | " + " | ".join(DEC_LABEL[d] for d in DEC_ORDER) + " | Total |"]
    out += ["|---" * (len(DEC_ORDER) + 2) + "|"]
    for sev in present_sevs:
        row = [xtab[(sev, d)] for d in DEC_ORDER]
        out += [f"| {sev.title()} | " + " | ".join(str(x) for x in row) + f" | {sum(row)} |"]

    demoted = [
        r
        for r in results
        if severity_of(r) in ("CRITICAL", "HIGH") and _decision(r) in ("track", "track*")
    ]
    promoted = [
        r
        for r in results
        if severity_of(r) in ("LOW", "MEDIUM") and _decision(r) in ("attend", "act")
    ]
    out += ["", "### Criticals/Highs vulnctl de-prioritizes (Track / Track*)", ""]
    out += [("\n".join(_divergence_line(r) for r in demoted)) or "_none_"]
    out += ["", "### Lows/Mediums vulnctl escalates (Attend / Act)", ""]
    out += [("\n".join(_divergence_line(r) for r in promoted)) or "_none_"]
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Case-study stats from vulnctl JSON output.")
    parser.add_argument("report", help="vulnctl --format json output file, or '-' for stdin")
    args = parser.parse_args()
    doc = json.loads(_read(args.report))
    sys.stdout.write(render(doc))


if __name__ == "__main__":
    main()
