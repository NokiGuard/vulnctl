"""Vulnerability-ID-list ingestion: bare CVE/GHSA IDs from the CLI → Findings.

Malformed IDs are hard errors with an actionable message (CLAUDE.md
architecture rule 3: fail loud on input). GHSA IDs are accepted alongside
CVEs; the pipeline alias-resolves them to CVEs via OSV where possible.
"""

from __future__ import annotations

from collections.abc import Iterable

from vulnctl.models import CVE_ID_RE, GHSA_ID_RE, Finding, IngestSource


def _normalize(raw: str) -> str:
    """Canonical case: CVEs uppercase; GHSA suffixes lowercase.

    OSV's ``/v1/vulns/{id}`` path and the cache keys are case-sensitive, and
    scanners emit lowercase GHSA suffixes — normalizing here keeps CLI input
    hitting the same cache rows a scanner run wrote.
    """
    if CVE_ID_RE.fullmatch(raw):
        return raw.upper()
    return "GHSA-" + raw[len("GHSA-") :].lower()


def parse_vuln_ids(raw_ids: Iterable[str]) -> list[Finding]:
    """Validate, case-normalize, and order-preservingly dedupe IDs into Findings.

    Raises:
        ValueError: if any ID is neither a CVE nor a GHSA identifier, naming
            the offending values.
    """
    ids = list(raw_ids)
    invalid = [raw for raw in ids if not (CVE_ID_RE.fullmatch(raw) or GHSA_ID_RE.fullmatch(raw))]
    if invalid:
        raise ValueError(
            f"not valid CVE or GHSA IDs: {', '.join(repr(i) for i in invalid)} "
            "(expected CVE-YYYY-NNNN, e.g. CVE-2021-44228, "
            "or GHSA-xxxx-xxxx-xxxx, e.g. GHSA-35jh-r3h4-6jhm)"
        )
    seen: dict[str, None] = {}
    for raw in ids:
        seen.setdefault(_normalize(raw))
    return [Finding(cve_id=vuln_id, source=IngestSource.CLI) for vuln_id in seen]
