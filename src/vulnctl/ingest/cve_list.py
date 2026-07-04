"""CVE-ID-list ingestion: bare CVE IDs from the command line → Findings.

Malformed IDs are hard errors with an actionable message (CLAUDE.md
architecture rule 3: fail loud on input).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from vulnctl.models import Finding, IngestSource

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def parse_cve_ids(raw_ids: Iterable[str]) -> list[Finding]:
    """Validate, uppercase, and order-preservingly dedupe CVE IDs into Findings.

    Raises:
        ValueError: if any ID is not of the form CVE-YYYY-NNNN…, naming the
            offending values.
    """
    invalid = [raw for raw in raw_ids if not CVE_ID_RE.fullmatch(raw)]
    if invalid:
        raise ValueError(
            f"not valid CVE IDs: {', '.join(repr(i) for i in invalid)} "
            "(expected CVE-YYYY-NNNN, e.g. CVE-2021-44228)"
        )
    seen: dict[str, None] = {}
    for raw in raw_ids:
        seen.setdefault(raw.upper())
    return [Finding(cve_id=cve_id, source=IngestSource.CLI) for cve_id in seen]
