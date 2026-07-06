"""Grype JSON ingestion: scanner matches → Findings (FRAMEWORK.md §3.1).

Purely local — Grype already names the vulnerabilities, so this path never
touches the network. Parsing hard-fails on malformed input with a message
naming what is wrong and where (CLAUDE.md rule 3).

Grype match IDs are often ecosystem-native (GHSA-… from the GitHub
namespace) with the CVE carried in ``relatedVulnerabilities``; the same
canonical-ID rule as the OSV adapter applies: a CVE when one exists, else
the native ID, everything else kept as aliases. Grype's own severity is
carried on ``Finding.scanner_severity`` as informational metadata only —
the verdict is the SSVC engine's job.

Dedup: the same vulnerability reported for the same package across several
image layers collapses into one Finding whose ``locations`` lists every
reported path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from vulnctl.ingest import IngestError
from vulnctl.ingest.cve_list import CVE_ID_RE
from vulnctl.models import Finding, IngestSource, PackageRef

MAX_GRYPE_FILE_BYTES = 64 * 1024 * 1024


def load_grype(source: str) -> tuple[list[Finding], list[str]]:
    """Read Grype JSON from a file path, or from stdin when ``source`` is ``-``."""
    if source == "-":
        text = sys.stdin.read(MAX_GRYPE_FILE_BYTES + 1)
        if len(text) > MAX_GRYPE_FILE_BYTES:
            raise IngestError(f"<stdin>: input exceeds {MAX_GRYPE_FILE_BYTES} bytes")
        return parse_grype_json(text, origin="<stdin>")
    path = Path(source)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise IngestError(f"cannot read Grype output: {exc}") from exc
    if size > MAX_GRYPE_FILE_BYTES:
        raise IngestError(f"{path}: file is {size} bytes; limit is {MAX_GRYPE_FILE_BYTES}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise IngestError(f"cannot read Grype output: {exc}") from exc
    return parse_grype_json(text, origin=str(path))


def parse_grype_json(text: str, *, origin: str) -> tuple[list[Finding], list[str]]:
    """Parse Grype ``-o json`` output into deduplicated Findings.

    Returns ``(findings, warnings)``; warnings currently cover only an empty
    match list (a clean scan is a real answer, but worth surfacing).

    Raises:
        IngestError: on invalid JSON, a document without a ``matches`` list,
            or a structurally malformed match.
    """
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise IngestError(f"{origin}: not valid JSON ({exc})") from exc
    if not isinstance(raw, dict):
        raise IngestError(f"{origin}: root must be a JSON object")
    if "matches" not in raw:
        raise IngestError(f"{origin}: no 'matches' key (is this `grype -o json` output?)")
    matches = raw["matches"]
    if not isinstance(matches, list):
        raise IngestError(f"{origin}: 'matches' must be a list")

    drafts: dict[tuple[str, str], _Draft] = {}
    for index, match in enumerate(matches):
        native_id, severity, related = _parse_vulnerability(match, index, origin)
        package, package_key, locations = _parse_artifact(match, index, origin)
        canonical_id = _canonical_id(native_id, related)
        draft = drafts.setdefault(
            (canonical_id, package_key),
            _Draft(canonical_id=canonical_id, package=package, severity=severity),
        )
        for alias in (native_id, *related):
            if CVE_ID_RE.fullmatch(alias):
                alias = alias.upper()
            if alias != canonical_id:
                draft.aliases.setdefault(alias)
        for location in locations:
            draft.locations.setdefault(location)

    findings = [
        Finding(
            cve_id=draft.canonical_id,
            source=IngestSource.GRYPE,
            package=draft.package,
            aliases=list(draft.aliases),
            scanner_severity=draft.severity,
            locations=list(draft.locations),
        )
        for draft in drafts.values()
    ]
    warnings = ["grype: no matches in scan output"] if not matches else []
    return findings, warnings


class _Draft:
    """Mutable accumulator for one (vulnerability, package) while deduping."""

    def __init__(self, *, canonical_id: str, package: PackageRef | None, severity: str | None):
        self.canonical_id = canonical_id
        self.package = package
        self.severity = severity
        self.aliases: dict[str, None] = {}
        self.locations: dict[str, None] = {}


def _canonical_id(native_id: str, related: list[str]) -> str:
    if CVE_ID_RE.fullmatch(native_id):
        return native_id.upper()
    cves = sorted(rel.upper() for rel in related if CVE_ID_RE.fullmatch(rel))
    return cves[0] if cves else native_id


def _parse_vulnerability(match: Any, index: int, origin: str) -> tuple[str, str | None, list[str]]:
    if not isinstance(match, dict):
        raise IngestError(f"{origin}: matches[{index}] must be an object")
    vulnerability = match.get("vulnerability")
    if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
        raise IngestError(f"{origin}: matches[{index}].vulnerability.id is missing")
    severity = vulnerability.get("severity")
    if severity is not None and not isinstance(severity, str):
        raise IngestError(f"{origin}: matches[{index}].vulnerability.severity must be a string")
    related_raw = match.get("relatedVulnerabilities")
    related = [
        entry["id"]
        for entry in (related_raw if isinstance(related_raw, list) else [])
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    ]
    return vulnerability["id"], severity, related


def _parse_artifact(
    match: dict[str, Any], index: int, origin: str
) -> tuple[PackageRef | None, str, list[str]]:
    """Return (package, dedup key, locations) for one match's artifact."""
    artifact = match.get("artifact")
    if not isinstance(artifact, dict):
        raise IngestError(f"{origin}: matches[{index}].artifact is missing")
    purl = artifact.get("purl")
    if purl is not None and not isinstance(purl, str):
        raise IngestError(f"{origin}: matches[{index}].artifact.purl must be a string")
    version = artifact.get("version")
    if version is not None and not isinstance(version, str):
        raise IngestError(f"{origin}: matches[{index}].artifact.version must be a string")
    package = PackageRef(purl=purl, version=version or None) if purl else None
    # Purl-less artifacts still dedupe by name+version rather than colliding.
    package_key = purl or f"{artifact.get('name')}@{version}"
    locations_raw = artifact.get("locations")
    locations = [
        entry["path"]
        for entry in (locations_raw if isinstance(locations_raw, list) else [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    ]
    return package, package_key, locations
