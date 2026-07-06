"""CycloneDX 1.4/1.5 JSON SBOM ingestion (FRAMEWORK.md §3.1).

Parsing is pure and hard-fails on malformed input with a message naming what
is wrong and where (CLAUDE.md rule 3). Component→CVE resolution flows through
the OSV adapter — the one place the ingest layer touches the network.

Only top-level ``components`` are read; the SBOM subject
(``metadata.component``) and nested sub-components are out of scope for v0.1.
Components without a purl cannot be queried against OSV; they are skipped and
surfaced as a warning in run metadata rather than silently dropped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnctl.adapters.osv import OsvAdapter, PackageVulns
from vulnctl.ingest import IngestError
from vulnctl.models import Finding, IngestSource, PackageRef

MAX_SBOM_FILE_BYTES = 64 * 1024 * 1024
SUPPORTED_SPEC_VERSIONS = ("1.4", "1.5")


def parse_sbom(path: Path) -> tuple[list[PackageRef], list[str]]:
    """Parse a CycloneDX JSON SBOM into unique package references.

    Returns ``(packages, warnings)``; warnings cover skipped purl-less
    components and an empty component list.

    Raises:
        IngestError: on unreadable files, invalid JSON, a non-CycloneDX
            document, an unsupported spec version, or a malformed component.
    """
    raw = _load_json(path)
    if not isinstance(raw, dict):
        raise IngestError(f"{path}: SBOM root must be a JSON object")
    bom_format = raw.get("bomFormat")
    if bom_format != "CycloneDX":
        raise IngestError(
            f"{path}: not a CycloneDX SBOM (bomFormat={bom_format!r}; expected 'CycloneDX')"
        )
    spec_version = raw.get("specVersion")
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise IngestError(
            f"{path}: unsupported specVersion {spec_version!r} "
            f"(supported: {', '.join(SUPPORTED_SPEC_VERSIONS)})"
        )
    components = raw.get("components", [])
    if not isinstance(components, list):
        raise IngestError(f"{path}: 'components' must be a list")

    packages: dict[tuple[str, str | None], PackageRef] = {}
    skipped = 0
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise IngestError(f"{path}: components[{index}] must be an object")
        purl = component.get("purl")
        if purl is not None and not isinstance(purl, str):
            raise IngestError(f"{path}: components[{index}].purl must be a string")
        if not purl:
            skipped += 1
            continue
        version = component.get("version")
        if version is not None and not isinstance(version, str):
            raise IngestError(f"{path}: components[{index}].version must be a string")
        packages.setdefault((purl, version or None), PackageRef(purl=purl, version=version or None))

    warnings: list[str] = []
    if skipped:
        warnings.append(f"sbom: skipped {skipped} component(s) without a purl")
    if not components:
        warnings.append("sbom: no components found")
    return list(packages.values()), warnings


async def resolve_findings(
    packages: list[PackageRef], adapter: OsvAdapter
) -> tuple[list[Finding], list[str]]:
    """Component→CVE resolution via OSV: the ingest layer's one network touch."""
    return findings_from_package_vulns(await adapter.query_packages(packages))


def findings_from_package_vulns(
    package_vulns: list[PackageVulns],
) -> tuple[list[Finding], list[str]]:
    """Map discovery answers to Findings: one per (package, canonical ID).

    Multiple native records aliasing the same CVE for one package (e.g. a
    GHSA and a PYSEC record) merge into one Finding with combined aliases.
    A package whose discovery failed becomes a warning, never a silent gap.
    """
    findings: list[Finding] = []
    warnings: list[str] = []
    for package_result in package_vulns:
        if package_result.unavailable is not None:
            reason = package_result.unavailable.reason.value
            warnings.append(
                f"sbom: {package_result.package.purl}: OSV discovery unavailable ({reason})"
            )
            continue
        merged: dict[str, dict[str, None]] = {}
        for vuln in package_result.vulns:
            aliases = merged.setdefault(vuln.canonical_id, {})
            for alias in vuln.aliases:
                aliases.setdefault(alias)
        for canonical_id, aliases in merged.items():
            findings.append(
                Finding(
                    cve_id=canonical_id,
                    source=IngestSource.CYCLONEDX,
                    package=package_result.package,
                    aliases=list(aliases),
                )
            )
    return findings, warnings


def _load_json(path: Path) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise IngestError(f"cannot read SBOM: {exc}") from exc
    if size > MAX_SBOM_FILE_BYTES:
        raise IngestError(f"{path}: SBOM is {size} bytes; limit is {MAX_SBOM_FILE_BYTES}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise IngestError(f"cannot read SBOM: {exc}") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise IngestError(f"{path}: not valid JSON ({exc})") from exc
