"""SARIF 2.1.0 output (SPEC.md FR-15) for GitHub code scanning and friends.

Level mapping (FRAMEWORK.md §3.6): ACT→error, ATTEND→warning, TRACK*→note,
TRACK→none. Each finding becomes one ``result``; each distinct CVE becomes one
``reportingDescriptor`` (rule) whose ``helpUri`` points at the NVD detail page.
The full SSVC decision path is serialized into ``result.message.markdown`` —
the audit trail is the product — with a plain one-liner in ``message.text``.
Verdict facts that have no standard SARIF home live in ``result.properties``.

Artifact locations:

* **CVE-list** findings have no artifact, so their results omit ``locations``
  entirely — the CVE identity is carried by ``ruleId``. A result may
  legitimately have no location; inventing a fake path would mislead a UI.
* **Grype** findings point at the component's own in-image path
  (``finding.locations``); the affected purl rides along as a
  ``logicalLocation``.
* **SBOM** findings point at the SBOM file (``artifact_uri``) with the purl as
  a ``logicalLocation`` — "which component" without a real filesystem path.
"""

from __future__ import annotations

import json
from typing import Any

from vulnctl import __version__
from vulnctl.models import (
    Decision,
    EpssData,
    ExploitData,
    Finding,
    IngestSource,
    KevData,
    RankedResult,
    RunMetadata,
    Verdict,
)
from vulnctl.output import result_sort_key

SARIF_VERSION = "2.1.0"
SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/NokiGuard/vulnctl"
_NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"

_LEVEL = {
    Decision.ACT: "error",
    Decision.ATTEND: "warning",
    Decision.TRACK_STAR: "note",
    Decision.TRACK: "none",
}


def _rule_description(finding: Finding) -> str:
    return finding.cve_id


def _path_markdown(verdict: Verdict) -> str:
    lines = [f"**SSVC decision: {verdict.decision.value.upper()}** (tree `{verdict.tree_id}`)", ""]
    lines += [
        f"{i}. `{step.node}` = `{step.value}` — _{step.value_source}_"
        for i, step in enumerate(verdict.path.steps, start=1)
    ]
    if verdict.inputs_degraded:
        lines += ["", "_Degraded: one or more inputs fell back to a tree default._"]
    return "\n".join(lines)


def _path_text(verdict: Verdict) -> str:
    steps = " → ".join(f"{s.node}={s.value}" for s in verdict.path.steps)
    return f"{verdict.decision.value.upper()} [{steps}]"


def _locations(finding: Finding, artifact_uri: str | None) -> list[dict[str, Any]]:
    uri = finding.locations[0] if finding.locations else artifact_uri
    if finding.source is IngestSource.CLI or (uri is None and finding.package is None):
        return []
    location: dict[str, Any] = {}
    if uri is not None:
        location["physicalLocation"] = {"artifactLocation": {"uri": uri}}
    if finding.package is not None:
        location["logicalLocations"] = [
            {"fullyQualifiedName": finding.package.purl, "kind": "module"}
        ]
    return [location] if location else []


def _properties(result: RankedResult) -> dict[str, Any]:
    enrichment = result.enrichment
    props: dict[str, Any] = {
        "decision": result.verdict.decision.value,
        "treeId": result.verdict.tree_id,
        "inputsDegraded": result.verdict.inputs_degraded,
    }
    if isinstance(enrichment.epss, EpssData):
        props["epssScore"] = enrichment.epss.score
    if isinstance(enrichment.kev, KevData):
        props["kevListed"] = enrichment.kev.listed
    if isinstance(enrichment.exploits, ExploitData):
        props["exploitPresent"] = bool(
            enrichment.exploits.edb_ids
            or enrichment.exploits.msf_modules
            or enrichment.exploits.nuclei_templates
        )
    return props


def _result(result: RankedResult, rule_index: int, artifact_uri: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "ruleId": result.finding.cve_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[result.verdict.decision],
        "message": {"text": _path_text(result.verdict), "markdown": _path_markdown(result.verdict)},
        "properties": _properties(result),
    }
    locations = _locations(result.finding, artifact_uri)
    if locations:
        body["locations"] = locations
    return body


def build_sarif(
    results: list[RankedResult],
    metadata: RunMetadata,
    *,
    artifact_uri: str | None = None,
) -> dict[str, Any]:
    """Build the SARIF 2.1.0 log document (one run, tool=vulnctl)."""
    ordered = sorted(results, key=result_sort_key)

    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for result in ordered:
        cve_id = result.finding.cve_id
        if cve_id not in rule_index:
            rule_index[cve_id] = len(rules)
            rules.append(
                {
                    "id": cve_id,
                    "shortDescription": {"text": _rule_description(result.finding)},
                    "helpUri": f"{_NVD_DETAIL}{cve_id}",
                }
            )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "vulnctl",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": [_result(r, rule_index[r.finding.cve_id], artifact_uri) for r in ordered],
        "properties": {
            "offline": metadata.offline,
            "sources": metadata.sources,
            "degradedFields": len(metadata.degradations),
        },
    }
    return {"$schema": SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(
    results: list[RankedResult],
    metadata: RunMetadata,
    *,
    artifact_uri: str | None = None,
) -> str:
    """Serialize the SARIF log to an indented JSON string."""
    return json.dumps(build_sarif(results, metadata, artifact_uri=artifact_uri), indent=2) + "\n"
