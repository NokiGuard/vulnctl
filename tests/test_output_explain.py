"""Explain renderer: structure, provenance, counterfactuals, hostile strings."""

from __future__ import annotations

from datetime import UTC, date, datetime

from rich.console import Console, RenderableType

from vulnctl.models import (
    Counterfactual,
    CvssData,
    Decision,
    DecisionPath,
    DecisionPathStep,
    Enrichment,
    EpssData,
    ExploitData,
    Finding,
    GhsaData,
    IngestSource,
    KevData,
    PackageRef,
    RankedResult,
    RunMetadata,
    SourceMeta,
    Unavailable,
    UnavailableReason,
    Verdict,
    VersionData,
)
from vulnctl.output.explain import build_explain

_FETCHED = datetime(2026, 7, 4, 12, 30, tzinfo=UTC)
_NA = Unavailable(reason=UnavailableReason.OFFLINE)
_METADATA = RunMetadata(
    sources=["epss", "kev"], offline=True, cache_hit_rate={"epss": 1.0, "kev": 0.0}
)


def _meta(source: str, *, cache_hit: bool) -> SourceMeta:
    return SourceMeta(source=source, fetched_at=_FETCHED, cache_hit=cache_hit)


def _render(renderable: RenderableType) -> str:
    console = Console(width=200, force_terminal=False, legacy_windows=False)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


def _full_result() -> RankedResult:
    return RankedResult(
        finding=Finding(
            cve_id="CVE-2021-23337",
            source=IngestSource.GRYPE,
            package=PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20"),
            aliases=["GHSA-35jh-r3h4-6jhm"],
        ),
        enrichment=Enrichment(
            epss=EpssData(score=0.224, percentile=0.974, date=date(2026, 7, 30)),
            kev=KevData(listed=True, date_added=date(2021, 12, 10), ransomware=True),
            cvss=CvssData(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N", base_score=7.2, severity="HIGH"),
            cwes=["CWE-77", "CWE-94"],
            versions=VersionData(
                affected=["pkg:npm/lodash <4.17.21"], fixed=["pkg:npm/lodash 4.17.21"]
            ),
            advisory=GhsaData(
                ghsa_id="GHSA-35jh-r3h4-6jhm",
                severity="high",
                summary="Command Injection in lodash",
                versions=VersionData(),
            ),
            exploits=ExploitData(edb_ids=["50590"], msf_modules=["exploit/multi/x"]),
            provenance={
                "epss": _meta("epss", cache_hit=True),
                "kev": _meta("kev", cache_hit=False),
                "nvd": _meta("nvd", cache_hit=True),
                "osv": _meta("osv", cache_hit=True),
                "ghsa": _meta("ghsa", cache_hit=True),
                "exploits": _meta("exploits", cache_hit=False),
            },
        ),
        verdict=Verdict(
            decision=Decision.ACT,
            path=DecisionPath(
                steps=[DecisionPathStep(node="exploitation", value="active", value_source="kev")]
            ),
            tree_id="cisa-deployer-v1",
            inputs_degraded=False,
        ),
    )


def test_explain_shows_identity_evidence_provenance_and_flips() -> None:
    flips = [Counterfactual(node="exposure", value="small", decision=Decision.ATTEND)]
    text = _render(build_explain(_full_result(), _METADATA, flips))

    assert "CVE-2021-23337" in text
    assert "also known as: GHSA-35jh-r3h4-6jhm" in text
    assert "package: npm/lodash@4.17.20" in text
    assert "Command Injection in lodash" in text
    assert "verdict: ACT" in text and "(tree cisa-deployer-v1)" in text
    assert "exploitation = active" in text and "[kev]" in text

    # Evidence detail the table format elides:
    assert "0.224 (p97.4), scored 2026-07-30" in text
    assert "listed, added 2021-12-10" in text and "known ransomware use" in text
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N" in text
    assert "CWE-77, CWE-94" in text
    assert "affected: pkg:npm/lodash <4.17.21" in text
    assert "fixed: pkg:npm/lodash 4.17.21" in text
    assert "Exploit-DB: 50590" in text and "Metasploit: exploit/multi/x" in text
    assert "2026-07-04 12:30" in text  # provenance timestamps
    assert "hit" in text and "miss" in text

    assert "what would change this verdict" in text
    assert "exposure = small" in text and "ATTEND" in text
    assert "offline mode" in text


def test_explain_without_flips_says_so() -> None:
    text = _render(build_explain(_full_result(), _METADATA, []))
    assert "no single input change alters this verdict" in text


def test_explain_escapes_hostile_strings() -> None:
    result = _full_result()
    hostile = result.model_copy(
        update={
            "enrichment": result.enrichment.model_copy(
                update={
                    "advisory": GhsaData(
                        ghsa_id="GHSA-0000-0000-0000",
                        severity="high",
                        summary="[on red]pwned[/on red]",
                        versions=VersionData(),
                    ),
                    "exploits": ExploitData(edb_ids=["[blink]1[/blink]"]),
                    "versions": _NA,
                }
            )
        }
    )
    text = _render(build_explain(hostile, _METADATA, []))
    assert "[on red]pwned[/on red]" in text  # literal, not styled
    assert "[blink]1[/blink]" in text
