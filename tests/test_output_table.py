"""Table formatter tests: rendering, three-key sorting, visible degradation, paths."""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from rich.console import Console, RenderableType

from vulnctl.models import (
    CvssData,
    Decision,
    DecisionPath,
    DecisionPathStep,
    Enrichment,
    EpssData,
    ExploitData,
    Finding,
    IngestSource,
    KevData,
    PackageRef,
    RankedResult,
    RunMetadata,
    SourceMeta,
    Unavailable,
    UnavailableReason,
    Verdict,
)
from vulnctl.output.table import build_paths, build_table

_META = SourceMeta(source="test", fetched_at=datetime(2026, 7, 4, tzinfo=UTC), cache_hit=False)
_DOWN = Unavailable(reason=UnavailableReason.SOURCE_DOWN)
_NOT_IMPL = Unavailable(reason=UnavailableReason.NOT_FOUND, detail="no adapter yet")
_STEPS = [
    DecisionPathStep(node="exploitation", value="active", value_source="kev"),
    DecisionPathStep(node="automatable", value="yes", value_source="default"),
]


def _result(
    cve_id: str,
    *,
    decision: Decision,
    epss: EpssData | Unavailable = _DOWN,
    kev: KevData | Unavailable = _DOWN,
    cvss: CvssData | Unavailable = _DOWN,
    degraded: bool = False,
    package: PackageRef | None = None,
    exploits: ExploitData | Unavailable = _NOT_IMPL,
) -> RankedResult:
    return RankedResult(
        finding=Finding(cve_id=cve_id, source=IngestSource.CLI, package=package),
        enrichment=Enrichment(
            epss=epss,
            kev=kev,
            cvss=cvss,
            versions=_NOT_IMPL,
            advisory=_NOT_IMPL,
            exploits=exploits,
            provenance={"test": _META},
        ),
        verdict=Verdict(
            decision=decision,
            path=DecisionPath(steps=_STEPS),
            tree_id="toy-v1",
            inputs_degraded=degraded,
        ),
    )


def _epss(score: float) -> EpssData:
    return EpssData(score=score, percentile=score, date=date(2026, 7, 4))


def _cvss(base: float) -> CvssData:
    return CvssData(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=base, severity="HIGH"
    )


def _render(renderable: RenderableType) -> str:
    console = Console(width=180, force_terminal=False, legacy_windows=False)
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


_METADATA = RunMetadata(
    sources=["epss", "kev", "nvd"],
    offline=False,
    cache_hit_rate={"epss": 1.0, "kev": 0.0, "nvd": 0.5},
    degradations=["nvd: CVE-2020-0001 unavailable (source_down)"],
)


def test_sort_is_decision_then_epss_then_cvss() -> None:
    rows = [
        _result("CVE-2020-1111", decision=Decision.TRACK, epss=_epss(0.99)),
        _result("CVE-2020-2222", decision=Decision.ACT, epss=_epss(0.10)),
        _result("CVE-2020-3333", decision=Decision.ATTEND, epss=_epss(0.50)),
        _result("CVE-2020-4444", decision=Decision.ATTEND, epss=_epss(0.70)),
        _result("CVE-2020-5555", decision=Decision.ATTEND, epss=_epss(0.70), cvss=_cvss(9.8)),
        _result("CVE-2020-6666", decision=Decision.TRACK_STAR, epss=_DOWN),
    ]
    text = _render(build_table(rows, _METADATA))
    order = [
        text.index("CVE-2020-2222"),  # act
        text.index("CVE-2020-5555"),  # attend, epss .70, cvss 9.8
        text.index("CVE-2020-4444"),  # attend, epss .70, no cvss
        text.index("CVE-2020-3333"),  # attend, epss .50
        text.index("CVE-2020-6666"),  # track*, epss unavailable
        text.index("CVE-2020-1111"),  # track, even with epss .99
    ]
    assert order == sorted(order)


def test_decision_labels_rendered() -> None:
    rows = [
        _result("CVE-2020-1111", decision=Decision.ACT),
        _result("CVE-2020-2222", decision=Decision.TRACK_STAR),
    ]
    text = _render(build_table(rows, _METADATA))
    assert "ACT" in text
    assert "TRACK*" in text


def test_unavailable_renders_reason_not_blank() -> None:
    text = _render(build_table([_result("CVE-2020-3333", decision=Decision.TRACK)], _METADATA))
    assert text.count("n/a (source down)") >= 2


def test_kev_cell_shows_date_and_ransomware() -> None:
    listed = _result(
        "CVE-2021-44228",
        decision=Decision.ACT,
        epss=_epss(0.99),
        kev=KevData(listed=True, date_added=date(2021, 12, 10), ransomware=True),
    )
    text = _render(build_table([listed], _METADATA))
    assert "yes 2021-12-10 ransomware" in text
    assert "0.990 (p99.0)" in text


def test_caption_summarizes_run_metadata() -> None:
    row = _result("CVE-2020-1111", decision=Decision.TRACK)
    text = " ".join(_render(build_table([row], _METADATA)).split())
    assert "sources: epss, kev, nvd" in text
    assert "epss 100%" in text
    assert "1 degraded field(s)" in text
    assert "offline" not in text

    offline_meta = _METADATA.model_copy(update={"offline": True})
    assert "offline mode" in " ".join(_render(build_table([row], offline_meta)).split())


def test_package_column_only_on_package_bearing_runs() -> None:
    plain = _render(build_table([_result("CVE-2020-1111", decision=Decision.TRACK)], _METADATA))
    assert "Package" not in plain

    rows = [
        _result(
            "CVE-2021-23337",
            decision=Decision.TRACK,
            package=PackageRef(purl="pkg:npm/lodash@4.17.20", version="4.17.20"),
        ),
        _result("CVE-2020-1111", decision=Decision.TRACK),  # mixed run: cell falls back to —
    ]
    text = _render(build_table(rows, _METADATA))
    assert "Package" in text
    assert "pkg:npm/lodash@4.17.20" in text
    # The version is not appended twice when the purl already embeds it.
    assert "4.17.20@4.17.20" not in text


@pytest.mark.parametrize(
    ("decisions", "threshold", "expected"),
    [
        ([Decision.ACT], Decision.ACT, 2),
        ([Decision.ATTEND], Decision.ACT, 0),  # below threshold
        ([Decision.ATTEND], Decision.ATTEND, 2),
        ([Decision.TRACK, Decision.ATTEND], Decision.ATTEND, 2),  # any one meeting it trips
        ([Decision.TRACK, Decision.TRACK_STAR], Decision.ATTEND, 0),
        ([Decision.TRACK], Decision.TRACK, 2),  # track threshold trips on anything
        ([Decision.ACT], None, 0),  # no gate
        ([], Decision.ACT, 0),  # no findings
    ],
)
def test_gate_exit_code(
    decisions: list[Decision], threshold: Decision | None, expected: int
) -> None:
    from vulnctl.output import gate_exit_code

    rows = [_result(f"CVE-2020-{i:04d}", decision=d) for i, d in enumerate(decisions)]
    assert gate_exit_code(rows, threshold) == expected


def test_exploits_column_renders_counts_and_none() -> None:
    rows = [
        _result(
            "CVE-2021-44228",
            decision=Decision.ACT,
            exploits=ExploitData(edb_ids=["1", "2"], msf_modules=["m"], nuclei_templates=[]),
        ),
        _result("CVE-2020-1111", decision=Decision.TRACK, exploits=ExploitData()),
    ]
    text = _render(build_table(rows, _METADATA))
    assert "EDB·2" in text
    assert "MSF·1" in text
    assert "nuclei" not in text  # zero-count kinds are omitted
    assert "none" in text  # empty ExploitData renders as an explicit 'none'


def test_untrusted_strings_render_literally_not_as_markup() -> None:
    # IDs, purls, and severity labels arrive from scanner files and NVD; a
    # hostile value must not restyle the table (e.g. dim an ACT verdict or
    # hide a cell) — rich markup in them has to survive as literal text.
    hostile = _result(
        "[green]CVE-2020-0001[/green]",
        decision=Decision.ACT,
        cvss=CvssData(vector="CVSS:3.1/AV:N", base_score=9.8, severity="[dim]HIGH[/dim]"),
        package=PackageRef(purl="pkg:npm/[bold red on white]evil[/]"),
    )
    text = _render(build_table([hostile], _METADATA))
    assert "[green]CVE-2020-0001[/green]" in text
    assert "[dim]HIGH[/dim]" in text
    assert "pkg:npm/[bold red on white]evil[/]" in text


def test_paths_render_every_step_with_sources() -> None:
    rows = [
        _result("CVE-2020-2222", decision=Decision.ACT, degraded=True),
        _result("CVE-2020-1111", decision=Decision.TRACK),
    ]
    text = _render(build_paths(rows))
    # Table order: ACT first.
    assert text.index("CVE-2020-2222") < text.index("CVE-2020-1111")
    assert "1. exploitation = active" in text
    assert "[kev]" in text
    assert "2. automatable  = yes" in text  # node names aligned
    assert "[default]" in text
    assert "[degraded: defaults applied]" in text
    assert "(tree toy-v1)" in text
