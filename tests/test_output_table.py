"""Table formatter tests: rendering, sorting, and visible degradation."""

from __future__ import annotations

from datetime import UTC, date, datetime

from rich.console import Console

from vulnctl.models import (
    EnrichedFinding,
    Enrichment,
    EpssData,
    Finding,
    IngestSource,
    KevData,
    RunMetadata,
    SourceMeta,
    Unavailable,
    UnavailableReason,
)
from vulnctl.output.table import build_table

_META = SourceMeta(source="test", fetched_at=datetime(2026, 7, 4, tzinfo=UTC), cache_hit=False)
_DOWN = Unavailable(reason=UnavailableReason.SOURCE_DOWN)
_NOT_IMPL = Unavailable(reason=UnavailableReason.NOT_FOUND, detail="no adapter yet")


def _result(
    cve_id: str, *, epss: EpssData | Unavailable, kev: KevData | Unavailable
) -> EnrichedFinding:
    return EnrichedFinding(
        finding=Finding(cve_id=cve_id, source=IngestSource.CLI),
        enrichment=Enrichment(
            epss=epss,
            kev=kev,
            cvss=_DOWN,
            versions=_NOT_IMPL,
            exploits=_NOT_IMPL,
            provenance={"test": _META},
        ),
    )


def _render(results: list[EnrichedFinding], metadata: RunMetadata) -> str:
    console = Console(width=160, force_terminal=False, legacy_windows=False)
    with console.capture() as capture:
        console.print(build_table(results, metadata))
    return capture.get()


_METADATA = RunMetadata(
    sources=["epss", "kev", "nvd"],
    offline=False,
    cache_hit_rate={"epss": 1.0, "kev": 0.0, "nvd": 0.5},
    degradations=["nvd: CVE-2020-0001 unavailable (source_down)"],
)


def test_rows_sorted_by_epss_desc_with_unavailable_last() -> None:
    low = _result(
        "CVE-2020-1111",
        epss=EpssData(score=0.1, percentile=0.4, date=date(2026, 7, 4)),
        kev=KevData(listed=False),
    )
    high = _result(
        "CVE-2020-2222",
        epss=EpssData(score=0.9, percentile=0.99, date=date(2026, 7, 4)),
        kev=KevData(listed=False),
    )
    degraded = _result("CVE-2020-3333", epss=_DOWN, kev=KevData(listed=False))

    text = _render([low, degraded, high], _METADATA)
    assert text.index("CVE-2020-2222") < text.index("CVE-2020-1111") < text.index("CVE-2020-3333")


def test_unavailable_renders_reason_not_blank() -> None:
    degraded = _result("CVE-2020-3333", epss=_DOWN, kev=_DOWN)
    text = _render([degraded], _METADATA)
    assert text.count("n/a (source down)") >= 2


def test_kev_cell_shows_date_and_ransomware() -> None:
    listed = _result(
        "CVE-2021-44228",
        epss=EpssData(score=0.99, percentile=1.0, date=date(2026, 7, 4)),
        kev=KevData(listed=True, date_added=date(2021, 12, 10), ransomware=True),
    )
    text = _render([listed], _METADATA)
    assert "yes 2021-12-10 ransomware" in text
    assert "0.990 (p100.0)" in text


def test_caption_summarizes_run_metadata() -> None:
    row = _result("CVE-2020-1111", epss=_DOWN, kev=KevData(listed=False))
    # The caption wraps to the table width; collapse whitespace before asserting.
    text = " ".join(_render([row], _METADATA).split())
    assert "sources: epss, kev, nvd" in text
    assert "epss 100%" in text
    assert "1 degraded field(s)" in text
    assert "offline" not in text

    offline_meta = _METADATA.model_copy(update={"offline": True})
    assert "offline mode" in " ".join(_render([row], offline_meta).split())
