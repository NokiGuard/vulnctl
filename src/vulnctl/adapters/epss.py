"""FIRST EPSS adapter: exploitation probability + percentile per CVE.

API: https://api.first.org/data/v1/epss (batched via comma-separated ``cve``
param; numeric fields arrive as *strings* and are converted explicitly before
strict model construction). TTL 24h.

Offline: ``vulnctl/data/epss_snapshot.csv.gz`` — a dated capture of ~50
well-known CVEs in ``cve,epss,percentile,date`` form (header comment records
the snapshot date). A malformed response row degrades that CVE to
``Unavailable(not_found)`` with detail; it never crashes the run.
"""

from __future__ import annotations

import csv
import gzip
from datetime import UTC, date, datetime, time, timedelta
from functools import cache as memoize
from importlib import resources
from typing import Any

import httpx
from pydantic import ValidationError

from vulnctl.adapters.base import SourceAdapter, SourceResult, register
from vulnctl.models import EpssData, SourceMeta, Unavailable, UnavailableReason

API_URL = "https://api.first.org/data/v1/epss"
_BATCH_SIZE = 100  # the API caps rows per response at its `limit` param


@memoize
def _load_snapshot() -> dict[str, EpssData]:
    path = resources.files("vulnctl.data").joinpath("epss_snapshot.csv.gz")
    with path.open("rb") as f:
        text = gzip.decompress(f.read()).decode("utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    snapshot: dict[str, EpssData] = {}
    for row in csv.DictReader(lines):
        parsed = _parse_row(row)
        if parsed is not None:
            snapshot[parsed[0]] = parsed[1]
    return snapshot


def _parse_row(row: Any) -> tuple[str, EpssData] | None:
    """Convert one API/CSV row into (cve_id, EpssData); None if malformed."""
    if not isinstance(row, dict):
        return None
    try:
        cve_id = str(row["cve"]).upper()
        data = EpssData(
            score=float(row["epss"]),
            percentile=float(row["percentile"]),
            date=date.fromisoformat(str(row["date"])),
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None
    return cve_id, data


@register
class EpssAdapter(SourceAdapter):
    """Cache-through EPSS lookups, batched ``_BATCH_SIZE`` CVEs per request."""

    name = "epss"
    ttl = timedelta(hours=24)
    supports_offline = True

    async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
        results: dict[str, SourceResult] = {}
        misses: list[str] = []
        for cve_id in cve_ids:
            entry = self._cache.get_entry(self.name, cve_id, self._cache_ttl())
            if entry is not None:
                results[cve_id] = SourceResult(
                    data=EpssData.model_validate_json(entry.payload),
                    meta=self._meta(entry.fetched_at, cache_hit=True),
                )
            else:
                misses.append(cve_id)

        if self._offline:
            results.update(self._from_snapshot(misses))
        else:
            for start in range(0, len(misses), _BATCH_SIZE):
                batch = misses[start : start + _BATCH_SIZE]
                results.update(await self._fetch_batch(batch))
        return results

    def _from_snapshot(self, cve_ids: list[str]) -> dict[str, SourceResult]:
        snapshot = _load_snapshot()
        results: dict[str, SourceResult] = {}
        for cve_id in cve_ids:
            data = snapshot.get(cve_id)
            if data is not None:
                # Snapshot rows carry their own score date; use it as fetched_at.
                fetched_at = datetime.combine(data.date, time.min, tzinfo=UTC)
                results[cve_id] = SourceResult(
                    data=data, meta=self._meta(fetched_at, cache_hit=False)
                )
            else:
                results[cve_id] = self._unavailable(
                    UnavailableReason.OFFLINE, "not in cache or bundled EPSS snapshot"
                )
        return results

    async def _fetch_batch(self, batch: list[str]) -> dict[str, SourceResult]:
        try:
            response = await self._client.get(
                API_URL, params={"cve": ",".join(batch), "limit": str(len(batch))}
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            failure = self._unavailable(UnavailableReason.SOURCE_DOWN, str(exc))
            return dict.fromkeys(batch, failure)

        results: dict[str, SourceResult] = {}
        rows = payload.get("data") if isinstance(payload, dict) else None
        for row in rows if isinstance(rows, list) else []:
            parsed = _parse_row(row)
            if parsed is None:
                continue  # malformed row: the CVE degrades to not_found below
            cve_id, data = parsed
            if cve_id not in batch:
                continue
            self._cache.set(self.name, cve_id, data.model_dump_json())
            results[cve_id] = SourceResult(
                data=data, meta=self._meta(datetime.now(UTC), cache_hit=False)
            )
        for cve_id in batch:
            if cve_id not in results:
                results[cve_id] = self._unavailable(
                    UnavailableReason.NOT_FOUND, "no usable EPSS row for this CVE"
                )
        return results

    def _meta(self, fetched_at: datetime, *, cache_hit: bool) -> SourceMeta:
        return SourceMeta(source=self.name, fetched_at=fetched_at, cache_hit=cache_hit)

    def _unavailable(self, reason: UnavailableReason, detail: str) -> SourceResult:
        return SourceResult(
            data=Unavailable(reason=reason, detail=detail),
            meta=self._meta(datetime.now(UTC), cache_hit=False),
        )
