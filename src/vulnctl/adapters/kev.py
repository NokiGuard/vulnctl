"""CISA KEV adapter: known-exploited membership per CVE.

The feed is one JSON document covering the whole catalog, so a single fetch
serves every CVE in the run. The catalog is reduced to a validated
``{cve_id: entry}`` mapping before caching (key ``catalog``, TTL 6h).

Absence from the catalog is a *real answer* — ``KevData(listed=False)`` —
never ``Unavailable``. Only an unreachable feed (with nothing cached) degrades
to ``Unavailable(source_down)``.

Offline: ``vulnctl/data/kev_snapshot.json.gz`` — a verbatim gzipped capture of
the real feed; its ``dateReleased`` field records the snapshot date.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, date, datetime, timedelta
from importlib import resources
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from vulnctl.adapters.base import SourceAdapter, SourceResult, register
from vulnctl.models import KevData, SourceMeta, Unavailable, UnavailableReason

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CATALOG_KEY = "catalog"


class _KevEntry(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    date_added: date | None = None
    ransomware: bool = False


class _KevCatalog(BaseModel):
    """Reduced, validated form of the feed — what we cache and read back."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    date_released: datetime | None = None
    entries: dict[str, _KevEntry]


def _reduce_feed(feed: Any) -> _KevCatalog | None:
    """Boil the raw feed down to the catalog mapping; None if unrecognizable."""
    if not isinstance(feed, dict) or not isinstance(feed.get("vulnerabilities"), list):
        return None
    entries: dict[str, _KevEntry] = {}
    for vuln in feed["vulnerabilities"]:
        if not isinstance(vuln, dict) or "cveID" not in vuln:
            continue  # malformed entry: skip it, keep the rest of the catalog
        try:
            date_added = date.fromisoformat(str(vuln.get("dateAdded")))
        except ValueError:
            date_added = None
        entries[str(vuln["cveID"]).upper()] = _KevEntry(
            date_added=date_added,
            ransomware=vuln.get("knownRansomwareCampaignUse") == "Known",
        )
    try:
        released = datetime.fromisoformat(str(feed.get("dateReleased")))
        if released.tzinfo is None:
            released = released.replace(tzinfo=UTC)
    except ValueError:
        released = None
    return _KevCatalog(date_released=released, entries=entries)


def _load_snapshot() -> _KevCatalog | None:
    path = resources.files("vulnctl.data").joinpath("kev_snapshot.json.gz")
    with path.open("rb") as f:
        return _reduce_feed(json.loads(gzip.decompress(f.read())))


@register
class KevAdapter(SourceAdapter):
    """One catalog fetch per run; every CVE is answered from the mapping."""

    name = "kev"
    ttl = timedelta(hours=6)
    supports_offline = True

    async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
        catalog, meta = await self._get_catalog()
        if catalog is None:
            reason = UnavailableReason.OFFLINE if self._offline else UnavailableReason.SOURCE_DOWN
            failure = SourceResult(
                data=Unavailable(reason=reason, detail="KEV catalog unavailable"), meta=meta
            )
            return dict.fromkeys(cve_ids, failure)

        results: dict[str, SourceResult] = {}
        for cve_id in cve_ids:
            entry = catalog.entries.get(cve_id)
            if entry is None:
                data = KevData(listed=False)
            else:
                data = KevData(
                    listed=True, date_added=entry.date_added, ransomware=entry.ransomware
                )
            results[cve_id] = SourceResult(data=data, meta=meta)
        return results

    async def _get_catalog(self) -> tuple[_KevCatalog | None, SourceMeta]:
        cached = self._cache.get_entry(self.name, _CATALOG_KEY, self._cache_ttl())
        if cached is not None:
            try:
                catalog = _KevCatalog.model_validate_json(cached.payload)
            except ValidationError:
                catalog = None  # cache written by an incompatible version: refetch
            if catalog is not None:
                return catalog, self._meta(cached.fetched_at, cache_hit=True)

        if self._offline:
            snapshot = _load_snapshot()
            fetched_at = (
                snapshot.date_released
                if snapshot is not None and snapshot.date_released is not None
                else datetime.now(UTC)
            )
            return snapshot, self._meta(fetched_at, cache_hit=False)

        try:
            response = await self._client.get(FEED_URL, follow_redirects=True)
            response.raise_for_status()
            catalog = _reduce_feed(response.json())
        except (httpx.HTTPError, ValueError):
            catalog = None
        if catalog is not None:
            self._cache.set(self.name, _CATALOG_KEY, catalog.model_dump_json())
        return catalog, self._meta(datetime.now(UTC), cache_hit=False)

    def _meta(self, fetched_at: datetime, *, cache_hit: bool) -> SourceMeta:
        return SourceMeta(source=self.name, fetched_at=fetched_at, cache_hit=cache_hit)
