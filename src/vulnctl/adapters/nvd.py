"""NVD CVE API 2.0 adapter: CVSS scoring + CWE classification per CVE.

One request per CVE. Pagination cannot occur on this path: a ``cveId`` query
returns at most one result, which always fits the first page (the parser
still scans the ``vulnerabilities`` list rather than assuming index 0).
Broad queries that do paginate are out of scope for v0.1. TTL 7d.

The API key comes from ``VULNCTL_NVD_API_KEY`` only — never from config
files or CLI flags (CLAUDE.md rule 6). Rate limits stay
well under NVD's published ceilings (5 req/30s unkeyed, 50 req/30s keyed);
403/429/503 responses are retried with exponential backoff.

CVSS selection: prefer v3.1, then v3.0, then v2; within a version prefer the
NVD-provided ``Primary`` entry. A v2-only CVE therefore yields a ``CvssData``
whose vector has no ``CVSS:3.1/`` prefix — recorded as available data, not
degraded. Rejected and unknown/reserved CVEs are ``Unavailable(not_found)``.

No bundled snapshot: offline mode answers from cache only (``supports_offline
= False``); cache misses degrade to ``Unavailable(offline)``.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from pydantic import ValidationError

from vulnctl.adapters.base import (
    RateLimit,
    RateLimiter,
    SourceAdapter,
    SourceResult,
    body_too_large,
    bounded_gather,
    register,
)
from vulnctl.cache import Cache
from vulnctl.models import CvssData, NvdData, SourceMeta, Unavailable, UnavailableReason

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "VULNCTL_NVD_API_KEY"

_CWE_RE = re.compile(r"^CWE-\d+$")
_METRIC_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _select_cvss(metrics: Any) -> CvssData | Unavailable:
    """Pick the best CVSS entry: v3.1 → v3.0 → v2, Primary before Secondary."""
    if not isinstance(metrics, dict):
        metrics = {}
    for kind in _METRIC_PREFERENCE:
        entries = metrics.get(kind)
        if not isinstance(entries, list):
            continue
        ordered = sorted(
            (e for e in entries if isinstance(e, dict)),
            key=lambda e: e.get("type") != "Primary",
        )
        for entry in ordered:
            cvss_data = entry.get("cvssData")
            if not isinstance(cvss_data, dict):
                continue
            # v3.x carries severity inside cvssData; v2 carries it on the metric.
            severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
            if severity is None:
                continue
            try:
                return CvssData(
                    vector=str(cvss_data["vectorString"]),
                    base_score=float(cvss_data["baseScore"]),
                    severity=str(severity),
                )
            except (KeyError, TypeError, ValueError, ValidationError):
                continue
    return Unavailable(
        reason=UnavailableReason.NOT_FOUND, detail="no usable CVSS metrics published"
    )


def _extract_cwes(weaknesses: Any) -> list[str]:
    """Collect CWE-### ids, dropping NVD-CWE-Other/noinfo placeholders."""
    found: set[str] = set()
    for weakness in weaknesses if isinstance(weaknesses, list) else []:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description") or []:
            value = description.get("value") if isinstance(description, dict) else None
            if isinstance(value, str) and _CWE_RE.match(value):
                found.add(value)
    return sorted(found, key=lambda cwe: int(cwe.split("-")[1]))


@register
class NvdAdapter(SourceAdapter):
    """Cache-through NVD lookups with polite rate limiting and backoff."""

    name = "nvd"
    ttl = timedelta(days=7)
    supports_offline = False

    _MAX_ATTEMPTS = 4
    _RETRY_STATUSES = frozenset({403, 429, 503})
    _backoff_base = 1.0  # seconds; doubled per attempt, shrunk in tests

    def __init__(self, client: httpx.AsyncClient, cache: Cache, *, offline: bool = False) -> None:
        super().__init__(client, cache, offline=offline)
        api_key = os.environ.get(API_KEY_ENV)
        self._headers = {"apiKey": api_key} if api_key else {}
        self.rate_limit = (
            RateLimit(requests=40, window_seconds=32.0)
            if api_key
            else RateLimit(requests=4, window_seconds=32.0)
        )
        self._limiter = RateLimiter(self.rate_limit)

    async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
        results: dict[str, SourceResult] = {}
        misses: list[str] = []
        for cve_id in cve_ids:
            cached = self._cached_result(cve_id)
            if cached is not None:
                results[cve_id] = cached
            else:
                misses.append(cve_id)

        if self._offline:
            for cve_id in misses:
                results[cve_id] = self._unavailable(
                    UnavailableReason.OFFLINE, "NVD has no bundled snapshot; cache miss"
                )
        elif misses:
            fetched = await bounded_gather((self._fetch_one(cve_id) for cve_id in misses), limit=4)
            results.update(zip(misses, fetched, strict=True))
        return results

    def _cached_result(self, cve_id: str) -> SourceResult | None:
        entry = self._cache.get_entry(self.name, cve_id, self._cache_ttl())
        if entry is None:
            return None
        try:
            data = NvdData.model_validate_json(entry.payload)
        except ValidationError:
            return None  # cache row written by an incompatible version: refetch
        return SourceResult(data=data, meta=self._meta(entry.fetched_at, cache_hit=True))

    async def _fetch_one(self, cve_id: str) -> SourceResult:
        last_status = 0
        for attempt in range(self._MAX_ATTEMPTS):
            if attempt:
                await asyncio.sleep(self._backoff_base * 2 ** (attempt - 1))
            await self._limiter.acquire()
            try:
                response = await self._client.get(
                    API_URL, params={"cveId": cve_id}, headers=self._headers
                )
            except httpx.HTTPError as exc:
                return self._unavailable(UnavailableReason.SOURCE_DOWN, str(exc))
            last_status = response.status_code
            if last_status in self._RETRY_STATUSES:
                continue
            if last_status != 200:
                return self._unavailable(UnavailableReason.SOURCE_DOWN, f"HTTP {last_status}")
            if body_too_large(response):
                return self._unavailable(
                    UnavailableReason.SOURCE_DOWN, "response exceeds size limit"
                )
            try:
                payload = response.json()
            except ValueError as exc:
                return self._unavailable(UnavailableReason.SOURCE_DOWN, f"invalid JSON: {exc}")
            return self._parse(cve_id, payload)
        reason = (
            UnavailableReason.RATE_LIMITED
            if last_status in (403, 429)
            else UnavailableReason.SOURCE_DOWN
        )
        return self._unavailable(
            reason, f"gave up after {self._MAX_ATTEMPTS} attempts (HTTP {last_status})"
        )

    def _parse(self, cve_id: str, payload: Any) -> SourceResult:
        if not isinstance(payload, dict):
            return self._unavailable(UnavailableReason.SOURCE_DOWN, "unrecognized response shape")
        if payload.get("totalResults") == 0:
            return self._unavailable(UnavailableReason.NOT_FOUND, "unknown or reserved CVE ID")

        vulnerabilities = payload.get("vulnerabilities")
        record: dict[str, Any] | None = None
        for vuln in vulnerabilities if isinstance(vulnerabilities, list) else []:
            cve = vuln.get("cve") if isinstance(vuln, dict) else None
            if isinstance(cve, dict) and str(cve.get("id", "")).upper() == cve_id:
                record = cve
                break
        if record is None:
            return self._unavailable(UnavailableReason.NOT_FOUND, "CVE missing from NVD response")
        if record.get("vulnStatus") == "Rejected":
            return self._unavailable(UnavailableReason.NOT_FOUND, "rejected by NVD")

        data = NvdData(
            cvss=_select_cvss(record.get("metrics")),
            cwes=_extract_cwes(record.get("weaknesses")),
        )
        self._cache.set(self.name, cve_id, data.model_dump_json())
        return SourceResult(data=data, meta=self._meta(datetime.now(UTC), cache_hit=False))

    def _meta(self, fetched_at: datetime, *, cache_hit: bool) -> SourceMeta:
        return SourceMeta(source=self.name, fetched_at=fetched_at, cache_hit=cache_hit)

    def _unavailable(self, reason: UnavailableReason, detail: str) -> SourceResult:
        return SourceResult(
            data=Unavailable(reason=reason, detail=detail),
            meta=self._meta(datetime.now(UTC), cache_hit=False),
        )
