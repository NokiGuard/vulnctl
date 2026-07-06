"""OSV.dev adapter: version ranges per CVE and package→vulnerability discovery.

Two roles:

1. Standard enrichment (:meth:`OsvAdapter.fetch`): ``GET /v1/vulns/{id}`` per
   cache miss. OSV serves CVE-native records, so the pipeline's CVE IDs
   resolve directly; an unknown ID is a 404 → ``Unavailable(not_found)``.
   TTL 24h.
2. SBOM discovery (:meth:`OsvAdapter.query_packages`): ``POST /v1/querybatch``
   with (purl, version) yields vulnerability IDs whose detail records are then
   fetched and alias-resolved. Called only by the CycloneDX ingester — the one
   place ingest touches the network (FRAMEWORK.md §3.1).

Alias resolution: the canonical ID for a discovered vulnerability is the
record's own ID if it is a CVE, else the lexically first CVE among its
aliases, else the native ID is kept (``Finding.cve_id`` semantics in
models.py). Version data parsed on the discovery path is also cached under
the canonical ID, so the pipeline's later ``fetch`` for the same finding is a
cache hit rather than a second request.

Version ranges: SEMVER/ECOSYSTEM ranges become human-readable strings
("pkg:npm/lodash >=1.0 <4.17.21") and their ``fixed`` events populate
``VersionData.fixed``. GIT commit ranges and enumerated version lists are
skipped — commit hashes and hundred-entry version lists are not actionable
output — so a record publishing only those yields an *empty* ``VersionData``:
a real answer, distinct from ``Unavailable``. Only the first querybatch page
per package is consulted (1,000 vulnerabilities); no real package approaches
that.

No bundled snapshot: offline mode answers from cache only
(``supports_offline = False``); misses degrade to ``Unavailable(offline)``.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from vulnctl.adapters.base import (
    SourceAdapter,
    SourceResult,
    body_too_large,
    bounded_gather,
    register,
)
from vulnctl.models import (
    PackageRef,
    SourceMeta,
    Unavailable,
    UnavailableReason,
    VersionData,
)

API_URL = "https://api.osv.dev/v1"
_QUERY_BATCH_SIZE = 100  # queries per querybatch request (API cap: 1,000)
_CONCURRENCY = 8  # parallel detail fetches

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM"})


class ResolvedVuln(BaseModel):
    """One vulnerability discovered for a package, alias-resolved."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    canonical_id: str  # CVE ID when one exists, else the native ID
    native_id: str  # the OSV record's own ID
    aliases: list[str] = []  # every other ID this vulnerability is known by
    versions: VersionData | Unavailable


class PackageVulns(BaseModel):
    """Discovery answer for one package: its vulns, or why discovery failed."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    package: PackageRef
    vulns: list[ResolvedVuln] = []
    unavailable: Unavailable | None = None


def _canonical_id(native_id: str, aliases: list[str]) -> str:
    """The ID a Finding should carry: the CVE if one exists, else the native ID."""
    if _CVE_RE.fullmatch(native_id):
        return native_id.upper()
    cves = sorted(alias.upper() for alias in aliases if _CVE_RE.fullmatch(alias))
    return cves[0] if cves else native_id


def _split_purl(package: PackageRef) -> tuple[str, str | None]:
    """Split into (purl without version/qualifiers, version); explicit version wins.

    A trailing ``@version`` is recognized only when the part after the last
    ``@`` contains no ``/`` — this keeps unencoded npm scopes
    (``pkg:npm/@scope/name``) intact.
    """
    base = package.purl.split("#", 1)[0].split("?", 1)[0]
    version = package.version
    head, sep, tail = base.rpartition("@")
    if sep and tail and "/" not in tail and head not in ("", "pkg:"):
        base = head
        version = version or tail
    return base, version


def _format_range(label: str | None, introduced: str | None, bound: str | None) -> str:
    parts: list[str] = []
    if introduced not in (None, "0"):
        parts.append(f">={introduced}")
    if bound is not None:
        parts.append(bound)
    range_text = " ".join(parts) if parts else "all versions"
    return f"{label} {range_text}" if label else range_text


def _range_strings(label: str | None, events: Any) -> tuple[list[str], list[str]]:
    """Fold one range's introduced/fixed/last_affected events into strings."""
    affected: list[str] = []
    fixed: list[str] = []
    introduced: str | None = None
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event["introduced"])
        elif "fixed" in event:
            fix = str(event["fixed"])
            affected.append(_format_range(label, introduced, f"<{fix}"))
            fixed.append(f"{label} {fix}" if label else fix)
            introduced = None
        elif "last_affected" in event:
            affected.append(_format_range(label, introduced, f"<={event['last_affected']}"))
            introduced = None
    if introduced is not None:  # open-ended range: introduced but never closed
        affected.append(_format_range(label, introduced, None))
    return affected, fixed


def _parse_versions(record: dict[str, Any]) -> VersionData:
    """Extract affected/fixed version strings from an OSV record, defensively."""
    affected: list[str] = []
    fixed: list[str] = []
    entries = record.get("affected")
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        raw_label = (
            package.get("purl") or package.get("name") if isinstance(package, dict) else None
        )
        label = str(raw_label) if raw_label is not None else None
        ranges = entry.get("ranges")
        for rng in ranges if isinstance(ranges, list) else []:
            if not isinstance(rng, dict) or rng.get("type") not in _RANGE_TYPES:
                continue
            more_affected, more_fixed = _range_strings(label, rng.get("events"))
            affected.extend(more_affected)
            fixed.extend(more_fixed)
    return VersionData(affected=list(dict.fromkeys(affected)), fixed=list(dict.fromkeys(fixed)))


@register
class OsvAdapter(SourceAdapter):
    """Cache-through OSV lookups; also the SBOM path's package→CVE resolver."""

    name = "osv"
    ttl = timedelta(hours=24)
    supports_offline = False

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
                    UnavailableReason.OFFLINE, "OSV has no bundled snapshot; cache miss"
                )
        elif misses:
            fetched = await bounded_gather(
                (self._fetch_one(cve_id) for cve_id in misses), limit=_CONCURRENCY
            )
            results.update(zip(misses, fetched, strict=True))
        return results

    async def query_packages(self, packages: list[PackageRef]) -> list[PackageVulns]:
        """Resolve each package to its vulnerabilities (the ``--sbom`` path)."""
        ids_per_package: list[list[str] | Unavailable] = []
        pending: list[tuple[int, str, str, str]] = []  # (index, cache key, purl, version)
        for package in packages:
            purl, version = _split_purl(package)
            if version is None:
                ids_per_package.append(
                    Unavailable(
                        reason=UnavailableReason.NOT_FOUND,
                        detail="package has no version; cannot query OSV",
                    )
                )
                continue
            cache_key = f"pkg:{purl}@{version}"
            cached = self._cached_ids(cache_key)
            if cached is not None:
                ids_per_package.append(cached)
            elif self._offline:
                ids_per_package.append(
                    Unavailable(reason=UnavailableReason.OFFLINE, detail="package not in cache")
                )
            else:
                ids_per_package.append([])  # placeholder, filled from the batch below
                pending.append((len(ids_per_package) - 1, cache_key, purl, version))

        for start in range(0, len(pending), _QUERY_BATCH_SIZE):
            chunk = pending[start : start + _QUERY_BATCH_SIZE]
            answers = await self._query_chunk(chunk)
            for (index, cache_key, _, _), answer in zip(chunk, answers, strict=True):
                ids_per_package[index] = answer
                if not isinstance(answer, Unavailable):
                    self._cache.set(self.name, cache_key, json.dumps(answer))

        unique_ids = list(
            dict.fromkeys(
                vuln_id
                for ids in ids_per_package
                if not isinstance(ids, Unavailable)
                for vuln_id in ids
            )
        )
        details = await self._resolve_details(unique_ids)

        results: list[PackageVulns] = []
        for package, ids in zip(packages, ids_per_package, strict=True):
            if isinstance(ids, Unavailable):
                results.append(PackageVulns(package=package, unavailable=ids))
            else:
                results.append(
                    PackageVulns(package=package, vulns=[details[vuln_id] for vuln_id in ids])
                )
        return results

    # --- enrichment path -------------------------------------------------------

    def _cached_result(self, cve_id: str) -> SourceResult | None:
        entry = self._cache.get_entry(self.name, cve_id, self._cache_ttl())
        if entry is None:
            return None
        try:
            data = VersionData.model_validate_json(entry.payload)
        except ValidationError:
            return None  # cache row written by an incompatible version: refetch
        return SourceResult(data=data, meta=self._meta(entry.fetched_at, cache_hit=True))

    async def _fetch_one(self, cve_id: str) -> SourceResult:
        record = await self._get_record(cve_id)
        if isinstance(record, Unavailable):
            return SourceResult(data=record, meta=self._meta(datetime.now(UTC), cache_hit=False))
        data = _parse_versions(record)
        self._cache.set(self.name, cve_id, data.model_dump_json())
        return SourceResult(data=data, meta=self._meta(datetime.now(UTC), cache_hit=False))

    async def _get_record(self, vuln_id: str) -> dict[str, Any] | Unavailable:
        try:
            response = await self._client.get(f"{API_URL}/vulns/{vuln_id}")
        except httpx.HTTPError as exc:
            return Unavailable(reason=UnavailableReason.SOURCE_DOWN, detail=str(exc))
        if response.status_code == 404:
            return Unavailable(
                reason=UnavailableReason.NOT_FOUND, detail="OSV has no record for this ID"
            )
        if response.status_code == 429:
            return Unavailable(reason=UnavailableReason.RATE_LIMITED, detail="HTTP 429")
        if response.status_code != 200:
            return Unavailable(
                reason=UnavailableReason.SOURCE_DOWN, detail=f"HTTP {response.status_code}"
            )
        if body_too_large(response):
            return Unavailable(
                reason=UnavailableReason.SOURCE_DOWN, detail="response exceeds size limit"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            return Unavailable(reason=UnavailableReason.SOURCE_DOWN, detail=f"invalid JSON: {exc}")
        if not isinstance(payload, dict):
            return Unavailable(
                reason=UnavailableReason.SOURCE_DOWN, detail="unrecognized response shape"
            )
        return payload

    # --- discovery path --------------------------------------------------------

    def _cached_ids(self, cache_key: str) -> list[str] | None:
        payload = self._cache.get(self.name, cache_key, self._cache_ttl())
        if payload is None:
            return None
        try:
            ids = json.loads(payload)
        except ValueError:
            return None
        if isinstance(ids, list) and all(isinstance(vuln_id, str) for vuln_id in ids):
            return ids
        return None  # cache row written by an incompatible version: refetch

    async def _query_chunk(
        self, chunk: list[tuple[int, str, str, str]]
    ) -> list[list[str] | Unavailable]:
        queries = [{"package": {"purl": purl}, "version": version} for _, _, purl, version in chunk]
        try:
            response = await self._client.post(f"{API_URL}/querybatch", json={"queries": queries})
            response.raise_for_status()
            if body_too_large(response):
                return [
                    Unavailable(
                        reason=UnavailableReason.SOURCE_DOWN, detail="response exceeds size limit"
                    )
                ] * len(chunk)
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            reason = (
                UnavailableReason.RATE_LIMITED
                if exc.response.status_code == 429
                else UnavailableReason.SOURCE_DOWN
            )
            failure = Unavailable(reason=reason, detail=f"HTTP {exc.response.status_code}")
            return [failure] * len(chunk)
        except (httpx.HTTPError, ValueError) as exc:
            failure = Unavailable(reason=UnavailableReason.SOURCE_DOWN, detail=str(exc))
            return [failure] * len(chunk)

        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            failure = Unavailable(
                reason=UnavailableReason.SOURCE_DOWN,
                detail="unrecognized querybatch response shape",
            )
            return [failure] * len(chunk)

        answers: list[list[str] | Unavailable] = []
        for result in results:
            vulns = result.get("vulns") if isinstance(result, dict) else None
            ids: list[str] = []
            for vuln in vulns if isinstance(vulns, list) else []:
                vuln_id = vuln.get("id") if isinstance(vuln, dict) else None
                if isinstance(vuln_id, str):
                    ids.append(vuln_id)
            answers.append(ids)
        return answers

    async def _resolve_details(self, vuln_ids: list[str]) -> dict[str, ResolvedVuln]:
        resolved: dict[str, ResolvedVuln] = {}
        misses: list[str] = []
        for vuln_id in vuln_ids:
            cached = self._cached_vuln(vuln_id)
            if cached is not None:
                resolved[vuln_id] = cached
            else:
                misses.append(vuln_id)
        if self._offline:
            for vuln_id in misses:
                resolved[vuln_id] = ResolvedVuln(
                    canonical_id=vuln_id,
                    native_id=vuln_id,
                    versions=Unavailable(
                        reason=UnavailableReason.OFFLINE, detail="record not in cache"
                    ),
                )
            return resolved
        fetched = await bounded_gather(
            (self._resolve_one(vuln_id) for vuln_id in misses), limit=_CONCURRENCY
        )
        resolved.update(zip(misses, fetched, strict=True))
        return resolved

    def _cached_vuln(self, vuln_id: str) -> ResolvedVuln | None:
        payload = self._cache.get(self.name, f"vuln:{vuln_id}", self._cache_ttl())
        if payload is None:
            return None
        try:
            return ResolvedVuln.model_validate_json(payload)
        except ValidationError:
            return None  # cache row written by an incompatible version: refetch

    async def _resolve_one(self, vuln_id: str) -> ResolvedVuln:
        record = await self._get_record(vuln_id)
        if isinstance(record, Unavailable):
            # Keep the vuln, visibly degraded — discovery must not drop it.
            return ResolvedVuln(canonical_id=vuln_id, native_id=vuln_id, versions=record)
        raw_aliases = record.get("aliases")
        aliases = (
            [a for a in raw_aliases if isinstance(a, str)] if isinstance(raw_aliases, list) else []
        )
        native_id = str(record.get("id") or vuln_id)
        canonical_id = _canonical_id(native_id, aliases)
        versions = _parse_versions(record)
        resolved = ResolvedVuln(
            canonical_id=canonical_id,
            native_id=native_id,
            aliases=[a for a in dict.fromkeys([native_id, *aliases]) if a != canonical_id],
            versions=versions,
        )
        self._cache.set(self.name, f"vuln:{vuln_id}", resolved.model_dump_json())
        # Cache-through under the canonical ID: the pipeline's later fetch()
        # for this finding becomes a cache hit instead of a second request.
        self._cache.set(self.name, canonical_id, versions.model_dump_json())
        return resolved

    # --- shared helpers --------------------------------------------------------

    def _meta(self, fetched_at: datetime, *, cache_hit: bool) -> SourceMeta:
        return SourceMeta(source=self.name, fetched_at=fetched_at, cache_hit=cache_hit)

    def _unavailable(self, reason: UnavailableReason, detail: str) -> SourceResult:
        return SourceResult(
            data=Unavailable(reason=reason, detail=detail),
            meta=self._meta(datetime.now(UTC), cache_hit=False),
        )
