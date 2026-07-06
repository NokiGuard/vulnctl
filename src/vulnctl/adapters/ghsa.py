"""GitHub Security Advisories adapter (REST Global Advisories API).

REST rather than GraphQL: the GraphQL endpoint rejects anonymous requests
outright, while ``GET /advisories`` works unauthenticated (60 req/h) — and
SPEC.md NFR-2 requires zero mandatory credentials. ``VULNCTL_GITHUB_TOKEN``
(env only, CLAUDE.md rule 6) raises the limit to 5,000 req/h. There is no
client-side rate limiter — pacing 60 req/h would stall runs; instead a
403/429 answer degrades that CVE to ``Unavailable(rate_limited)`` with no
retries, and the 24h cache keeps repeat runs cheap.

Lookup by ID kind: CVE IDs via ``?cve_id=`` (a JSON *list*; empty →
``not_found``; the first GitHub-reviewed entry is used — the API orders by
relevance); GHSA IDs via ``/advisories/{ghsa_id}`` (404 → ``not_found``).
Any other ID kind (PYSEC-…, GO-…) is ``not_found`` without a request —
GitHub cannot answer for those.

Version ranges are normalized to the exact format the OSV adapter emits
(purl-style label + ``<4.17.21``-style ranges) so the pipeline's keep-both
merge can compare the two sources without false conflicts.

No bundled snapshot: offline mode answers from cache only
(``supports_offline = False``); misses degrade to ``Unavailable(offline)``.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from pydantic import ValidationError

from vulnctl.adapters.base import (
    SourceAdapter,
    SourceResult,
    body_too_large,
    bounded_gather,
    register,
)
from vulnctl.cache import Cache
from vulnctl.models import GhsaData, SourceMeta, Unavailable, UnavailableReason, VersionData

API_URL = "https://api.github.com/advisories"
TOKEN_ENV = "VULNCTL_GITHUB_TOKEN"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
_CONCURRENCY = 8

#: GHSA ecosystem names → purl types, matching the labels OSV records carry.
_PURL_TYPES = {
    "npm": "npm",
    "pip": "pypi",
    "rubygems": "gem",
    "maven": "maven",
    "nuget": "nuget",
    "composer": "composer",
    "go": "golang",
    "rust": "cargo",
    "erlang": "hex",
    "pub": "pub",
    "swift": "swift",
}


def _purl_label(package: Any) -> str | None:
    if not isinstance(package, dict):
        return None
    name = package.get("name")
    if not isinstance(name, str) or not name:
        return None
    ecosystem = str(package.get("ecosystem") or "generic").lower()
    purl_type = _PURL_TYPES.get(ecosystem, ecosystem)
    if purl_type == "maven":
        name = name.replace(":", "/")  # group:artifact → group/artifact purl form
    return f"pkg:{purl_type}/{name}"


def _normalize_range(range_text: str) -> str:
    """``">= 3.0.0, < 3.9.2"`` → ``">=3.0.0 <3.9.2"`` (the OSV adapter's format)."""
    clauses = [clause.strip().replace(" ", "") for clause in range_text.split(",")]
    return " ".join(clause for clause in clauses if clause)


def _parse_versions(vulnerabilities: Any) -> VersionData:
    affected: list[str] = []
    fixed: list[str] = []
    for entry in vulnerabilities if isinstance(vulnerabilities, list) else []:
        if not isinstance(entry, dict):
            continue
        label = _purl_label(entry.get("package"))
        range_text = entry.get("vulnerable_version_range")
        if isinstance(range_text, str) and range_text:
            normalized = _normalize_range(range_text)
            affected.append(f"{label} {normalized}" if label else normalized)
        patched = entry.get("first_patched_version")
        if isinstance(patched, str) and patched:
            fixed.append(f"{label} {patched}" if label else patched)
    return VersionData(affected=list(dict.fromkeys(affected)), fixed=list(dict.fromkeys(fixed)))


def _parse_advisory(advisory: Any) -> GhsaData | None:
    """One advisory object → GhsaData; None if the shape is unusable."""
    if not isinstance(advisory, dict) or not isinstance(advisory.get("ghsa_id"), str):
        return None
    severity = advisory.get("severity")
    summary = advisory.get("summary")
    return GhsaData(
        ghsa_id=advisory["ghsa_id"],
        severity=severity if isinstance(severity, str) and severity else "unknown",
        summary=summary if isinstance(summary, str) else "",
        versions=_parse_versions(advisory.get("vulnerabilities")),
    )


def _pick_advisory(payload: list[Any]) -> Any:
    """Prefer the first GitHub-reviewed advisory; fall back to the first entry."""
    for entry in payload:
        if isinstance(entry, dict) and entry.get("github_reviewed_at") is not None:
            return entry
    return payload[0]


@register
class GhsaAdapter(SourceAdapter):
    """Cache-through GitHub advisory lookups, anonymous or token-keyed."""

    name = "ghsa"
    ttl = timedelta(hours=24)
    supports_offline = False

    def __init__(self, client: httpx.AsyncClient, cache: Cache, *, offline: bool = False) -> None:
        super().__init__(client, cache, offline=offline)
        token = os.environ.get(TOKEN_ENV)
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    async def fetch(self, cve_ids: list[str]) -> dict[str, SourceResult]:
        results: dict[str, SourceResult] = {}
        misses: list[str] = []
        for cve_id in cve_ids:
            if not (_CVE_RE.fullmatch(cve_id) or _GHSA_RE.fullmatch(cve_id)):
                results[cve_id] = self._unavailable(
                    UnavailableReason.NOT_FOUND, "GitHub answers only CVE or GHSA IDs"
                )
                continue
            cached = self._cached_result(cve_id)
            if cached is not None:
                results[cve_id] = cached
            else:
                misses.append(cve_id)

        if self._offline:
            for cve_id in misses:
                results[cve_id] = self._unavailable(
                    UnavailableReason.OFFLINE, "GHSA has no bundled snapshot; cache miss"
                )
        elif misses:
            fetched = await bounded_gather(
                (self._fetch_one(cve_id) for cve_id in misses), limit=_CONCURRENCY
            )
            results.update(zip(misses, fetched, strict=True))
        return results

    def _cached_result(self, cve_id: str) -> SourceResult | None:
        entry = self._cache.get_entry(self.name, cve_id, self._cache_ttl())
        if entry is None:
            return None
        try:
            data = GhsaData.model_validate_json(entry.payload)
        except ValidationError:
            return None  # cache row written by an incompatible version: refetch
        return SourceResult(data=data, meta=self._meta(entry.fetched_at, cache_hit=True))

    async def _fetch_one(self, cve_id: str) -> SourceResult:
        if _CVE_RE.fullmatch(cve_id):
            url, params = API_URL, {"cve_id": cve_id}
        else:
            url, params = f"{API_URL}/{cve_id}", {}
        try:
            response = await self._client.get(url, params=params, headers=self._headers)
        except httpx.HTTPError as exc:
            return self._unavailable(UnavailableReason.SOURCE_DOWN, str(exc))
        if response.status_code == 404:
            return self._unavailable(UnavailableReason.NOT_FOUND, "no GitHub advisory")
        if response.status_code in (403, 429):
            return self._unavailable(UnavailableReason.RATE_LIMITED, f"HTTP {response.status_code}")
        if response.status_code != 200:
            return self._unavailable(UnavailableReason.SOURCE_DOWN, f"HTTP {response.status_code}")
        if body_too_large(response):
            return self._unavailable(UnavailableReason.SOURCE_DOWN, "response exceeds size limit")
        try:
            payload = response.json()
        except ValueError as exc:
            return self._unavailable(UnavailableReason.SOURCE_DOWN, f"invalid JSON: {exc}")

        if isinstance(payload, list):  # the ?cve_id= endpoint
            if not payload:
                return self._unavailable(UnavailableReason.NOT_FOUND, "no GitHub advisory")
            payload = _pick_advisory(payload)
        data = _parse_advisory(payload)
        if data is None:
            return self._unavailable(UnavailableReason.SOURCE_DOWN, "unrecognized advisory shape")
        self._cache.set(self.name, cve_id, data.model_dump_json())
        return SourceResult(data=data, meta=self._meta(datetime.now(UTC), cache_hit=False))

    def _meta(self, fetched_at: datetime, *, cache_hit: bool) -> SourceMeta:
        return SourceMeta(source=self.name, fetched_at=fetched_at, cache_hit=cache_hit)

    def _unavailable(self, reason: UnavailableReason, detail: str) -> SourceResult:
        return SourceResult(
            data=Unavailable(reason=reason, detail=detail),
            meta=self._meta(datetime.now(UTC), cache_hit=False),
        )
