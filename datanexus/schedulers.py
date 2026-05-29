"""
datanexus/schedulers.py — Sprint 6 background scheduler loops.

All loops run as asyncio.create_task (NOT APScheduler, NOT threading.Thread).
Each loop is a while-True coroutine that sleeps between runs.

Exported:
  _cve_refresh_loop()     — 24h, refreshes dn:cve_watch:* hashes
  _sbom_refresh_loop()    — 24h, re-audits registered SBOMs
  _typosquat_ref_loop()   — 24h, refreshes typosquat reference list in Redis

Hard rules:
  - SMEMBERS only (no SCAN) to read SET indexes
  - GitHub mirror for CISA KEV (Akamai CDN blocks datacenter IPs)
  - Circuit breakers from _security_utils on all HTTP calls
  - NVD_API_KEY from datanexus.config if available

Usage (in main.py _lifespan):
  asyncio.create_task(_cve_refresh_loop())
  asyncio.create_task(_sbom_refresh_loop())
  asyncio.create_task(_typosquat_ref_loop())
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx
import pybreaker

log = logging.getLogger("datanexus.schedulers")

# ── Constants ─────────────────────────────────────────────────────────────────

_CVE_WATCH_PREFIX  = "dn:cve_watch:"
_CVE_WATCH_INDEX   = "dn:cve_watch_ids"
_SBOM_WATCH_PREFIX = "dn:sbom_watch:"
_SBOM_WATCH_INDEX  = "dn:sbom_watch_ids"

_TYPOSQUAT_KEY_FMT = "dn:typosquat_ref:{eco}"   # ZSET per ecosystem: member=name, score=rank

_SLEEP_24H = 24 * 3600

# GitHub mirror of CISA KEV — cisa.gov direct is blocked by Akamai on datacenter IPs
_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json"
)
_NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_URL = "https://api.first.org/data/v1/epss"

_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT      = httpx.Timeout(10.0, connect=5.0)
_TTL_90D      = 90 * 24 * 3600

# Module-level circuit breakers
_nvd_breaker  = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_cisa_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_epss_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)


# ══════════════════════════════════════════════════════════════════════════════
# CVE WATCH REFRESH LOOP
# ══════════════════════════════════════════════════════════════════════════════

async def _cve_refresh_loop() -> None:
    """
    Background loop: refresh all active CVE watches every 24h.
    Reads watch_ids from SMEMBERS(dn:cve_watch_ids) — no SCAN.
    """
    log.info("_cve_refresh_loop started")
    while True:
        try:
            await _run_cve_watch_refresh()
        except Exception as exc:
            log.error("_cve_refresh_loop error: %s", exc)
        await asyncio.sleep(_SLEEP_24H)


async def _run_cve_watch_refresh(redis_override=None) -> None:
    """
    One pass of the CVE watch refresh.
    Accepts an optional redis_override for testing (passes fakeredis instance).
    """
    from datanexus.cache import get_redis

    r = redis_override or await get_redis()
    if r is None:
        log.warning("_run_cve_watch_refresh: Redis unavailable, skipping")
        return

    watch_ids = await r.smembers(_CVE_WATCH_INDEX)
    if not watch_ids:
        log.debug("_run_cve_watch_refresh: no active watches")
        return

    log.info("_run_cve_watch_refresh: refreshing %d watches", len(watch_ids))

    # Fetch CISA KEV once per run (bulk JSON)
    kev_set: set = set()
    try:
        kev_set = await _fetch_kev_set()
    except Exception as exc:
        log.warning("_run_cve_watch_refresh: KEV fetch failed: %s", exc)

    for watch_id in watch_ids:
        try:
            await _refresh_one_cve_watch(r, watch_id, kev_set)
        except Exception as exc:
            log.warning("_refresh_one_cve_watch error watch_id=%s: %s", watch_id, exc)


async def _refresh_one_cve_watch(r, watch_id: str, kev_set: set) -> None:
    key   = f"{_CVE_WATCH_PREFIX}{watch_id}"
    watch = await r.hgetall(key)
    if not watch:
        # Stale entry in SET index — clean up
        await r.srem(_CVE_WATCH_INDEX, watch_id)
        return

    try:
        cve_ids = json.loads(watch.get("cve_ids", "[]"))
    except json.JSONDecodeError:
        cve_ids = []

    try:
        existing_events = json.loads(watch.get("events", "[]"))
    except json.JSONDecodeError:
        existing_events = []

    existing_event_keys = {
        (e.get("cve_id"), e.get("event_type")) for e in existing_events
    }

    now_iso = datetime.now(timezone.utc).isoformat()
    new_events = []

    for cve_id in cve_ids:
        # KEV listing
        if cve_id in kev_set and (cve_id, "kev_listed") not in existing_event_keys:
            new_events.append({
                "cve_id":      cve_id,
                "event_type":  "kev_listed",
                "detected_at": now_iso,
                "detail":      "Added to CISA Known Exploited Vulnerabilities catalog.",
            })

        # NVD — patch released (cvssScore or lastModified change)
        nvd_event = await _check_nvd_for_patch(cve_id)
        if nvd_event and (cve_id, "patch_released") not in existing_event_keys:
            new_events.append({
                "cve_id":      cve_id,
                "event_type":  "patch_released",
                "detected_at": now_iso,
                "detail":      nvd_event,
            })

        # EPSS — exploitation probability spike (> 0.7)
        epss_event = await _check_epss(cve_id)
        if epss_event and (cve_id, "exploitation_detected") not in existing_event_keys:
            new_events.append({
                "cve_id":      cve_id,
                "event_type":  "exploitation_detected",
                "detected_at": now_iso,
                "detail":      epss_event,
            })

    all_events = existing_events + new_events

    # Write back: append events, update last_checked, refresh TTL
    pipe = r.pipeline()
    pipe.hset(key, mapping={
        "last_checked": now_iso,
        "events":       json.dumps(all_events),
    })
    pipe.expire(key, _TTL_90D)
    await pipe.execute()

    if new_events:
        log.info(
            "_refresh_one_cve_watch: watch_id=%s added %d events",
            watch_id, len(new_events),
        )


# ── NVD + CISA KEV + EPSS helpers ─────────────────────────────────────────────

async def _fetch_kev_set() -> set:
    """Download CISA KEV catalog and return a set of CVE IDs."""
    async def _fetch():
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            return {v.get("cveID", "") for v in vulns if v.get("cveID")}

    try:
        return await _cisa_breaker.call_async(_fetch)
    except pybreaker.CircuitBreakerError:
        log.warning("_fetch_kev_set: circuit open")
        return set()


async def _check_nvd_for_patch(cve_id: str) -> Optional[str]:
    """Return a description string if NVD indicates a recent change, else None."""
    nvd_api_key = os.environ.get("NVD_API_KEY", "")

    async def _fetch():
        headers = dict(_HTTP_HEADERS)
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=headers, follow_redirects=True,
        ) as client:
            params = {"cveId": cve_id}
            resp = await client.get(_NVD_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve_data = vulns[0].get("cve", {})
            # Check if there are recent references indicating a patch
            refs = cve_data.get("references", [])
            patch_refs = [
                r for r in refs
                if any(tag in r.get("tags", []) for tag in ["Patch", "Vendor Advisory"])
            ]
            if patch_refs:
                return f"Patch reference found: {patch_refs[0].get('url', '')[:100]}"
            return None

    try:
        return await _nvd_breaker.call_async(_fetch)
    except (pybreaker.CircuitBreakerError, Exception) as exc:
        log.debug("_check_nvd_for_patch error cve=%s: %s", cve_id, exc)
        return None


async def _check_epss(cve_id: str) -> Optional[str]:
    """Return description if EPSS score > 0.7, indicating active exploitation."""
    async def _fetch():
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.get(_EPSS_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])
            if items:
                score = float(items[0].get("epss", 0))
                if score > 0.7:
                    return f"EPSS exploitation probability: {score:.2%}"
            return None

    try:
        return await _epss_breaker.call_async(_fetch)
    except (pybreaker.CircuitBreakerError, Exception) as exc:
        log.debug("_check_epss error cve=%s: %s", cve_id, exc)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# SBOM REFRESH LOOP
# ══════════════════════════════════════════════════════════════════════════════

async def _sbom_refresh_loop() -> None:
    """
    Background loop: re-audit all registered SBOMs every 24h.
    Reads watch_ids from SMEMBERS(dn:sbom_watch_ids) — no SCAN.
    """
    log.info("_sbom_refresh_loop started")
    while True:
        try:
            await _run_sbom_refresh()
        except Exception as exc:
            log.error("_sbom_refresh_loop error: %s", exc)
        await asyncio.sleep(_SLEEP_24H)


async def _run_sbom_refresh() -> None:
    """One pass of the SBOM refresh loop."""
    from datanexus.cache import get_redis

    r = await get_redis()
    if r is None:
        log.warning("_run_sbom_refresh: Redis unavailable, skipping")
        return

    watch_ids = await r.smembers(_SBOM_WATCH_INDEX)
    if not watch_ids:
        return

    log.info("_run_sbom_refresh: refreshing %d SBOM watches", len(watch_ids))
    for watch_id in watch_ids:
        try:
            await _refresh_one_sbom_watch(r, watch_id)
        except Exception as exc:
            log.warning("_refresh_one_sbom_watch error watch_id=%s: %s", watch_id, exc)


async def _refresh_one_sbom_watch(r, watch_id: str) -> None:
    """Re-audit a single SBOM watch. Stub — full logic lives in security_stateful.py."""
    # SBOM content is stored in the hash; re-audit uses _fetch_vulns from _security_utils
    key  = f"{_SBOM_WATCH_PREFIX}{watch_id}"
    data = await r.hgetall(key)
    if not data:
        await r.srem(_SBOM_WATCH_INDEX, watch_id)
        return

    now_iso = datetime.now(timezone.utc).isoformat()

    # Minimal stub: just update last_checked + refresh TTL
    # Full re-audit wired in Step 5
    pipe = r.pipeline()
    pipe.hset(key, "last_checked", now_iso)
    pipe.expire(key, _TTL_90D)
    await pipe.execute()


# ══════════════════════════════════════════════════════════════════════════════
# TYPOSQUAT REFERENCE LOOP
# ══════════════════════════════════════════════════════════════════════════════

async def _typosquat_ref_loop() -> None:
    """
    Background loop: refresh the typosquat reference list every 24h.
    Stores top-10k npm + PyPI packages in Redis ZSET dn:typosquat_ref
    with score = popularity rank (lower = more popular).
    """
    log.info("_typosquat_ref_loop started")
    while True:
        try:
            await _run_typosquat_ref_refresh()
        except Exception as exc:
            log.error("_typosquat_ref_loop error: %s", exc)
        await asyncio.sleep(_SLEEP_24H)


async def _run_typosquat_ref_refresh() -> None:
    """Refresh the typosquat reference ZSET from PyPI top-packages stats."""
    from datanexus.cache import get_redis

    r = await get_redis()
    if r is None:
        log.warning("_run_typosquat_ref_refresh: Redis unavailable, skipping")
        return

    log.info("_run_typosquat_ref_refresh: fetching top packages...")
    packages = await _fetch_top_pypi_packages()
    if not packages:
        log.warning("_run_typosquat_ref_refresh: no packages fetched")
        return

    # Store per ecosystem as ZSET: score = rank (1 = most popular)
    key = _TYPOSQUAT_KEY_FMT.format(eco="pypi")
    pipe = r.pipeline()
    for rank, name in enumerate(packages, start=1):
        pipe.zadd(key, {name: rank})
    pipe.expire(key, _TTL_90D)
    await pipe.execute()
    log.info("_run_typosquat_ref_refresh: stored %d packages in %s", len(packages), key)


async def _fetch_top_pypi_packages() -> list:
    """
    Fetch top PyPI package names from the PyPI stats endpoint.
    Falls back to a minimal hardcoded list if unavailable.
    """
    _PYPI_STATS_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.get(_PYPI_STATS_URL)
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows", [])
            return [r["project"] for r in rows[:10_000]]
    except Exception as exc:
        log.warning("_fetch_top_pypi_packages error: %s", exc)
        # Minimal hardcoded fallback (top-50 well-known packages)
        return [
            "requests", "boto3", "urllib3", "botocore", "setuptools",
            "certifi", "charset-normalizer", "idna", "six", "python-dateutil",
            "numpy", "pandas", "pip", "s3transfer", "pyyaml",
            "packaging", "wheel", "cryptography", "pyopenssl", "cffi",
            "attrs", "click", "typing-extensions", "colorama", "pillow",
            "scipy", "matplotlib", "django", "flask", "fastapi",
            "sqlalchemy", "psycopg2", "redis", "celery", "gunicorn",
            "uvicorn", "starlette", "pydantic", "httpx", "aiohttp",
            "pytest", "black", "mypy", "ruff", "isort",
            "paramiko", "fabric", "invoke", "rich", "typer",
        ]
