"""
datanexus/tools/_cve_utils.py — Core HTTP utilities for CVE intelligence.

Extracted for Sprint 7: fetch_cve_risk_summary calls these directly via
asyncio.gather. The Sprint 4 tool handlers (fetch_cve_detail, fetch_cisa_kev,
fetch_cve_epss in t10.py) remain unchanged — they keep their own caching,
audit contexts, and structured error responses.

These utilities return raw data dicts or raise on upstream failure.
Callers use return_exceptions=True and treat exceptions as degraded (null) values.

Circuit breakers imported from _circuit_breakers.py — never defined here.
"""

import logging
import os
from typing import Optional

import httpx
import pybreaker

from datanexus.tools._circuit_breakers import (
    _nvd_breaker,
    _cisa_breaker,
    _epss_breaker,
)
from datanexus.core.cache import get_cached as _get_cached_sync, set_cached as _set_cached_sync

log = logging.getLogger("datanexus.tools._cve_utils")

_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT      = httpx.Timeout(8.0, connect=5.0)

_NVD_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_API_KEY  = os.environ.get("DATANEXUS_NVD_API_KEY", "")
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL     = "https://api.first.org/data/v1/epss"

# In-process cache for CISA KEV catalog (avoid re-fetching on every aggregator call)
_kev_catalog_cache: Optional[list] = None


async def _fetch_cve_detail_util(cve_id: str) -> dict:
    """
    Fetch CVE detail from NIST NVD.

    Returns:
        {
            "cvss_score": float | None,
            "references": list[{"url": str, "tags": list}],
            "configurations": list,   # raw NVD configurations for ecosystem extraction
            "description": str,
        }
    Raises on upstream failure so callers can catch as degraded.
    """
    headers = {**_HTTP_HEADERS}
    if _NVD_API_KEY:
        headers["apiKey"] = _NVD_API_KEY

    async def _call() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=headers, follow_redirects=True,
        ) as client:
            resp = await client.get(_NVD_URL, params={"cveId": cve_id})
            resp.raise_for_status()
            return resp.json()

    raw = await _nvd_breaker.call_async(_call)
    vulns = raw.get("vulnerabilities", [])
    if not vulns:
        return {"cvss_score": None, "references": [], "configurations": [], "description": ""}

    cve = vulns[0].get("cve", {})

    cvss_score: Optional[float] = None
    metrics = cve.get("metrics", {})
    for m in metrics.get("cvssMetricV31", []):
        score = m.get("cvssData", {}).get("baseScore")
        if score is not None:
            cvss_score = float(score)
            break
    if cvss_score is None:
        for m in metrics.get("cvssMetricV2", []):
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                cvss_score = float(score)
                break

    refs = [
        {"url": r.get("url", ""), "tags": r.get("tags", [])}
        for r in cve.get("references", [])
    ]

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")[:500]
            break

    return {
        "cvss_score":      cvss_score,
        "references":      refs,
        "configurations":  cve.get("configurations", []),
        "description":     desc,
    }


async def _fetch_cisa_kev_util(cve_id: str) -> dict:
    """
    Check whether a CVE is in the CISA KEV catalog.

    Returns:
        {
            "kev_listed": bool,
        }
    Raises on upstream failure so callers can catch as degraded (null).
    """
    global _kev_catalog_cache

    if _kev_catalog_cache is None:
        # 1. Try Redis first — t10.py stores the catalog here after every live fetch.
        #    Key: datanexus:kev:catalog  (written by _set_cached("kev", "catalog", ...))
        cached = _get_cached_sync("kev", "catalog")
        if cached and isinstance(cached, dict) and "vulnerabilities" in cached:
            _kev_catalog_cache = cached["vulnerabilities"]
        elif cached and isinstance(cached, list):
            _kev_catalog_cache = cached

    if _kev_catalog_cache is None:
        # 2. Redis miss — fetch live from CISA and populate both caches.
        async def _call() -> list:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                headers=_HTTP_HEADERS,
                follow_redirects=True,
            ) as client:
                resp = await client.get(_CISA_KEV_URL)
                resp.raise_for_status()
                data = resp.json()
                return data.get("vulnerabilities", [])

        _kev_catalog_cache = await _cisa_breaker.call_async(_call)
        # Populate Redis so t10.py and future util calls share the same catalog.
        _set_cached_sync("kev", "catalog", {"vulnerabilities": _kev_catalog_cache}, 25 * 3600)

    found = any(
        v.get("cveID", "").upper() == cve_id.upper()
        for v in _kev_catalog_cache
    )
    return {"kev_listed": found}


async def _fetch_cve_epss_util(cve_id: str) -> dict:
    """
    Fetch EPSS exploit probability from FIRST.org.

    Returns:
        {
            "epss_score": float,   # 0.0–1.0
        }
    Raises on upstream failure so callers can catch as degraded (null).
    """
    async def _call() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.get(_EPSS_URL, params={"cve": cve_id})
            resp.raise_for_status()
            return resp.json()

    raw = await _epss_breaker.call_async(_call)
    data_items = raw.get("data", [])
    if not data_items:
        raise ValueError(f"{cve_id} not found in EPSS database")

    return {"epss_score": float(data_items[0].get("epss", 0.0))}
