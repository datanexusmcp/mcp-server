"""
datanexus/tests/canary.py — Live upstream health canary suite.

One canary per upstream source. Each makes ONE real HTTP call and writes a
structured JSON result. Designed to catch upstream API breakage before users do.

Rules:
  - Read-only only — no writes, no side effects
  - No Redis or PostgreSQL dependency (safe to run standalone)
  - Runs in under 60 seconds total (concurrent via asyncio)
  - Skips canaries whose required API key is absent (SKIP ≠ FAIL)
  - Writes results to Redis if available (datanexus:canary:{source})

Usage:
  python3 -m datanexus.tests.canary
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

log = logging.getLogger("datanexus.canary")

# ── Result helpers ─────────────────────────────────────────────────────────────

def _result(
    source: str,
    tool_id: str,
    status: str,
    latency_ms: int,
    check: str,
    error: Optional[str] = None,
) -> dict:
    return {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "source":      source,
        "tool_id":     tool_id,
        "status":      status,      # PASS | FAIL | DEGRADED | SKIP
        "latency_ms":  latency_ms,
        "error":       error,
        "check":       check,
    }


def _skip(source: str, tool_id: str, reason: str) -> dict:
    return _result(source, tool_id, "SKIP", 0, reason, error=reason)


# ── Individual canaries ────────────────────────────────────────────────────────

async def canary_irs_bmf(client: httpx.AsyncClient) -> dict:
    """T04 — IRS EO BMF: check eo1.csv responds and is non-empty."""
    source, tool_id = "irs_bmf", "T04"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://www.irs.gov/pub/irs-soi/eo1.csv",
            headers={"Range": "bytes=0-1023"},  # fetch only first 1 KB
            timeout=httpx.Timeout(20.0, connect=8.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        if resp.status_code in (200, 206) and len(resp.content) > 100:
            return _result(source, tool_id, "PASS", lat,
                           f"IRS BMF eo1.csv returned {resp.status_code}, {len(resp.content)} bytes")
        return _result(source, tool_id, "FAIL", lat,
                       f"IRS BMF eo1.csv status {resp.status_code}",
                       error=f"HTTP {resp.status_code}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "IRS BMF eo1.csv reachable", error=str(exc))


async def canary_uk_charity(client: httpx.AsyncClient) -> dict:
    """T04 — UK Charity Commission: HEAD check on the bulk extract blob."""
    source, tool_id = "uk_charity", "T04"
    t0 = time.monotonic()
    try:
        resp = await client.head(
            "https://ccewuksprdoneregsadata1.blob.core.windows.net"
            "/data/json/publicextract.charity.zip",
            timeout=httpx.Timeout(20.0, connect=8.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        if resp.status_code in (200, 302):
            return _result(source, tool_id, "PASS", lat,
                           f"UK Charity bulk extract HEAD returned {resp.status_code}")
        return _result(source, tool_id, "FAIL", lat,
                       f"UK Charity bulk extract HEAD {resp.status_code}",
                       error=f"HTTP {resp.status_code}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "UK Charity blob reachable", error=str(exc))


async def canary_osv(client: httpx.AsyncClient) -> dict:
    """T10 — OSV.dev: POST query for requests/PyPI, expect vulns key."""
    source, tool_id = "osv_dev", "T10"
    t0 = time.monotonic()
    try:
        resp = await client.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": "requests", "ecosystem": "PyPI"}},
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "vulns" in data:
            return _result(source, tool_id, "PASS", lat,
                           f"OSV.dev returned vulns key ({len(data['vulns'])} entries)")
        return _result(source, tool_id, "FAIL", lat, "OSV.dev vulns key present",
                       error=f"Missing vulns key; got: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "OSV.dev query success", error=str(exc))


async def canary_nist_nvd(client: httpx.AsyncClient) -> dict:
    """T10 — NIST NVD: search log4j, expect totalResults > 0."""
    source, tool_id = "nist_nvd", "T10"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "log4j", "resultsPerPage": 1},
            timeout=httpx.Timeout(20.0, connect=8.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        total = data.get("totalResults", 0)
        if total > 0:
            return _result(source, tool_id, "PASS", lat,
                           f"NIST NVD returned totalResults={total}")
        return _result(source, tool_id, "FAIL", lat, "NIST NVD totalResults > 0",
                       error=f"totalResults={total}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "NIST NVD search success", error=str(exc))


async def canary_deps_dev(client: httpx.AsyncClient) -> dict:
    """T10 — deps.dev: fetch requests/PyPI package, expect versions list."""
    source, tool_id = "deps_dev", "T10"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://api.deps.dev/v3/systems/PYPI/packages/requests",
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        versions = data.get("versions", [])
        if versions:
            return _result(source, tool_id, "PASS", lat,
                           f"deps.dev returned {len(versions)} version(s)")
        return _result(source, tool_id, "FAIL", lat, "deps.dev versions list non-empty",
                       error=f"Keys: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "deps.dev package fetch success", error=str(exc))


async def canary_nppes_npi(client: httpx.AsyncClient) -> dict:
    """T22 — NPPES NPI: lookup NPI 1003000126, expect non-empty results."""
    source, tool_id = "nppes_npi", "T22"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://npiregistry.cms.hhs.gov/api/",
            params={"number": "1003000126", "version": "2.1"},
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        if results:
            return _result(source, tool_id, "PASS", lat,
                           f"NPPES NPI returned {len(results)} result(s)")
        return _result(source, tool_id, "FAIL", lat, "NPPES NPI results non-empty",
                       error=f"Empty results; result_count={data.get('result_count')}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "NPPES NPI lookup success", error=str(exc))


async def canary_finra(client: httpx.AsyncClient) -> dict:
    """T22 — FINRA BrokerCheck: lookup CRD 1234567, expect HTTP 200."""
    source, tool_id = "finra_brokercheck", "T22"
    key = os.environ.get("FINRA_API_KEY", "")
    if not key:
        return _skip(source, tool_id, "FINRA_API_KEY not set")
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://api.finra.org/data/group/registration/name/brokerCheck/individual/1234567",
            headers={"Authorization": f"Bearer {key}",
                     "User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"},
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        # 200 or 404 (not found) both mean the API is reachable
        if resp.status_code in (200, 404):
            return _result(source, tool_id, "PASS", lat,
                           f"FINRA BrokerCheck API returned {resp.status_code}")
        return _result(source, tool_id, "FAIL", lat,
                       f"FINRA BrokerCheck API reachable",
                       error=f"HTTP {resp.status_code}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "FINRA BrokerCheck reachable", error=str(exc))


async def canary_sam_gov(client: httpx.AsyncClient) -> dict:
    """T22 — SAM.gov entity API: name search, expect totalRecords present."""
    source, tool_id = "sam_gov", "T22"
    key = os.environ.get("SAM_GOV_API_KEY", "")
    if not key:
        return _skip(source, tool_id, "SAM_GOV_API_KEY not set")
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://api.sam.gov/entity-information/v3/entities",
            params={
                "api_key": key,
                "legalBusinessName": "IBM",
                "includeSections": "entityRegistration",
            },
            timeout=httpx.Timeout(20.0, connect=8.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "totalRecords" in data:
            return _result(source, tool_id, "PASS", lat,
                           f"SAM.gov totalRecords={data['totalRecords']}")
        return _result(source, tool_id, "FAIL", lat, "SAM.gov totalRecords present",
                       error=f"Keys: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "SAM.gov API success", error=str(exc))


async def canary_iana_rdap(client: httpx.AsyncClient) -> dict:
    """T07 — IANA RDAP: lookup example.com, expect ldhName field."""
    source, tool_id = "iana_rdap", "T07"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://rdap.org/domain/example.com",
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "ldhName" in data:
            return _result(source, tool_id, "PASS", lat,
                           f"RDAP ldhName={data['ldhName']}")
        return _result(source, tool_id, "FAIL", lat, "RDAP ldhName present",
                       error=f"Keys: {list(data.keys())[:8]}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "IANA RDAP lookup success", error=str(exc))


async def canary_crt_sh(client: httpx.AsyncClient) -> dict:
    """T07 — crt.sh: query our own domain (fewer results, faster), expect JSON array."""
    source, tool_id = "crt_sh", "T07"
    t0 = time.monotonic()
    try:
        # Use own domain — returns small result set; example.com returns thousands
        # and times out under load. Timeout 45s; DEGRADED if >20s.
        resp = await client.get(
            "https://crt.sh/",
            params={"q": "datanexusmcp.com", "output": "json"},
            timeout=httpx.Timeout(45.0, connect=10.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        # 502/503 = upstream hardware degraded (known issue since April 2026).
        # Treat as DEGRADED — cached fallback active in tool layer, not a hard FAIL.
        if resp.status_code in (502, 503):
            return _result(source, tool_id, "DEGRADED", lat,
                           f"crt.sh {resp.status_code} — upstream degraded, cached fallback active",
                           error=f"HTTP {resp.status_code}: upstream hardware issue (April 2026)")
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and len(data) > 0:
            status = "PASS" if lat < 20000 else "DEGRADED"
            return _result(source, tool_id, status, lat,
                           f"crt.sh returned {len(data)} cert(s) for datanexusmcp.com")
        return _result(source, tool_id, "FAIL", lat, "crt.sh non-empty JSON array",
                       error=f"Got {type(data).__name__} with {len(data) if isinstance(data, list) else '?'} items")
    except httpx.TimeoutException as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "crt.sh query within 45s",
                       error=f"Timeout after {lat}ms: {exc!r}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "crt.sh query success", error=str(exc))


async def canary_cloudflare_doh(client: httpx.AsyncClient) -> dict:
    """T07 — Cloudflare DoH: resolve example.com A, expect Answer array."""
    source, tool_id = "cloudflare_doh", "T07"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": "example.com", "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=httpx.Timeout(10.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "Answer" in data:
            return _result(source, tool_id, "PASS", lat,
                           f"Cloudflare DoH Answer has {len(data['Answer'])} record(s)")
        return _result(source, tool_id, "FAIL", lat, "Cloudflare DoH Answer present",
                       error=f"Keys: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "Cloudflare DoH query success", error=str(exc))


def _get_epo_token_sync() -> Optional[str]:
    """Fetch EPO OPS OAuth token synchronously for use in async context."""
    client_id     = os.environ.get("EPO_CLIENT_ID", "")
    client_secret = os.environ.get("EPO_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None
    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0)) as c:
            resp = c.post(
                "https://ops.epo.org/3.2/auth/accesstoken",
                data={"grant_type": "client_credentials"},
                auth=(client_id, client_secret),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            return resp.json().get("access_token")
    except Exception:
        return None


async def canary_epo_ops(client: httpx.AsyncClient) -> dict:
    """T11 — EPO OPS: get token, run minimal search, expect HTTP 200."""
    source, tool_id = "epo_ops", "T11"
    client_id = os.environ.get("EPO_CLIENT_ID", "")
    if not client_id:
        return _skip(source, tool_id, "EPO_CLIENT_ID not set")

    t0 = time.monotonic()
    try:
        token = await asyncio.get_event_loop().run_in_executor(None, _get_epo_token_sync)
        if not token:
            lat = int((time.monotonic() - t0) * 1000)
            return _result(source, tool_id, "FAIL", lat,
                           "EPO OPS token fetch", error="Token fetch returned None")

        # Use ti (title field) — validated format for EPO OPS CQL
        resp = await client.get(
            "https://ops.epo.org/3.2/rest-services/published-data/search/biblio",
            params={"q": 'ti = "solar"', "Range": "1-3"},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)",
            },
            timeout=httpx.Timeout(20.0, connect=8.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            search_result = (
                data.get("ops:world-patent-data", {})
                    .get("ops:biblio-search", {})
            )
            total = search_result.get("@total-result-count", "?")
            return _result(source, tool_id, "PASS", lat,
                           f"EPO OPS search returned 200, total-result-count={total}")
        return _result(source, tool_id, "FAIL", lat,
                       f"EPO OPS search HTTP 200",
                       error=f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "EPO OPS search success", error=str(exc))


async def canary_usaspending(client: httpx.AsyncClient) -> dict:
    """T18 — USASpending.gov: minimal search, expect results array."""
    source, tool_id = "usaspending", "T18"
    t0 = time.monotonic()
    try:
        payload = {
            "filters": {
                "keywords": ["software"],
                "award_type_codes": ["A", "B", "C", "D"],
            },
            "fields": ["Award ID", "Recipient Name", "Award Amount"],
            "page": 1, "limit": 1, "sort": "Award Amount",
            "order": "desc", "subawards": False,
        }
        resp = await client.post(
            "https://api.usaspending.gov/api/v2/search/spending_by_award/",
            json=payload,
            timeout=httpx.Timeout(20.0, connect=8.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "results" in data:
            return _result(source, tool_id, "PASS", lat,
                           f"USASpending results array present ({len(data['results'])} item(s))")
        return _result(source, tool_id, "FAIL", lat, "USASpending results array present",
                       error=f"Keys: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "USASpending search success", error=str(exc))


async def canary_cisa_kev(client: httpx.AsyncClient) -> dict:
    """T10 — CISA KEV: fetch catalog JSON, assert HTTP 200 + vulnerabilities key."""
    source, tool_id = "cisa_kev", "T10"
    t0 = time.monotonic()
    try:
        # GitHub mirror used instead of cisa.gov direct — Akamai CDN blocks
        # all datacenter IPs (403). Mirror is maintained by CISA officially:
        # https://github.com/cisagov/kev-data
        resp = await client.get(
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
            headers={"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"},
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "vulnerabilities" in data:
            count = len(data["vulnerabilities"])
            return _result(source, tool_id, "PASS", lat,
                           f"CISA KEV catalog returned {count} vulnerabilities")
        return _result(source, tool_id, "FAIL", lat, "CISA KEV vulnerabilities key present",
                       error=f"Missing vulnerabilities key; got: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "CISA KEV catalog fetch success", error=str(exc))


async def canary_epss(client: httpx.AsyncClient) -> dict:
    """T10 — FIRST EPSS: GET api.first.org/epss?cve=CVE-2021-44228, assert HTTP 200 + data key."""
    source, tool_id = "first_epss", "T10"
    t0 = time.monotonic()
    try:
        resp = await client.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": "CVE-2021-44228"},
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "data" in data and data["data"]:
            epss_val = data["data"][0].get("epss", "?")
            return _result(source, tool_id, "PASS", lat,
                           f"FIRST EPSS returned epss={epss_val} for CVE-2021-44228")
        return _result(source, tool_id, "FAIL", lat, "FIRST EPSS data key non-empty",
                       error=f"data={data.get('data', [])!r}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "FIRST EPSS API fetch success", error=str(exc))


async def canary_regulations_gov(client: httpx.AsyncClient) -> dict:
    """T19 — Regulations.gov: fetch 5 EPA documents, expect data array."""
    source, tool_id = "regulations_gov", "T19"
    key = os.environ.get("REGULATIONS_GOV_KEY", "")
    if not key:
        return _skip(source, tool_id, "REGULATIONS_GOV_KEY not set")
    t0 = time.monotonic()
    try:
        # pageSize must be >= 5; filter[agencyId] required to avoid 400
        resp = await client.get(
            "https://api.regulations.gov/v4/documents",
            params={
                "api_key":            key,
                "filter[agencyId]":   "EPA",
                "page[number]":       1,
                "page[size]":         5,
            },
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        lat = int((time.monotonic() - t0) * 1000)
        resp.raise_for_status()
        data = resp.json()
        if "data" in data:
            return _result(source, tool_id, "PASS", lat,
                           f"Regulations.gov data array present ({len(data['data'])} item(s))")
        return _result(source, tool_id, "FAIL", lat, "Regulations.gov data array present",
                       error=f"Keys: {list(data.keys())}")
    except Exception as exc:
        lat = int((time.monotonic() - t0) * 1000)
        return _result(source, tool_id, "FAIL", lat, "Regulations.gov fetch success", error=str(exc))


# ── Per-canary run intervals (quota protection) ────────────────────────────────

# Maps canary source names to minimum hours between runs.
# SAM.gov has a hard 1,000 req/day limit — running it every canary cycle
# (hourly) exhausts the quota before real user tool calls can use it.
_CANARY_INTERVALS: dict[str, int] = {
    "sam_gov": 24,  # run_interval_hours=24: once per day at most
}


def _get_canary_last_run(source: str) -> Optional[str]:
    """Read last canary run timestamp from Redis. Returns ISO string or None."""
    try:
        import redis as _redis
        _r = _redis.from_url(
            os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379"),
            decode_responses=True, socket_connect_timeout=2,
        )
        return _r.get(f"datanexus:canary:{source}:last_run")
    except Exception:
        return None


def _set_canary_last_run(source: str, interval_h: int) -> None:
    """Write canary run timestamp to Redis (TTL = interval + 1h buffer)."""
    try:
        import redis as _redis
        _r = _redis.from_url(
            os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379"),
            decode_responses=True, socket_connect_timeout=2,
        )
        _r.set(
            f"datanexus:canary:{source}:last_run",
            datetime.now(timezone.utc).isoformat(),
            ex=interval_h * 3600 + 3600,
        )
    except Exception:
        pass


def _should_throttle_canary(source: str) -> bool:
    """Return True if this canary is within its run_interval_hours window."""
    interval_h = _CANARY_INTERVALS.get(source, 0)
    if not interval_h:
        return False
    last_run_str = _get_canary_last_run(source)
    if not last_run_str:
        return False
    try:
        last_dt = datetime.fromisoformat(last_run_str)
        elapsed_h = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600
        return elapsed_h < interval_h
    except Exception:
        return False


async def _run_or_throttle(canary_fn, client: httpx.AsyncClient) -> dict:
    """Run a canary or return SKIP if within its run_interval_hours window."""
    source = canary_fn.__name__.removeprefix("canary_")
    if _should_throttle_canary(source):
        interval_h = _CANARY_INTERVALS[source]
        return _skip(source, "T22",
                     f"run_interval_hours={interval_h}: SAM.gov quota protection active")
    result = await canary_fn(client)
    # Record run time after attempting (protects quota even on 429)
    if source in _CANARY_INTERVALS:
        _set_canary_last_run(source, _CANARY_INTERVALS[source])
    return result


# ── Redis write ────────────────────────────────────────────────────────────────

def _write_to_redis(results: list[dict]) -> None:
    """Write canary results to Redis (fire-and-forget, never raises)."""
    try:
        import redis
        redis_url = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
        r = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
        r.ping()
        pipe = r.pipeline()
        for res in results:
            key = f"datanexus:canary:{res['source']}"
            pipe.hset(key, mapping={
                "status":     res["status"],
                "latency_ms": str(res["latency_ms"]),
                "checked_at": res["ts"],
                "tool_id":    res["tool_id"],
                "check":      res["check"],
                "error":      res["error"] or "",
            })
            pipe.expire(key, 7200)  # 2-hour TTL
        pipe.execute()
        log.info("Canary results written to Redis (%d keys)", len(results))
    except Exception as exc:
        log.warning("Redis write skipped: %s", exc)


# ── Runner ─────────────────────────────────────────────────────────────────────

_CANARIES = [
    canary_irs_bmf,
    canary_uk_charity,
    canary_osv,
    canary_nist_nvd,
    canary_deps_dev,
    canary_cisa_kev,      # Sprint 4 — T10 CISA KEV
    canary_epss,          # Sprint 4 — T10 FIRST EPSS
    canary_nppes_npi,
    canary_finra,
    canary_sam_gov,
    canary_iana_rdap,
    canary_crt_sh,
    canary_cloudflare_doh,
    canary_epo_ops,
    canary_usaspending,
    canary_regulations_gov,
]

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}


async def run_all() -> list[dict]:
    """Run all canaries concurrently. Returns list of result dicts."""
    async with httpx.AsyncClient(
        headers=_HEADERS,
        follow_redirects=True,
    ) as client:
        tasks = [_run_or_throttle(canary, client) for canary in _CANARIES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    final = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            name = _CANARIES[i].__name__
            final.append(_result(name, "??", "FAIL", 0,
                                 "canary raised exception", error=str(res)))
        else:
            final.append(res)
    return final


def main() -> int:
    """Entry point for standalone execution. Returns exit code (0=all pass/skip)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )

    t_start = time.monotonic()
    results = asyncio.run(run_all())
    elapsed = time.monotonic() - t_start

    counts = {"PASS": 0, "FAIL": 0, "DEGRADED": 0, "SKIP": 0}
    print(f"\n{'─'*72}")
    print(f"  DataNexus Upstream Canary — {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'─'*72}")

    for r in results:
        icon = {"PASS": "✓", "FAIL": "✗", "DEGRADED": "~", "SKIP": "·"}.get(r["status"], "?")
        lat  = f"{r['latency_ms']:>5}ms" if r["status"] not in ("SKIP",) else "      "
        print(f"  {icon} [{r['tool_id']:<3}] {r['source']:<22} {lat}  {r['check']}")
        if r["error"] and r["status"] not in ("SKIP",):
            print(f"          ERROR: {r['error']}")
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        # Print machine-readable line for log parsing
        print(json.dumps(r))

    print(f"{'─'*72}")
    print(f"  PASS={counts['PASS']}  FAIL={counts['FAIL']}  "
          f"DEGRADED={counts['DEGRADED']}  SKIP={counts['SKIP']}  "
          f"elapsed={elapsed:.1f}s")
    print(f"{'─'*72}\n")

    _write_to_redis(results)

    return 1 if counts["FAIL"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
