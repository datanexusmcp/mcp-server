"""
datanexus/tools/t04.py — T04 IRS 990 / Nonprofit Data tool.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 12.4 / Phase 2 Step B

Exactly 3 data functions + 2 infrastructure stubs = 5 total.
(Section 11.3, Table 163 — authoritative signatures)

Data sources:
  Primary:   IRS EO BMF (irs.gov) — public domain
  Secondary: IRS TEOS bulk downloads (irs.gov) — public domain
  Tertiary:  UK Charity Commission public bulk extract (no auth required)
             ccewuksprdoneregsadata1.blob.core.windows.net
             Open Government Licence v3.0
             Commercial use permitted WITH UK GDPR mitigation.

Hard stops:
  - IRS direct sources only — no third-party aggregators (CC-NC restricted).
  - NEVER return trustee names, officer details, or personal addresses.
  - UK charity cache TTL: 86400s (24h) — UK GDPR maximum.
  - NEVER add donor data, individual giving history, or donation amounts.

UK GDPR data controller statement (required in all UK charity responses):
  "DataNexus acts as data controller for UK charity data processed via this
  tool. Data sourced from Charity Commission for England and Wales under
  Open Government Licence v3.0."
"""

import asyncio
import csv
import io
import json
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import Field

import httpx
from fastmcp import FastMCP

from datanexus.analytics import fire_and_forget, track_tool_call, track_tool_error

from datanexus.core.audit import (
    AuditContext,
    make_params_hash,
    standard_response_fields,
)
from datanexus.core.cache import (
    compute_payload_hash,
    get_cached,
    set_cached,
)
from datanexus.core.circuit_breaker import (
    get_staleness_notice,
    is_tripped,
    record_failure_sync,
    record_success_sync,
)
from payment.entitlement import verify_entitlement
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout

log = logging.getLogger("datanexus.tools.t04")

mcp = FastMCP("datanexus-t04")

# ── Constants ─────────────────────────────────────────────────────────────────

T04_DISCLAIMER = (
    "Data sourced from IRS EO BMF and IRS TEOS (public domain). "
    "DataNexus does not warrant accuracy. "
    "Verify against primary source before making business decisions."
)

UK_DISCLAIMER = (
    "UK charity data sourced from the Charity Commission for England and Wales "
    "under Open Government Licence v3.0. "
    "DataNexus acts as data controller for UK charity data processed via this tool. "
    "For due diligence and research purposes. "
    "Not for profiling individuals associated with charities. "
    "Individuals may contact dataprotection@datanexusmcp.com to exercise "
    "rights under UK GDPR Article 17."
)

_IRS_BMF_URLS = [
    "https://www.irs.gov/pub/irs-soi/eo1.csv",
    "https://www.irs.gov/pub/irs-soi/eo2.csv",
    "https://www.irs.gov/pub/irs-soi/eo3.csv",
    "https://www.irs.gov/pub/irs-soi/eo4.csv",
]

# UK Charity Commission public bulk extract — no authentication required.
# Attribution URL: the official register download page (charitycommission.gov.uk).
UK_CHARITY_SOURCE_URL = (
    "https://register-of-charities.charitycommission.gov.uk"
    "/register/full-register-download"
)
UK_CHARITY_BULK_URL = (
    "https://ccewuksprdoneregsadata1.blob.core.windows.net"
    "/data/json/publicextract.charity.zip"
)

_HTTP_TIMEOUT = httpx.Timeout(45.0, connect=10.0)
_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

IRS_BMF_TTL   = 604800   # 7 days
UK_CHARITY_TTL = 86400   # 24h — UK GDPR maximum


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 1 — fetch_nonprofit_by_ein
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T04")
async def fetch_nonprofit_by_ein(ein: Annotated[str, Field(description="EIN in format XX-XXXXXXX e.g. 46-5734087. Required.")]) -> dict:
    """Fetch IRS 990 filing data for any US nonprofit by EIN. Read-only. No side effects. Idempotent. US only. ein: 9-digit Employer ID with or without dash, e.g. 46-5734087 or 465734087. Required. Returns name, revenue, expenses, assets, NTEE code, and mission from the most recent 990 filing. Use this when you have the exact EIN. Use nonprofit_search_nonprofits_by_name instead when you only have a name. Verified source: IRS EO BMF + IRS TEOS. 7-day cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="nonprofit_fetch_nonprofit_by_ein", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        # Normalise EIN — strip dashes, leading zeros
        ein_clean = ein.replace("-", "").strip()
        params = {"ein": ein_clean}

        async with AuditContext("T04", params, "1.0") as ctx:
            phash = make_params_hash(params)

            # ── 1. Cache check ────────────────────────────────────────────────────
            cached = get_cached("T04", phash)
            if cached:
                ctx.set_cache_hit(True)
                log.info("t04.fetch_nonprofit_by_ein cache_hit ein=%s", ein_clean)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            # ── 2. Circuit breaker check ──────────────────────────────────────────
            bmf_down  = is_tripped("irs_bmf")
            teos_down = is_tripped("irs_teos")

            if bmf_down and teos_down:
                archive = get_cached("T04", phash + "_archive")
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
                return {
                    "tool_id":         "T04",
                    "data":            archive or {},
                    "markdown_output": _archive_markdown(archive, ein_clean),
                    "staleness_notice": get_staleness_notice(
                        "irs_bmf",
                        (archive or {}).get("data_as_of", "unknown"),
                    ),
                    "disclaimer": T04_DISCLAIMER,
                    "cache_hit":  False,
                    "sha256_hash": "",
                    **standard_response_fields(ctx.query_hash, "", False),
                }

            # ── 3. Live lookup — Redis BMF index first ────────────────────────────
            result = await _lookup_ein(ein_clean)
            ingest_healthy = True

            if not result:
                # BMF worker hasn't run yet or EIN not found
                ingest_healthy = False
                return error_response(
                    error_code=ErrorCode.NOT_FOUND,
                    message=f"EIN {ein_clean} not found in IRS EO BMF. "
                            "Verify the EIN is correct and the organisation is active.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                )

            # ── 4. Build payload ──────────────────────────────────────────────────
            raw_bytes      = json.dumps(result).encode()
            payload_hash   = compute_payload_hash(raw_bytes)
            markdown       = _build_nonprofit_markdown(result, ein_clean)
            data_as_of     = datetime.now(timezone.utc).isoformat()

            payload = {
                "tool_id":         "T04",
                "source_url":      "https://www.irs.gov/pub/irs-soi/eo1.csv",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            result,
                "markdown_output": markdown,
                "disclaimer":      T04_DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  ingest_healthy,
            }

            # ── 5. Store in cache ─────────────────────────────────────────────────
            set_cached("T04", phash, payload, IRS_BMF_TTL)
            set_cached("T04", phash + "_archive", payload, IRS_BMF_TTL * 4)
            ctx.set_cache_hit(False)
            record_success_sync("irs_bmf")

            log.info("t04.fetch_nonprofit_by_ein ok ein=%s name=%s",
                     ein_clean, result.get("name", ""))

            _out = {
                **payload,
                **standard_response_fields(ctx.query_hash, data_as_of, ingest_healthy),
            }
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T04",
            tool_name="fetch_nonprofit_by_ein",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — search_nonprofits_by_name
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T04")
async def search_nonprofits_by_name(name: Annotated[str, Field(description="Organization name to search e.g. Red Cross. Required.")], state: Annotated[str, Field(description="Two-letter US state code e.g. CA. Optional.")] = "") -> dict:
    """Search US nonprofits by name with optional state filter. Read-only. No side effects. Idempotent. US only. Returns up to 25 matches. name: Full or partial organisation name. Required. state: Two-letter US state code e.g. CA, NY. Optional, defaults to all states. Returns EIN, name, state, revenue, and NTEE code for each match. Use this when you have a name but not the EIN. Use nonprofit_fetch_nonprofit_by_ein instead when you have the exact EIN for a precise single lookup. Verified source: IRS EO BMF. 7-day cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="nonprofit_search_nonprofits_by_name", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        name_clean  = name.strip().upper()
        state_clean = state.strip().upper()
        params      = {"name": name_clean, "state": state_clean}

        async with AuditContext("T04", params, "1.0") as ctx:
            phash = make_params_hash(params)

            # ── Cache check ───────────────────────────────────────────────────────
            cached = get_cached("T04", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        True,
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            # ── Live search — stream CSVs ─────────────────────────────────────────
            results = await _search_by_name_live(name_clean, state_clean, limit=25)
            data_as_of = datetime.now(timezone.utc).isoformat()
            if not results and is_tripped("irs_bmf"):
                return error_response(
                    error_code=ErrorCode.CIRCUIT_OPEN,
                    message="IRS data source currently unavailable. Try again later.",
                    query_hash=ctx.query_hash,
                    retry_after=300,
                    ingest_healthy=False,
                )

            raw_bytes    = json.dumps(results).encode()
            payload_hash = compute_payload_hash(raw_bytes)
            markdown     = _build_search_markdown(results, name, state)

            payload = {
                "tool_id":         "T04",
                "source_url":      "https://www.irs.gov/pub/irs-soi/eo1.csv",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            {"results": results, "count": len(results)},
                "markdown_output": markdown,
                "disclaimer":      T04_DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            set_cached("T04", phash, payload, IRS_BMF_TTL)
            ctx.set_cache_hit(False)
            record_success_sync("irs_bmf")

            log.info("t04.search_nonprofits_by_name results=%d name=%s state=%s",
                     len(results), name_clean, state_clean)

            _out = {
                **payload,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T04",
            tool_name="search_nonprofits_by_name",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_charity_uk
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T04")
async def fetch_charity_uk(charity_number_or_name: Annotated[str, Field(description="UK charity number e.g. 1089464 or name substring. Required.")]) -> dict:
    """Fetch UK registered charity details by charity number or organisation name. Read-only. No side effects. Idempotent. UK only. charity_number_or_name: UK registered charity number (7 digits, e.g. 1234567) or full/partial organisation name. Required. Returns registration status, income, expenditure, activities, and trustee count. Use this for UK charities. Use nonprofit_fetch_nonprofit_by_ein or nonprofit_search_nonprofits_by_name for US nonprofits. Verified source: UK Charity Commission OGL v3. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="nonprofit_fetch_charity_uk", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        query = charity_number_or_name.strip()
        params = {"charity_number_or_name": query}

        async with AuditContext("T04", params, "1.0") as ctx:
            # Determine if query is a registration number or name
            is_number = query.replace("-", "").isdigit()
            regno = query if is_number else None
            phash = make_params_hash(params)

            # ── Cache check ───────────────────────────────────────────────────────
            cache_key = f"uk:{regno}" if regno else phash
            cached = get_cached("T04", cache_key) or get_cached("T04", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        True,
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            # ── Circuit breaker ───────────────────────────────────────────────────
            if is_tripped("uk_charity"):
                archive = get_cached("T04", cache_key + "_archive")
                _error_code = "CIRCUIT_OPEN"
                return {
                    "tool_id":         "T04",
                    "data":            archive or {},
                    "markdown_output": "UK Charity data temporarily unavailable. "
                                       "Please try again later.",
                    "staleness_notice": get_staleness_notice(
                        "uk_charity",
                        (archive or {}).get("data_as_of", "unknown"),
                    ),
                    "disclaimer":  UK_DISCLAIMER,
                    "cache_hit":   False,
                    "sha256_hash": "",
                    **standard_response_fields(ctx.query_hash, "", False),
                }

            # ── Live fetch — bulk extract (no auth required) ─────────────────────
            # Primary: Redis index populated by UKCharityWorker (fast).
            # Fallback: download full bulk extract ZIP from Azure blob storage.
            # No API key needed for either path.
            try:
                if regno:
                    result = await _fetch_uk_by_number(regno)
                else:
                    result = await _search_uk_by_name(query)

            except httpx.TimeoutException:
                record_failure_sync("uk_charity")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="UK Charity Commission bulk data timed out. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )
            except Exception:
                record_failure_sync("uk_charity")
                log.exception("t04.fetch_charity_uk unexpected error query=%s", query)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                )

            if not result:
                return error_response(
                    error_code=ErrorCode.NOT_FOUND,
                    message=f"Charity '{query}' not found in UK Charity Commission register.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            raw_bytes    = json.dumps(result).encode()
            payload_hash = compute_payload_hash(raw_bytes)
            data_as_of   = datetime.now(timezone.utc).isoformat()
            markdown     = _build_uk_charity_markdown(result)

            payload = {
                "status":          "ok",
                "tool_id":         "T04",
                "source_url":      UK_CHARITY_SOURCE_URL,
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            result,
                "markdown_output": markdown,
                "disclaimer":      UK_DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            # TTL: 86400s — UK GDPR maximum, not negotiable
            set_cached("T04", phash, payload, UK_CHARITY_TTL)
            if regno:
                set_cached("T04", f"uk:{regno}", payload, UK_CHARITY_TTL)
                set_cached("T04", f"uk:{regno}_archive", payload, UK_CHARITY_TTL * 4)
            ctx.set_cache_hit(False)
            record_success_sync("uk_charity")

            log.info("t04.fetch_charity_uk ok regno=%s name=%s",
                     regno, result.get("name", ""))

            _out = {
                **payload,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T04",
            tool_name="fetch_charity_uk",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE STUBS (replaced in Phase 4 and Phase 5)
# ══════════════════════════════════════════════════════════════════════════════

async def report_feedback(
    tool_id: str,
    query_hash: str,
    signal: str,
    comment: str = "",
) -> dict:
    """
    Submit feedback about a tool response.
    Stub — replaced by feedback.collector.report_feedback in Phase 4.
    Always returns {'status': 'recorded'}.
    """
    return {"status": "recorded"}


async def report_mcpize_link(tool_id: str = "T04") -> dict:
    """
    Get the MCPize subscription link for T04.
    Delegates to payment.tools.report_mcpize_link (Phase 5).
    Returns status='free' during the free window, or upgrade_url when active.
    """
    from payment.tools import report_mcpize_link as _real
    return _real(tool_id)


# Register infrastructure stubs
mcp.tool()(report_feedback)
mcp.tool()(report_mcpize_link)


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def _lookup_ein(ein_clean: str) -> Optional[dict]:
    # 1. Redis cache (populated by IRSBMFWorker)
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    r = _get_redis()
    if r is not None:
        try:
            raw = r.get(f"datanexus:T04:bmf:{ein_clean}")
            if raw:
                return json.loads(raw)
        except Exception:
            pass

    # 2. Live CSV stream fallback (BMF worker not yet run)
    return await _lookup_ein_csv_live(ein_clean)


async def _lookup_ein_csv_live(ein_clean: str) -> Optional[dict]:
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True
    ) as client:
        for url in _IRS_BMF_URLS:
            try:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    content = await resp.aread()

                text   = content.decode("utf-8", errors="replace")
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    if row.get("EIN", "").strip() == ein_clean:
                        record_success_sync("irs_bmf")
                        return {
                            "ein":        row.get("EIN", "").strip(),
                            "name":       row.get("NAME", "").strip(),
                            "street":     row.get("STREET", "").strip(),
                            "city":       row.get("CITY", "").strip(),
                            "state":      row.get("STATE", "").strip(),
                            "zip":        row.get("ZIP", "").strip(),
                            "ntee_code":  row.get("NTEE_CD", "").strip(),
                            "ruling":     row.get("RULING", "").strip(),
                            "subsection": row.get("SUBSECTION", "").strip(),
                            "status":     row.get("STATUS", "").strip(),
                            "tax_period": row.get("TAX_PERIOD", "").strip(),
                            "asset_amt":  row.get("ASSET_AMT", "").strip(),
                            "income_amt": row.get("INCOME_AMT", "").strip(),
                            "revenue_amt":row.get("REVENUE_AMT", "").strip(),
                            "source":     "IRS EO BMF",
                        }
            except Exception as exc:
                log.warning("_lookup_ein_csv_live url=%s error=%s", url, exc)
                record_failure_sync("irs_bmf")
                continue

    return None


async def _search_by_name_live(name: str, state: str, limit: int = 25) -> list:
    results = []
    name_upper = name.upper()

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True
    ) as client:
        for url in _IRS_BMF_URLS:
            if len(results) >= limit:
                break
            try:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    content = await resp.aread()

                text   = content.decode("utf-8", errors="replace")
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    if len(results) >= limit:
                        break
                    row_name  = row.get("NAME", "").upper()
                    row_state = row.get("STATE", "").upper()
                    if name_upper not in row_name:
                        continue
                    if state and row_state != state:
                        continue
                    results.append({
                        "ein":       row.get("EIN", "").strip(),
                        "name":      row.get("NAME", "").strip(),
                        "city":      row.get("CITY", "").strip(),
                        "state":     row.get("STATE", "").strip(),
                        "ntee_code": row.get("NTEE_CD", "").strip(),
                        "revenue":   row.get("REVENUE_AMT", "").strip(),
                        "source":    "IRS EO BMF",
                    })
            except Exception as exc:
                log.warning("_search_by_name_live url=%s error=%s", url, exc)
                continue

    return results


async def _fetch_uk_by_number(regno: str) -> Optional[dict]:
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    from datanexus.ingest.t04_worker import fetch_uk_charity_bulk_single

    # Fast path: Redis
    r = _get_redis()
    if r is not None:
        try:
            raw = r.get(f"datanexus:T04:uk:{regno}")
            if raw:
                return json.loads(raw)
        except Exception:
            pass

    # Slow fallback: bulk extract download (no auth, ~30-40s, one-time per boot)
    return await fetch_uk_charity_bulk_single(regno)


async def _search_uk_by_name(name: str) -> Optional[dict]:
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    from datanexus.ingest.t04_worker import search_uk_charity_bulk_by_name

    name_upper = name.upper()

    # Fast path: Redis prefix index
    r = _get_redis()
    if r is not None:
        try:
            prefix = name_upper[:4]
            regnos = r.smembers(f"datanexus:T04:uk:name:{prefix}")
            for regno in regnos:
                raw = r.get(f"datanexus:T04:uk:{regno}")
                if raw:
                    record = json.loads(raw)
                    if name_upper in record.get("name", "").upper():
                        return record
        except Exception:
            pass

    # Slow fallback: bulk extract search
    results = await search_uk_charity_bulk_by_name(name, limit=1)
    return results[0] if results else None


# ── Markdown builders ─────────────────────────────────────────────────────────

def _build_nonprofit_markdown(result: dict, ein: str) -> str:
    """Build AI-Ready Markdown for a US nonprofit EIN lookup result."""
    name      = result.get("name", "Unknown")
    city      = result.get("city", "")
    state     = result.get("state", "")
    ntee      = result.get("ntee_code", "")
    ruling    = result.get("ruling", "")
    assets    = _fmt_amount(result.get("asset_amt", ""))
    income    = _fmt_amount(result.get("income_amt", ""))
    revenue   = _fmt_amount(result.get("revenue_amt", ""))
    tax_per   = result.get("tax_period", "")

    lines = [
        f"## {name}",
        f"**EIN:** {ein}  |  **Location:** {city}, {state}",
        "",
    ]
    if ntee:
        lines.append(f"**NTEE Code:** {ntee}")
    if ruling:
        lines.append(f"**IRS Ruling Date:** {ruling[:4]}-{ruling[4:6]}" if len(ruling) >= 6 else f"**Ruling:** {ruling}")
    if tax_per:
        lines.append(f"**Tax Period End:** {tax_per[:4]}-{tax_per[4:6]}" if len(tax_per) >= 6 else f"**Tax Period:** {tax_per}")
    lines.append("")
    lines.append("### Financial Summary (most recent IRS filing)")
    lines.append("| Metric | Amount |")
    lines.append("|--------|--------|")
    lines.append(f"| Revenue | {revenue} |")
    lines.append(f"| Income | {income} |")
    lines.append(f"| Total Assets | {assets} |")
    lines.append("")
    lines.append(f"*{T04_DISCLAIMER}*")
    return "\n".join(lines)


def _build_search_markdown(results: list, name: str, state: str) -> str:
    """Build AI-Ready Markdown for a nonprofit name search."""
    header = f"## US Nonprofit Search: '{name}'"
    if state:
        header += f" (State: {state})"
    lines = [header, f"Found **{len(results)}** results.\n"]

    if not results:
        lines.append("No organisations found matching the search criteria.")
    else:
        lines.append("| EIN | Name | City | State | NTEE | Revenue |")
        lines.append("|-----|------|------|-------|------|---------|")
        for r in results:
            lines.append(
                f"| {r.get('ein','')} | {r.get('name','')} "
                f"| {r.get('city','')} | {r.get('state','')} "
                f"| {r.get('ntee_code','')} "
                f"| {_fmt_amount(r.get('revenue',''))} |"
            )

    lines.append(f"\n*{T04_DISCLAIMER}*")
    return "\n".join(lines)


def _build_uk_charity_markdown(result: dict) -> str:
    """Build AI-Ready Markdown for a UK charity lookup."""
    name   = result.get("name", "Unknown")
    regno  = result.get("charity_number", "")
    status = result.get("status", "")
    income = result.get("income", "")
    expend = result.get("expenditure", "")
    acts   = result.get("activities", "")
    regdat = result.get("registration_date", "")
    web    = result.get("web", "")

    lines = [
        f"## {name}",
        f"**Charity Number:** {regno}  |  **Status:** {status}",
        "",
    ]
    if regdat:
        lines.append(f"**Registered:** {regdat}")
    if web:
        lines.append(f"**Website:** {web}")
    lines.append("")
    lines.append("### Financial Summary")
    lines.append("| Metric | Amount |")
    lines.append("|--------|--------|")
    lines.append(f"| Latest Income | {_fmt_amount(str(income))} |")
    lines.append(f"| Latest Expenditure | {_fmt_amount(str(expend))} |")
    if acts:
        lines.append("")
        lines.append("### Activities")
        lines.append(acts)
    lines.append("")
    lines.append(f"*{UK_DISCLAIMER}*")
    return "\n".join(lines)


def _archive_markdown(archive: Optional[dict], ein: str) -> str:
    if archive and archive.get("markdown_output"):
        return archive["markdown_output"]
    return (
        f"## EIN {ein} — Archived Data\n"
        "IRS data sources are temporarily unavailable. "
        "Serving last known data.\n\n"
        f"*{T04_DISCLAIMER}*"
    )


def _fmt_amount(raw: str) -> str:
    """Format a raw dollar amount string for display."""
    if not raw or raw.strip() in ("", "0", "00"):
        return "N/A"
    try:
        val = int(raw.strip())
        if val == 0:
            return "N/A"
        if val >= 1_000_000_000:
            return f"${val/1_000_000_000:.1f}B"
        if val >= 1_000_000:
            return f"${val/1_000_000:.1f}M"
        if val >= 1_000:
            return f"${val/1_000:.0f}K"
        return f"${val:,}"
    except (ValueError, TypeError):
        return raw.strip() or "N/A"
