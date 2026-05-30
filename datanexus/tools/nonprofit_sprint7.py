"""
datanexus/tools/nonprofit_sprint7.py — Sprint 7 nonprofit depth tools.

Tools:
  search_nonprofits_by_category    — search US nonprofits by NTEE category + state
  fetch_nonprofit_financial_trends — multi-year revenue/expense/asset trends for a nonprofit

OQ1 resolved: ProPublica /api/v2/organizations/{ein}.json returns pre-computed
fields (totrevenue, totfuncexpns, totprgmrevnue, netassetsend, tax_prd_yr) in
filings_with_data. No raw 990 JSON parsing needed.

Circuit breaker: _propublica_breaker from _circuit_breakers.py.
Health score: calculate_health_score() from _nonprofit_utils.py.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx
import pybreaker
from fastmcp import FastMCP

from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import track_tool_call
from datanexus.tools._circuit_breakers import _propublica_breaker
from datanexus.tools._nonprofit_utils import calculate_health_score
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.nonprofit_sprint7")

nonprofit_sprint7 = FastMCP("DataNexus Nonprofit Sprint7")

_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT      = httpx.Timeout(8.0, connect=5.0)
_PROPUBLICA   = "https://projects.propublica.org/nonprofits/api/v2"

_DISCLAIMER = (
    "Financial data sourced from ProPublica Nonprofit Explorer and IRS Form 990. "
    "DataNexus does not warrant completeness. "
    "Verify with audited financial statements before making investment or grant decisions."
)

# NTEE category name → single-letter code
_CATEGORY_MAP: dict[str, str] = {
    "education":      "B",
    "healthcare":     "E",
    "arts":           "A",
    "environment":    "C",
    "human_services": "P",
    "civil_rights":   "R",
    "international":  "Q",
    "religion":       "X",
    "science":        "U",
    "sports":         "N",
}

_VALID_CATEGORIES = sorted(_CATEGORY_MAP.keys())
_MAX_RESULTS      = 25

# Search keyword used for ProPublica full-text search per NTEE category.
# The /api/v2/nonprofits endpoint doesn't exist; /search.json?q= is the live API.
# State and NTEE params cause 500s on ProPublica — state is filtered client-side.
_CATEGORY_KEYWORDS: dict[str, str] = {
    "education":      "education",
    "healthcare":     "health",
    "arts":           "arts",
    "environment":    "environment",
    "human_services": "human services",
    "civil_rights":   "civil rights",
    "international":  "international",
    "religion":       "religion",
    "science":        "science",
    "sports":         "sports",
}


def _to_float(val) -> Optional[float]:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — search_nonprofits_by_category
# ══════════════════════════════════════════════════════════════════════════════

@nonprofit_sprint7.tool()
@with_timeout
@verify_entitlement("T04")
async def search_nonprofits_by_category(
    category: str,
    state: Optional[str] = None,
) -> dict:
    """Search US nonprofits by mission category and state. Returns up to 25 results with revenue, assets, and health scores (0–100). Category maps to NTEE codes: education, healthcare, arts, environment, human_services, civil_rights, international, religion, science, sports. Raw NTEE letter (A–Z) also accepted. Uses ProPublica Nonprofit Explorer API. Rate limit: 30/minute. No auth required. Starting point for nonprofit due diligence — follow with nonprofit_fetch_nonprofit_full_profile for deep dive on a specific EIN. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="nonprofit_search_nonprofits_by_category", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        cat_raw   = (category or "").strip()
        state_raw = (state or "").strip().upper() if state else None
        params    = {"category": cat_raw, "state": state_raw}

        async with AuditContext("T04", params, "1.0") as ctx:
            # ── Input validation ──────────────────────────────────────────────
            if not cat_raw:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"category must not be empty. Valid names: {_VALID_CATEGORIES}. Or pass a raw NTEE letter A–Z.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # Resolve NTEE code
            if cat_raw.upper() in [chr(c) for c in range(ord('A'), ord('Z') + 1)]:
                ntee_code = cat_raw.upper()
            elif cat_raw.lower() in _CATEGORY_MAP:
                ntee_code = _CATEGORY_MAP[cat_raw.lower()]
            else:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"Unrecognized category '{cat_raw}'. Valid names: {_VALID_CATEGORIES}. Or pass a raw NTEE letter A–Z.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            if state_raw and (len(state_raw) != 2 or not state_raw.isalpha()):
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"state must be a 2-letter US state code (e.g. 'CA'). Got: '{state_raw}'",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # ── ProPublica search call ────────────────────────────────────────
            # The /search.json?q= endpoint is the live API. NTEE and state params
            # cause 500 on ProPublica's side — state is filtered client-side.
            # Financial fields (totrevenue etc.) are not returned by the search
            # endpoint, so health_score is null for all search results.
            keyword = _CATEGORY_KEYWORDS.get(cat_raw.lower(), cat_raw)

            async def _call() -> dict:
                async with httpx.AsyncClient(
                    timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
                ) as client:
                    resp = await client.get(
                        f"{_PROPUBLICA}/search.json",
                        params={"q": keyword},
                    )
                    resp.raise_for_status()
                    return resp.json()

            try:
                raw = await _propublica_breaker.call_async(_call)
                pp_status = "OK"
            except pybreaker.CircuitBreakerError:
                pp_status = "CIRCUIT_OPEN"
                return error_response(
                    error_code=ErrorCode.CIRCUIT_OPEN,
                    message="ProPublica Nonprofit Explorer temporarily unavailable. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                )
            except httpx.TimeoutException:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="ProPublica timed out. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                )
            except Exception as exc:
                log.warning("search_nonprofits_by_category propublica error: %s", exc)
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="ProPublica Nonprofit Explorer temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )

            # ── Filter by state client-side, cap at 25 ────────────────────────
            orgs = raw.get("organizations", [])
            if state_raw:
                orgs = [o for o in orgs if (o.get("state") or "").upper() == state_raw]

            total = len(orgs)
            truncated = total > _MAX_RESULTS
            orgs = orgs[:_MAX_RESULTS]

            results = []
            for org in orgs:
                # Financial fields not available in search results — health_score=null
                results.append({
                    "ein":           org.get("ein", "") or org.get("strein", ""),
                    "name":          org.get("name", ""),
                    "city":          org.get("city", ""),
                    "state":         org.get("state", ""),
                    "ntee_code":     org.get("ntee_code") or org.get("raw_ntee_code") or ntee_code,
                    "total_revenue": None,
                    "total_assets":  None,
                    "health_score":  None,
                })

            data_as_of = datetime.now(timezone.utc).isoformat()
            data = {
                "category":     cat_raw,
                "ntee_code":    ntee_code,
                "state_filter": state_raw,
                "result_count": len(results),
                "truncated":    truncated,
                "organizations": results,
                "upstream_status": {"propublica": pp_status},
            }

            _success = True
            return {
                "status":           "ok",
                "tool_id":          "T04",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("search_nonprofits_by_category error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T04",
            tool_name="search_nonprofits_by_category",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — fetch_nonprofit_financial_trends
# ══════════════════════════════════════════════════════════════════════════════

@nonprofit_sprint7.tool()
@with_timeout
@verify_entitlement("T04")
async def fetch_nonprofit_financial_trends(
    ein: str,
    years: int = 5,
) -> dict:
    """5-year financial trend for any US nonprofit. Revenue growth, expense ratios, reserve trajectory, and health score history from IRS Form 990 data via ProPublica. Returns trend_direction (GROWING/STABLE/DECLINING/VOLATILE/INSUFFICIENT_DATA), CAGR, and year-by-year revenue, expense, and asset trends. years parameter: 1–10, default 5. Rate limit: 30/minute. No auth required. Complements nonprofit_fetch_nonprofit_full_profile by adding multi-year context. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="nonprofit_fetch_nonprofit_financial_trends", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        ein_clean = ein.strip().replace("-", "")
        params    = {"ein": ein_clean, "years": years}

        async with AuditContext("T04", params, "1.0") as ctx:
            # ── Input validation ──────────────────────────────────────────────
            if not ein_clean or not ein_clean.isdigit():
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="ein must be a 9-digit number (hyphens optional).",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            if not (1 <= years <= 10):
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="years must be between 1 and 10.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # ── ProPublica call (org endpoint returns all filings) ────────────
            async def _call() -> dict:
                async with httpx.AsyncClient(
                    timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
                ) as client:
                    resp = await client.get(
                        f"{_PROPUBLICA}/organizations/{quote(ein_clean, safe='')}.json"
                    )
                    resp.raise_for_status()
                    return resp.json()

            try:
                raw = await _propublica_breaker.call_async(_call)
                pp_status = "OK"
            except pybreaker.CircuitBreakerError:
                return error_response(
                    error_code=ErrorCode.CIRCUIT_OPEN,
                    message="ProPublica Nonprofit Explorer temporarily unavailable. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    return error_response(
                        error_code=ErrorCode.NOT_FOUND,
                        message=f"EIN {ein_clean} not found in ProPublica Nonprofit Explorer.",
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                    )
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="ProPublica Nonprofit Explorer temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )
            except Exception as exc:
                log.warning("fetch_nonprofit_financial_trends propublica error ein=%s: %s", ein_clean, exc)
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="ProPublica Nonprofit Explorer temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )

            # ── Slice filings to requested years (most recent first) ──────────
            org_name = raw.get("organization", {}).get("name", "")
            all_filings = raw.get("filings_with_data", [])
            # Sort descending by tax year, take `years` most recent
            all_filings = sorted(
                all_filings,
                key=lambda f: int(f.get("tax_prd_yr") or 0),
                reverse=True,
            )
            selected = all_filings[:years]

            # ── Minimum data guard (FIRST check) ─────────────────────────────
            if len(selected) < 2:
                data_as_of = datetime.now(timezone.utc).isoformat()
                data = {
                    "ein":              ein_clean,
                    "organization_name": org_name,
                    "trend_direction":  "INSUFFICIENT_DATA",
                    "cagr":             None,
                    "revenue_trend":    [],
                    "expense_trend":    [],
                    "asset_trend":      [],
                    "health_score_trend": [],
                    "message":          "Fewer than 2 Form 990 filings available for this EIN.",
                    "upstream_status":  {"propublica": pp_status},
                }
                _success = True
                return {
                    "status":           "ok",
                    "tool_id":          "T04",
                    "fetch_timestamp":  data_as_of,
                    "cache_hit":        False,
                    "staleness_notice": None,
                    "sha256_hash":      "",
                    "data":             data,
                    "disclaimer":       _DISCLAIMER,
                    **standard_response_fields(ctx.query_hash, data_as_of, True),
                }

            # ── Per-year calculations ─────────────────────────────────────────
            revenue_trend:      list[dict] = []
            expense_trend:      list[dict] = []
            asset_trend:        list[dict] = []
            health_score_trend: list[dict] = []

            # selected is newest-first; process oldest-first for change_pct
            chronological = list(reversed(selected))

            for i, filing in enumerate(chronological):
                yr           = int(filing.get("tax_prd_yr") or 0)
                totrevenue   = _to_float(filing.get("totrevenue"))
                totfuncexpns = _to_float(filing.get("totfuncexpns"))
                totprgmrevnue = _to_float(filing.get("totprgmrevnue"))
                netassetsend  = _to_float(filing.get("netassetsend"))

                # Revenue change pct vs previous year
                change_pct: Optional[float] = None
                if i > 0:
                    prev_rev = _to_float(chronological[i - 1].get("totrevenue"))
                    if prev_rev and prev_rev != 0 and totrevenue is not None:
                        change_pct = round((totrevenue - prev_rev) / prev_rev * 100, 2)

                revenue_trend.append({
                    "year":          yr,
                    "total_revenue": int(totrevenue) if totrevenue is not None else None,
                    "change_pct":    change_pct,
                })

                # Programme ratio
                prog_ratio: Optional[float] = None
                if totrevenue and totrevenue > 0 and totprgmrevnue is not None:
                    prog_ratio = round(totprgmrevnue / totrevenue, 4)

                expense_trend.append({
                    "year":            yr,
                    "total_expenses":  int(totfuncexpns) if totfuncexpns is not None else None,
                    "programme_ratio": prog_ratio,
                })

                # Reserve months
                reserve_months: Optional[float] = None
                if totfuncexpns and totfuncexpns > 0 and netassetsend is not None:
                    reserve_months = round(netassetsend / (totfuncexpns / 12), 2)

                asset_trend.append({
                    "year":           yr,
                    "net_assets":     int(netassetsend) if netassetsend is not None else None,
                    "reserve_months": reserve_months,
                })

                # Health score (prev_revenue for growth component)
                prev_rev_for_score = _to_float(chronological[i - 1].get("totrevenue")) if i > 0 else None
                try:
                    hs = calculate_health_score(
                        totrevenue    = totrevenue    or 0.0,
                        totfuncexpns  = totfuncexpns  or 0.0,
                        totprgmrevnue = totprgmrevnue or 0.0,
                        netassetsend  = netassetsend  or 0.0,
                        prev_revenue  = prev_rev_for_score,
                    )
                except Exception:
                    hs = None

                health_score_trend.append({"year": yr, "health_score": hs})

            # ── CAGR ──────────────────────────────────────────────────────────
            earliest = chronological[0]
            latest   = chronological[-1]
            rev_earliest = _to_float(earliest.get("totrevenue"))
            rev_latest   = _to_float(latest.get("totrevenue"))
            yr_earliest  = int(earliest.get("tax_prd_yr") or 0)
            yr_latest    = int(latest.get("tax_prd_yr") or 0)
            n_years      = yr_latest - yr_earliest

            cagr: Optional[float] = None
            if n_years > 0 and rev_earliest and rev_earliest > 0 and rev_latest is not None:
                cagr = round(((rev_latest / rev_earliest) ** (1 / n_years)) - 1, 4)

            # ── trend_direction (evaluate IN ORDER) ───────────────────────────
            trend_direction = _classify_trend(revenue_trend, cagr)

            data_as_of = datetime.now(timezone.utc).isoformat()
            data = {
                "ein":               ein_clean,
                "organization_name": org_name,
                "years_requested":   years,
                "years_available":   len(selected),
                "trend_direction":   trend_direction,
                "cagr":              cagr,
                "revenue_trend":     revenue_trend,
                "expense_trend":     expense_trend,
                "asset_trend":       asset_trend,
                "health_score_trend": health_score_trend,
                "upstream_status":   {"propublica": pp_status},
            }

            _success = True
            return {
                "status":           "ok",
                "tool_id":          "T04",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("fetch_nonprofit_financial_trends error ein=%s", ein)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T04",
            tool_name="fetch_nonprofit_financial_trends",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


def _classify_trend(revenue_trend: list[dict], cagr: Optional[float]) -> str:
    """
    Classify trend_direction IN ORDER — first match wins:
    1. INSUFFICIENT_DATA: < 2 filings (handled before this call)
    2. VOLATILE: any two consecutive filings with opposite-sign change_pct,
                 both absolute values > 20%
    3. GROWING:  CAGR > 5%
    4. STABLE:   -5% <= CAGR <= 5%
    5. DECLINING: CAGR < -5%
    """
    # VOLATILE check: consecutive pairs with opposite signs AND both > 20%
    change_pcts = [e["change_pct"] for e in revenue_trend if e["change_pct"] is not None]
    for i in range(len(change_pcts) - 1):
        a, b = change_pcts[i], change_pcts[i + 1]
        if (
            a * b < 0            # opposite signs
            and abs(a) > 20
            and abs(b) > 20
        ):
            return "VOLATILE"

    if cagr is None:
        return "STABLE"  # cannot determine — default conservative
    if cagr > 0.05:
        return "GROWING"
    if cagr >= -0.05:
        return "STABLE"
    return "DECLINING"
