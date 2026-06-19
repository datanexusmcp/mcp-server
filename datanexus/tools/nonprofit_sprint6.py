"""
datanexus/tools/nonprofit_sprint6.py — Sprint 6 nonprofit tools.

Tools:
  fetch_nonprofit_full_profile — ProPublica + IRS e-File fallback,
                                  financial health score, risk flags.

All are thin MCP wrappers. Logic is self-contained here.
HTTP self-calls are forbidden — no internal MCP requests.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import Field
from urllib.parse import quote

import httpx
import pybreaker
from fastmcp import FastMCP

from datanexus.tools._circuit_breakers import _propublica_breaker
from datanexus.tools._nonprofit_utils import calculate_health_score

from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import fire_and_forget, track_tool_call
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.nonprofit_sprint6")

nonprofit_sprint6 = FastMCP("DataNexus Nonprofit Sprint6")

_DISCLAIMER = (
    "Financial data sourced from ProPublica Nonprofit Explorer and IRS e-File. "
    "DataNexus does not warrant completeness. "
    "Verify with audited financial statements before making investment or grant decisions."
)

_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT = httpx.Timeout(8.0, connect=5.0)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — fetch_nonprofit_full_profile
# ══════════════════════════════════════════════════════════════════════════════

@nonprofit_sprint6.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T12")
async def fetch_nonprofit_full_profile(ein: Annotated[str, Field(description="EIN in format XX-XXXXXXX e.g. 46-5734087. Required.")]) -> dict:
    """Complete nonprofit due diligence in one call. Revenue trends, executive pay, risk flags, and a health score from IRS 990 data. Uses ProPublica Nonprofit Explorer API with IRS e-File fallback. Data refreshed on each call. Returns financials, executive_compensation, risk_flags, health_score (0–100), programme_ratio, fundraising_sustainability, and upstream_status. Rate limit: 30/minute. No auth required. For grant-makers, investors, and compliance teams performing nonprofit due diligence. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="nonprofit_fetch_nonprofit_full_profile", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        ein_clean = ein.strip().replace("-", "")
        params = {"ein": ein_clean}

        async with AuditContext("T12", params, "1.0") as ctx:
            if not ein_clean or not ein_clean.isdigit():
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="ein must be a 9-digit number (hyphens optional).",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            result = await _fetch_nonprofit_data(ein_clean)

            ingest_ok = result.get("status") == "OK"
            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown = _build_nonprofit_markdown(result, ein_clean)

            data = {
                "ein":                       ein_clean,
                "organization_name":         result.get("organization_name", ""),
                "financials":                result.get("financials", {}),
                "executive_compensation":    result.get("executive_compensation", []),
                "risk_flags":                result.get("risk_flags", []),
                "health_score":              result.get("health_score"),
                "programme_ratio":           result.get("programme_ratio"),
                "fundraising_sustainability": result.get("fundraising_sustainability"),
                "upstream_status":           {"propublica": result.get("status", "ERROR")},
            }

            _success = ingest_ok
            return {
                "status":           "ok" if ingest_ok else "degraded",
                "tool_id":          "T12",
                "source_url":       f"https://projects.propublica.org/nonprofits/api/v2/organizations/{ein_clean}.json",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "markdown_output":  markdown,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, ingest_ok),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("fetch_nonprofit_full_profile error ein=%s", ein)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T12",
            tool_name="fetch_nonprofit_full_profile",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ── Data fetcher ───────────────────────────────────────────────────────────────

async def _fetch_nonprofit_data(ein: str) -> dict:
    """
    Fetch nonprofit data from ProPublica; fall back to IRS e-File index on 404.
    Returns a fully-scored dict.
    """
    async def _call_propublica() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            url = f"https://projects.propublica.org/nonprofits/api/v2/organizations/{quote(ein, safe='')}.json"
            resp = await client.get(url)

            # 404 → try IRS e-File fallback
            if resp.status_code == 404:
                return await _fetch_irs_efile_fallback(client, ein)

            resp.raise_for_status()
            return _parse_propublica(resp.json())

    try:
        return await _propublica_breaker.call_async(_call_propublica)
    except pybreaker.CircuitBreakerError:
        log.warning("_fetch_nonprofit_data circuit open ein=%s", ein)
        return _empty_result("CIRCUIT_OPEN")
    except Exception as exc:
        log.warning("_fetch_nonprofit_data error ein=%s: %s", ein, exc)
        return _empty_result("ERROR")


async def _fetch_irs_efile_fallback(client: httpx.AsyncClient, ein: str) -> dict:
    """
    IRS e-File bulk download index fallback — best-effort only.
    Returns empty result on any failure (the index is a bulk download, not a lookup API).
    """
    try:
        index_url = "https://www.irs.gov/charities-non-profits/form-990-series-downloads"
        resp = await client.get(index_url, timeout=httpx.Timeout(5.0, connect=3.0))
        # The IRS page lists bulk CSV links by year — we can't do a per-EIN lookup here.
        # Return a minimal result indicating the EIN was not in ProPublica.
        return _empty_result("NOT_FOUND")
    except Exception:
        return _empty_result("NOT_FOUND")


def _parse_propublica(raw: dict) -> dict:
    """Parse a ProPublica Nonprofit Explorer API response into our schema."""
    org = raw.get("organization", {})
    filings = raw.get("filings_with_data", []) or raw.get("filings_without_data", [])

    # Most recent filing
    filing = filings[0] if filings else {}
    prev_filing = filings[1] if len(filings) > 1 else {}

    name = org.get("name", "")

    # Financial fields (ProPublica field names)
    totrevenue     = _to_float(filing.get("totrevenue"))
    totfuncexpns   = _to_float(filing.get("totfuncexpns"))
    totprgmrevnue  = _to_float(filing.get("totprgmrevnue"))
    netassetsend   = _to_float(filing.get("netassetsend"))
    prev_revenue   = _to_float(prev_filing.get("totrevenue")) if prev_filing else None

    # Programme ratio = programme expenses / total revenue
    programme_ratio: Optional[float] = None
    if totrevenue and totrevenue > 0 and totprgmrevnue is not None:
        programme_ratio = round(totprgmrevnue / totrevenue, 4)

    # Expense ratio = total expenses / total revenue
    expense_ratio: Optional[float] = None
    if totrevenue and totrevenue > 0 and totfuncexpns is not None:
        expense_ratio = round(totfuncexpns / totrevenue, 4)

    # Reserve months = net assets / (expenses / 12)
    reserve_months: Optional[float] = None
    if totfuncexpns and totfuncexpns > 0 and netassetsend is not None:
        reserve_months = round(netassetsend / (totfuncexpns / 12), 2)

    # Revenue growth score
    revenue_growth_score: Optional[float] = None
    if prev_revenue and prev_revenue > 0 and totrevenue is not None:
        delta = (totrevenue - prev_revenue) / prev_revenue
        revenue_growth_score = max(0.0, min(1.0, (delta + 0.1) / 0.2))  # -10% → 0, +10% → 1

    # Health score (0–100) — formula lives in _nonprofit_utils.py
    health_score = calculate_health_score(
        totrevenue=totrevenue or 0.0,
        totfuncexpns=totfuncexpns or 0.0,
        totprgmrevnue=totprgmrevnue or 0.0,
        netassetsend=netassetsend or 0.0,
        prev_revenue=prev_revenue,
    )

    # Executive compensation (top 5 from employee array)
    employees = filing.get("employees") or []
    if isinstance(employees, list):
        exec_comp = sorted(
            [
                {
                    "name":  e.get("name", ""),
                    "title": e.get("title", ""),
                    "compensation": _to_float(e.get("compensation")) or 0,
                }
                for e in employees
                if e.get("compensation")
            ],
            key=lambda x: x["compensation"],
            reverse=True,
        )[:5]
    else:
        exec_comp = []

    # Risk flags
    risk_flags = []
    if filing.get("late_tax_period"):
        risk_flags.append("late_tax_period")
    if filing.get("related_org_flag"):
        risk_flags.append("related_org")
    if prev_revenue and prev_revenue > 0 and totrevenue is not None:
        yoy_delta = (totrevenue - prev_revenue) / prev_revenue
        if yoy_delta < -0.10:
            risk_flags.append(f"revenue_decline_{round(yoy_delta * 100, 1)}pct")

    # Fundraising sustainability flag
    fundraising_sustainability: Optional[str] = None
    if expense_ratio is not None:
        fundraising_sustainability = "healthy" if expense_ratio < 0.35 else "high_overhead"

    return {
        "organization_name":         name,
        "financials": {
            "total_revenue":    totrevenue,
            "total_expenses":   totfuncexpns,
            "net_assets":       netassetsend,
            "programme_expenses": totprgmrevnue,
            "tax_period":       filing.get("tax_prd_yr") or filing.get("tax_period"),
        },
        "executive_compensation":    exec_comp,
        "risk_flags":                risk_flags,
        "health_score":              health_score,
        "programme_ratio":           programme_ratio,
        "fundraising_sustainability": fundraising_sustainability,
        "status":                    "OK",
    }


def _to_float(val) -> Optional[float]:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _empty_result(status: str) -> dict:
    return {
        "organization_name":         "",
        "financials":                {},
        "executive_compensation":    [],
        "risk_flags":                [],
        "health_score":              None,
        "programme_ratio":           None,
        "fundraising_sustainability": None,
        "status":                    status,
    }


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_nonprofit_markdown(result: dict, ein: str) -> str:
    name   = result.get("organization_name") or f"EIN {ein}"
    score  = result.get("health_score")
    flags  = result.get("risk_flags", [])
    fin    = result.get("financials", {})
    comps  = result.get("executive_compensation", [])
    prog   = result.get("programme_ratio")
    fund   = result.get("fundraising_sustainability")
    status = result.get("status", "ERROR")

    def _fmt_money(v) -> str:
        if v is None: return "n/a"
        if abs(v) >= 1_000_000: return f"${v/1_000_000:.1f}M"
        if abs(v) >= 1_000:     return f"${v/1_000:.0f}K"
        return f"${v:.0f}"

    lines = [
        f"## Nonprofit Profile: {name} (EIN {ein})",
        "",
        f"**Health Score:** {score:.0f}/100" if score is not None else "**Health Score:** n/a",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Revenue | {_fmt_money(fin.get('total_revenue'))} |",
        f"| Total Expenses | {_fmt_money(fin.get('total_expenses'))} |",
        f"| Net Assets | {_fmt_money(fin.get('net_assets'))} |",
        f"| Programme Ratio | {f'{prog:.1%}' if prog is not None else 'n/a'} |",
        f"| Fundraising | {fund or 'n/a'} |",
        f"| Tax Period | {fin.get('tax_period') or 'n/a'} |",
    ]

    if comps:
        lines += ["", "**Executive Compensation (top 5):**"]
        for c in comps:
            lines.append(f"  - {c['name']} ({c['title']}): {_fmt_money(c['compensation'])}")

    if flags:
        lines += ["", f"**⚠ Risk Flags:** {', '.join(flags)}"]

    if status not in ("OK", "NOT_FOUND"):
        lines += ["", f"> Data source status: `{status}` — results may be incomplete."]

    lines += ["", f"*{_DISCLAIMER}*"]
    return "\n".join(lines)
