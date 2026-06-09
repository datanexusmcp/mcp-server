"""
datanexus/tools/t18.py — T18 Government Contracting & Procurement tool.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 5, T18 entry

Exactly 3 data functions. Shared infrastructure tools (report_feedback,
report_mcpize_link) are registered ONCE in main.py — NOT here.

Data sources:
  Primary:   USASpending.gov API — api.usaspending.gov — no key required
             Built first: no key, immediate data, good fallback
  Secondary: SAM.gov API — api.sam.gov/prod/opportunities/v2
             Requires SAM_GOV_API_KEY from environment
  Supporting: EU TED API — ted.europa.eu/api — no key
             EU public procurement database
  Supporting: UK Find-a-Tender — find-tender.service.gov.uk/api — no key
             UK public procurement notices

Hard stop (absolute — never violate):
  Do NOT add procurement guidance, bid coaching, win likelihood analysis,
  sourcing analysis, or advisory output of any kind. Do NOT add classified
  contract data.

Cache TTL: 14400 seconds (4 hours)
Circuit breaker source IDs: "usaspending", "sam_gov", "eu_ted",
  "uk_find_a_tender"
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Annotated

from pydantic import Field
import httpx
from fastmcp import FastMCP

from datanexus.core.audit import (
    AuditContext,
    make_params_hash,
    standard_response_fields,
)
from datanexus.core.cache import (
    get_cached,
    set_cached,
)
from datanexus.core.circuit_breaker import (
    is_tripped,
    record_failure_sync,
    record_success_sync,
)
from payment.entitlement import verify_entitlement
from datanexus.core.timeout import with_timeout
from datanexus.analytics import track_tool_call, track_tool_error

log = logging.getLogger("datanexus.tools.t18")

mcp = FastMCP("datanexus-t18")

# ── Constants ─────────────────────────────────────────────────────────────────

T18_TTL = 14400  # 4 hours — spec requirement

DISCLAIMER = (
    "Contract data sourced from USASpending.gov, SAM.gov, EU TED, and "
    "UK Find-a-Tender public databases. DataNexus does not provide "
    "procurement guidance, bid coaching, or sourcing analysis. "
    "Verify award data with contracting authority before any business decision."
)

USASPENDING_URL   = "https://api.usaspending.gov/api/v2"
SAM_GOV_OPPS_URL  = "https://api.sam.gov/prod/opportunities/v2/search"
EU_TED_URL        = "https://api.ted.europa.eu/v3/notices/search"
UK_FAT_URL        = "https://www.find-tender.service.gov.uk/api/1.0/ocds/search"

# USASpending contract award type codes — contracts group only (single-group rule)
_AWARD_TYPE_CODES = ["A", "B", "C", "D"]

_HTTP_TIMEOUT = httpx.Timeout(20.0, connect=8.0)
_HEADERS      = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

_INJECTION_PATTERNS = (
    "ignore previous",
    "you are now",
    "system:",
    "<script",
    "<iframe",
    "forget your instructions",
    "new persona",
    "disregard",
)


def _validate_canary(markdown_output: str) -> None:
    """Raise ValueError if any injection pattern is found in markdown_output."""
    lower = markdown_output.lower()
    for pattern in _INJECTION_PATTERNS:
        if pattern.lower() in lower:
            raise ValueError(
                f"Canary: injection pattern '{pattern}' detected in "
                "markdown_output — response blocked."
            )


def _incr_calls(tool_id: str) -> None:
    """Increment datanexus:calls:{tool_id}:{today} telemetry counter."""
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    r = _get_redis()
    if r is None:
        return
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"datanexus:calls:{tool_id}:{today}"
    try:
        r.incr(key)
        r.expire(key, 35 * 86400)
    except Exception:
        pass


def _sam_gov_key() -> str:
    return os.environ.get("SAM_GOV_API_KEY", "")


def _fmt_amount(val) -> str:
    """Format a dollar amount with commas, or return '—' if absent."""
    try:
        return f"${int(float(val)):,}"
    except (TypeError, ValueError):
        return "—"


def _usaspending_payload(keywords: list, agency: str = "", date_from: str = "", limit: int = 10) -> dict:
    """Build a valid USASpending spending_by_award payload."""
    filters: dict = {
        "keywords": keywords,
        "award_type_codes": _AWARD_TYPE_CODES,
    }
    if agency:
        filters["agencies"] = [{"type": "awarding", "tier": "toptier", "name": agency}]
    if date_from:
        filters["time_period"] = [{
            "start_date": date_from,
            "end_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        }]
    return {
        "filters": filters,
        "fields": [
            "Award ID", "Recipient Name", "Award Amount",
            "Awarding Agency", "Award Type", "NAICS Code",
            "Start Date", "End Date", "Description",
        ],
        "page": 1,
        "limit": limit,
        "sort": "Award Amount",
        "order": "desc",
        "subawards": False,
    }


def _parse_usaspending_result(result: dict) -> dict:
    return {
        "award_id":    result.get("Award ID", ""),
        "recipient":   result.get("Recipient Name", ""),
        "amount":      result.get("Award Amount"),
        "agency":      result.get("Awarding Agency", ""),
        "award_type":  result.get("Award Type", ""),
        "naics_code":  result.get("NAICS Code", ""),
        "start_date":  result.get("Start Date", ""),
        "end_date":    result.get("End Date", ""),
        "description": result.get("Description", ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 1 — search_contract_awards
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T18")
async def search_contract_awards(
    keyword: Annotated[str, Field(description="Search terms describing the contract scope e.g. cybersecurity software. Required.")],
    agency: Annotated[str, Field(description="Awarding agency name e.g. Department of Defense. Optional.")] = "",
    date_from: Annotated[str, Field(description="Earliest award date ISO 8601 e.g. 2024-01-31. Optional.")] = "",
    jurisdiction: Annotated[str, Field(description="Jurisdiction: US, EU, or UK. Default US. Optional.")] = "US",
) -> dict:
    """Search government contract awards by keyword, agency, and date range.

    keyword: Contract scope e.g. "cybersecurity software".
    agency: Awarding agency e.g. "Department of Defense". Optional.
    date_from: Earliest award date ISO 8601 e.g. "2024-01-31". Optional.
    jurisdiction: "US", "EU", or "UK". Default "US".

    Returns: award amounts, recipient vendors, NAICS codes, award dates.
    Use govcon_fetch_vendor_contract_history for all contracts by a specific vendor.
    Use govcon_fetch_open_solicitations for active bids, not past awards.
    Source: USASpending.gov + SAM.gov. 4-hour cache.

    Example: search_contract_awards(keyword="cybersecurity software", agency="Department of Defense")
    """
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        kw_clean     = keyword.strip()
        agency_clean = agency.strip()
        date_clean   = date_from.strip()
        juris_clean  = jurisdiction.strip().upper()
        params = {
            "keyword": kw_clean, "agency": agency_clean,
            "date_from": date_clean, "jurisdiction": juris_clean,
        }

        async with AuditContext("T18", params, "1.0") as _:
            _incr_calls("T18")
            phash = make_params_hash(params)

            cached = get_cached("T18", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        awards: list[dict] = []
        source_used = ""
        upstream_err = ""

        # ── USASpending.gov (US) ──────────────────────────────────────────────
        if juris_clean == "US" and not is_tripped("usaspending"):
            try:
                payload = _usaspending_payload([kw_clean], agency_clean, date_clean)
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.post(
                        f"{USASPENDING_URL}/search/spending_by_award/",
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    awards = [_parse_usaspending_result(r) for r in data.get("results", [])[:10]]
                    source_used = "USASpending.gov"
                    record_success_sync("usaspending")
            except Exception as exc:
                log.warning("USASpending search_contract_awards failed: %s", exc)
                record_failure_sync("usaspending")
                upstream_err = str(exc)

        # ── EU TED (EU) ───────────────────────────────────────────────────────
        elif juris_clean == "EU" and not is_tripped("eu_ted"):
            try:
                payload = {
                    "query": kw_clean,
                    "fields": ["title", "contracting-authority", "estimated-value",
                               "publication-date", "deadline", "cpv"],
                    "pageSize": 10, "page": 0,
                }
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.post(EU_TED_URL, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    for notice in data.get("notices", [])[:10]:
                        awards.append({
                            "award_id":    notice.get("id", ""),
                            "recipient":   notice.get("contracting-authority", {}).get("name", ""),
                            "amount":      notice.get("estimated-value", {}).get("value"),
                            "agency":      notice.get("contracting-authority", {}).get("name", ""),
                            "award_type":  notice.get("notice-type", ""),
                            "naics_code":  notice.get("cpv", ""),
                            "start_date":  notice.get("publication-date", ""),
                            "end_date":    notice.get("deadline", ""),
                            "description": notice.get("title", ""),
                        })
                    source_used = "EU TED"
                    record_success_sync("eu_ted")
            except Exception as exc:
                log.warning("EU TED search_contract_awards failed: %s", exc)
                record_failure_sync("eu_ted")
                upstream_err = str(exc)

        # ── UK Find-a-Tender ──────────────────────────────────────────────────
        elif juris_clean == "UK" and not is_tripped("uk_find_a_tender"):
            try:
                uk_params = {"q": kw_clean, "limit": 10}
                if agency_clean:
                    uk_params["buyerName"] = agency_clean
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.get(UK_FAT_URL, params=uk_params)
                    resp.raise_for_status()
                    data = resp.json()
                    for release in data.get("releases", [])[:10]:
                        tender = release.get("tender", {})
                        buyer  = release.get("buyer", {})
                        awards.append({
                            "award_id":    release.get("id", ""),
                            "recipient":   buyer.get("name", ""),
                            "amount":      tender.get("value", {}).get("amount"),
                            "agency":      buyer.get("name", ""),
                            "award_type":  tender.get("procurementMethod", ""),
                            "naics_code":  "",
                            "start_date":  tender.get("tenderPeriod", {}).get("startDate", ""),
                            "end_date":    tender.get("tenderPeriod", {}).get("endDate", ""),
                            "description": tender.get("title", ""),
                        })
                    source_used = "UK Find-a-Tender"
                    record_success_sync("uk_find_a_tender")
            except Exception as exc:
                log.warning("UK FAT search_contract_awards failed: %s", exc)
                record_failure_sync("uk_find_a_tender")
                upstream_err = str(exc)

        # Graceful empty
        if not awards:
            note = f"\n\n*No awards found. {upstream_err[:120] if upstream_err else 'Try broadening the keyword.'}*"
            md = f"""## Contract Awards: {kw_clean} ({juris_clean})

{note}

**Source:** {source_used or 'unavailable'}

{DISCLAIMER}"""
            _validate_canary(md)
            _success = True
            return {
                "keyword": kw_clean, "jurisdiction": juris_clean,
                "count": 0, "awards": [],
                "source": source_used, "markdown": md, "disclaimer": DISCLAIMER,
                **standard_response_fields("T18", phash, "1.0"),
            }

        rows = []
        for a in awards:
            amt   = _fmt_amount(a.get("amount"))
            recip = (a.get("recipient") or "—")[:45]
            ag    = (a.get("agency") or "—")[:35]
            naics = a.get("naics_code") or "—"
            atype = a.get("award_type") or "—"
            rows.append(f"| {recip} | {ag} | {amt} | {naics} | {atype} |")

        table = (
            "| Recipient | Agency | Amount | NAICS | Type |\n"
            "|---|---|---|---|---|\n"
            + "\n".join(rows)
        )
        agency_note = f" · Agency: {agency_clean}" if agency_clean else ""
        date_note   = f" · From: {date_clean}" if date_clean else ""
        md = f"""## Contract Awards: {kw_clean} ({juris_clean}){agency_note}{date_note}

**Source:** {source_used}  **Results:** {len(awards)}

{table}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "keyword": kw_clean, "jurisdiction": juris_clean,
            "agency": agency_clean, "date_from": date_clean,
            "count": len(awards), "awards": awards,
            "source": source_used, "markdown": md, "disclaimer": DISCLAIMER,
            **standard_response_fields("T18", phash, "1.0"),
        }
        set_cached("T18", phash, out, T18_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T18",
            tool_name="search_contract_awards",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
            jurisdiction=jurisdiction,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — fetch_vendor_contract_history
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T18")
async def fetch_vendor_contract_history(
    vendor_name: Annotated[str, Field(description="Vendor or company name to search e.g. Booz Allen Hamilton. Required.")],
    jurisdiction: Annotated[str, Field(description="Jurisdiction: US, EU, or UK. Default US. Optional.")] = "US",
) -> dict:
    """Fetch the complete federal contract award history for a specific vendor. Read-only. No side effects. Idempotent. vendor_name: Company or organisation name e.g. Booz Allen Hamilton. Required. Fuzzy match used. jurisdiction: One of US, EU, or UK. Optional. Default US. Returns total award value, top awarding agencies, contract types, and recent awards with amounts and dates. Use this when researching a specific company's government contracting history. Use govcon_search_contract_awards instead when exploring a topic area without a specific vendor. Verified source: USASpending.gov. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="govcon_fetch_vendor_contract_history", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        vendor_clean = vendor_name.strip()
        juris_clean  = jurisdiction.strip().upper()
        params = {"vendor_name": vendor_clean, "jurisdiction": juris_clean}

        async with AuditContext("T18", params, "1.0") as _:
            _incr_calls("T18")
            phash = make_params_hash(params)

            cached = get_cached("T18", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        awards: list[dict] = []
        total_amount = 0.0
        source_used  = ""

        if not is_tripped("usaspending"):
            try:
                payload = _usaspending_payload([vendor_clean], limit=20)
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.post(
                        f"{USASPENDING_URL}/search/spending_by_award/",
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for result in data.get("results", [])[:20]:
                        a = _parse_usaspending_result(result)
                        try:
                            total_amount += float(a.get("amount") or 0)
                        except (TypeError, ValueError):
                            pass
                        awards.append(a)
                    source_used = "USASpending.gov"
                    record_success_sync("usaspending")
            except Exception as exc:
                log.warning("USASpending fetch_vendor_contract_history failed: %s", exc)
                record_failure_sync("usaspending")

        if not awards:
            md = f"""## Vendor Contract History: {vendor_clean}

No contract history found for this vendor in {juris_clean}.

**Source:** {source_used or 'unavailable'}

{DISCLAIMER}"""
            _validate_canary(md)
            _success = True
            return {
                "vendor_name": vendor_clean, "jurisdiction": juris_clean,
                "total_awards": 0, "total_amount": 0.0, "awards": [],
                "source": source_used, "markdown": md, "disclaimer": DISCLAIMER,
                **standard_response_fields("T18", phash, "1.0"),
            }

        agency_totals: dict[str, float] = {}
        for a in awards:
            ag = a.get("agency") or "Unknown"
            try:
                agency_totals[ag] = agency_totals.get(ag, 0.0) + float(a.get("amount") or 0)
            except (TypeError, ValueError):
                pass
        top_agencies = sorted(agency_totals.items(), key=lambda x: x[1], reverse=True)[:5]

        rows = []
        for a in awards[:10]:
            amt   = _fmt_amount(a.get("amount"))
            ag    = (a.get("agency") or "—")[:40]
            atype = a.get("award_type") or "—"
            start = a.get("start_date") or "—"
            rows.append(f"| {amt} | {ag} | {atype} | {start} |")

        table = (
            "| Amount | Agency | Type | Start |\n"
            "|---|---|---|---|\n"
            + "\n".join(rows)
        )
        top_ag_lines = "\n".join(
            f"- **{ag}**: {_fmt_amount(tot)}" for ag, tot in top_agencies
        )

        md = f"""## Vendor Contract History: {vendor_clean}

**Total Awards Found:** {len(awards)}
**Total Value:** {_fmt_amount(total_amount)}
**Source:** {source_used}

### Top Agencies
{top_ag_lines}

### Recent Awards
{table}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "vendor_name":  vendor_clean,
            "jurisdiction": juris_clean,
            "total_awards": len(awards),
            "total_amount": total_amount,
            "top_agencies": [{"agency": ag, "total": tot} for ag, tot in top_agencies],
            "awards":       awards,
            "source":       source_used,
            "markdown":     md,
            "disclaimer":   DISCLAIMER,
            **standard_response_fields("T18", phash, "1.0"),
        }
        set_cached("T18", phash, out, T18_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T18",
            tool_name="fetch_vendor_contract_history",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_open_solicitations
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T18")
async def fetch_open_solicitations(
    keyword: Annotated[str, Field(description="Description of goods or services sought e.g. cloud computing. Required.")],
    agency: Annotated[str, Field(description="Awarding agency name. Optional, defaults to all agencies.")] = "",
    jurisdiction: Annotated[str, Field(description="Jurisdiction: US, EU, or UK. Default US. Optional.")] = "US",
) -> dict:
    """Fetch currently open government contract solicitations matching a keyword. Read-only. No side effects. Idempotent. keyword: Description of goods or services sought e.g. cloud computing services. Required. Encode special characters — + becomes %2B. agency: Awarding agency name. Optional, defaults to all agencies. jurisdiction: One of US, EU, or UK. Optional. Default US. Returns solicitation title, agency, response deadline, estimated value, and NAICS code. Use this when looking for active bid opportunities. Use govcon_search_contract_awards instead when you need historical awards not open solicitations. Verified source: SAM.gov + USASpending.gov. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="govcon_fetch_open_solicitations", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        kw_clean     = keyword.strip()
        agency_clean = agency.strip()
        juris_clean  = jurisdiction.strip().upper()
        params = {"keyword": kw_clean, "agency": agency_clean, "jurisdiction": juris_clean}

        async with AuditContext("T18", params, "1.0") as _:
            _incr_calls("T18")
            phash = make_params_hash(params)

            cached = get_cached("T18", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        solicitations: list[dict] = []
        source_used = ""

        # ── SAM.gov open opportunities (US, primary) ──────────────────────────
        if juris_clean == "US" and not is_tripped("sam_gov"):
            api_key = _sam_gov_key()
            if api_key:
                try:
                    sam_params: dict = {
                        "api_key": api_key,
                        "keywords": kw_clean,
                        "limit": 10,
                        "offset": 0,
                        "active": "Yes",
                    }
                    if agency_clean:
                        sam_params["organizationName"] = agency_clean
                    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                        resp = await client.get(SAM_GOV_OPPS_URL, params=sam_params)
                        resp.raise_for_status()
                        data = resp.json()
                        for opp in (data.get("opportunitiesData") or [])[:10]:
                            solicitations.append({
                                "sol_id":      opp.get("noticeId", ""),
                                "title":       opp.get("title", ""),
                                "agency":      opp.get("organizationName", ""),
                                "deadline":    opp.get("responseDeadLine", ""),
                                "value":       opp.get("estimatedTotalValue"),
                                "naics":       opp.get("naicsCode", ""),
                                "type":        opp.get("type", ""),
                                "posted_date": opp.get("postedDate", ""),
                            })
                        source_used = "SAM.gov"
                        record_success_sync("sam_gov")
                except Exception as exc:
                    log.warning("SAM.gov fetch_open_solicitations failed: %s", exc)
                    record_failure_sync("sam_gov")

        # ── Fallback: USASpending for US when SAM unavailable ─────────────────
        if juris_clean == "US" and not solicitations and not is_tripped("usaspending"):
            try:
                payload = _usaspending_payload([kw_clean], agency_clean, limit=10)
                # Override sort to show most recent
                payload["sort"] = "Start Date"
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.post(
                        f"{USASPENDING_URL}/search/spending_by_award/",
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for result in data.get("results", [])[:10]:
                        a = _parse_usaspending_result(result)
                        solicitations.append({
                            "sol_id":      a.get("award_id", ""),
                            "title":       a.get("description") or a.get("award_id", ""),
                            "agency":      a.get("agency", ""),
                            "deadline":    a.get("end_date", ""),
                            "value":       a.get("amount"),
                            "naics":       a.get("naics_code", ""),
                            "type":        a.get("award_type", ""),
                            "posted_date": a.get("start_date", ""),
                        })
                    sam_note = " (SAM key not configured — showing recent awards)" if not _sam_gov_key() else ""
                    source_used = f"USASpending.gov{sam_note}"
                    record_success_sync("usaspending")
            except Exception as exc:
                log.warning("USASpending fallback fetch_open_solicitations failed: %s", exc)
                record_failure_sync("usaspending")

        # ── EU TED ────────────────────────────────────────────────────────────
        elif juris_clean == "EU" and not is_tripped("eu_ted"):
            try:
                payload = {
                    "query": kw_clean,
                    "fields": ["title", "contracting-authority", "estimated-value",
                               "deadline", "cpv", "notice-type"],
                    "pageSize": 10, "page": 0,
                }
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.post(EU_TED_URL, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    for notice in data.get("notices", [])[:10]:
                        solicitations.append({
                            "sol_id":      notice.get("id", ""),
                            "title":       notice.get("title", ""),
                            "agency":      notice.get("contracting-authority", {}).get("name", ""),
                            "deadline":    notice.get("deadline", ""),
                            "value":       notice.get("estimated-value", {}).get("value"),
                            "naics":       notice.get("cpv", ""),
                            "type":        notice.get("notice-type", ""),
                            "posted_date": notice.get("publication-date", ""),
                        })
                    source_used = "EU TED"
                    record_success_sync("eu_ted")
            except Exception as exc:
                log.warning("EU TED fetch_open_solicitations failed: %s", exc)
                record_failure_sync("eu_ted")

        # ── UK Find-a-Tender ──────────────────────────────────────────────────
        elif juris_clean == "UK" and not is_tripped("uk_find_a_tender"):
            try:
                uk_params = {"q": kw_clean, "limit": 10, "status": "active"}
                if agency_clean:
                    uk_params["buyerName"] = agency_clean
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.get(UK_FAT_URL, params=uk_params)
                    resp.raise_for_status()
                    data = resp.json()
                    for release in data.get("releases", [])[:10]:
                        tender = release.get("tender", {})
                        buyer  = release.get("buyer", {})
                        solicitations.append({
                            "sol_id":      release.get("id", ""),
                            "title":       tender.get("title", ""),
                            "agency":      buyer.get("name", ""),
                            "deadline":    tender.get("tenderPeriod", {}).get("endDate", ""),
                            "value":       tender.get("value", {}).get("amount"),
                            "naics":       "",
                            "type":        tender.get("procurementMethod", ""),
                            "posted_date": tender.get("tenderPeriod", {}).get("startDate", ""),
                        })
                    source_used = "UK Find-a-Tender"
                    record_success_sync("uk_find_a_tender")
            except Exception as exc:
                log.warning("UK FAT fetch_open_solicitations failed: %s", exc)
                record_failure_sync("uk_find_a_tender")

        # Graceful empty
        if not solicitations:
            md = f"""## Open Solicitations: {kw_clean} ({juris_clean})

No open solicitations found for this keyword.

**Source:** {source_used or 'unavailable'}

{DISCLAIMER}"""
            _validate_canary(md)
            _success = True
            return {
                "keyword": kw_clean, "jurisdiction": juris_clean,
                "count": 0, "solicitations": [],
                "source": source_used, "markdown": md, "disclaimer": DISCLAIMER,
                **standard_response_fields("T18", phash, "1.0"),
            }

        rows = []
        for s in solicitations:
            title    = (s.get("title") or "—")[:50]
            ag       = (s.get("agency") or "—")[:35]
            deadline = s.get("deadline") or "—"
            val      = _fmt_amount(s.get("value"))
            naics    = s.get("naics") or "—"
            rows.append(f"| {title} | {ag} | {deadline} | {val} | {naics} |")

        table = (
            "| Title | Agency | Deadline | Est. Value | NAICS |\n"
            "|---|---|---|---|---|\n"
            + "\n".join(rows)
        )
        agency_note = f" · Agency: {agency_clean}" if agency_clean else ""
        md = f"""## Open Solicitations: {kw_clean} ({juris_clean}){agency_note}

**Source:** {source_used}  **Results:** {len(solicitations)}

{table}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "keyword":       kw_clean,
            "agency":        agency_clean,
            "jurisdiction":  juris_clean,
            "count":         len(solicitations),
            "solicitations": solicitations,
            "source":        source_used,
            "markdown":      md,
            "disclaimer":    DISCLAIMER,
            **standard_response_fields("T18", phash, "1.0"),
        }
        set_cached("T18", phash, out, T18_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T18",
            tool_name="fetch_open_solicitations",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))
