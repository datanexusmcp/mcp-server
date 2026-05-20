"""
datanexus/tools/t19.py — T19 Regulatory Docket & Comment Tracking tool.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 5, T19 entry

Exactly 3 data functions. Shared infrastructure tools (report_feedback,
report_mcpize_link) are registered ONCE in main.py — NOT here.

Data sources:
  Primary:   Regulations.gov API — api.regulations.gov/v4
             REGULATIONS_GOV_KEY required. Free tier: 1,000 req/day.
  Secondary: Federal Register API — federalregister.gov/api/v1
             No key required.
  Supporting: EU Have Your Say — ec.europa.eu/info/law/better-regulation
             No key required.

Hard stop (absolute — never violate):
  Do NOT add regulatory analysis of rule impact on any party,
  legal direction, or any advisory output about what a rule
  requires. Do NOT characterise rule scope for any entity.
  Legal advisory territory.

Cache TTL: 14400 seconds (4 hours)
Circuit breaker source IDs: "regulations_gov", "federal_register",
  "eu_have_your_say"

Rate limit: Regulations.gov 1,000 req/day free tier.
  Ingest worker runs at 21600s (6h) intervals to stay within limit.
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timezone

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

log = logging.getLogger("datanexus.tools.t19")

mcp = FastMCP("datanexus-t19")

# ── Constants ─────────────────────────────────────────────────────────────────

T19_TTL = 14400  # 4 hours — spec requirement

DISCLAIMER = (
    "Regulatory data sourced from Regulations.gov, Federal Register, and "
    "EU Have Your Say public APIs. DataNexus does not provide regulatory "
    "analysis, legal direction, or compliance guidance. Consult qualified "
    "regulatory counsel before acting on any regulatory information."
)

REGS_GOV_URL    = "https://api.regulations.gov/v4"
FED_REG_URL     = "https://www.federalregister.gov/api/v1"
EU_HYS_URL      = "https://ec.europa.eu/info/law/better-regulation/have-your-say/api/allinitiatives"

_HTTP_TIMEOUT = httpx.Timeout(20.0, connect=8.0)
_HEADERS      = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

# Federal Register agency abbreviation → slug mapping (common agencies)
_FR_AGENCY_SLUGS: dict[str, str] = {
    "SEC":   "securities-and-exchange-commission",
    "FTC":   "federal-trade-commission",
    "FDA":   "food-and-drug-administration",
    "EPA":   "environmental-protection-agency",
    "FCC":   "federal-communications-commission",
    "CFTC":  "commodity-futures-trading-commission",
    "CFPB":  "consumer-financial-protection-bureau",
    "GSA":   "general-services-administration",
    "DOD":   "defense-department",
    "HHS":   "health-and-human-services-department",
    "DOJ":   "justice-department",
    "DHS":   "homeland-security-department",
    "DOT":   "transportation-department",
    "DOE":   "energy-department",
    "USDA":  "agriculture-department",
    "DOL":   "labor-department",
    "DOC":   "commerce-department",
    "HUD":   "housing-and-urban-development-department",
    "FERC":  "federal-energy-regulatory-commission",
    "NRC":   "nuclear-regulatory-commission",
    "FED":   "federal-reserve-system",
    "FDIC":  "federal-deposit-insurance-corporation",
    "OCC":   "comptroller-of-the-currency-office",
    "OMB":   "management-and-budget-office",
    "OSHA":  "occupational-safety-and-health-administration",
    "NLRB":  "national-labor-relations-board",
    "FHA":   "federal-housing-administration",
    "SBA":   "small-business-administration",
    "CMS":   "centers-for-medicare-medicaid-services",
    "IRS":   "internal-revenue-service",
    "CBP":   "customs-and-border-protection-bureau",
    "TSA":   "transportation-security-administration",
}


def _fr_agency_slug(agency: str) -> str:
    """Return Federal Register slug for agency abbreviation or name."""
    upper = agency.strip().upper()
    if upper in _FR_AGENCY_SLUGS:
        return _FR_AGENCY_SLUGS[upper]
    # Try lowercase hyphenated form for full names passed in
    return agency.strip().lower().replace(" ", "-").replace("_", "-")


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


def _regs_gov_key() -> str:
    return os.environ.get("REGULATIONS_GOV_KEY", "")


def _regs_gov_headers() -> dict:
    key = _regs_gov_key()
    h = {**_HEADERS}
    if key:
        h["X-Api-Key"] = key
    return h


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 1 — search_open_rulemakings
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T19")
async def search_open_rulemakings(
    keyword: str,
    agency: str = "",
    status: str = "open",
) -> dict:
    """Search open rulemakings and public comment periods on Regulations.gov and the Federal Register. Read-only. No side effects. Idempotent. US federal only. keyword: Topic keywords e.g. artificial intelligence, data privacy. Required. agency: Agency abbreviation e.g. FTC, FDA, SEC, EPA. Optional, defaults to all agencies. status: One of open, closed, or all. Optional. Default open. Returns docket title, agency, comment deadline, docket ID, and document count. Use this when monitoring regulatory activity on a topic. Use regulatory_fetch_docket_details instead when you have a docket ID and need full detail. Verified source: Regulations.gov + Federal Register. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="regulatory_search_open_rulemakings", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        kw_clean     = keyword.strip()
        agency_clean = agency.strip().upper()
        status_clean = status.strip().lower()
        if status_clean not in ("open", "closed", "all"):
            status_clean = "open"

        params = {"keyword": kw_clean, "agency": agency_clean, "status": status_clean}

        async with AuditContext("T19", params, "1.0") as _:
            _incr_calls("T19")
            phash = make_params_hash(params)

            cached = get_cached("T19", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        dockets: list[dict] = []
        source_used = ""

        # ── Regulations.gov dockets ───────────────────────────────────────────
        if not is_tripped("regulations_gov") and _regs_gov_key():
            try:
                rg_params: dict = {
                    "filter[searchTerm]": kw_clean,
                    "filter[docketType]": "Rulemaking",
                    "page[size]": 10,
                    "sort": "lastModifiedDate",
                }
                if agency_clean:
                    rg_params["filter[agencyId]"] = agency_clean
                # Map status to Regulations.gov filter
                if status_clean == "open":
                    rg_params["filter[commentStartDate][ge]"] = "2020-01-01"

                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_regs_gov_headers()
                ) as client:
                    resp = await client.get(
                        f"{REGS_GOV_URL}/dockets",
                        params=rg_params,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for item in (data.get("data") or [])[:10]:
                        attrs = item.get("attributes", {})
                        dockets.append({
                            "docket_id":       item.get("id", ""),
                            "title":           attrs.get("title", ""),
                            "agency":          attrs.get("agencyId", ""),
                            "docket_type":     attrs.get("docketType", ""),
                            "comment_deadline": attrs.get("commentDueDate", ""),
                            "last_modified":   attrs.get("lastModifiedDate", ""),
                            "doc_count":       attrs.get("numberOfComments"),
                            "source":          "Regulations.gov",
                        })
                    source_used = "Regulations.gov"
                    record_success_sync("regulations_gov")
            except Exception as exc:
                log.warning("Regulations.gov search_open_rulemakings failed: %s", exc)
                record_failure_sync("regulations_gov")

        # ── Fallback: Federal Register ────────────────────────────────────────
        if not dockets and not is_tripped("federal_register"):
            try:
                # Build params as list of tuples — Federal Register requires
                # proper bracket notation for repeated keys
                fr_params: list = [
                    ("conditions[term]", kw_clean),
                    ("fields[]", "document_number"),
                    ("fields[]", "title"),
                    ("fields[]", "agency_names"),
                    ("fields[]", "publication_date"),
                    ("fields[]", "effective_on"),
                    ("fields[]", "docket_id"),
                    ("fields[]", "type"),
                    ("per_page", 10),
                    ("order", "newest"),
                ]
                if agency_clean:
                    fr_params.append(("conditions[agencies][]", _fr_agency_slug(agency_clean)))
                # Only filter by comment_date if it makes sense (avoid empty results)
                # for 'open' status — omit filter to maximise results on fallback

                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HEADERS
                ) as client:
                    resp = await client.get(
                        f"{FED_REG_URL}/documents.json",
                        params=fr_params,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for doc in (data.get("results") or [])[:10]:
                        agencies = doc.get("agency_names") or []
                        dockets.append({
                            "docket_id":        doc.get("docket_id", doc.get("document_number", "")),
                            "title":            doc.get("title", ""),
                            "agency":           agencies[0] if agencies else "",
                            "docket_type":      doc.get("type", ""),
                            "comment_deadline": doc.get("effective_on", ""),
                            "last_modified":    doc.get("publication_date", ""),
                            "doc_count":        None,
                            "source":           "Federal Register",
                        })
                    source_used = source_used or "Federal Register"
                    record_success_sync("federal_register")
            except Exception as exc:
                log.warning("Federal Register search_open_rulemakings failed: %s", exc)
                record_failure_sync("federal_register")

        if not dockets:
            md = f"""## Open Rulemakings: {kw_clean}

No rulemakings found for this keyword and status.

**Source:** {source_used or 'unavailable'}

{DISCLAIMER}"""
            _validate_canary(md)
            _success = True
            return {
                "keyword": kw_clean, "agency": agency_clean, "status": status_clean,
                "count": 0, "dockets": [],
                "source": source_used, "markdown": md, "disclaimer": DISCLAIMER,
                **standard_response_fields("T19", phash, "1.0"),
            }

        rows = []
        for d in dockets:
            title    = (d.get("title") or "—")[:55]
            ag       = (d.get("agency") or "—")[:20]
            deadline = d.get("comment_deadline") or "—"
            did      = d.get("docket_id") or "—"
            rows.append(f"| {did} | {title} | {ag} | {deadline} |")

        table = (
            "| Docket ID | Title | Agency | Comment Deadline |\n"
            "|---|---|---|---|\n"
            + "\n".join(rows)
        )
        agency_note = f" · Agency: {agency_clean}" if agency_clean else ""
        md = f"""## Open Rulemakings: {kw_clean}{agency_note}

**Source:** {source_used}  **Status:** {status_clean}  **Results:** {len(dockets)}

{table}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "keyword":  kw_clean,
            "agency":   agency_clean,
            "status":   status_clean,
            "count":    len(dockets),
            "dockets":  dockets,
            "source":   source_used,
            "markdown": md,
            "disclaimer": DISCLAIMER,
            **standard_response_fields("T19", phash, "1.0"),
        }
        set_cached("T19", phash, out, T19_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T19",
            tool_name="search_open_rulemakings",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — fetch_docket_details
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T19")
async def fetch_docket_details(docket_id: str) -> dict:
    """Fetch full details for a specific regulatory docket by ID. Read-only. No side effects. Idempotent. US federal only. docket_id: Docket identifier in agency format e.g. EPA-HQ-OAR-2021-0317 or FTC-2024-0041. Required. Timeout is 30 seconds — large dockets may be slow. Returns docket title, agency, status, comment period dates, total comment count, and list of related documents. Use this when you have a docket ID from a search. Use regulatory_search_open_rulemakings instead when you need to find dockets by topic first. Verified source: Regulations.gov + Federal Register fallback. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="regulatory_fetch_docket_details", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        did_clean = docket_id.strip().upper()
        params = {"docket_id": did_clean}

        async with AuditContext("T19", params, "1.0") as _:
            _incr_calls("T19")
            phash = make_params_hash(params)

            cached = get_cached("T19", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        detail: dict = {}
        documents: list[dict] = []
        source_used = ""

        # ── Regulations.gov docket detail ────────────────────────────────────
        if not is_tripped("regulations_gov") and _regs_gov_key():
            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_regs_gov_headers()
                ) as client:
                    resp = await client.get(
                        f"{REGS_GOV_URL}/dockets/{did_clean}",
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    detail = {
                        "docket_id":        did_clean,
                        "title":            attrs.get("title", ""),
                        "agency":           attrs.get("agencyId", ""),
                        "docket_type":      attrs.get("docketType", ""),
                        "comment_deadline": attrs.get("commentDueDate", ""),
                        "comment_start":    attrs.get("commentStartDate", ""),
                        "num_comments":     attrs.get("numberOfComments"),
                        "last_modified":    attrs.get("lastModifiedDate", ""),
                        "keywords":         attrs.get("keywords") or [],
                    }
                    source_used = "Regulations.gov"
                    record_success_sync("regulations_gov")

                    # Fetch related documents (up to 5)
                    doc_resp = await client.get(
                        f"{REGS_GOV_URL}/documents",
                        params={
                            "filter[docketId]": did_clean,
                            "page[size]": 5,
                            "sort": "lastModifiedDate",
                        },
                    )
                    if doc_resp.status_code == 200:
                        doc_data = doc_resp.json()
                        for doc in (doc_data.get("data") or [])[:5]:
                            da = doc.get("attributes", {})
                            documents.append({
                                "doc_id":   doc.get("id", ""),
                                "title":    da.get("title", ""),
                                "type":     da.get("documentType", ""),
                                "posted":   da.get("postedDate", ""),
                            })

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    # Graceful not-found — not an error
                    md = f"""## Docket: {did_clean}

Docket not found in Regulations.gov. The docket ID may be incorrect or not yet indexed.

{DISCLAIMER}"""
                    _validate_canary(md)
                    _success = True
                    return {
                        "docket_id": did_clean, "found": False,
                        "source": "Regulations.gov", "markdown": md,
                        "disclaimer": DISCLAIMER,
                        **standard_response_fields("T19", phash, "1.0"),
                    }
                log.warning("Regulations.gov fetch_docket_details failed: %s", exc)
                record_failure_sync("regulations_gov")
            except Exception as exc:
                log.warning("Regulations.gov fetch_docket_details failed: %s", exc)
                record_failure_sync("regulations_gov")

        # ── Fallback: Federal Register document search ────────────────────────
        if not detail and not is_tripped("federal_register"):
            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HEADERS
                ) as client:
                    resp = await client.get(
                        f"{FED_REG_URL}/documents.json",
                        params=[
                            ("conditions[docket_id]", did_clean),
                            ("fields[]", "document_number"),
                            ("fields[]", "title"),
                            ("fields[]", "agency_names"),
                            ("fields[]", "publication_date"),
                            ("fields[]", "type"),
                            ("fields[]", "effective_on"),
                            ("per_page", 5),
                        ],
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    results = data.get("results") or []
                    if results:
                        first = results[0]
                        agencies = first.get("agency_names") or []
                        detail = {
                            "docket_id":        did_clean,
                            "title":            first.get("title", ""),
                            "agency":           agencies[0] if agencies else "",
                            "docket_type":      first.get("type", ""),
                            "comment_deadline": first.get("comment_date", ""),
                            "comment_start":    first.get("publication_date", ""),
                            "num_comments":     None,
                            "last_modified":    first.get("publication_date", ""),
                            "keywords":         [],
                        }
                        documents = [
                            {
                                "doc_id":  d.get("document_number", ""),
                                "title":   d.get("title", ""),
                                "type":    d.get("type", ""),
                                "posted":  d.get("publication_date", ""),
                            }
                            for d in results[:5]
                        ]
                        source_used = "Federal Register"
                        record_success_sync("federal_register")
            except Exception as exc:
                log.warning("Federal Register fetch_docket_details failed: %s", exc)
                record_failure_sync("federal_register")

        if not detail:
            md = f"""## Docket: {did_clean}

Docket details unavailable from all sources. Try again shortly.

{DISCLAIMER}"""
            _validate_canary(md)
            _success = True
            return {
                "docket_id": did_clean, "found": False,
                "source": source_used or "unavailable",
                "markdown": md, "disclaimer": DISCLAIMER,
                **standard_response_fields("T19", phash, "1.0"),
            }

        doc_lines = "\n".join(
            f"- **{d.get('type','—')}** — {d.get('title','—')} ({d.get('posted','—')})"
            for d in documents
        ) or "None indexed"

        num_comments = detail.get("num_comments")
        comments_str = f"{num_comments:,}" if isinstance(num_comments, int) else "—"

        md = f"""## Docket: {did_clean}

**Title:** {detail.get('title', '—')}
**Agency:** {detail.get('agency', '—')}
**Type:** {detail.get('docket_type', '—')}
**Comment Period:** {detail.get('comment_start', '—')} → {detail.get('comment_deadline', '—')}
**Comments Received:** {comments_str}
**Last Modified:** {detail.get('last_modified', '—')}
**Source:** {source_used}

### Related Documents
{doc_lines}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "docket_id":  did_clean,
            "found":      True,
            "detail":     detail,
            "documents":  documents,
            "source":     source_used,
            "markdown":   md,
            "disclaimer": DISCLAIMER,
            **standard_response_fields("T19", phash, "1.0"),
        }
        set_cached("T19", phash, out, T19_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T19",
            tool_name="fetch_docket_details",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_federal_register_notices
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T19")
async def fetch_federal_register_notices(
    agency: str,
    keyword: str = "",
    date_from: str = "",
) -> dict:
    """Fetch recent Federal Register notices and rules for a specific agency. Read-only. No side effects. Idempotent. US federal only. agency: Agency name or abbreviation e.g. SEC, Food and Drug Administration, EPA. Required. keyword: Optional topic filter e.g. cryptocurrency. Optional, defaults to all notices. date_from: Earliest publication date in ISO 8601 format e.g. 2024-01-31. Optional, defaults to last 90 days. Returns document type, title, publication date, effective date, and CFR citations. Use this to monitor recent regulatory activity for an agency. Use regulatory_search_open_rulemakings instead when filtering by topic across all agencies. Verified source: Federal Register API. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="regulatory_fetch_federal_register_notices", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        agency_clean  = agency.strip()
        keyword_clean = keyword.strip()
        date_clean    = date_from.strip()
        params = {"agency": agency_clean, "keyword": keyword_clean, "date_from": date_clean}

        async with AuditContext("T19", params, "1.0") as _:
            _incr_calls("T19")
            phash = make_params_hash(params)

            cached = get_cached("T19", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        notices: list[dict] = []
        source_used = ""

        if not is_tripped("federal_register"):
            try:
                # Build params as list of tuples for correct bracket encoding
                fr_params: list = [
                    ("conditions[agencies][]", _fr_agency_slug(agency_clean)),
                    ("fields[]", "document_number"),
                    ("fields[]", "title"),
                    ("fields[]", "agency_names"),
                    ("fields[]", "publication_date"),
                    ("fields[]", "effective_on"),
                    ("fields[]", "docket_id"),
                    ("fields[]", "type"),
                    ("fields[]", "citation"),
                    ("fields[]", "cfr_references"),
                    ("per_page", 10),
                    ("order", "newest"),
                ]
                if keyword_clean:
                    fr_params.append(("conditions[term]", keyword_clean))
                if date_clean:
                    fr_params.append(("conditions[publication_date][gte]", date_clean))

                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HEADERS
                ) as client:
                    resp = await client.get(
                        f"{FED_REG_URL}/documents.json",
                        params=fr_params,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for doc in (data.get("results") or [])[:10]:
                        agencies = doc.get("agency_names") or []
                        cfr_refs = doc.get("cfr_references") or []
                        cfr_str = ", ".join(
                            f"{c.get('title')} CFR {c.get('part')}"
                            for c in cfr_refs[:3]
                            if c.get("title") and c.get("part")
                        )
                        notices.append({
                            "doc_number":    doc.get("document_number", ""),
                            "title":         doc.get("title", ""),
                            "type":          doc.get("type", ""),
                            "agency":        agencies[0] if agencies else agency_clean,
                            "published":     doc.get("publication_date", ""),
                            "effective_on":  doc.get("effective_on", ""),
                            "comment_date":  doc.get("comment_date", ""),
                            "docket_id":     doc.get("docket_id", ""),
                            "citation":      doc.get("citation", ""),
                            "cfr":           cfr_str,
                        })
                    source_used = "Federal Register"
                    record_success_sync("federal_register")
            except Exception as exc:
                log.warning("Federal Register fetch_federal_register_notices failed: %s", exc)
                record_failure_sync("federal_register")

        if not notices:
            md = f"""## Federal Register: {agency_clean}

No notices found for this agency{' and keyword' if keyword_clean else ''}.

**Source:** {source_used or 'unavailable'}

{DISCLAIMER}"""
            _validate_canary(md)
            _success = True
            return {
                "agency": agency_clean, "keyword": keyword_clean, "date_from": date_clean,
                "count": 0, "notices": [],
                "source": source_used, "markdown": md, "disclaimer": DISCLAIMER,
                **standard_response_fields("T19", phash, "1.0"),
            }

        rows = []
        for n in notices:
            title   = (n.get("title") or "—")[:55]
            ntype   = n.get("type") or "—"
            pub     = n.get("published") or "—"
            eff     = n.get("effective_on") or "—"
            cfr     = n.get("cfr") or "—"
            rows.append(f"| {title} | {ntype} | {pub} | {eff} | {cfr} |")

        table = (
            "| Title | Type | Published | Effective | CFR |\n"
            "|---|---|---|---|---|\n"
            + "\n".join(rows)
        )
        kw_note   = f" · Keyword: {keyword_clean}" if keyword_clean else ""
        date_note = f" · From: {date_clean}" if date_clean else ""
        md = f"""## Federal Register: {agency_clean}{kw_note}{date_note}

**Source:** {source_used}  **Results:** {len(notices)}

{table}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "agency":    agency_clean,
            "keyword":   keyword_clean,
            "date_from": date_clean,
            "count":     len(notices),
            "notices":   notices,
            "source":    source_used,
            "markdown":  md,
            "disclaimer": DISCLAIMER,
            **standard_response_fields("T19", phash, "1.0"),
        }
        set_cached("T19", phash, out, T19_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T19",
            tool_name="fetch_federal_register_notices",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))
