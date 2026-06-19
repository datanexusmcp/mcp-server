"""
datanexus/tools/t11.py — T11 Global Patent Intelligence tool.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 4, T11 entry

Exactly 4 data functions. Shared infrastructure tools (report_feedback,
report_mcpize_link) are registered ONCE in main.py — NOT here.

Data sources:
  Primary:   EPO OPS (Open Patent Services) — ops.epo.org — OAuth client_credentials
             European Patent Office API; 4 GB/month free tier
  Secondary: USPTO PatentsView — api.patentsview.org — no key required
             US patent data open API
  Supporting: WIPO PATENTSCOPE — patentscope.wipo.int/search/api — no key
             International patent search

Hard stop (absolute — never violate):
  Do NOT produce patent monetary assessments, claims about patent scope,
  claims of patent ownership suitability, legal advice, or opinions on
  whether a patent is valid or actionable against a third party.
  See spec Section 4 T11 for the complete list of prohibited terms.

Cache TTL: 86400 seconds (24 hours)
Circuit breaker source IDs: "epo_ops", "patentsview", "wipo_patentscope"
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Annotated, Optional

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
    get_staleness_notice,
    is_tripped,
    record_failure_sync,
    record_success_sync,
)
from datanexus.core.schema import ErrorCode, error_response
from payment.entitlement import verify_entitlement
from datanexus.core.timeout import with_timeout
from datanexus.analytics import fire_and_forget, track_tool_call, track_tool_error

log = logging.getLogger("datanexus.tools.t11")

mcp = FastMCP("datanexus-t11")

# ── Constants ─────────────────────────────────────────────────────────────────

T11_TTL = 86400  # 24 hours — spec requirement

DISCLAIMER = (
    "Patent data sourced from EPO Open Patent Services and WIPO PATENTSCOPE. "
    "USPTO PatentsView decommissioned May 2026; US patent search is no longer "
    "available from free sources. DataNexus does not warrant completeness or "
    "legal accuracy. Patent status and claims should be verified with the "
    "issuing authority. Not legal advice."
)

EPO_AUTH_URL      = "https://ops.epo.org/3.2/auth/accesstoken"
EPO_OPS_URL       = "https://ops.epo.org/3.2/rest-services"
PATENTSVIEW_URL   = "https://api.patentsview.org/patents/query"  # decommissioned May 2026
WIPO_SEARCH_URL   = "https://patentscope.wipo.int/search/api/patents"

_HTTP_TIMEOUT = httpx.Timeout(20.0, connect=8.0)
_HEADERS      = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

# EPO free tier: 4 GB/month; trip circuit breaker at 3.8 GB
_EPO_BYTES_LIMIT = 3_800_000_000

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

# Country codes accepted by EPO OPS EPODOC cross-reference lookup.
# EP and WO are EPO-native; all others are cross-country references.
_EPODOC_COUNTRY_PREFIXES: frozenset = frozenset({
    "EP", "WO",                                         # EPO native
    "CN", "JP", "KR", "US", "DE", "FR", "GB", "AU",    # major filing offices
    "CA", "IN", "RU", "BR", "MX", "CH", "AT", "NL",
    "SE", "IT", "ES", "PL", "BE", "DK", "FI", "NO",
    "PT", "HU", "CZ", "SK", "RO", "BG", "HR", "SI",
    "TW", "IL", "ZA", "SG",
})


def _normalize_epodoc(patent_clean: str) -> tuple:
    """
    Normalize a patent number string to a valid EPO EPODOC identifier.

    Returns ``(epodoc_id, country_code)`` where ``epodoc_id`` can be passed
    directly to the EPO OPS ``/published-data/publication/epodoc/{id}/``
    endpoint, and ``country_code`` is the 2-letter authority prefix.

    Examples:
      "EP1000000"     → ("EP1000000", "EP")     standard EP patent
      "WO2020123456"  → ("WO2020123456", "WO")  PCT application
      "CN120586032"   → ("CN120586032", "CN")   Chinese patent — used as-is
      "EPCN120586032" → ("CN120586032", "CN")   malformed: EP prepended to CN
      "1000000"       → ("EP1000000", "EP")     bare number — assume EP

    Root cause of the EPCN bug: callers were passing the full EPODOC identifier
    (e.g. "CN120586032") but the tool additionally prepended the jurisdiction
    kind code ("EP"), producing "EPCN120586032" which EPO OPS rejects as 400.
    """
    if len(patent_clean) >= 2:
        prefix = patent_clean[:2]
        if prefix in _EPODOC_COUNTRY_PREFIXES:
            if prefix in ("EP", "WO"):
                # Check for malformed "EP" + <other country> compound, e.g. "EPCN120586032"
                remainder = patent_clean[2:]
                if len(remainder) >= 2 and remainder[:2] in _EPODOC_COUNTRY_PREFIXES:
                    # Strip the erroneous leading "EP"/"WO" — use the embedded identifier
                    inner_country = remainder[:2]
                    return remainder, inner_country
            # Standard: "EP1000000", "CN120586032", "JP2020123456", etc.
            return patent_clean, prefix
    # Bare number with no recognisable prefix — assume EP
    return f"EP{patent_clean}", "EP"


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


# ── EPO OAuth token management ────────────────────────────────────────────────

def _get_epo_token() -> Optional[str]:
    """
    Fetch or return a cached EPO OPS OAuth token.

    Token stored in Redis at datanexus:epo:token:{expiry_ts}.
    Lifetime: 20 minutes per EPO spec. Refreshed with 60s buffer.
    Returns None if EPO credentials are absent or request fails.
    """
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    client_id     = os.environ.get("EPO_CLIENT_ID", "")
    client_secret = os.environ.get("EPO_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None

    r = _get_redis()
    now = int(time.time())

    # Scan for a valid cached token (key pattern datanexus:epo:token:*)
    if r is not None:
        try:
            keys = r.keys("datanexus:epo:token:*")
            for key in keys:
                parts = key.split(":")
                if len(parts) == 4:
                    expiry_ts = int(parts[3])
                    if expiry_ts > now + 60:  # 60s buffer
                        token = r.get(key)
                        if token:
                            return token
        except Exception:
            pass

    # Fetch new token
    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            resp = client.post(
                EPO_AUTH_URL,
                data={"grant_type": "client_credentials"},
                auth=(client_id, client_secret),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            token = data.get("access_token", "")
            expires_in = int(data.get("expires_in", 1200))  # default 20 min
            expiry_ts = now + expires_in

            if r is not None and token:
                cache_key = f"datanexus:epo:token:{expiry_ts}"
                try:
                    r.setex(cache_key, expires_in, token)
                except Exception:
                    pass

            return token or None
    except Exception as exc:
        log.warning("EPO token fetch failed: %s", exc)
        return None


def _track_epo_bytes(byte_count: int) -> None:
    """
    Increment EPO monthly byte counter. Trip circuit breaker at 3.8 GB.

    Redis key: datanexus:epo:bytes_used:{month_iso}  (e.g. 2026-05)
    """
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    from datanexus.core.circuit_breaker import record_failure_sync
    r = _get_redis()
    if r is None:
        return
    month_iso = datetime.now(timezone.utc).strftime("%Y-%m")
    key = f"datanexus:epo:bytes_used:{month_iso}"
    try:
        total = r.incrby(key, byte_count)
        r.expire(key, 40 * 86400)  # 40-day TTL so key survives end of month
        if total > _EPO_BYTES_LIMIT:
            record_failure_sync("epo_ops")
            log.warning(json.dumps({
                "event":      "epo_free_tier_exceeded",
                "bytes_used": total,
                "limit":      _EPO_BYTES_LIMIT,
                "month":      month_iso,
            }))
    except Exception:
        pass


# ── EPO response normalisation ────────────────────────────────────────────────

def _epo_doc_to_dict(doc: dict) -> dict:
    """Extract key fields from a single EPO OPS bibliographic document."""
    bib = doc.get("bibliographic-data", doc)

    # Title
    title_obj = bib.get("invention-title", {})
    if isinstance(title_obj, list):
        title_obj = title_obj[0] if title_obj else {}
    title = title_obj.get("$", title_obj.get("#text", "")) if isinstance(title_obj, dict) else str(title_obj)

    # Applicants/assignees
    parties = bib.get("parties", {})
    applicants_raw = parties.get("applicants", {}).get("applicant", [])
    if isinstance(applicants_raw, dict):
        applicants_raw = [applicants_raw]
    applicants = []
    for ap in applicants_raw:
        name_obj = ap.get("applicant-name", {}).get("name", {})
        name = name_obj.get("$", "") if isinstance(name_obj, dict) else str(name_obj)
        if name:
            applicants.append(name)

    # Inventors
    inventors_raw = parties.get("inventors", {}).get("inventor", [])
    if isinstance(inventors_raw, dict):
        inventors_raw = [inventors_raw]
    inventors = []
    for inv in inventors_raw:
        name_obj = inv.get("inventor-name", {}).get("name", {})
        name = name_obj.get("$", "") if isinstance(name_obj, dict) else str(name_obj)
        if name:
            inventors.append(name)

    # Dates
    pub_ref = bib.get("publication-reference", {}).get("document-id", {})
    if isinstance(pub_ref, list):
        pub_ref = pub_ref[0] if pub_ref else {}
    pub_date = pub_ref.get("date", {})
    pub_date = pub_date.get("$", "") if isinstance(pub_date, dict) else str(pub_date)

    # IPC classification
    ipc_raw = bib.get("classifications-ipcr", {}).get("classification-ipcr", [])
    if isinstance(ipc_raw, dict):
        ipc_raw = [ipc_raw]
    ipc_codes = []
    for ipc in ipc_raw[:3]:
        section = ipc.get("section", {}).get("$", "")
        cls = ipc.get("class", {}).get("$", "")
        sub = ipc.get("subclass", {}).get("$", "")
        if section:
            ipc_codes.append(f"{section}{cls}{sub}".strip())

    return {
        "title":       title,
        "applicants":  applicants,
        "inventors":   inventors,
        "pub_date":    pub_date,
        "ipc_codes":   ipc_codes,
    }


def _extract_epo_search_docs(data: dict) -> list:
    """
    Extract exchange-document list from EPO OPS /published-data/search response.

    EPO changed their response format: results are now under
    ops:search-result > exchange-documents (list of {exchange-document: ...})
    rather than the old ops:search-result > ops:publication-reference path.
    """
    sr = (
        data.get("ops:world-patent-data", {})
            .get("ops:biblio-search", {})
            .get("ops:search-result", {})
    )
    exchange_docs = sr.get("exchange-documents", [])
    if isinstance(exchange_docs, dict):
        exchange_docs = [exchange_docs]
    docs = []
    for item in exchange_docs:
        doc = item.get("exchange-document", item)
        if isinstance(doc, list):
            doc = doc[0]  # multiple family members — take the first
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def _patentsview_doc_to_dict(patent: dict) -> dict:
    """Extract key fields from a PatentsView patent record."""
    inventors = [
        f"{i.get('inventor_first_name', '')} {i.get('inventor_last_name', '')}".strip()
        for i in patent.get("inventors", [])
        if i.get("inventor_last_name")
    ]
    assignees = [
        a.get("assignee_organization") or
        f"{a.get('assignee_first_name', '')} {a.get('assignee_last_name', '')}".strip()
        for a in patent.get("assignees", [])
        if a.get("assignee_organization") or a.get("assignee_last_name")
    ]
    return {
        "patent_id":   patent.get("patent_id", ""),
        "title":       patent.get("patent_title", ""),
        "date":        patent.get("patent_date", ""),
        "inventors":   inventors,
        "assignees":   assignees,
        "num_claims":  patent.get("patent_num_claims"),
    }


# ── Source-limitation notice ──────────────────────────────────────────────────

def _source_limitation(reason: str) -> str:
    return f"[Source limitation: {reason}. {DISCLAIMER}]"


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 1 — fetch_patent_by_number
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T11")
async def fetch_patent_by_number(patent_number: Annotated[str, Field(description="Patent number e.g. EP3456789 or US10123456. Required.")], jurisdiction: Annotated[str, Field(description="Patent office code: EP, US, WO. Default EP. Optional.")] = "EP") -> dict:
    """Fetch full patent details by patent number and jurisdiction. Read-only. No side effects. Idempotent. patent_number: Patent number in EPODOC format e.g. EP1000000 for European, CN120586032 for Chinese, JP2020123456 for Japanese, WO2020123456 for PCT, US10000000 for US. Required. jurisdiction: Optional hint — one of EP, CN, JP, KR, US, WO, etc. Default EP. The tool normalises the patent number automatically; passing CN120586032 with jurisdiction EP is valid. Returns title, abstract, inventors, assignees, filing date, claims summary, and citation count. Use this when you have a specific patent number. Use legal_search_patents_by_keyword instead when you only have keywords and need to find patents. Verified source: EPO OPS. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="legal_fetch_patent_by_number", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        patent_clean = patent_number.strip().upper()
        juris_clean  = jurisdiction.strip().upper()
        params = {"patent_number": patent_clean, "jurisdiction": juris_clean}

        async with AuditContext("T11", params, "1.0") as _:
            _incr_calls("T11")
            phash = make_params_hash(params)

            cached = get_cached("T11", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        result: dict = {}
        source_used = ""
        staleness: list[str] = []

        # ── Try EPO OPS (supports EP, WO, and cross-country EPODOC lookups) ────
        epodoc_id, country_code = _normalize_epodoc(patent_clean)
        if country_code in _EPODOC_COUNTRY_PREFIXES and not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    url = (
                        f"{EPO_OPS_URL}/published-data/publication/"
                        f"epodoc/{epodoc_id}/biblio"
                    )
                    async with httpx.AsyncClient(
                        timeout=_HTTP_TIMEOUT, headers=_HEADERS
                    ) as client:
                        resp = await client.get(
                            url,
                            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                        )
                        resp.raise_for_status()
                        _track_epo_bytes(len(resp.content))
                        data = resp.json()
                        doc_list = (
                            data.get("ops:world-patent-data", {})
                            .get("ops:biblio-search", {})
                            .get("ops:search-result", {})
                            .get("ops:publication-reference", [])
                        )
                        if not doc_list:
                            # Single result path
                            doc_list = (
                                data.get("ops:world-patent-data", {})
                                .get("exchange-documents", {})
                                .get("exchange-document", [])
                            )
                        if isinstance(doc_list, dict):
                            doc_list = [doc_list]
                        if doc_list:
                            result = _epo_doc_to_dict(doc_list[0])
                            result["patent_number"] = patent_clean
                            result["jurisdiction"]  = juris_clean
                            source_used = "EPO OPS"
                            record_success_sync("epo_ops")
                except Exception as exc:
                    log.warning("EPO fetch_patent_by_number failed: %s", exc)
                    record_failure_sync("epo_ops")
                    staleness.append(get_staleness_notice("epo_ops", "unknown"))

        # Note: USPTO PatentsView decommissioned May 2026. US patents only
        # available via EPO cross-reference for US-published EP families.

        if not result:
            resp = error_response(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "Patent data unavailable from all sources.",
                params,
            )
            if staleness:
                resp["staleness_notices"] = staleness
            return resp

        title   = result.get("title", patent_clean)
        juris_l = result.get("jurisdiction", juris_clean)
        num_out = result.get("patent_number", patent_clean)
        invs    = ", ".join(result.get("inventors", [])) or "—"
        appls   = ", ".join(result.get("applicants", result.get("assignees", []))) or "—"
        ipc     = ", ".join(result.get("ipc_codes", [])) or "—"
        pub_dt  = result.get("pub_date", result.get("date", "—"))
        claims  = result.get("num_claims", "—")

        md = f"""## Patent {num_out} ({juris_l})

**Title:** {title}
**Applicants/Assignees:** {appls}
**Inventors:** {invs}
**IPC Classification:** {ipc}
**Publication Date:** {pub_dt}
**Claims:** {claims}
**Source:** {source_used}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "patent_number": num_out,
            "jurisdiction":  juris_l,
            "title":         title,
            "applicants":    result.get("applicants", result.get("assignees", [])),
            "inventors":     result.get("inventors", []),
            "ipc_codes":     result.get("ipc_codes", []),
            "pub_date":      pub_dt,
            "source":        source_used,
            "markdown":      md,
            "disclaimer":    DISCLAIMER,
            **standard_response_fields("T11", phash, "1.0"),
        }
        if staleness:
            out["staleness_notices"] = staleness

        set_cached("T11", phash, out, T11_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T11",
            tool_name="fetch_patent_by_number",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
            jurisdiction=jurisdiction,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — search_patents_by_keyword
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T11")
async def search_patents_by_keyword(
    keywords: Annotated[str, Field(description="Search keyword or phrase e.g. CRISPR gene editing. Required.")],
    jurisdiction: Annotated[str, Field(description="Patent office code: EP, US, WO. Default EP. Optional.")] = "EP",
    date_from: Annotated[str, Field(description="Earliest filing date ISO 8601 e.g. 2020-01-31. Optional.")] = "",
) -> dict:
    """Search patents by keyword across EPO, USPTO, or WIPO. Read-only. No side effects. Idempotent. Returns up to 10 matches. keywords: Search terms describing the invention e.g. neural network image classification. Required. jurisdiction: One of EP, US, or WO. Optional. Default EP. date_from: Earliest filing date in ISO 8601 format e.g. 2020-01-31. Optional, defaults to no lower bound. Returns patent numbers, titles, and filing dates. Use this when finding prior art or exploring a technology landscape without a specific number. Use legal_fetch_patent_by_number instead when you have the patent number already. Verified source: EPO OPS + USPTO. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="legal_search_patents_by_keyword", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        kw_clean    = keywords.strip()
        juris_clean = jurisdiction.strip().upper()
        params = {
            "keywords":    kw_clean,
            "jurisdiction": juris_clean,
            "date_from":   date_from.strip(),
        }

        async with AuditContext("T11", params, "1.0") as _:
            _incr_calls("T11")
            phash = make_params_hash(params)

            cached = get_cached("T11", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        results: list[dict] = []
        source_used = ""
        staleness: list[str] = []

        # ── Keyword preprocessing ─────────────────────────────────────────────
        # Strip meta-words that won't appear in patent title/abstract text.
        # Users naturally type "cat vaccine patents" but "patent(s)" is never
        # in a patent's own abstract — including it causes EPO to return 0 results.
        _META_WORDS = {
            "patent", "patents", "patented", "application", "applications",
            "prior art", "prior", "art", "invention", "inventions",
            "filing", "filed", "claim", "claims",
        }
        kw_tokens = kw_clean.split()
        kw_filtered = " ".join(t for t in kw_tokens if t.lower() not in _META_WORDS)
        kw_cql = kw_filtered.strip() or kw_clean  # fallback to original if all stripped
        if kw_cql != kw_clean:
            log.debug("search_patents_by_keyword: meta-word filter: %r → %r", kw_clean, kw_cql)

        # ── EPO OPS full-text search ──────────────────────────────────────────
        if juris_clean in ("EP", "WO") and not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    # EPO OPS CQL: use 'ta all "phrase"' (title AND abstract,
                    # contains all words).  'ti = "phrase"' causes HTTP 404 for
                    # multi-word queries because = is strict field equality.
                    # Use kw_cql (meta-words stripped) not kw_clean.
                    cql = f'ta all "{kw_cql}"'
                    if date_from:
                        # EPO date format: YYYYMMDD (no hyphens)
                        cql += f' AND pd >= {date_from.replace("-", "")}'
                    url = f"{EPO_OPS_URL}/published-data/search/biblio"
                    async with httpx.AsyncClient(
                        timeout=_HTTP_TIMEOUT, headers=_HEADERS
                    ) as client:
                        resp = await client.get(
                            url,
                            params={"q": cql, "Range": "1-10"},
                            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                        )
                        resp.raise_for_status()
                        _track_epo_bytes(len(resp.content))
                        data = resp.json()
                        # EPO search returns exchange-documents (not ops:publication-reference)
                        docs = _extract_epo_search_docs(data)
                        for doc in docs[:10]:
                            entry = _epo_doc_to_dict(doc)
                            entry["patent_number"] = (
                                doc.get("@country", "") + doc.get("@doc-number", "")
                            )
                            entry["jurisdiction"] = juris_clean
                            results.append(entry)
                        source_used = "EPO OPS"
                        record_success_sync("epo_ops")
                except Exception as exc:
                    log.warning("EPO search_patents_by_keyword failed: %s", exc)
                    record_failure_sync("epo_ops")
                    staleness.append(get_staleness_notice("epo_ops", "unknown"))

        # Note: USPTO PatentsView decommissioned May 2026. No free US patent
        # search API is currently available without registration.

        if not results:
            resp = error_response(
                ErrorCode.NOT_FOUND,
                f"No patent results found for '{kw_clean}'.",
                params,
            )
            if staleness:
                resp["staleness_notices"] = staleness
            return resp

        rows = []
        for r in results:
            t     = r.get("title") or r.get("patent_title", "—")
            appl  = (", ".join(r.get("applicants", r.get("assignees", []))) or "—")[:60]
            date  = r.get("pub_date", r.get("date", "—"))
            ipc   = ", ".join(r.get("ipc_codes", [])) or "—"
            pid   = r.get("patent_number", r.get("patent_id", ""))
            rows.append(f"| {pid} | {t[:60]} | {appl} | {date} | {ipc} |")

        table = (
            "| Patent | Title | Applicant | Published | IPC |\n"
            "|---|---|---|---|---|\n"
            + "\n".join(rows)
        )
        md = f"""## Patent Search: {kw_clean} ({juris_clean})

**Source:** {source_used}  **Results:** {len(results)}

{table}

{DISCLAIMER}"""

        _validate_canary(md)

        phash_out = make_params_hash(params)
        out = {
            "keywords":    kw_clean,
            "jurisdiction": juris_clean,
            "count":       len(results),
            "results":     results,
            "source":      source_used,
            "markdown":    md,
            "disclaimer":  DISCLAIMER,
            **standard_response_fields("T11", phash_out, "1.0"),
        }
        if staleness:
            out["staleness_notices"] = staleness

        set_cached("T11", phash_out, out, T11_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T11",
            tool_name="search_patents_by_keyword",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_patent_citations
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T11")
async def fetch_patent_citations(
    patent_number: Annotated[str, Field(description="Patent number e.g. EP3456789 or US10123456. Required.")],
    jurisdiction: Annotated[str, Field(description="Patent office code: EP, US, WO. Default EP. Optional.")] = "EP",
) -> dict:
    """Fetch forward and backward citation chains for a specific patent. Read-only. No side effects. Idempotent. patent_number: Patent number in EPODOC format e.g. EP1000000 for European, CN120586032 for Chinese, JP2020123456 for Japanese, WO2020123456 for PCT, US10000000 for US. Required. jurisdiction: Optional hint — one of EP, US, WO, CN, JP, KR, etc. Default EP. The tool normalises the patent number automatically; passing CN120586032 with jurisdiction EP is valid. Returns citing patents (forward citations) and cited patents (backward citations) with filing dates and titles. Use this when building a prior art citation chain for a specific patent you already have. Use legal_search_patents_by_keyword instead when you need to find patents by topic not by citation. Verified source: EPO OPS. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="legal_fetch_patent_citations", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        patent_clean = patent_number.strip().upper()
        juris_clean  = jurisdiction.strip().upper()
        params = {"patent_number": patent_clean, "jurisdiction": juris_clean}

        async with AuditContext("T11", params, "1.0") as _:
            _incr_calls("T11")
            phash = make_params_hash(params)

        cached = get_cached("T11", phash)
        if cached:
            _success = True
            _cache_hit = True
            return cached

        cited_by:  list[dict] = []
        cites:     list[dict] = []
        source_used = ""
        staleness: list[str] = []

        # ── EPO OPS citations endpoint ────────────────────────────────────────
        epodoc_id, country_code = _normalize_epodoc(patent_clean)
        if country_code in _EPODOC_COUNTRY_PREFIXES and not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    url = (
                        f"{EPO_OPS_URL}/published-data/publication/"
                        f"epodoc/{epodoc_id}/citations"
                    )
                    async with httpx.AsyncClient(
                        timeout=_HTTP_TIMEOUT, headers=_HEADERS
                    ) as client:
                        resp = await client.get(
                            url,
                            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                        )
                        resp.raise_for_status()
                        _track_epo_bytes(len(resp.content))
                        data = resp.json()
                        refs = (
                            data.get("ops:world-patent-data", {})
                            .get("exchange-documents", {})
                            .get("exchange-document", {})
                            .get("references-cited", {})
                            .get("citation", [])
                        )
                        if isinstance(refs, dict):
                            refs = [refs]
                        for ref in refs[:20]:
                            doc_id = ref.get("patcit", {}).get("document-id", {})
                            if isinstance(doc_id, list):
                                doc_id = doc_id[0] if doc_id else {}
                            ref_num = doc_id.get("doc-number", {})
                            ref_num = ref_num.get("$", "") if isinstance(ref_num, dict) else str(ref_num)
                            cites.append({"patent_number": ref_num})
                        source_used = "EPO OPS"
                        record_success_sync("epo_ops")
                except Exception as exc:
                    log.warning("EPO fetch_patent_citations failed: %s", exc)
                    record_failure_sync("epo_ops")
                    staleness.append(get_staleness_notice("epo_ops", "unknown"))

        # ── PatentsView citations (US) ────────────────────────────────────────
        if juris_clean == "US" and not is_tripped("patentsview"):
            try:
                pnum = patent_clean.lstrip("US")
                payload = {
                    "q": {"_eq": {"patent_number": pnum}},
                    "f": ["patent_id", "cited_patent_number", "citedby_patent_number",
                          "cited_patent_title", "citedby_patent_title",
                          "cited_patent_date", "citedby_patent_date"],
                    "o": {"per_page": 1},
                }
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HEADERS
                ) as client:
                    resp = await client.post(
                        PATENTSVIEW_URL,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    patents = data.get("patents") or []
                    if patents:
                        for entry in patents[0].get("cited_patents", [])[:20]:
                            cites.append({
                                "patent_number": entry.get("cited_patent_number", ""),
                                "title":         entry.get("cited_patent_title", ""),
                                "date":          entry.get("cited_patent_date", ""),
                            })
                        for entry in patents[0].get("citedby_patents", [])[:20]:
                            cited_by.append({
                                "patent_number": entry.get("citedby_patent_number", ""),
                                "title":         entry.get("citedby_patent_title", ""),
                                "date":          entry.get("citedby_patent_date", ""),
                            })
                        source_used = "USPTO PatentsView"
                        record_success_sync("patentsview")
            except Exception as exc:
                log.warning("PatentsView fetch_patent_citations failed: %s", exc)
                record_failure_sync("patentsview")
                staleness.append(get_staleness_notice("patentsview", "unknown"))

        cites_md = "\n".join(
            f"- {c.get('patent_number', '')} {c.get('title', '')}"
            for c in cites
        ) or "None found"
        cited_by_md = "\n".join(
            f"- {c.get('patent_number', '')} {c.get('title', '')}"
            for c in cited_by
        ) or "None found"

        display_num = epodoc_id if epodoc_id != patent_clean else patent_clean
        md = f"""## Citations — {display_num} ({country_code})

**Source:** {source_used}

### Patents Cited (backward citations)
{cites_md}

### Cited By (forward citations)
{cited_by_md}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "patent_number": patent_clean,
            "jurisdiction":  juris_clean,
            "cites":         cites,
            "cited_by":      cited_by,
            "source":        source_used,
            "markdown":      md,
            "disclaimer":    DISCLAIMER,
            **standard_response_fields("T11", phash, "1.0"),
        }
        if staleness:
            out["staleness_notices"] = staleness

        set_cached("T11", phash, out, T11_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T11",
            tool_name="fetch_patent_citations",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — fetch_inventor_portfolio
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T11")
async def fetch_inventor_portfolio(
    inventor_name: Annotated[str, Field(description="Inventor surname or full name e.g. John Smith. Required.")],
    assignee: Annotated[str, Field(description="Company name to filter results e.g. Apple Inc. Optional.")] = "",
) -> dict:
    """Fetch the patent portfolio for a named inventor with optional assignee filter. Read-only. No side effects. Idempotent. inventor_name: Inventor surname or full name e.g. Smith or John Smith. Required. Fuzzy match — common names may return many results. assignee: Company or organisation name to narrow results e.g. Apple Inc. Optional. Returns patent numbers, titles, filing dates, jurisdictions, and current status. Use this when researching an inventor's work or a company's patent portfolio. Use legal_search_patents_by_keyword instead when you need patents by topic not by inventor. Verified source: EPO OPS + USPTO. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="legal_fetch_inventor_portfolio", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        name_clean     = inventor_name.strip()
        assignee_clean = assignee.strip()
        params = {"inventor_name": name_clean, "assignee": assignee_clean}

        async with AuditContext("T11", params, "1.0") as _:
            _incr_calls("T11")
            phash = make_params_hash(params)

            cached = get_cached("T11", phash)
            if cached:
                _success = True
                _cache_hit = True
                return cached

        results: list[dict] = []
        source_used = ""
        staleness: list[str] = []

        # ── EPO OPS inventor search ───────────────────────────────────────────
        if not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    # EPO OPS CQL: spaces around = are required
                    cql = f'in = "{name_clean}"'
                    if assignee_clean:
                        cql += f' AND pa = "{assignee_clean}"'
                    url = f"{EPO_OPS_URL}/published-data/search/biblio"
                    async with httpx.AsyncClient(
                        timeout=_HTTP_TIMEOUT, headers=_HEADERS
                    ) as client:
                        resp = await client.get(
                            url,
                            params={"q": cql, "Range": "1-20"},
                            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                        )
                        resp.raise_for_status()
                        _track_epo_bytes(len(resp.content))
                        data = resp.json()
                        # EPO search returns exchange-documents (not ops:publication-reference)
                        docs = _extract_epo_search_docs(data)
                        for doc in docs[:20]:
                            entry = _epo_doc_to_dict(doc)
                            entry["patent_number"] = (
                                doc.get("@country", "") + doc.get("@doc-number", "")
                            )
                            entry["jurisdiction"] = "EP"
                            results.append(entry)
                        source_used = "EPO OPS"
                        record_success_sync("epo_ops")
                except Exception as exc:
                    log.warning("EPO fetch_inventor_portfolio failed: %s", exc)
                    record_failure_sync("epo_ops")
                    staleness.append(get_staleness_notice("epo_ops", "unknown"))

        # Note: USPTO PatentsView decommissioned May 2026. EP portfolio only.

        if not results:
            resp = error_response(
                ErrorCode.NOT_FOUND,
                f"No patents found for inventor '{name_clean}'.",
                params,
            )
            if staleness:
                resp["staleness_notices"] = staleness
            return resp

        rows = []
        for r in results:
            t    = (r.get("title") or r.get("patent_title", "—"))[:60]
            date = r.get("pub_date", r.get("date", "—"))
            pid  = r.get("patent_number", r.get("patent_id", ""))
            jur  = r.get("jurisdiction", "—")
            rows.append(f"| {pid} | {t} | {date} | {jur} |")

        table = (
            "| Patent | Title | Published | Jurisdiction |\n"
            "|---|---|---|---|\n"
            + "\n".join(rows)
        )
        filter_note = f" (Assignee filter: {assignee_clean})" if assignee_clean else ""
        md = f"""## Patent Portfolio — {name_clean}{filter_note}

**Source:** {source_used}  **Total:** {len(results)}

{table}

{DISCLAIMER}"""

        _validate_canary(md)

        out = {
            "inventor_name": name_clean,
            "assignee":      assignee_clean,
            "count":         len(results),
            "results":       results,
            "source":        source_used,
            "markdown":      md,
            "disclaimer":    DISCLAIMER,
            **standard_response_fields("T11", phash, "1.0"),
        }
        if staleness:
            out["staleness_notices"] = staleness

        set_cached("T11", phash, out, T11_TTL)
        _success = True
        _cache_hit = bool(out.get("cache_hit", False))
        return out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T11",
            tool_name="fetch_inventor_portfolio",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))
