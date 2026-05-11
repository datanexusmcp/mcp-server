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

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

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

log = logging.getLogger("datanexus.tools.t11")

mcp = FastMCP("datanexus-t11")

# ── Constants ─────────────────────────────────────────────────────────────────

T11_TTL = 86400  # 24 hours — spec requirement

DISCLAIMER = (
    "Patent data sourced from EPO Open Patent Services, USPTO PatentsView, "
    "and WIPO PATENTSCOPE. DataNexus does not warrant completeness or legal "
    "accuracy. Patent status and claims should be verified with the issuing "
    "authority. Not legal advice."
)

EPO_AUTH_URL      = "https://ops.epo.org/3.2/auth/accesstoken"
EPO_OPS_URL       = "https://ops.epo.org/3.2/rest-services"
PATENTSVIEW_URL   = "https://api.patentsview.org/patents/query"
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

@mcp.tool()
@with_timeout
@verify_entitlement("T11")
async def fetch_patent_by_number(patent_number: str, jurisdiction: str = "EP") -> dict:
    """Use this to look up a specific patent by its number.
    Provide the patent number and jurisdiction: US, EP, or WO.
    Returns filing details, claims summary, inventor, and current assignee."""
    patent_clean = patent_number.strip().upper()
    juris_clean  = jurisdiction.strip().upper()
    params = {"patent_number": patent_clean, "jurisdiction": juris_clean}

    async with AuditContext("T11", params, "1.0") as _:
        _incr_calls("T11")
        phash = make_params_hash(params)

        cached = get_cached("T11", phash)
        if cached:
            return cached

        result: dict = {}
        source_used = ""
        staleness: list[str] = []

        # ── Try EPO OPS for EP/WO jurisdiction ───────────────────────────────
        if juris_clean in ("EP", "WO") and not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    epo_num = patent_clean.lstrip("EP").lstrip("WO")
                    epo_kind = "EP" if juris_clean == "EP" else "WO"
                    url = (
                        f"{EPO_OPS_URL}/published-data/publication/"
                        f"epodoc/{epo_kind}{epo_num}/biblio"
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

        # ── Fallback: USPTO PatentsView (US jurisdiction or EPO failure) ─────
        if not result and not is_tripped("patentsview"):
            try:
                q = {"_eq": {"patent_number": patent_clean.lstrip("US")}}
                payload = {
                    "q": q,
                    "f": [
                        "patent_id", "patent_title", "patent_date",
                        "patent_num_claims", "inventor_first_name",
                        "inventor_last_name", "assignee_organization",
                        "assignee_first_name", "assignee_last_name",
                    ],
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
                        result = _patentsview_doc_to_dict(patents[0])
                        result["patent_number"] = patent_clean
                        result["jurisdiction"]  = "US"
                        source_used = "USPTO PatentsView"
                        record_success_sync("patentsview")
            except Exception as exc:
                log.warning("PatentsView fetch_patent_by_number failed: %s", exc)
                record_failure_sync("patentsview")
                staleness.append(get_staleness_notice("patentsview", "unknown"))

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
        return out


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — search_patents_by_keyword
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T11")
async def search_patents_by_keyword(
    keywords: str,
    jurisdiction: str = "EP",
    date_from: str = "",
) -> dict:
    """Use this to search for patents by keyword to find prior art before filing.
    Provide keywords and optional jurisdiction.
    Returns matching patents with numbers, titles, and filing dates."""
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
            return cached

        results: list[dict] = []
        source_used = ""
        staleness: list[str] = []

        # ── EPO OPS full-text search ──────────────────────────────────────────
        if juris_clean in ("EP", "WO") and not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    cql_parts = [f'txt="{kw_clean}"']
                    if juris_clean == "WO":
                        cql_parts.append('pn=WO')
                    if date_from:
                        cql_parts.append(f'pd>={date_from.replace("-", "")}')
                    cql = " AND ".join(cql_parts)
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
                        docs = (
                            data.get("ops:world-patent-data", {})
                            .get("ops:biblio-search", {})
                            .get("ops:search-result", {})
                            .get("ops:publication-reference", [])
                        )
                        if isinstance(docs, dict):
                            docs = [docs]
                        for doc in docs[:10]:
                            entry = _epo_doc_to_dict(doc)
                            entry["jurisdiction"] = juris_clean
                            results.append(entry)
                        source_used = "EPO OPS"
                        record_success_sync("epo_ops")
                except Exception as exc:
                    log.warning("EPO search_patents_by_keyword failed: %s", exc)
                    record_failure_sync("epo_ops")
                    staleness.append(get_staleness_notice("epo_ops", "unknown"))

        # ── USPTO PatentsView fallback ────────────────────────────────────────
        if not results and not is_tripped("patentsview"):
            try:
                q_parts: list[dict] = [{"_text_any": {"patent_title": kw_clean}}]
                if date_from:
                    q_parts.append({"_gte": {"patent_date": date_from}})
                query = {"_and": q_parts} if len(q_parts) > 1 else q_parts[0]
                payload = {
                    "q": query,
                    "f": [
                        "patent_id", "patent_title", "patent_date",
                        "inventor_first_name", "inventor_last_name",
                        "assignee_organization",
                    ],
                    "o": {"per_page": 10},
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
                    for p in (data.get("patents") or []):
                        entry = _patentsview_doc_to_dict(p)
                        entry["jurisdiction"] = "US"
                        results.append(entry)
                    source_used = "USPTO PatentsView"
                    record_success_sync("patentsview")
            except Exception as exc:
                log.warning("PatentsView search_patents_by_keyword failed: %s", exc)
                record_failure_sync("patentsview")
                staleness.append(get_staleness_notice("patentsview", "unknown"))

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
        return out


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_patent_citations
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T11")
async def fetch_patent_citations(
    patent_number: str,
    jurisdiction: str = "EP",
) -> dict:
    """Use this to get citation chains for a specific patent.
    Provide the patent number and jurisdiction.
    Returns patents that cite this one and patents this one cites."""
    patent_clean = patent_number.strip().upper()
    juris_clean  = jurisdiction.strip().upper()
    params = {"patent_number": patent_clean, "jurisdiction": juris_clean}

    async with AuditContext("T11", params, "1.0") as _:
        _incr_calls("T11")
        phash = make_params_hash(params)

        cached = get_cached("T11", phash)
        if cached:
            return cached

        cited_by:  list[dict] = []
        cites:     list[dict] = []
        source_used = ""
        staleness: list[str] = []

        # ── EPO OPS citations endpoint ────────────────────────────────────────
        if juris_clean in ("EP", "WO") and not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    epo_num = patent_clean.lstrip("EP").lstrip("WO")
                    epo_kind = "EP" if juris_clean == "EP" else "WO"
                    url = (
                        f"{EPO_OPS_URL}/published-data/publication/"
                        f"epodoc/{epo_kind}{epo_num}/citations"
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

        md = f"""## Citations — {patent_clean} ({juris_clean})

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
        return out


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — fetch_inventor_portfolio
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T11")
async def fetch_inventor_portfolio(
    inventor_name: str,
    assignee: str = "",
) -> dict:
    """Use this to get all patents filed by a specific inventor.
    Provide the inventor name and optional assignee to narrow results.
    Returns the full portfolio with filing dates and current status."""
    name_clean     = inventor_name.strip()
    assignee_clean = assignee.strip()
    params = {"inventor_name": name_clean, "assignee": assignee_clean}

    async with AuditContext("T11", params, "1.0") as _:
        _incr_calls("T11")
        phash = make_params_hash(params)

        cached = get_cached("T11", phash)
        if cached:
            return cached

        results: list[dict] = []
        source_used = ""
        staleness: list[str] = []

        # ── EPO OPS inventor search ───────────────────────────────────────────
        if not is_tripped("epo_ops"):
            token = _get_epo_token()
            if token:
                try:
                    cql = f'in="{name_clean}"'
                    if assignee_clean:
                        cql += f' AND pa="{assignee_clean}"'
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
                        docs = (
                            data.get("ops:world-patent-data", {})
                            .get("ops:biblio-search", {})
                            .get("ops:search-result", {})
                            .get("ops:publication-reference", [])
                        )
                        if isinstance(docs, dict):
                            docs = [docs]
                        for doc in docs[:20]:
                            entry = _epo_doc_to_dict(doc)
                            entry["jurisdiction"] = "EP"
                            results.append(entry)
                        source_used = "EPO OPS"
                        record_success_sync("epo_ops")
                except Exception as exc:
                    log.warning("EPO fetch_inventor_portfolio failed: %s", exc)
                    record_failure_sync("epo_ops")
                    staleness.append(get_staleness_notice("epo_ops", "unknown"))

        # ── USPTO PatentsView inventor search ─────────────────────────────────
        if not results and not is_tripped("patentsview"):
            try:
                name_parts = name_clean.rsplit(" ", 1)
                first = name_parts[0] if len(name_parts) > 1 else ""
                last  = name_parts[-1]
                q_parts: list[dict] = [{"_eq": {"inventor_last_name": last}}]
                if first:
                    q_parts.append({"_eq": {"inventor_first_name": first}})
                if assignee_clean:
                    q_parts.append({"_contains": {"assignee_organization": assignee_clean}})
                query = {"_and": q_parts} if len(q_parts) > 1 else q_parts[0]
                payload = {
                    "q": query,
                    "f": [
                        "patent_id", "patent_title", "patent_date",
                        "inventor_first_name", "inventor_last_name",
                        "assignee_organization",
                    ],
                    "o": {"per_page": 20},
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
                    for p in (data.get("patents") or []):
                        entry = _patentsview_doc_to_dict(p)
                        entry["jurisdiction"] = "US"
                        results.append(entry)
                    source_used = "USPTO PatentsView"
                    record_success_sync("patentsview")
            except Exception as exc:
                log.warning("PatentsView fetch_inventor_portfolio failed: %s", exc)
                record_failure_sync("patentsview")
                staleness.append(get_staleness_notice("patentsview", "unknown"))

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
        return out
