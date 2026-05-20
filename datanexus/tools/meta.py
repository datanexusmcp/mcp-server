"""
P02 — search_datanexus_tools meta-tool.
Keyword overlap scoring against TOOL_REGISTRY task descriptions.
Analytics: INCR redis key analytics:search:{YYYY-MM-DD} — no raw query text stored.
"""

import logging
import re
from datetime import date
from typing import Optional

from datanexus.cache import get_redis

log = logging.getLogger(__name__)

TOOL_REGISTRY = [
    {"name": "nonprofit_fetch_nonprofit_by_ein",         "task": "research a US charity or nonprofit by EIN number"},
    {"name": "nonprofit_search_nonprofits_by_name",      "task": "search for nonprofits or charities by organisation name"},
    {"name": "nonprofit_fetch_charity_uk",               "task": "look up a UK registered charity by number or name"},
    {"name": "security_fetch_package_vulnerabilities",   "task": "check a software package for known CVEs and security vulnerabilities"},
    {"name": "security_fetch_dependency_graph",          "task": "get the full dependency tree for a software package"},
    {"name": "security_fetch_cve_detail",                "task": "get full detail on a specific CVE vulnerability by ID"},
    {"name": "security_audit_sbom_vulnerabilities",      "task": "audit a software bill of materials for known vulnerabilities"},
    {"name": "security_fetch_package_licence",           "task": "check the open source licence for a package version"},
    {"name": "compliance_fetch_npi_provider",            "task": "verify a US healthcare provider by NPI number"},
    {"name": "compliance_search_npi_by_name",            "task": "search for a healthcare provider by name and state"},
    {"name": "compliance_fetch_finra_broker",            "task": "verify a financial broker or advisor registration with FINRA"},
    {"name": "compliance_check_sam_exclusion",           "task": "check whether a person or company is excluded from federal contracting"},
    {"name": "domain_fetch_domain_rdap",                 "task": "look up domain registration and ownership details"},
    {"name": "domain_fetch_ssl_certificate_chain",       "task": "inspect the SSL certificate chain for a domain"},
    {"name": "domain_fetch_dns_records",                 "task": "get DNS records for a domain"},
    {"name": "domain_fetch_domain_history",              "task": "get historical SSL certificate records for a domain"},
    {"name": "legal_fetch_patent_by_number",             "task": "look up a specific patent by number across US EP or WO"},
    {"name": "legal_search_patents_by_keyword",          "task": "search for patents by keyword to find prior art"},
    {"name": "legal_fetch_patent_citations",             "task": "get forward and backward citation chains for a patent"},
    {"name": "legal_fetch_inventor_portfolio",           "task": "get all patents filed by a specific inventor or assignee"},
    {"name": "govcon_search_contract_awards",            "task": "search government contract awards by keyword or agency"},
    {"name": "govcon_fetch_vendor_contract_history",     "task": "get the full government contract history for a specific vendor"},
    {"name": "govcon_fetch_open_solicitations",          "task": "find currently open government procurement opportunities"},
    {"name": "regulatory_search_open_rulemakings",       "task": "find open regulatory rulemakings and comment periods"},
    {"name": "regulatory_fetch_docket_details",          "task": "get full details for a specific regulatory docket by ID"},
    {"name": "regulatory_fetch_federal_register_notices","task": "fetch recent Federal Register notices for an agency"},
]

_STOPWORDS = {"a", "an", "the", "for", "by", "or", "and", "to", "of", "in", "on", "at", "is", "with", "from", "all"}


def _tokenize(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in _STOPWORDS]


def _token_match(qt: str, tt: str) -> bool:
    if qt == tt:
        return True
    # Handle plurals and simple suffix variations (e.g. "patent" / "patents")
    if len(qt) >= 4 and len(tt) >= 4:
        return tt.startswith(qt) or qt.startswith(tt)
    return False


def _score(query_tokens: list[str], task_tokens: list[str]) -> int:
    count = 0
    for qt in query_tokens:
        for tt in task_tokens:
            if _token_match(qt, tt):
                count += 1
                break
    return count


async def search_datanexus_tools(query: str, domain: Optional[str] = None) -> dict:
    """Find the right DataNexus tool by describing your task in plain English. Read-only. No side effects. Call this before any other DataNexus tool to reduce context load from 40000 to 800 tokens. query: Plain English description of your task e.g. check if a Python package has CVEs or look up a UK charity by name. Required. domain: Restrict results to one sub-server: nonprofit, security, compliance, domain, legal, govcon, or regulatory. Optional. Returns matching tool names and parameter hints you can call directly. Do not call this recursively or to validate results — use validate_tool_output for that. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="search_datanexus_tools", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    # Analytics: INCR daily counter — raw query text is never stored
    analytics_key = f"analytics:search:{date.today().isoformat()}"
    try:
        r = await get_redis()
        if r is not None:
            await r.incr(analytics_key)
    except Exception:
        log.error("analytics_incr_failed key=%s", analytics_key)

    query_tokens = _tokenize(query)
    results = []
    for entry in TOOL_REGISTRY:
        if domain and not entry["name"].startswith(f"{domain}_"):
            continue
        score = _score(query_tokens, _tokenize(entry["task"]))
        if score > 0:
            results.append({"name": entry["name"], "task": entry["task"], "score": score})

    results.sort(key=lambda x: x["score"], reverse=True)
    log.info("meta_search query_len=%d results=%d", len(query), len(results))
    return {"tools": results}
