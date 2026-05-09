"""
DataNexus MCP — Sprint 1 + Section 13 + Sprint 2 (T22, T07, T11) entry point.

Spec:      DataNexus_MCP_Spec_v7_4.docx (authoritative)
Transport: streamable-http (CLAUDE.md rule — SSE deprecated April 2026)
Server:    datanexusmcp.com  |  Hetzner CAX11  |  178.104.251.70

Registered tools (23 total after T11):
  T04 (3): fetch_nonprofit_by_ein, search_nonprofits_by_name, fetch_charity_uk
  T10 (5): fetch_package_vulnerabilities, fetch_dependency_graph,
           fetch_cve_detail, audit_sbom_vulnerabilities, fetch_package_licence
  T22 (4): fetch_npi_provider, search_npi_by_name,
           fetch_finra_broker, check_sam_exclusion
  T07 (4): fetch_domain_rdap, fetch_ssl_certificate_chain,
           fetch_dns_records, fetch_domain_history
  T11 (4): fetch_patent_by_number, search_patents_by_keyword,
           fetch_patent_citations, fetch_inventor_portfolio
  Shared (2): report_feedback, report_mcpize_link
  S13 (1):    validate_tool_output

Phase 4: report_feedback delegates to feedback.collector.report_feedback.
Phase 5: report_mcpize_link delegates to payment.tools.report_mcpize_link.
         @verify_entitlement sourced from payment.entitlement (tool modules).
         report_feedback and report_mcpize_link are registered ONCE as shared
         infrastructure — tool_id parameter routes to the correct data source.

# ── SECTION 13 ADDITIONS (v7.4) ─────────────────
# validate_tool_output: added in Section 13
#   See: DataNexus_MCP_Spec_v7_4.docx Section 13.6
#
# Haiku triggers — exactly 4, no others permitted:
#   T1: anomaly_reviewer.review_anomaly()
#   T2: feedback_classifier.classify_feedback()
#   T3: schema_monitor.assess_schema_change()
#   T4: digest_generator.generate_weekly_digest()
#
# Tool count after Sprint 1 + S13: 11
# Tool count after Sprint 2 T22:   15
# Tool count after Sprint 2 T07:   19
# Tool count after Sprint 2 T11:   23
#   T04: fetch_nonprofit_by_ein,
#        search_nonprofits_by_name, fetch_charity_uk
#   T10: fetch_package_vulnerabilities,
#        fetch_dependency_graph, fetch_cve_detail,
#        audit_sbom_vulnerabilities,
#        fetch_package_licence
#   T22: fetch_npi_provider, search_npi_by_name,
#        fetch_finra_broker, check_sam_exclusion
#   T07: fetch_domain_rdap, fetch_ssl_certificate_chain,
#        fetch_dns_records, fetch_domain_history
#   T11: fetch_patent_by_number, search_patents_by_keyword,
#        fetch_patent_citations, fetch_inventor_portfolio
#   Shared: report_feedback, report_mcpize_link
#   S13:    validate_tool_output
# ─────────────────────────────────────────────────
"""

import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from datanexus.db_init import init_db

# ── T04 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t04 import (
    fetch_nonprofit_by_ein,
    fetch_charity_uk,
    search_nonprofits_by_name,
)

# ── T10 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t10 import (
    fetch_package_vulnerabilities,
    fetch_dependency_graph,
    fetch_cve_detail,
    audit_sbom_vulnerabilities,
    fetch_package_licence,
)

# ── T22 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t22 import (
    fetch_npi_provider,
    search_npi_by_name,
    fetch_finra_broker,
    check_sam_exclusion,
)

# ── T07 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t07 import (
    fetch_domain_rdap,
    fetch_ssl_certificate_chain,
    fetch_dns_records,
    fetch_domain_history,
)

# ── T11 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t11 import (
    fetch_patent_by_number,
    search_patents_by_keyword,
    fetch_patent_citations,
    fetch_inventor_portfolio,
)

# ── T18 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t18 import (
    search_contract_awards,
    fetch_vendor_contract_history,
    fetch_open_solicitations,
)

# ── T19 data tools ────────────────────────────────────────────────────────────
from datanexus.tools.t19 import (
    search_open_rulemakings,
    fetch_docket_details,
    fetch_federal_register_notices,
)

# ── Section 13 validation tool ───────────────────────────────────────────────
from datanexus.tools.validation import validate_tool_output

# ── Shared infrastructure tools ───────────────────────────────────────────────
# report_feedback and report_mcpize_link are registered ONCE on the shared server.
# tool_id parameter ('T04' or 'T10') routes feedback and payment lookups correctly.
from feedback.collector import report_feedback as _real_report_feedback
from payment.tools import report_mcpize_link as _real_report_mcpize_link
from typing import List as _List, Optional as _Optional


async def report_feedback(
    tool_id: str,
    query_hash: str,
    signal: str,
    comment: str = "",
    missing_fields: _Optional[_List[str]] = None,
) -> dict:
    """
    Report a data quality issue with any DataNexus tool response. Call this after receiving a result that appears wrong, outdated, or incomplete — for example: an EIN returns the wrong organisation, a CVE severity looks incorrect, or a field expected in the response is absent.
    Parameters: tool_id (required) — 'T04' (nonprofit) or 'T10' (vulnerability), the tool that returned the suspect result. query_hash (required) — the query_hash field from that tool response. signal (required) — one of: incorrect_data, missing_field, stale_data, not_useful, wrong_entity. comment (optional) — description of what appears wrong (max 200 chars).
    Returns: {'status': 'recorded'} — always. Response time: <200 ms. No auth required. Token-efficient.
    """
    return await _real_report_feedback(tool_id, query_hash, signal, comment, missing_fields)


async def report_mcpize_link(tool_id: str) -> dict:
    """
    Check whether a DataNexus tool requires a paid subscription and retrieve the upgrade URL if so. Call this when a user asks about pricing, access limits, or subscription status.
    Parameters: tool_id (required) — 'T04' (nonprofit data) or 'T10' (vulnerability intelligence).
    Returns: status 'free' — tool is currently free, no action needed; or upgrade_url — subscription link if the free window has ended. Backed by DataNexus billing system. Response time: <200 ms. No auth required. Token-efficient.
    """
    return _real_report_mcpize_link(tool_id)

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("datanexus.main")


# ── Startup lifespan — DB table init ─────────────────────────────────────────
@asynccontextmanager
async def _lifespan(server):
    """Run DB table initialisation once before the first request is served."""
    await init_db()
    yield


app = FastMCP(
    "DataNexus MCP",
    lifespan=_lifespan,
    instructions=(
        "DataNexus MCP provides AI-Ready access to public data sources. "
        "Token-efficient. Verified sources. "
        "T04: US/UK nonprofits — IRS EO BMF + IRS TEOS + UK Charity Commission. "
        "fetch_nonprofit_by_ein: look up any US nonprofit by EIN. "
        "search_nonprofits_by_name: search US nonprofits by name and state. "
        "fetch_charity_uk: look up UK registered charities. "
        "T10: OSS Dependency & Vulnerability Intelligence — OSV.dev + NIST NVD + deps.dev. "
        "fetch_package_vulnerabilities: CVEs for a package version. "
        "fetch_dependency_graph: full dep tree (hard 8s timeout). "
        "fetch_cve_detail: full CVE detail by CVE ID. "
        "audit_sbom_vulnerabilities: audit CycloneDX/SPDX SBOM against OSV.dev. "
        "fetch_package_licence: SPDX licence for a package version. "
        "T22: Professional Licence Verification — NPPES NPI Registry + FINRA BrokerCheck + SAM.gov. "
        "fetch_npi_provider: look up any US healthcare provider by NPI number. "
        "search_npi_by_name: search NPI registry by provider name with state/speciality filters. "
        "fetch_finra_broker: look up FINRA BrokerCheck registration by CRD number. "
        "check_sam_exclusion: check federal exclusions list by name or EIN. "
        "T07: Domain & DNS Intelligence — IANA RDAP + crt.sh + Cloudflare DoH. "
        "fetch_domain_rdap: WHOIS-replacement RDAP lookup for any domain. "
        "fetch_ssl_certificate_chain: CT log certificates for a domain. "
        "fetch_dns_records: A/AAAA/MX/TXT/NS/CNAME records via Cloudflare DoH. "
        "fetch_domain_history: historical certificate issuance from CT logs. "
        "T11: Global Patent Intelligence — EPO OPS + USPTO PatentsView + WIPO PATENTSCOPE. "
        "fetch_patent_by_number: full bibliographic data for a patent by number and jurisdiction. "
        "search_patents_by_keyword: search EP/US/WO patents by keyword and date. "
        "fetch_patent_citations: forward and backward citations for a patent. "
        "fetch_inventor_portfolio: patent portfolio for an inventor, optionally by assignee. "
        "T18: Government Contracting & Procurement — USASpending.gov + SAM.gov + EU TED + UK Find-a-Tender. "
        "search_contract_awards: search federal contract awards by keyword and agency. "
        "fetch_vendor_contract_history: contract history for a specific vendor. "
        "fetch_open_solicitations: open bid opportunities matching a keyword. "
        "T19: Regulatory Docket & Comment Tracking — Regulations.gov + Federal Register + EU Have Your Say. "
        "search_open_rulemakings: open rulemakings and comment periods. "
        "fetch_docket_details: full docket details by ID. "
        "fetch_federal_register_notices: recent Federal Register notices by agency. "
        "All responses include query_hash, schema_version, data_as_of, ingest_healthy."
    ),
)

# ── Register T04 data tools ───────────────────────────────────────────────────
app.tool()(fetch_nonprofit_by_ein)
app.tool()(search_nonprofits_by_name)
app.tool()(fetch_charity_uk)

# ── Register T10 data tools ───────────────────────────────────────────────────
app.tool()(fetch_package_vulnerabilities)
app.tool()(fetch_dependency_graph)
app.tool()(fetch_cve_detail)
app.tool()(audit_sbom_vulnerabilities)
app.tool()(fetch_package_licence)

# ── Register T22 data tools ───────────────────────────────────────────────────
app.tool()(fetch_npi_provider)
app.tool()(search_npi_by_name)
app.tool()(fetch_finra_broker)
app.tool()(check_sam_exclusion)

# ── Register T07 data tools ───────────────────────────────────────────────────
app.tool()(fetch_domain_rdap)
app.tool()(fetch_ssl_certificate_chain)
app.tool()(fetch_dns_records)
app.tool()(fetch_domain_history)

# ── Register T11 data tools ───────────────────────────────────────────────────
app.tool()(fetch_patent_by_number)
app.tool()(search_patents_by_keyword)
app.tool()(fetch_patent_citations)
app.tool()(fetch_inventor_portfolio)

# ── Register T18 data tools ───────────────────────────────────────────────────
app.tool()(search_contract_awards)
app.tool()(fetch_vendor_contract_history)
app.tool()(fetch_open_solicitations)

# ── Register T19 data tools ───────────────────────────────────────────────────
app.tool()(search_open_rulemakings)
app.tool()(fetch_docket_details)
app.tool()(fetch_federal_register_notices)

# ── Register shared infrastructure tools (once — not per-tool duplicates) ─────
app.tool()(report_feedback)
app.tool()(report_mcpize_link)

# ── Register Section 13 validation tool ──────────────────────────────────────
app.tool()(validate_tool_output)

# ── Health endpoint ───────────────────────────────────────────────────────────
@app.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    """Service health check — used by load-balancer and gate verification."""
    return JSONResponse({
        "status": "ok",
        "service": "datanexus-mcp",
        "tools": 29,
        "ts": datetime.now(timezone.utc).isoformat(),
    })

# ── MCP manifest (registry discovery) ────────────────────────────────────────
import json as _json
import pathlib as _pathlib

@app.custom_route("/.well-known/mcp-manifest.json", methods=["GET"])
async def mcp_manifest(request: Request) -> JSONResponse:
    """Serve .well-known/mcp-manifest.json for registry discovery."""
    manifest_path = _pathlib.Path(__file__).parent.parent / ".well-known" / "mcp-manifest.json"
    try:
        data = _json.loads(manifest_path.read_text())
    except Exception:
        data = {"name": "DataNexus MCP", "version": "1.0.1"}
    return JSONResponse(data)

if __name__ == "__main__":
    logger.info(
        "DataNexus MCP starting — transport=streamable-http — "
        "29 tools registered (T04×3, T10×5, T22×4, T07×4, T11×4, T18×3, T19×3, Shared×2, Section13×1)"
    )
    app.run(transport="streamable-http", host="0.0.0.0", port=8000)
