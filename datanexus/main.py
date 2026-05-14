"""
DataNexus MCP — Sprint 3 P01 entry point.

Spec:      DataNexus_MCP_Spec_v7_5.docx (authoritative)
Transport: streamable-http (CLAUDE.md rule — SSE deprecated April 2026)
Server:    datanexusmcp.com  |  Hetzner CAX11  |  178.104.251.70

Registered tools (29 total):
  nonprofit  (3): fetch_nonprofit_by_ein, search_nonprofits_by_name, fetch_charity_uk
  security   (5): fetch_package_vulnerabilities, fetch_dependency_graph,
                  fetch_cve_detail, audit_sbom_vulnerabilities, fetch_package_licence
  compliance (4): fetch_npi_provider, search_npi_by_name,
                  fetch_finra_broker, check_sam_exclusion
  domain     (4): fetch_domain_rdap, fetch_ssl_certificate_chain,
                  fetch_dns_records, fetch_domain_history
  legal      (4): fetch_patent_by_number, search_patents_by_keyword,
                  fetch_patent_citations, fetch_inventor_portfolio
  govcon     (3): search_contract_awards, fetch_vendor_contract_history,
                  fetch_open_solicitations
  regulatory (3): search_open_rulemakings, fetch_docket_details,
                  fetch_federal_register_notices
  Shared     (3): report_feedback, report_mcpize_link, validate_tool_output

Sprint 3 P01: 26 data tools regrouped into 7 FastMCP sub-servers via mount().
Tool logic unchanged — only mcp-tool registrations moved.
Sprint 3 P02: search_datanexus_tools meta-tool added (30 total).
"""

import asyncio
import json as _json
import logging
import pathlib as _pathlib
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List as _List, Optional as _Optional

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from datanexus.db_init import init_db
from datanexus.core.prewarm import prewarm_cache
from datanexus.analytics import track_server_start, shutdown as ph_shutdown

# ── Sub-server imports (P01) ──────────────────────────────────────────────────
from datanexus.tools.nonprofit  import nonprofit
from datanexus.tools.security   import security
from datanexus.tools.compliance import compliance
from datanexus.tools.domain     import domain
from datanexus.tools.legal      import legal
from datanexus.tools.govcon     import govcon
from datanexus.tools.regulatory import regulatory

# ── Section 13 validation tool ───────────────────────────────────────────────
from datanexus.tools.validation import validate_tool_output

# ── P02 meta-tool ─────────────────────────────────────────────────────────────
from datanexus.tools.meta import search_datanexus_tools

# ── Shared infrastructure tools ───────────────────────────────────────────────
# report_feedback and report_mcpize_link registered ONCE as shared infrastructure.
# tool_id parameter routes feedback and payment lookups to the correct data source.
from feedback.collector import report_feedback as _real_report_feedback
from payment.tools import report_mcpize_link as _real_report_mcpize_link


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
    """Run DB init and cache pre-warm before the first request is served."""
    await init_db()
    # Pre-warm fires in the background — errors are silently swallowed inside
    # prewarm_cache so startup is never blocked by upstream API failures.
    asyncio.ensure_future(prewarm_cache())
    tools = await server.list_tools()
    asyncio.create_task(track_server_start(len(tools)))
    yield
    ph_shutdown()


main = FastMCP(
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

# ── Mount 7 sub-servers (P01) ─────────────────────────────────────────────────
main.mount(nonprofit,   namespace="nonprofit")
main.mount(security,    namespace="security")
main.mount(compliance,  namespace="compliance")
main.mount(domain,      namespace="domain")
main.mount(legal,       namespace="legal")
main.mount(govcon,      namespace="govcon")
main.mount(regulatory,  namespace="regulatory")

# ── Register shared infrastructure tools (once — not per-tool duplicates) ─────
main.tool()(report_feedback)
main.tool()(report_mcpize_link)

# ── Register Section 13 validation tool ──────────────────────────────────────
main.tool()(validate_tool_output)

# ── Register P02 meta-tool (no namespace — top-level) ────────────────────────
main.tool()(search_datanexus_tools)

# ── Health endpoint ───────────────────────────────────────────────────────────
@main.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    """Service health check — used by load-balancer and gate verification."""
    return JSONResponse({
        "status": "ok",
        "service": "datanexus-mcp",
        "tools": 30,
        "ts": datetime.now(timezone.utc).isoformat(),
    })


# ── MCP manifest (registry discovery) ────────────────────────────────────────
@main.custom_route("/.well-known/mcp-manifest.json", methods=["GET"])
async def mcp_manifest(request: Request) -> JSONResponse:
    """Serve .well-known/mcp-manifest.json for registry discovery."""
    manifest_path = _pathlib.Path(__file__).parent.parent / "static" / ".well-known" / "mcp-manifest.json"
    try:
        data = _json.loads(manifest_path.read_text())
    except Exception:
        data = {"name": "DataNexus MCP", "version": "1.0.1"}
    return JSONResponse(data)


if __name__ == "__main__":
    logger.info(
        "DataNexus MCP starting — transport=streamable-http — "
        "30 tools registered (nonprofit×3, security×5, compliance×4, domain×4, "
        "legal×4, govcon×3, regulatory×3, Shared×3, meta×1)"
    )
    main.run(transport="streamable-http", host="0.0.0.0", port=8000)  # nosec B104
