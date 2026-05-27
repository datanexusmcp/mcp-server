"""
DataNexus MCP — Sprint 4 entry point.

Spec:      DataNexus_MCP_Spec_v7_6.docx (authoritative)
Transport: streamable-http (CLAUDE.md rule — SSE deprecated April 2026)
Server:    datanexusmcp.com  |  Hetzner CAX11  |  178.104.251.70

Registered tools (35 total):
  nonprofit  (3): nonprofit_fetch_nonprofit_by_ein, nonprofit_search_nonprofits_by_name, nonprofit_fetch_charity_uk
  security   (7): security_fetch_package_vulnerabilities, security_fetch_dependency_graph,
                  security_fetch_cve_detail, security_audit_sbom_vulnerabilities, security_fetch_package_licence,
                  security_fetch_cisa_kev, security_fetch_cve_epss
  compliance (4): compliance_fetch_npi_provider, compliance_search_npi_by_name,
                  compliance_fetch_finra_broker, compliance_check_sam_exclusion
  domain     (7): domain_fetch_domain_rdap, domain_fetch_ssl_certificate_chain,
                  domain_fetch_dns_records, domain_fetch_domain_history,
                  domain_fetch_subdomains, domain_check_email_security, domain_fetch_reverse_ip
  legal      (4): legal_fetch_patent_by_number, legal_search_patents_by_keyword,
                  legal_fetch_patent_citations, legal_fetch_inventor_portfolio
  govcon     (3): govcon_search_contract_awards, govcon_fetch_vendor_contract_history,
                  govcon_fetch_open_solicitations
  regulatory (3): regulatory_search_open_rulemakings, regulatory_fetch_docket_details,
                  regulatory_fetch_federal_register_notices
  Shared     (3): report_feedback, report_mcpize_link, validate_tool_output
  meta       (1): search_datanexus_tools

Sprint 3 P01: 26 data tools regrouped into 7 FastMCP sub-servers via mount().
Sprint 3 P02: search_datanexus_tools meta-tool added (30 total).
Sprint 4: T10 + T07 Security Pack — 5 new tools, KEV refresh, batch vulns, remediation (35 total).
"""

import asyncio
import json as _json
import logging
import pathlib as _pathlib
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List as _List, Literal as _Literal, Optional as _Optional

from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from datanexus.core.request_context import client_ip_var


class _ClientIPMiddleware:
    """
    Pure-ASGI middleware — extracts the real client IP from the X-Real-IP
    header (set by Caddy) and stores it in client_ip_var for the duration
    of the request.

    Falls back through X-Forwarded-For → ASGI client host → 'unknown'.
    Pure-ASGI (not BaseHTTPMiddleware) so contextvars are correctly
    propagated into all coroutines within the same task chain.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            ip = (
                headers.get(b"x-real-ip", b"").decode().strip()
                or headers.get(b"x-forwarded-for", b"").decode().split(",")[0].strip()
                or (scope.get("client") or ("unknown", 0))[0]
            )
            token = client_ip_var.set(ip or "unknown")
            try:
                await self.app(scope, receive, send)
            finally:
                client_ip_var.reset(token)
        else:
            await self.app(scope, receive, send)

from datanexus.db_init import init_db
from datanexus.core.prewarm import prewarm_cache
from datanexus.analytics import track_server_start, shutdown as ph_shutdown
from datanexus.kev_refresh import kev_initial_load

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
    feedback_type: _Literal["user_feedback", "agent_gap"] = "user_feedback",
    intended_query: _Optional[str] = None,
    gap_description: _Optional[str] = None,
) -> dict:
    """Report a data quality issue or agent intent gap with a DataNexus tool response. Read-only call. Records feedback for human and AI review. tool_id: Tool identifier e.g. T04 or security_fetch_cve_detail. Required. query_hash: Hash from the response being reported. Required. Found in the query_hash field of any response. signal: One of incorrect_data, missing_field, stale_data, not_useful, wrong_entity, or data_quality. Required for user_feedback. feedback_type: user_feedback (default) or agent_gap. Use agent_gap when the tool returned a valid 200 response but the result did not serve the user's actual need. intended_query: What the agent was trying to accomplish — used when feedback_type=agent_gap. Optional. Max 256 chars. gap_description: What was missing or wrong in the result — used when feedback_type=agent_gap. Optional. Max 256 chars. comment: Description of the issue. Optional. Max 500 characters. missing_fields: List of field names that are absent or wrong. Optional. Call this after receiving a result that appears wrong, outdated, or incomplete. Do not call this to report network errors — those resolve on retry. If this tool response did not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="{this_tool_id}", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    return await _real_report_feedback(
        tool_id, query_hash, signal, comment, missing_fields,
        feedback_type=feedback_type,
        intended_query=intended_query,
        gap_description=gap_description,
    )


async def report_mcpize_link(tool_id: str) -> dict:
    """Returns the MCPize subscription status and payment tier for the current DataNexus API key. Read-only. No side effects. Idempotent. tool_id: DataNexus tool identifier to check (e.g. "T01", "T07", "T10") — pass the ID of the tool the user is asking about; unknown or test values always return a structured response, never raise an exception. Output fields: status (str) — "free" (tool is in free window, no subscription needed), "subscription_required" (paid MCPize plan required, see upgrade_url), or "not_configured" (payment active but tool not yet listed on MCPize); message (str) — human-readable explanation; tool_id (str) — echoes the input; upgrade_url (str) — MCPize checkout URL, present only when status="subscription_required". Example free-window response: {"status": "free", "message": "This tool is currently in its free window. No subscription required.", "tool_id": "T10"}. Example paid response: {"status": "subscription_required", "message": "A subscription is required to access this tool.", "upgrade_url": "https://mcpize.com/checkout/...", "tool_id": "T10"}. Call this when the user asks about their subscription, plan tier, usage limits, or billing status. Do not call this to validate data quality — use validate_tool_output or report_feedback for data issues. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="report_mcpize_link", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
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
    # KEV catalog initial load — runs in background, swallows all errors
    asyncio.ensure_future(kev_initial_load())
    tools = await server.list_tools()
    asyncio.create_task(track_server_start(len(tools)))
    yield
    ph_shutdown()


main = FastMCP(
    "DataNexus MCP",
    lifespan=_lifespan,
    instructions=(
        "Use search_datanexus_tools first to find the right tool for your task. "
        "DataNexus MCP provides AI-Ready access to public data sources. "
        "Token-efficient. Verified sources. "
        "T04: US/UK nonprofits — IRS EO BMF + IRS TEOS + UK Charity Commission. "
        "nonprofit_fetch_nonprofit_by_ein: look up any US nonprofit by EIN. "
        "nonprofit_search_nonprofits_by_name: search US nonprofits by name and state. "
        "nonprofit_fetch_charity_uk: look up UK registered charities. "
        "T10: OSS Dependency & Vulnerability Intelligence — OSV.dev + NIST NVD + deps.dev + CISA KEV + FIRST EPSS. "
        "security_fetch_package_vulnerabilities: CVEs for a package version (or batch up to 50 packages). "
        "security_fetch_dependency_graph: full dep tree (hard 8s timeout). "
        "security_fetch_cve_detail: full CVE detail by CVE ID including remediation. "
        "security_audit_sbom_vulnerabilities: audit CycloneDX/SPDX SBOM against OSV.dev. "
        "security_fetch_package_licence: SPDX licence for a package version. "
        "security_fetch_cisa_kev: check if a CVE is in the CISA Known Exploited Vulnerabilities catalog. "
        "security_fetch_cve_epss: EPSS exploit probability score for a CVE from FIRST.org. "
        "T22: Professional Licence Verification — NPPES NPI Registry + FINRA BrokerCheck + SAM.gov. "
        "compliance_fetch_npi_provider: look up any US healthcare provider by NPI number. "
        "compliance_search_npi_by_name: search NPI registry by provider name with state/speciality filters. "
        "compliance_fetch_finra_broker: look up FINRA BrokerCheck registration by CRD number. "
        "compliance_check_sam_exclusion: check federal exclusions list by name or EIN. "
        "T07: Domain & DNS Intelligence — IANA RDAP + crt.sh + Cloudflare DoH + SecurityTrails. "
        "domain_fetch_domain_rdap: WHOIS-replacement RDAP lookup for any domain. "
        "domain_fetch_ssl_certificate_chain: CT log certificates for a domain. "
        "domain_fetch_dns_records: A/AAAA/MX/TXT/NS/CNAME records via Cloudflare DoH. "
        "domain_fetch_domain_history: historical certificate issuance from CT logs. "
        "domain_fetch_subdomains: enumerate known subdomains via crt.sh CT logs (24h cache). "
        "domain_check_email_security: SPF/DMARC/DKIM scored assessment with A-F grade. "
        "domain_fetch_reverse_ip: co-hosted domains on the same IPv4 via SecurityTrails. "
        "T11: Global Patent Intelligence — EPO OPS + USPTO PatentsView + WIPO PATENTSCOPE. "
        "legal_fetch_patent_by_number: full bibliographic data for a patent by number and jurisdiction. "
        "legal_search_patents_by_keyword: search EP/US/WO patents by keyword and date. "
        "legal_fetch_patent_citations: forward and backward citations for a patent. "
        "legal_fetch_inventor_portfolio: patent portfolio for an inventor, optionally by assignee. "
        "T18: Government Contracting & Procurement — USASpending.gov + SAM.gov + EU TED + UK Find-a-Tender. "
        "govcon_search_contract_awards: search federal contract awards by keyword and agency. "
        "govcon_fetch_vendor_contract_history: contract history for a specific vendor. "
        "govcon_fetch_open_solicitations: open bid opportunities matching a keyword. "
        "T19: Regulatory Docket & Comment Tracking — Regulations.gov + Federal Register + EU Have Your Say. "
        "regulatory_search_open_rulemakings: open rulemakings and comment periods. "
        "regulatory_fetch_docket_details: full docket details by ID. "
        "regulatory_fetch_federal_register_notices: recent Federal Register notices by agency. "
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
        "tools": 35,
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
        "35 tools registered (nonprofit×3, security×7, compliance×4, domain×7, "
        "legal×4, govcon×3, regulatory×3, Shared×3, meta×1)"
    )
    main.run(
        transport="streamable-http",
        host="0.0.0.0",   # nosec B104
        port=8000,
        middleware=[Middleware(_ClientIPMiddleware)],
    )
