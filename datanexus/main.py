"""
DataNexus MCP — Sprint 1 + Section 13 entry point.

Spec:      DataNexus_MCP_Spec_v7_4.docx (authoritative)
Transport: streamable-http (CLAUDE.md rule — SSE deprecated April 2026)
Server:    datanexusmcp.com  |  Hetzner CAX11  |  178.104.251.70

Registered tools (11 total):
  T04 (3): fetch_nonprofit_by_ein, search_nonprofits_by_name, fetch_charity_uk
  T10 (5): fetch_package_vulnerabilities, fetch_dependency_graph,
           fetch_cve_detail, audit_sbom_vulnerabilities, fetch_package_licence
  Shared (2): report_feedback, report_mcpize_link
  New (1):    validate_tool_output

Phase 4: report_feedback delegates to feedback.collector.report_feedback.
Phase 5: report_mcpize_link delegates to payment.tools.report_mcpize_link.
         @verify_entitlement sourced from payment.entitlement (t04.py, t10.py).
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
# Tool count after Section 13: 11 total
#   T04: fetch_nonprofit_by_ein,
#        search_nonprofits_by_name, fetch_charity_uk
#   T10: fetch_package_vulnerabilities,
#        fetch_dependency_graph, fetch_cve_detail,
#        audit_sbom_vulnerabilities,
#        fetch_package_licence
#   Shared: report_feedback, report_mcpize_link
#   New:    validate_tool_output
# ─────────────────────────────────────────────────
"""

import logging
import sys
from datetime import datetime, timezone

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

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

app = FastMCP(
    "DataNexus MCP",
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
        "tools": 11,
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
        "11 tools registered (T04×3, T10×5, Shared×2, Section13×1)"
    )
    app.run(transport="streamable-http", host="0.0.0.0", port=8000)
