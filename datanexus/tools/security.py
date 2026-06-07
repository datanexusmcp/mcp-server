"""
DataNexus Security sub-server — T10 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t10.py.
Sprint 4: added fetch_cisa_kev, fetch_cve_epss.
"""
from fastmcp import FastMCP

from datanexus.tools.t10 import (
    fetch_package_vulnerabilities,
    fetch_dependency_graph,
    fetch_cve_detail,
    audit_sbom_vulnerabilities,
    fetch_package_licence,
    fetch_cisa_kev,
    fetch_cve_epss,
)

security = FastMCP("DataNexus Security")

security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_package_vulnerabilities)
security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_dependency_graph)
security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_cve_detail)
security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(audit_sbom_vulnerabilities)
security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_package_licence)
security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_cisa_kev)
security.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_cve_epss)