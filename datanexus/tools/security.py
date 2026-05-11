"""
DataNexus Security sub-server — T10 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t10.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t10 import (
    fetch_package_vulnerabilities,
    fetch_dependency_graph,
    fetch_cve_detail,
    audit_sbom_vulnerabilities,
    fetch_package_licence,
)

security = FastMCP("DataNexus Security")

security.tool()(fetch_package_vulnerabilities)
security.tool()(fetch_dependency_graph)
security.tool()(fetch_cve_detail)
security.tool()(audit_sbom_vulnerabilities)
security.tool()(fetch_package_licence)
