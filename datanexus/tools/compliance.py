"""
DataNexus Compliance sub-server — T22 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t22.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t22 import (
    fetch_npi_provider,
    search_npi_by_name,
    fetch_finra_broker,
    check_sam_exclusion,
)

compliance = FastMCP("DataNexus Compliance")

compliance.tool()(fetch_npi_provider)
compliance.tool()(search_npi_by_name)
compliance.tool()(fetch_finra_broker)
compliance.tool()(check_sam_exclusion)
