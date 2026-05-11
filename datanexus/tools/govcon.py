"""
DataNexus GovCon sub-server — T18 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t18.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t18 import (
    search_contract_awards,
    fetch_vendor_contract_history,
    fetch_open_solicitations,
)

govcon = FastMCP("DataNexus GovCon")

govcon.tool()(search_contract_awards)
govcon.tool()(fetch_vendor_contract_history)
govcon.tool()(fetch_open_solicitations)
