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

govcon.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(search_contract_awards)
govcon.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_vendor_contract_history)
govcon.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_open_solicitations)