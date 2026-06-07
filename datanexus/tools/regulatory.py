"""
DataNexus Regulatory sub-server — T19 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t19.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t19 import (
    search_open_rulemakings,
    fetch_docket_details,
    fetch_federal_register_notices,
)

regulatory = FastMCP("DataNexus Regulatory")

regulatory.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(search_open_rulemakings)
regulatory.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_docket_details)
regulatory.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_federal_register_notices)