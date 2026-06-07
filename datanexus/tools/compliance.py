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

compliance.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_npi_provider)
compliance.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(search_npi_by_name)
compliance.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_finra_broker)
compliance.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(check_sam_exclusion)