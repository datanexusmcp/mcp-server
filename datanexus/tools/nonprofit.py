"""
DataNexus Nonprofit sub-server — T04 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t04.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t04 import (
    fetch_nonprofit_by_ein,
    fetch_charity_uk,
    search_nonprofits_by_name,
)

nonprofit = FastMCP("DataNexus Nonprofit")

nonprofit.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_nonprofit_by_ein)
nonprofit.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(search_nonprofits_by_name)
nonprofit.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_charity_uk)