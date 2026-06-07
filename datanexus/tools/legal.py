"""
DataNexus Legal sub-server — T11 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t11.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t11 import (
    fetch_patent_by_number,
    search_patents_by_keyword,
    fetch_patent_citations,
    fetch_inventor_portfolio,
)

legal = FastMCP("DataNexus Legal")

legal.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_patent_by_number)
legal.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(search_patents_by_keyword)
legal.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_patent_citations)
legal.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_inventor_portfolio)