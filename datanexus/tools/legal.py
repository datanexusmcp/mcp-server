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

legal.tool()(fetch_patent_by_number)
legal.tool()(search_patents_by_keyword)
legal.tool()(fetch_patent_citations)
legal.tool()(fetch_inventor_portfolio)
