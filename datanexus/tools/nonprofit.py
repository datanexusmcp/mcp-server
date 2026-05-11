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

nonprofit.tool()(fetch_nonprofit_by_ein)
nonprofit.tool()(search_nonprofits_by_name)
nonprofit.tool()(fetch_charity_uk)
