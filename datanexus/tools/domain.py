"""
DataNexus Domain sub-server — T07 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t07.py.
"""
from fastmcp import FastMCP

from datanexus.tools.t07 import (
    fetch_domain_rdap,
    fetch_ssl_certificate_chain,
    fetch_dns_records,
    fetch_domain_history,
)

domain = FastMCP("DataNexus Domain")

domain.tool()(fetch_domain_rdap)
domain.tool()(fetch_ssl_certificate_chain)
domain.tool()(fetch_dns_records)
domain.tool()(fetch_domain_history)
