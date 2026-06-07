"""
DataNexus Domain sub-server — T07 tools.
Sprint 3 P01: mcp-tool registrations only. Tool logic lives in t07.py.
Sprint 4: added fetch_subdomains, check_email_security, fetch_reverse_ip.
"""
from fastmcp import FastMCP

from datanexus.tools.t07 import (
    fetch_domain_rdap,
    fetch_ssl_certificate_chain,
    fetch_dns_records,
    fetch_domain_history,
    fetch_subdomains,
    check_email_security,
    fetch_reverse_ip,
)

domain = FastMCP("DataNexus Domain")

domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_domain_rdap)
domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_ssl_certificate_chain)
domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_dns_records)
domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_domain_history)
domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_subdomains)
domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(check_email_security)
domain.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(fetch_reverse_ip)