"""
datanexus/core/timeout.py — Hard timeout decorator for all tool handlers.

P04: Every mcp-tool handler (except report_feedback, report_mcpize_link,
validate_tool_output, search_datanexus_tools) must be wrapped with @with_timeout.

Decorator order (top to bottom):
    mcp.tool()
    @with_timeout
    @verify_entitlement("TXX")
    async def handler(...) -> dict:
"""

import asyncio
import functools

TOOL_TIMEOUT_SECONDS = 8.0


def with_timeout(fn):
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await asyncio.wait_for(fn(*args, **kwargs),
                                          timeout=TOOL_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            return {
                "status":         "error",
                "error_code":     "upstream_timeout",
                "message":        "Data source did not respond in time. Try again shortly.",
                "retry_after":    30,
                "query_hash":     None,
                "ingest_healthy": False,
                "schema_version": "1.0",
                "data_as_of":     None,
            }
    return wrapper
