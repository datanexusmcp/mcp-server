"""
datanexus/core/request_context.py — Per-request context variables.

Stores ambient state that must flow through the async call stack without
explicit parameter passing.  Set once per HTTP request by
ClientIPMiddleware (main.py) before any tool handler runs.

Reads in:
  datanexus/core/entitlement.py — verify_entitlement wrapper
  datanexus/core/usage_recorder.py — record_usage()

Default of 'unknown' is returned outside an HTTP context (smoke tests,
unit tests, cron jobs) so callers need no special handling.
"""

from contextvars import ContextVar

# Real client IP extracted from X-Real-IP header set by Caddy.
# Falls back to 'unknown' when called outside an HTTP request lifecycle.
client_ip_var: ContextVar[str] = ContextVar("client_ip", default="unknown")
