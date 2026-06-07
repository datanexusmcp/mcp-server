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

# SHA-256 hash of the validated X-DataNexus-Key or X-Api-Key header.
# Set by _ApiKeyMiddleware in main.py; None when no key is present or key is invalid.
api_key_var: ContextVar[str | None] = ContextVar("api_key", default=None)

# Sprint 8B: call classification set by _ApiKeyMiddleware after classify_call().
call_type_var: ContextVar[str] = ContextVar("call_type", default="unknown")
is_organic_var: ContextVar[bool] = ContextVar("is_organic", default=False)
