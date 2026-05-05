"""
datanexus/core/schema.py — Pydantic v2 base response model.

Spec: DataNexus_MCP_Spec_v7_3.docx  Phase 1 / schema.py
All tool responses must include the DataNexusResponse fields.
Canary validator on markdown_output blocks prompt-injection patterns.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, field_validator, HttpUrl


class DataNexusResponse(BaseModel):
    """Base response model inherited (or dict-spread) by every tool."""

    tool_id:          str
    source_url:       HttpUrl
    fetch_timestamp:  datetime          # UTC — when upstream was queried
    cache_hit:        bool
    staleness_notice: Optional[str]     # None when data is fresh
    sha256_hash:      str               # hex digest of raw upstream bytes
    data:             Dict[str, Any]    # tool-specific payload
    markdown_output:  str               # AI-Ready Markdown for agent
    query_hash:       str               # from AuditContext — links feedback
    schema_version:   str = "1.0"
    data_as_of:       str               # ISO timestamp of data freshness
    ingest_healthy:   bool              # False if ingest pipeline broke
    disclaimer:       str               # hardcoded per tool

    # ── Canary validator ──────────────────────────────────────────────────────
    # Raise ValueError if ANY injection pattern found in markdown_output.
    # This runs on every tool response — zero exceptions permitted.
    _INJECTION_PATTERNS: tuple = (
        "ignore previous",
        "you are now",
        "system:",
        "<script",
        "<iframe",
        "forget your instructions",
        "new persona",
        "disregard",
    )

    @field_validator("markdown_output")
    @classmethod
    def _no_injection(cls, v: str) -> str:
        for pattern in (
            "ignore previous",
            "you are now",
            "system:",
            "<script",
            "<iframe",
            "forget your instructions",
            "new persona",
            "disregard",
        ):
            if re.search(re.escape(pattern), v, re.IGNORECASE):
                raise ValueError(
                    f"Canary: injection pattern '{pattern}' detected in "
                    "markdown_output — response blocked."
                )
        return v

    model_config = {"arbitrary_types_allowed": True}


# ── Structured error response shape ──────────────────────────────────────────
# Return this dict on ANY error. Never raise. Never return str(e).
# error_code must come from ErrorCode enum below.
#
# {
#     'status':         'error',
#     'error_code':     str,   # from ErrorCode enum
#     'message':        str,   # human-readable, no internal detail
#     'retry_after':    int,   # seconds; 0 = do not retry
#     'query_hash':     str,   # always present — enables feedback
#     'ingest_healthy': bool,
# }

class ErrorCode:
    """Defined enum of error codes — no freeform strings in responses."""
    UPSTREAM_TIMEOUT      = "upstream_timeout"
    UPSTREAM_UNAVAILABLE  = "upstream_unavailable"
    UPSTREAM_RATE_LIMITED = "upstream_rate_limited"
    CACHE_ERROR           = "cache_error"
    VALIDATION_ERROR      = "validation_error"
    INTERNAL_ERROR        = "internal_error"
    CIRCUIT_OPEN          = "circuit_open"
    NOT_FOUND             = "not_found"


def error_response(
    error_code: str,
    message: str,
    query_hash: str = "",
    retry_after: int = 0,
    ingest_healthy: bool = False,
) -> dict:
    """Return a structured error dict. Never raise from tool handlers."""
    return {
        "status":         "error",
        "error_code":     error_code,
        "message":        message,
        "retry_after":    retry_after,
        "query_hash":     query_hash,
        "ingest_healthy": ingest_healthy,
    }
