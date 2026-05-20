"""
datanexus/core/failure_classifier.py — Rule-based failure classifier.

Sprint 5 Layer 1. Classifies every error_response() call into one of six classes
and records it to Redis for the daily digest.

Redis key: datanexus:failures:{YYYY-MM-DD}   — list, 72h TTL
Each entry JSON: {tool_id, error_class, error_code, upstream, params_hash,
                  traceback_hash, traceback_snippet, timestamp, user_agent}
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib

log = logging.getLogger("datanexus.core.failure_classifier")

FAILURE_CLASSES = [
    "user_error",      # invalid params, missing required fields, bad API key
    "format_error",    # input normalization failure (e.g., EPCN vs CN patent format)
    "upstream_error",  # 4xx/5xx from external API, circuit breaker tripped
    "rate_limit",      # HTTP 429 from upstream or our own Redis quota guards
    "code_bug",        # unhandled exception, logic error in our code, wrong output shape
    "infrastructure",  # Redis down, DB unreachable, timeout on our own infra
]

# error_code values that map to format_error
_FORMAT_ERROR_CODES = frozenset({
    "invalid_format",
    "invalid_patent_format",
    "invalid_ein",
    "invalid_npi",
})

# error_code values that map to upstream_error (when upstream field is set)
_UPSTREAM_ERROR_CODES = frozenset({
    "upstream_timeout",
    "upstream_unavailable",
    "circuit_open",
})

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_FAILURES_TTL = 72 * 3600  # 72h — 48h margin vs 24h digest cycle

# Redact quoted string values from traceback snippets to avoid storing param data
_REDACT_RE = re.compile(r'["\'][^"\']{1,200}["\']')

_redis_client: Optional[redis_lib.Redis] = None


def _get_redis() -> Optional[redis_lib.Redis]:
    """Lazy Redis connection with liveness check. Returns None if unavailable — never raises."""
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:
        log.warning("failure_classifier: Redis unavailable — %s", exc)
        return None


def classify(
    error_code: str,
    upstream: str = "",
    exc_type: Optional[str] = None,
) -> str:
    """Rule-based classification into one of FAILURE_CLASSES. Never raises.

    Decision tree (spec Layer 1):
      Exception redis.ConnectionError / redis.TimeoutError   → infrastructure
      Exception CircuitBreakerOpen                           → upstream_error
      Exception KeyError / ValueError / AssertionError       → code_bug
      Exception httpx.TimeoutException / httpx.ConnectError  → upstream_error
      error_code in FORMAT_ERROR_CODES                       → format_error
      upstream_rate_limited                                  → rate_limit
      upstream_timeout / upstream_unavailable + upstream set → upstream_error
      upstream_timeout / upstream_unavailable + no upstream  → code_bug
      circuit_open                                           → upstream_error
      internal_error + upstream set                          → upstream_error
      internal_error + no upstream                           → code_bug
      cache_error                                            → infrastructure
      validation_error / missing_params / not_found / …     → user_error
    """
    code = (error_code or "").lower()

    # Exception type takes highest priority
    if exc_type:
        et = exc_type.lower()
        if "redis" in et and ("connection" in et or "timeout" in et):
            return "infrastructure"
        if "circuitbreaker" in et:
            return "upstream_error"
        if et in ("keyerror", "valueerror", "assertionerror"):
            return "code_bug"
        if "timeout" in et or "connect" in et:
            return "upstream_error"

    if code in _FORMAT_ERROR_CODES:
        return "format_error"

    if code == "upstream_rate_limited":
        return "rate_limit"

    if code in _UPSTREAM_ERROR_CODES:
        if code == "circuit_open":
            return "upstream_error"
        return "upstream_error" if upstream else "code_bug"

    if code == "internal_error":
        return "upstream_error" if upstream else "code_bug"

    if code == "cache_error":
        return "infrastructure"

    if code in ("validation_error", "missing_params", "not_found",
                "ipv6_not_supported", "unauthorized", "forbidden"):
        return "user_error"

    # Unknown error codes default to code_bug for visibility
    return "code_bug"


def _redact_snippet(raw: str) -> str:
    """Strip quoted string values from traceback to avoid storing param values."""
    return _REDACT_RE.sub("'<redacted>'", raw)


def record_failure(
    error_code: str,
    upstream: str = "",
    tool_id: str = "",
    params_hash: str = "",
    exc_info: Optional[str] = None,
    user_agent: str = "",
    exc_type: Optional[str] = None,
) -> str:
    """Classify and persist a failure entry to Redis. Returns the error_class.

    Never raises. Silent on Redis unavailability.
    Spec: Redis key datanexus:failures:{YYYY-MM-DD}, 72h TTL.
    """
    try:
        error_class = classify(error_code, upstream, exc_type)

        tb_snippet = ""
        tb_hash = ""
        if exc_info:
            raw = exc_info[:500]
            tb_snippet = _redact_snippet(raw)
            tb_hash = hashlib.sha256(exc_info.encode()).hexdigest()[:16]

        entry = {
            "tool_id":           tool_id,
            "error_class":       error_class,
            "error_code":        error_code,
            "upstream":          upstream,
            "params_hash":       params_hash,
            "traceback_hash":    tb_hash,
            "traceback_snippet": tb_snippet,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "user_agent":        user_agent,
        }

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"datanexus:failures:{today}"

        r = _get_redis()
        if r is not None:
            pipe = r.pipeline()
            pipe.lpush(key, json.dumps(entry))
            pipe.expire(key, _FAILURES_TTL)
            pipe.execute()

        return error_class

    except Exception as exc:
        log.error("failure_classifier.record_failure: unexpected error — %s", exc)
        return "code_bug"
