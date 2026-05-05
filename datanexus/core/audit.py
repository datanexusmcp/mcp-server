"""
datanexus/core/audit.py — Audit, telemetry, and standard response fields.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 9.3.3 + Phase 1 / audit.py

Rules (CLAUDE.md):
- NEVER store raw parameter values — params_hash only.
- AuditContext NEVER suppresses exceptions.
- standard_response_fields returns EXACTLY 4 keys — never add more.

Redis counters (35-day TTL):
  dau:{tool_id}:{version}:{date}         — daily active usage
  errors:{tool_id}:{date}                — error count
  cache_miss:{tool_id}:{date}            — cache miss count
  audit:{query_hash}                     — AuditRecord hset
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib

log = logging.getLogger("datanexus.core.audit")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_COUNTER_TTL = 35 * 86400   # 35 days in seconds

_redis_client: Optional[redis_lib.Redis] = None


def _get_redis() -> Optional[redis_lib.Redis]:
    """Lazy Redis connection. Returns None if unavailable — never raises."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
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
        log.warning("audit._get_redis: Redis unavailable — %s", exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def make_params_hash(params: dict) -> str:
    """
    Deterministic SHA-256 of params dict, key-order-independent.

    Process: JSON-serialise with sort_keys=True → UTF-8 encode → SHA-256.
    Returns first 32 hex characters (16 bytes).

    Same params in ANY key order always produces the same hash.
    NEVER store raw param values — this hash is what goes into audit logs.
    """
    canonical = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def write_audit(
    tool_id: str,
    params: dict,
    version: str,
    response_time_ms: int,
    cache_hit: bool,
    error: bool,
    error_type: Optional[str],
    retry_attempt: int,
) -> str:
    """
    Write an AuditRecord to Redis and increment telemetry counters.

    Returns query_hash (the params_hash) — links tool response to feedback.

    Counters written (all with 35-day TTL):
      dau:{tool_id}:{version}:{date}    — always incremented
      errors:{tool_id}:{date}           — only if error=True
      cache_miss:{tool_id}:{date}       — only if cache_hit=False

    NEVER stores raw params — params_hash only.
    """
    query_hash = make_params_hash(params)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    r = _get_redis()

    if r is None:
        return query_hash

    try:
        pipe = r.pipeline()

        # AuditRecord hset
        pipe.hset(f"audit:{query_hash}", mapping={
            "tool_id":          tool_id,
            "version":          version,
            "params_hash":      query_hash,
            "response_time_ms": response_time_ms,
            "cache_hit":        str(cache_hit),
            "error":            str(error),
            "error_type":       error_type or "",
            "retry_attempt":    retry_attempt,
            "ts":               datetime.now(timezone.utc).isoformat(),
        })
        pipe.expire(f"audit:{query_hash}", _COUNTER_TTL)

        # DAU counter
        dau_key = f"dau:{tool_id}:{version}:{today}"
        pipe.incr(dau_key)
        pipe.expire(dau_key, _COUNTER_TTL)

        # Error counter
        if error:
            err_key = f"errors:{tool_id}:{today}"
            pipe.incr(err_key)
            pipe.expire(err_key, _COUNTER_TTL)

        # Cache-miss counter
        if not cache_hit:
            miss_key = f"cache_miss:{tool_id}:{today}"
            pipe.incr(miss_key)
            pipe.expire(miss_key, _COUNTER_TTL)

        pipe.execute()

    except Exception as exc:
        log.warning("audit.write_audit tool=%s: %s", tool_id, exc)

    return query_hash


class AuditContext:
    """
    Async context manager that wraps a tool call with full audit telemetry.

    Usage:
        async with AuditContext('T04', params, '1.0') as ctx:
            # ctx.query_hash available immediately
            ...
            ctx.set_cache_hit(True)

    On __aexit__: calls write_audit() with elapsed response_time_ms.
    NEVER suppresses exceptions — re-raises anything raised in the body.
    """

    def __init__(self, tool_id: str, params: dict, version: str) -> None:
        self.tool_id       = tool_id
        self.params        = params
        self.version       = version
        self.query_hash    = make_params_hash(params)
        self._start_ms:    float = 0.0
        self._cache_hit:   bool  = False
        self._error:       bool  = False
        self._error_type:  Optional[str] = None
        self._retry:       int   = 0

    async def __aenter__(self) -> "AuditContext":
        self._start_ms = time.monotonic() * 1000
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        elapsed = int(time.monotonic() * 1000 - self._start_ms)
        if exc_type is not None:
            self._error = True
            self._error_type = exc_type.__name__
        write_audit(
            tool_id=self.tool_id,
            params=self.params,
            version=self.version,
            response_time_ms=elapsed,
            cache_hit=self._cache_hit,
            error=self._error,
            error_type=self._error_type,
            retry_attempt=self._retry,
        )
        return False   # NEVER suppress exceptions

    def set_cache_hit(self, value: bool) -> None:
        self._cache_hit = value

    def set_error(self, error_type: str) -> None:
        self._error = True
        self._error_type = error_type

    def set_retry(self, attempt: int) -> None:
        self._retry = attempt


def standard_response_fields(
    query_hash: str,
    data_as_of: str,
    ingest_healthy: bool,
    schema_version: str = "1.0",
) -> dict:
    """
    Return the standard 4-key dict included in EVERY tool response.

    EXACTLY 4 keys — never add more, never remove any.
    Every tool response MUST include these via dict unpacking:
        return {**payload, **standard_response_fields(ctx.query_hash, ...)}

    Missing any of these = Glama score < 8.5 = deploy blocked.
    """
    return {
        "query_hash":     query_hash,
        "schema_version": schema_version,
        "data_as_of":     data_as_of,
        "ingest_healthy": ingest_healthy,
    }
