"""
payment/entitlement.py — Full @verify_entitlement implementation.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10.2 / Phase 5 Step 3

Replaces the stub in datanexus/core/entitlement.py for Phase 5.
Tools import @verify_entitlement from here (Step 7 wires this in).

Six check conditions (Section 10, Table 116) — evaluated in order:
  1. MCPIZE_ACTIVE=false        → passthrough (free window)
  2. MCPIZE_URL empty for tool  → passthrough (tool not monetised yet)
  3. Valid entitlement key       → allow
  4. Grace period active         → allow + grace_warning in response
  5. No entitlement, no grace   → 402 dict with upgrade_url
  6. Redis error                 → fail open (allow) + log warning

Telemetry runs on EVERY call regardless of which condition fires:
  INCR  datanexus:calls:{tool_id}:{date}
  SADD  datanexus:sessions:{tool_id}:{date}  {caller_id}
  LPUSH datanexus:feed  "{tool_id}|{caller_id}|{ts}|{tier}"  (LTRIM to 50)
  PostgreSQL: INSERT INTO sessions ON CONFLICT DO NOTHING

NEVER modify this file without a human PR.
(CLAUDE.md Rule #2 — billing bypass risk)
"""

from __future__ import annotations

import functools
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import redis as redis_lib

import payment.config as _cfg

log = logging.getLogger("payment.entitlement")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_DB_URL    = os.environ.get("DATANEXUS_DB_URL", "")

# Injectable Redis client for tests
_redis_client: Optional[redis_lib.Redis] = None

# Injectable caller_id for tests (replaces UUID generation)
_test_caller_id: Optional[str] = None


def _set_redis_client(client: Optional[redis_lib.Redis]) -> None:
    """Inject a Redis client (e.g. fakeredis) for testing. Pass None to reset."""
    global _redis_client
    _redis_client = client


def _set_caller_id(caller_id: Optional[str]) -> None:
    """Inject a fixed caller_id for testing. Pass None to reset."""
    global _test_caller_id
    _test_caller_id = caller_id


def _get_redis() -> Optional[redis_lib.Redis]:
    """Lazy Redis connection. Returns None if unavailable — never raises."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:
        log.warning("payment.entitlement: Redis unavailable — %s", exc)
        return None


def _resolve_caller_id(kwargs: dict) -> str:
    """Return injected test caller_id, kwargs session_id, or a new UUID."""
    if _test_caller_id:
        return _test_caller_id
    return str(kwargs.get("session_id") or uuid.uuid4())


def _payment_required(tool_id: str) -> dict:
    """Structured 402 response — matches datanexus ErrorCode pattern."""
    return {
        "status":      "error",
        "error_code":  "payment_required",
        "message":     "Subscription required to access this tool.",
        "upgrade_url": _cfg.MCPIZE_URLS.get(tool_id, ""),
        "tool_id":     tool_id,
        "retry_after": 0,
    }


async def _run_telemetry(tool_id: str, caller_id: str, tier: str = "free") -> None:
    """
    Write telemetry on EVERY call — regardless of entitlement outcome.
    Never raises.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ts    = datetime.now(timezone.utc).isoformat()
    r     = _get_redis()

    if r is not None:
        try:
            pipe = r.pipeline()

            # INCR call counter
            calls_key = _cfg.key_calls(tool_id, today)
            pipe.incr(calls_key)
            pipe.expire(calls_key, _cfg.COUNTER_TTL)

            # SADD session set
            sess_key = _cfg.key_sessions(tool_id, today)
            pipe.sadd(sess_key, caller_id)
            pipe.expire(sess_key, _cfg.COUNTER_TTL)

            # LPUSH feed entry, capped at FEED_MAX_ENTRIES
            feed_entry = f"{tool_id}|{caller_id}|{ts}|{tier}"
            pipe.lpush(_cfg.key_feed(), feed_entry)
            pipe.ltrim(_cfg.key_feed(), 0, _cfg.FEED_MAX_ENTRIES - 1)

            pipe.execute()
        except Exception as exc:
            log.warning("payment.entitlement: telemetry Redis error tool=%s — %s", tool_id, exc)

    # PostgreSQL session INSERT ON CONFLICT DO NOTHING
    if _DB_URL:
        try:
            import asyncpg  # optional dep
            conn = await asyncpg.connect(_DB_URL)
            try:
                await conn.execute(
                    "INSERT INTO sessions (session_id, tool_id, created_at)"
                    " VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    caller_id, tool_id, datetime.now(timezone.utc),
                )
            finally:
                await conn.close()
        except Exception as exc:
            log.warning("payment.entitlement: telemetry PG error tool=%s — %s", tool_id, exc)


# ── Decorator ─────────────────────────────────────────────────────────────────

def verify_entitlement(tool_id: str) -> Callable:
    """
    Full @verify_entitlement decorator.

    Decorator application order in tool files:
        @mcp.tool()
        @verify_entitlement('T04')
        async def fetch_nonprofit_by_ein(ein: str) -> dict:

    See module docstring for the six check conditions and telemetry spec.
    NEVER change without a human PR.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            caller_id = _resolve_caller_id(kwargs)

            # ── Telemetry — ALWAYS, regardless of outcome ─────────────────────
            await _run_telemetry(tool_id, caller_id)

            # ── Condition 1: free window ───────────────────────────────────────
            if not _cfg.MCPIZE_ACTIVE:
                return await fn(*args, **kwargs)

            # ── Condition 2: URL empty → tool not monetised yet ───────────────
            if not _cfg.MCPIZE_URLS.get(tool_id, ""):
                return await fn(*args, **kwargs)

            # ── Redis entitlement / grace check ────────────────────────────────
            try:
                r = _get_redis()

                # ── Condition 6: Redis unavailable → fail open ─────────────────
                if r is None:
                    log.warning(
                        "payment.entitlement: Redis unavailable for tool=%s — "
                        "fail open (allowing call)",
                        tool_id,
                    )
                    return await fn(*args, **kwargs)

                # ── Condition 3: valid entitlement key ─────────────────────────
                if r.exists(_cfg.key_entitlement(tool_id, caller_id)):
                    return await fn(*args, **kwargs)

                # ── Condition 4: grace period active ───────────────────────────
                if r.exists(_cfg.key_grace(tool_id, caller_id)):
                    result = await fn(*args, **kwargs)
                    if isinstance(result, dict):
                        result["grace_warning"] = (
                            "Your subscription has lapsed. "
                            "Service continues during the grace period. "
                            f"Renew at: {_cfg.MCPIZE_URLS.get(tool_id, '')}"
                        )
                    return result

                # ── Condition 5: no entitlement, no grace → 402 ────────────────
                log.info(
                    "payment.entitlement: 402 tool=%s caller=%s", tool_id, caller_id,
                )
                return _payment_required(tool_id)

            except Exception as exc:
                # ── Condition 6 (exception path): Redis error → fail open ──────
                log.warning(
                    "payment.entitlement: Redis error during check tool=%s — %s — "
                    "fail open",
                    tool_id, exc,
                )
                return await fn(*args, **kwargs)

        return wrapper
    return decorator
