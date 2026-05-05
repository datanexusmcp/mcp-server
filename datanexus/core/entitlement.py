"""
datanexus/core/entitlement.py — Free-window @verify_entitlement stub.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10 + Phase 1 / entitlement.py

MCPIZE_ACTIVE default: false
When false:  decorator is a no-op passthrough.
             TELEMETRY STILL RUNS — always, every call.
When true:   full enforcement delegated to payment/entitlement.py (Phase 5).
             For now: passthrough (stub).

NEVER change @verify_entitlement or payment/billing code without a human PR.
(CLAUDE.md Rule #2 — violation consequence: silent billing bypass)

Telemetry written on EVERY call (free or paid):
  INCR  datanexus:calls:{tool_id}:{date}
  SADD  datanexus:sessions:{tool_id}:{date}  {session_id}
  LPUSH datanexus:feed  "{tool_id}|{session_id}|{timestamp}|free"
  LTRIM datanexus:feed  0 49
  PostgreSQL: INSERT INTO sessions (session_id, tool_id, created_at)
              ON CONFLICT DO NOTHING
"""

import functools
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import redis as redis_lib

log = logging.getLogger("datanexus.core.entitlement")

# ── Switch ────────────────────────────────────────────────────────────────────
# Read once at import time.
# payment/config.py will be the single source once Phase 5 is built.
# Until then, read directly from env.
try:
    from payment.config import MCPIZE_ACTIVE  # type: ignore[import]
except ImportError:
    MCPIZE_ACTIVE: bool = (
        os.environ.get("MCPIZE_ACTIVE", "false").lower() == "true"
    )

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_DB_URL    = os.environ.get("DATANEXUS_DB_URL", "")
_FEED_MAX  = 50
_COUNTER_TTL = 35 * 86400  # 35 days

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
        log.warning("entitlement._get_redis: Redis unavailable — %s", exc)
        return None


def _get_or_create_session(kwargs: dict) -> str:
    """
    Extract session_id from kwargs if present, otherwise generate a new UUID.
    FastMCP tools may inject session context via kwargs; fall back to new UUID.
    """
    return str(kwargs.get("session_id") or uuid.uuid4())


async def _run_telemetry(tool_id: str, session_id: str) -> None:
    """
    Write telemetry counters for every tool call.

    Never raises — all errors are caught and logged.
    Runs regardless of MCPIZE_ACTIVE state.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ts    = datetime.now(timezone.utc).isoformat()
    r     = _get_redis()

    if r is not None:
        try:
            pipe = r.pipeline()

            # Call counter
            calls_key = f"datanexus:calls:{tool_id}:{today}"
            pipe.incr(calls_key)
            pipe.expire(calls_key, _COUNTER_TTL)

            # Session set
            sess_key = f"datanexus:sessions:{tool_id}:{today}"
            pipe.sadd(sess_key, session_id)
            pipe.expire(sess_key, _COUNTER_TTL)

            # Feed list (capped at 50 entries)
            feed_entry = f"{tool_id}|{session_id}|{ts}|free"
            pipe.lpush("datanexus:feed", feed_entry)
            pipe.ltrim("datanexus:feed", 0, _FEED_MAX - 1)

            pipe.execute()
        except Exception as exc:
            log.warning("entitlement._run_telemetry Redis error: %s", exc)

    # PostgreSQL — INSERT session on first seen (ON CONFLICT DO NOTHING)
    if _DB_URL:
        try:
            import asyncpg  # type: ignore[import]
            conn = await asyncpg.connect(_DB_URL)
            try:
                await conn.execute(
                    """
                    INSERT INTO sessions (session_id, tool_id, created_at)
                    VALUES ($1, $2, $3)
                    ON CONFLICT DO NOTHING
                    """,
                    session_id,
                    tool_id,
                    datetime.now(timezone.utc),
                )
            finally:
                await conn.close()
        except Exception as exc:
            log.warning("entitlement._run_telemetry PostgreSQL error: %s", exc)


# ── Decorator ─────────────────────────────────────────────────────────────────

def verify_entitlement(tool_id: str) -> Callable:
    """
    Free-window @verify_entitlement stub.

    Decorator order in tool files:
        @mcp.tool()
        @verify_entitlement('T04')
        async def fetch_nonprofit_by_ein(ein: str) -> dict:

    When MCPIZE_ACTIVE=false: telemetry runs, then passthrough.
    When MCPIZE_ACTIVE=true:  full enforcement via payment/entitlement.py
                               (Phase 5). Until then: passthrough.

    NEVER change this decorator logic without a human PR.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            session_id = _get_or_create_session(kwargs)
            await _run_telemetry(tool_id, session_id)

            if not MCPIZE_ACTIVE:
                # Free window — passthrough, telemetry already written above
                return await fn(*args, **kwargs)

            # MCPIZE_ACTIVE=true — full enforcement delegated to
            # payment/entitlement.py once Phase 5 is built.
            # Stub: passthrough until payment module is wired.
            return await fn(*args, **kwargs)

        return wrapper
    return decorator
