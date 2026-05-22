"""
datanexus/core/usage_recorder.py — Persistent usage event recorder.

Writes one row to the PostgreSQL usage table for every tool call.
Designed for fire-and-forget usage — never raises, never blocks the caller.

Table (columns added by migration 004):
  session_id  TEXT
  tool_id     TEXT
  call_uuid   TEXT  (unique)
  created_at  TIMESTAMPTZ
  client_ip   TEXT
  tool_input  JSONB  (sanitised — sensitive keys redacted)
  success     BOOLEAN
  error_msg   TEXT   (first 500 chars of exception message)
  latency_ms  INTEGER
  is_smoke    BOOLEAN  (true when DATANEXUS_SMOKE_RUN=1)

Smoke flag behaviour:
  - is_smoke=True rows are still written (useful for pass-rate tracking)
  - PostHog exclusion is handled separately in analytics.py

Usage:
  from datanexus.core.usage_recorder import record_usage
  asyncio.ensure_future(record_usage(...))   # fire and forget in finally block
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("datanexus.usage_recorder")

# ── Pool singleton ─────────────────────────────────────────────────────────────

_pool = None
_pool_init_attempted = False

# ── Sensitive key substrings — redacted from tool_input before persistence ────
# Checked against lowercased key names.
_SENSITIVE_SUBSTRINGS = (
    "api_key", "apikey", "api_secret", "secret", "token",
    "password", "passwd", "access_key", "private",
)


def _sanitize_input(raw: dict) -> dict:
    """
    Return a copy of raw with sensitive values replaced by [REDACTED].

    - Strips 'session_id' entirely (internal routing detail, not a search input).
    - Redacts any key whose lowercase name contains a sensitive substring.
    - Values are only redacted, never dropped, so the key structure is preserved
      for schema debugging.
    """
    result = {}
    for k, v in raw.items():
        if k == "session_id":
            continue  # never persist — internal only
        low = k.lower()
        if any(s in low for s in _SENSITIVE_SUBSTRINGS):
            result[k] = "[REDACTED]"
        else:
            result[k] = v
    return result


async def _get_pool():
    """
    Return a shared asyncpg connection pool, creating it on first call.
    Returns None (silently) when DB is unavailable or not configured.
    Never raises.
    """
    global _pool, _pool_init_attempted
    if _pool_init_attempted:
        return _pool
    _pool_init_attempted = True

    db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()
    if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
        log.debug("UsageRecorder: DATANEXUS_DB_URL not configured — recording disabled")
        return None

    try:
        import asyncpg  # optional dep — absent in local dev without Docker
        _pool = await asyncpg.create_pool(
            db_url,
            min_size=1,
            max_size=3,          # low max — usage recording is background work
            command_timeout=5,   # fast fail; never hold up a tool call
        )
        log.info("UsageRecorder: asyncpg pool ready")
    except ImportError:
        log.warning("UsageRecorder: asyncpg not installed — recording disabled")
        _pool = None
    except Exception as exc:
        log.warning("UsageRecorder: pool init failed (non-fatal): %s", exc)
        _pool = None

    return _pool


# ── Public API ─────────────────────────────────────────────────────────────────

async def record_usage(
    tool_id: str,
    session_id: str,
    tool_input: dict,
    client_ip: str,
    success: bool,
    error_msg: Optional[str] = None,
    latency_ms: Optional[int] = None,
) -> None:
    """
    Persist one tool call to the usage table.  Always returns — never raises.

    Parameters
    ----------
    tool_id    : e.g. "T10", "T04"
    session_id : MCP session identifier (UUID string)
    tool_input : raw kwargs from the tool call (will be sanitised)
    client_ip  : real client IP from X-Real-IP header (or 'unknown')
    success    : True if no exception was raised
    error_msg  : str(exception)[:500] on failure, else None
    latency_ms : wall-clock ms from tool entry to return/raise

    Smoke tests (DATANEXUS_SMOKE_RUN=1):
      Records the row with is_smoke=True — useful for pass-rate tracking.
      PostHog is excluded separately in analytics._fire().
    """
    is_smoke = os.environ.get("DATANEXUS_SMOKE_RUN") == "1"

    try:
        pool = await _get_pool()
        if pool is None:
            return

        safe_input = _sanitize_input(tool_input)

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO usage
                  (session_id, tool_id, call_uuid, created_at,
                   client_ip, tool_input, success, error_msg,
                   latency_ms, is_smoke)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                session_id,
                tool_id,
                str(uuid.uuid4()),
                datetime.now(timezone.utc),
                client_ip,
                json.dumps(safe_input),
                success,
                error_msg,
                latency_ms,
                is_smoke,
            )
    except Exception as exc:
        # Log but never raise — a DB hiccup must never kill a tool call
        log.warning("UsageRecorder.record_usage failed (non-fatal): %s", exc)
