"""
@verify_entitlement — free-tier decorator.

Every request is accepted (no API key required).  Per invocation the decorator:
  1. Assigns an anonymous session UUID.
  2. Persists the session_id + created_at (UTC) to PostgreSQL (fire-and-forget).
  3. Emits a structured audit-log line: tool_id, session_id, timestamp, params_hash.
  4. Writes the same entry to a bounded Redis list  datanexus:audit  (max 10 000).
  5. Increments the per-tool usage counter  datanexus:usage:{tool_id}  in Redis.
  6. Appends a machine-readable free_tier metadata comment to the returned string.

check_grandfather_status(session_id) — reads session_created_at from PostgreSQL
and returns True when the session predates FREE_TIER_END_DATE (or when that
variable is unset, in which case every session is grandfathered).

No Stripe calls.  No quota enforcement.  No API key validation.
"""

import functools
import hashlib
import inspect
import json
import logging
import re
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("datanexus.billing")
_audit = logging.getLogger("datanexus.audit")

_AUDIT_KEY  = "datanexus:audit"
_AUDIT_MAX  = 10_000
_USAGE_PREFIX = "datanexus:usage:"
_FEED_KEY   = "datanexus:feed"
_FEED_MAX   = 50
_KEY_TTL    = 30 * 86_400   # daily metric keys expire after 30 days


def _infer_tool_id(func) -> str:
    """
    Extract T0N from the function's module path.
    e.g. 'datanexus.tools.t04_nonprofit' -> 'T04'
    Falls back to 'T??' when the pattern is absent.
    """
    module = getattr(func, "__module__", "") or ""
    for segment in module.split("."):
        m = re.match(r"^(t\d+)", segment, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return "T??"


def _params_hash(kwargs: dict) -> str:
    """SHA-256[:16] of the sorted keyword-argument map (values cast to str)."""
    serialised = json.dumps(
        {k: str(v) for k, v in sorted(kwargs.items())},
        sort_keys=True,
    )
    return hashlib.sha256(serialised.encode()).hexdigest()[:16]


async def _record(tool_id: str, session_id: str, params_hash: str) -> None:
    """
    Fire-and-forget side-effects — all failures are swallowed so they never
    surface to callers:
      1. Persist session_id to PostgreSQL (created_at = now(), idempotent).
      2. Structured audit-log line to the datanexus.audit logger.
      3. LPUSH to datanexus:audit Redis list (trimmed to last 10 000 entries).
      4. INCR on datanexus:usage:{tool_id}.
    """
    ts = datetime.now(timezone.utc).isoformat()

    # 1. PostgreSQL session record (created_at captured at first call for this UUID)
    try:
        from datanexus.db import record_session  # late import — avoids circular dep
        await record_session(session_id)
    except Exception as exc:
        logger.warning("Session DB record failed session=%s: %s", session_id, exc)

    # 2. Audit logger — always emitted even when Redis/DB are unavailable
    _audit.info(
        "tool=%s session=%s ts=%s params_hash=%s free_tier=true",
        tool_id, session_id, ts, params_hash,
    )

    # 3–7. Redis pipeline — audit log + daily metrics + feed
    try:
        from datanexus.cache import get_redis  # late import to avoid circular dep
        r = await get_redis()
        if r is None:
            return

        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        calls_key    = f"datanexus:calls:{tool_id}:{date}"
        sessions_key = f"datanexus:sessions:{tool_id}:{date}"

        audit_entry = json.dumps({
            "tool_id": tool_id,
            "session_id": session_id,
            "timestamp": ts,
            "params_hash": params_hash,
            "free_tier": True,
        })
        feed_entry = json.dumps({
            "tool": tool_id,
            "session": session_id[:8],
            "ts": ts,
            "params_hash": params_hash,
        })

        pipe = r.pipeline()
        # Legacy running total (kept for backwards-compat)
        pipe.incr(f"{_USAGE_PREFIX}{tool_id}")
        # Daily call counter
        pipe.incr(calls_key)
        pipe.expire(calls_key, _KEY_TTL)
        # Unique sessions set (per tool per day)
        pipe.sadd(sessions_key, session_id)
        pipe.expire(sessions_key, _KEY_TTL)
        # Bounded audit list
        pipe.lpush(_AUDIT_KEY, audit_entry)
        pipe.ltrim(_AUDIT_KEY, 0, _AUDIT_MAX - 1)
        # Live feed (max 50 entries)
        pipe.lpush(_FEED_KEY, feed_entry)
        pipe.ltrim(_FEED_KEY, 0, _FEED_MAX - 1)
        await pipe.execute()

    except Exception as exc:
        logger.warning("Audit record failed tool=%s: %s", tool_id, exc)


def verify_entitlement(func):
    """
    Free-tier decorator — every caller is authorized.

    Preserves the original function's __signature__ so FastMCP can introspect
    parameter names and docstrings correctly.
    """
    tool_id = _infer_tool_id(func)

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        session_id = str(uuid.uuid4())
        ph = _params_hash(kwargs)

        # Side-effects run before the tool call so they're logged even on error
        await _record(tool_id, session_id, ph)

        result = await func(*args, **kwargs)

        # Append free_tier flag to every string response (HTML comment —
        # invisible in markdown renderers, machine-parseable by callers)
        if isinstance(result, str):
            result = (
                result
                + f"\n<!-- datanexus free_tier=true"
                  f" session={session_id[:8]}"
                  f" tool={tool_id} -->"
            )
        return result

    wrapper.__signature__ = inspect.signature(func)
    return wrapper


async def check_grandfather_status(session_id: str) -> bool:
    """
    Returns True when the session is grandfathered onto the free tier.

    Logic:
      1. If FREE_TIER_END_DATE is unset (None), all sessions are grandfathered → True.
      2. Look up session_created_at from PostgreSQL.
      3. If the session is not in the DB or the DB is unavailable, fail open → True.
      4. Return True iff session_created_at < FREE_TIER_END_DATE (strict: created
         before the cutoff is grandfathered; created at the exact cutoff is not).

    This function is a stub — it performs no enforcement and never blocks a request.
    Enforcement is wired at Gate 2 (Stripe billing integration).
    """
    from datanexus.config import FREE_TIER_END_DATE

    # Fast path: cutoff unset → everyone is grandfathered
    if FREE_TIER_END_DATE is None:
        return True

    from datanexus.db import get_session_created_at
    created_at = await get_session_created_at(session_id)

    # Fail open: unknown session or DB unavailable → treat as grandfathered
    if created_at is None:
        logger.warning(
            "check_grandfather_status: session=%s not found in DB — "
            "failing open (grandfathered=True)",
            session_id,
        )
        return True

    return created_at < FREE_TIER_END_DATE
