"""
datanexus/core/circuit_breaker.py — Per-source circuit breaker.

Spec: DataNexus_MCP_Spec_v7_3.docx  Phase 1 / circuit_breaker.py
      DataNexus_MCP_Spec_v7_5.docx  Sprint 3 P05 — async interface

Rules (CLAUDE.md):
- ALL state lives in Redis — no module-level dicts, no in-process cache decorators.
- Must work correctly across multiple Hetzner nodes (stateless app tier).
- Gracefully handles Redis unavailability (fails open — assumes not tripped).

Sync key prefix: datanexus:cb:{source_id}:
  :failures   — INCR counter, 600s TTL per increment
  :tripped    — SET flag when breaker trips
  :last_probe — SET timestamp of last probe attempt

Async (P05) key prefix: circuit:{tool_id}:{upstream}
  (hash)             — state, opened_at fields
  circuit:fails:{tool_id}:{upstream}  — INCR failure counter

Thresholds (spec):
  trip_threshold  = 3 consecutive failures
  trip_window     = 600 s  (10 min)
  probe_interval  = 900 s  (15 min)
"""

import json
import logging
import os
import time
from typing import Optional

import redis as redis_lib

log = logging.getLogger("datanexus.core.circuit_breaker")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

TRIP_THRESHOLD  = 3
TRIP_WINDOW     = 600   # seconds
PROBE_INTERVAL  = 900   # seconds

# P05 async thresholds
FAILURE_THRESHOLD = 3
FAILURE_WINDOW_S  = 60
RESET_TIMEOUT_S   = 30

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
        log.warning("circuit_breaker._get_redis: Redis unavailable — %s", exc)
        return None


def _key_failures(source_id: str) -> str:
    return f"datanexus:cb:{source_id}:failures"

def _key_tripped(source_id: str) -> str:
    return f"datanexus:cb:{source_id}:tripped"

def _key_last_probe(source_id: str) -> str:
    return f"datanexus:cb:{source_id}:last_probe"


# ── Sync public API (used by ingest workers and tool handlers) ────────────────

def record_failure_sync(source_id: str) -> bool:
    """
    Record one upstream failure for source_id (synchronous).

    Increments the :failures counter (TTL=TRIP_WINDOW per call).
    If count >= TRIP_THRESHOLD: sets :tripped flag, logs structured JSON.
    Returns True if the breaker JUST tripped on this call, False otherwise.
    """
    r = _get_redis()
    if r is None:
        return False
    try:
        key_f = _key_failures(source_id)
        count = r.incr(key_f)
        r.expire(key_f, TRIP_WINDOW)

        if count >= TRIP_THRESHOLD:
            already_tripped = r.exists(_key_tripped(source_id))
            r.set(_key_tripped(source_id), "1")
            if not already_tripped:
                log.error(json.dumps({
                    "ts":     _iso_now(),
                    "event":  "breaker_tripped",
                    "source": source_id,
                    "count":  count,
                }))
                return True
        return False
    except Exception as exc:
        log.warning("circuit_breaker.record_failure_sync source=%s: %s", source_id, exc)
        return False


def record_success_sync(source_id: str) -> None:
    """
    Record a successful upstream call for source_id (synchronous).

    Deletes :failures counter and :tripped flag.
    Logs structured JSON on reset.
    """
    r = _get_redis()
    if r is None:
        return
    try:
        was_tripped = r.exists(_key_tripped(source_id))
        r.delete(_key_failures(source_id), _key_tripped(source_id))
        if was_tripped:
            log.info(json.dumps({
                "ts":     _iso_now(),
                "event":  "breaker_reset",
                "source": source_id,
            }))
    except Exception as exc:
        log.warning("circuit_breaker.record_success_sync source=%s: %s", source_id, exc)


# ── Async public API (P05 — used by ingest_base and prewarm) ──────────────────

async def is_circuit_open(r, tool_id: str, upstream: str) -> bool:
    """
    Check whether the async circuit breaker is open for tool_id/upstream.

    - Reads hash at circuit:{tool_id}:{upstream}
    - If state == 'open' and opened_at within RESET_TIMEOUT_S: True (open)
    - If state == 'open' but timeout elapsed: set half-open, return False
    - Otherwise: False (closed — allow request)
    Fails open: any exception returns False.
    """
    try:
        state = await r.hgetall(f"circuit:{tool_id}:{upstream}")
        if not state:
            return False
        if state.get("state") == "open":
            if time.time() - float(state.get("opened_at", 0)) > RESET_TIMEOUT_S:
                await r.hset(f"circuit:{tool_id}:{upstream}", "state", "half-open")
                return False
            return True
        return False
    except Exception as exc:
        log.warning("circuit_breaker.is_circuit_open tool=%s upstream=%s: %s",
                    tool_id, upstream, exc)
        return False


async def record_failure(r, tool_id: str, upstream: str) -> None:
    """
    Record one upstream failure for tool_id/upstream (async, P05).

    Increments circuit:fails:{tool_id}:{upstream} counter with FAILURE_WINDOW_S TTL.
    Opens the circuit when count >= FAILURE_THRESHOLD.
    """
    try:
        fails_key = f"circuit:fails:{tool_id}:{upstream}"
        count = await r.incr(fails_key)
        await r.expire(fails_key, FAILURE_WINDOW_S)
        if count >= FAILURE_THRESHOLD:
            await r.hset(
                f"circuit:{tool_id}:{upstream}",
                mapping={"state": "open", "opened_at": str(time.time())},
            )
    except Exception as exc:
        log.warning("circuit_breaker.record_failure tool=%s upstream=%s: %s",
                    tool_id, upstream, exc)


async def record_success(r, tool_id: str, upstream: str) -> None:
    """
    Record a successful upstream call for tool_id/upstream (async, P05).

    Resets circuit state to closed and clears failure counter.
    """
    try:
        await r.hset(f"circuit:{tool_id}:{upstream}", "state", "closed")
        await r.delete(f"circuit:fails:{tool_id}:{upstream}")
    except Exception as exc:
        log.warning("circuit_breaker.record_success tool=%s upstream=%s: %s",
                    tool_id, upstream, exc)


def is_tripped(source_id: str) -> bool:
    """
    Check whether the breaker is currently tripped for source_id.

    - If :tripped key missing → return False (not tripped).
    - If :tripped exists but probe interval has passed → DELETE :tripped,
      return False (allow one probe request through).
    - Otherwise → return True (circuit open, serve from cache).

    Fails open: if Redis is unavailable, returns False (assume not tripped).
    """
    r = _get_redis()
    if r is None:
        return False   # fail open
    try:
        if not r.exists(_key_tripped(source_id)):
            return False

        # Check probe interval
        last_probe_raw = r.get(_key_last_probe(source_id))
        now = time.time()
        if last_probe_raw is not None:
            last_probe = float(last_probe_raw)
            if (now - last_probe) >= PROBE_INTERVAL:
                # Probe window: delete tripped flag, allow one request through
                r.delete(_key_tripped(source_id))
                r.set(_key_last_probe(source_id), str(now))
                log.info(json.dumps({
                    "ts":     _iso_now(),
                    "event":  "breaker_probe_allowed",
                    "source": source_id,
                }))
                return False
        else:
            # First probe check — record timestamp
            r.set(_key_last_probe(source_id), str(now))

        return True
    except Exception as exc:
        log.warning("circuit_breaker.is_tripped source=%s: %s", source_id, exc)
        return False   # fail open


def get_staleness_notice(source_id: str, cached_at: str) -> str:
    """
    Return the standard staleness notice string.

    Used in tool responses when serving archived data due to tripped breaker.
    """
    return (
        f"Source {source_id} unavailable. "
        f"Serving cached data from {cached_at}."
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
