"""
feedback/collector.py — report_feedback() FastMCP tool.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.4 / Section 11.6 Step 6

Contract (non-negotiable):
  ALWAYS returns {'status': 'recorded'}.
  Never raises. Never returns an error dict.
  Silent failure on every layer — validation, Redis, routing all degrade gracefully.

Four defense layers (inline, in order):
  1. Pydantic FeedbackInput validation — rejects malformed input silently.
  2. tool_id in FEEDBACK_ENABLED_TOOLS — explicit guard (belt-and-suspenders).
  3. Dedup: identical tool_id+query_hash+signal within DEDUP_WINDOW_SECS
       → HINCRBY vote_count on both dedup key and feedback record; no new entry.
  4. Route:
       BUG_SIGNAL       → LPUSH fb:alerts:immediate   (consumed by bug_listener)
       IMPROVEMENT_SIGNAL → LPUSH fb:queue             (consumed by digest worker)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import List, Optional

import redis as redis_lib
from pydantic import ValidationError

from feedback.config import (
    BUG_SIGNALS,
    DEDUP_WINDOW_SECS,
    FEEDBACK_ENABLED_TOOLS,
    FEEDBACK_TTL,
    key_alerts_immediate,
    key_dedup,
    key_feedback,
    key_feedback_list,
    key_feedback_queue,
    key_pause,
)
from feedback.models import FeedbackInput, FeedbackRecord

log = logging.getLogger("feedback.collector")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

# Module-level Redis client — replaced in tests via _set_redis_client().
_redis_client: Optional[redis_lib.Redis] = None


def _get_redis() -> Optional[redis_lib.Redis]:
    """
    Lazy Redis connection with liveness check.  Returns None if unavailable — never raises.

    Bug fix: cached client is ping-checked on every call.  If the connection has
    dropped (Redis restart, network blip) the stale client is discarded and a fresh
    connection is attempted rather than returning a broken client whose write errors
    would be silently swallowed by the outer try/except in report_feedback().
    """
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception as ping_exc:
            log.warning(
                "feedback.collector: cached Redis connection lost — reconnecting (%s)",
                ping_exc,
            )
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
        log.info("feedback.collector: Redis connected — %s", _REDIS_URL)
        return _redis_client
    except Exception as exc:
        log.error("feedback.collector: Redis unavailable — %s", exc)
        return None


def _set_redis_client(client: Optional[redis_lib.Redis]) -> None:
    """Inject a Redis client — used in tests (e.g. fakeredis). Pass None to reset."""
    global _redis_client
    _redis_client = client


# ── Core tool function ────────────────────────────────────────────────────────

async def report_feedback(
    tool_id: str,
    query_hash: str,
    signal: str,
    comment: str = "",
    missing_fields: Optional[List[str]] = None,
) -> dict:
    """
    Submit explicit feedback about a DataNexus tool response.

    ALWAYS returns {'status': 'recorded'} — never raises, never errors.
    Identical calls within 60 seconds increment vote_count rather than
    creating duplicate records. BUG_SIGNAL calls are routed immediately
    for alerting; improvement signals queue for daily digest.

    Args:
      tool_id:        Tool that produced the response (T04 or T10).
      query_hash:     query_hash field from the tool response — links feedback to audit.
      signal:         Feedback type — one of:
                        BUG:         not_useful, incorrect_data, missing_field,
                                     hallucination, wrong_entity, stale_data, data_quality
                        IMPROVEMENT: helpful, very_helpful, feature_request,
                                     good_result, saved_time
      comment:        Optional free-text comment (max 1000 chars).
      missing_fields: Required when signal == 'missing_field'.

    Returns:
      {'status': 'recorded'}  — always.
    """
    try:
        _handle_feedback(tool_id, query_hash, signal, comment, missing_fields)
    except Exception:
        log.exception(
            "feedback.collector: unexpected error tool=%s signal=%s — swallowing",
            tool_id, signal,
        )
    return {"status": "recorded"}


def _handle_feedback(
    tool_id: str,
    query_hash: str,
    signal: str,
    comment: str,
    missing_fields: Optional[List[str]],
) -> None:
    """
    Inner handler — all four defense layers.  May raise; caller swallows.
    """
    # ── Layer 1: Pydantic validation ──────────────────────────────────────────
    try:
        inp = FeedbackInput(
            tool_id=tool_id,
            query_hash=query_hash,
            signal=signal,
            comment=comment,
            missing_fields=missing_fields,
        )
    except ValidationError as exc:
        log.info(
            "feedback.collector: validation rejected tool=%s signal=%s — %s",
            tool_id, signal,
            exc.errors()[0]["msg"] if exc.errors() else str(exc),
        )
        return   # silently discard

    # ── Layer 2: tool_id guard ────────────────────────────────────────────────
    if inp.tool_id not in FEEDBACK_ENABLED_TOOLS:
        log.info("feedback.collector: tool %s not in FEEDBACK_ENABLED_TOOLS", inp.tool_id)
        return

    r = _get_redis()
    if r is None:
        log.info("feedback.collector: Redis unavailable — skipping persistence")
        return

    # Check pause key
    if r.exists(key_pause()):
        log.info("feedback.collector: paused — discarding signal tool=%s", inp.tool_id)
        return

    # ── Layer 3: Dedup ────────────────────────────────────────────────────────
    dedup_key = key_dedup(inp.tool_id, inp.query_hash, inp.signal)
    existing  = r.hgetall(dedup_key)

    if existing:
        # Duplicate within the dedup window — increment vote counts only.
        new_count = r.hincrby(dedup_key, "vote_count", 1)
        record_id = existing.get("record_id", "")
        if record_id:
            r.hincrby(key_feedback(inp.tool_id, record_id), "vote_count", 1)
        log.debug(
            "feedback.collector: dedup hit tool=%s signal=%s vote_count=%d",
            inp.tool_id, inp.signal, new_count,
        )
        return

    # ── Layer 4: New record — persist and route ───────────────────────────────
    record     = FeedbackRecord.from_input(inp)
    record_json = record.model_dump_json()
    now_score   = time.time()

    pipe = r.pipeline()

    # Persist the feedback record
    pipe.hset(
        key_feedback(inp.tool_id, record.record_id),
        mapping={"data": record_json, "vote_count": 1},
    )
    pipe.expire(key_feedback(inp.tool_id, record.record_id), FEEDBACK_TTL)

    # Add to per-tool sorted set (score = unix timestamp for ordering)
    pipe.zadd(key_feedback_list(inp.tool_id), {record.record_id: now_score})

    # Set dedup marker with vote_count=1 and short TTL
    pipe.hset(dedup_key, mapping={"record_id": record.record_id, "vote_count": 1})
    pipe.expire(dedup_key, DEDUP_WINDOW_SECS)

    # Route to the appropriate queue
    if inp.signal in BUG_SIGNALS:
        pipe.lpush(key_alerts_immediate(), record_json)
    else:
        pipe.lpush(key_feedback_queue(), record_json)

    try:
        results = pipe.execute()
    except Exception as exc:
        log.error(
            "feedback.collector: pipeline.execute() FAILED tool=%s signal=%s "
            "record_id=%s redis_url=%s — %s",
            inp.tool_id, inp.signal, record.record_id, _REDIS_URL, exc,
            exc_info=True,
        )
        return

    # Non-transactional pipelines collect per-command results; surface any failures.
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            log.error(
                "feedback.collector: pipeline command[%d] failed tool=%s "
                "record_id=%s — %s",
                i, inp.tool_id, record.record_id, result,
            )

    log.info(
        "feedback.collector: recorded tool=%s signal=%s record_id=%s "
        "key=feedback:%s:%s",
        inp.tool_id, inp.signal, record.record_id,
        inp.tool_id, record.record_id,
    )
