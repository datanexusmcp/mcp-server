"""
datanexus/agents/haiku_classifier.py — Shared Haiku API wrapper for all 4 triggers.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.2 / Phase 2

Rules (CLAUDE.md):
  S13-1: Called ONLY from the 4 permitted triggers — never directly from tool handlers.
  S13-2: HAIKU_MODEL imported from feedback/config.py. Never hardcoded here.
  S13-3: Daily cap HAIKU_MAX_CALLS_PER_DAY (100) enforced before every call.
         incr → expire → check, in that exact order.
  S13-4: On any API error: return error dict, never raise.

Daily cap counter:
  Redis key:  haiku:calls:{date.today()}     (date format: YYYY-MM-DD)
  TTL:        86400 seconds
  Behaviour:  incr first, then check. If count > 100: return limit error.

Public API:
  async classify(context: str, data: dict, task: str) -> dict
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date

import redis as redis_lib

from feedback.config import HAIKU_MODEL
from payment.config import HAIKU_MAX_CALLS_PER_DAY

log = logging.getLogger("datanexus.agents.haiku_classifier")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

# Lazy sync Redis singleton — used only for the atomic daily cap counter.
# The rest of the call (Anthropic API) is async-friendly without async Redis.
_redis_client: redis_lib.Redis | None = None


def _get_redis() -> redis_lib.Redis | None:
    """Return a Redis client for cap counting. Never raises."""
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
        log.warning(json.dumps({
            "event":  "haiku_redis_unavailable",
            "error":  str(exc),
        }))
        return None


def _check_and_increment_cap() -> tuple[int, bool]:
    """
    Atomically increment the daily Haiku call counter and check the cap.

    Order per spec: incr → expire → check.

    Returns:
        (count, over_limit)
        count:      current value after increment
        over_limit: True when count > HAIKU_MAX_CALLS_PER_DAY
    """
    today_key = f"haiku:calls:{date.today()}"
    r = _get_redis()
    if r is None:
        # Redis unavailable — allow the call (fail-open for cap; log warning)
        log.warning(json.dumps({
            "event":   "haiku_cap_redis_miss",
            "note":    "Redis unavailable — cap not enforced this call",
            "key":     today_key,
        }))
        return (0, False)
    try:
        count = r.incr(today_key)          # 1. increment first
        r.expire(today_key, 86400)         # 2. refresh TTL
        over = count > HAIKU_MAX_CALLS_PER_DAY  # 3. check
        return (count, over)
    except Exception as exc:
        log.warning(json.dumps({
            "event":  "haiku_cap_error",
            "error":  str(exc),
            "note":   "cap not enforced this call",
        }))
        return (0, False)


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

async def classify(context: str, data: dict, task: str) -> dict:
    """
    Call Claude Haiku with a structured classification prompt.

    Args:
        context: Plain-English description of what is being classified.
        data:    Supporting data dict serialised into the prompt.
        task:    Short instruction telling Haiku what JSON to return.

    Returns:
        On success: Haiku's parsed JSON response as a dict.
        On daily-cap breach or any API error: error dict with
          {'error': str, 'haiku_available': False}

    Never raises. All exceptions caught and returned as error dicts.
    """
    # ── Daily cap: incr → expire → check ─────────────────────────────────────
    count, over_limit = _check_and_increment_cap()
    if over_limit:
        log.warning(json.dumps({
            "event":            "haiku_daily_limit_reached",
            "count":            count,
            "limit":            HAIKU_MAX_CALLS_PER_DAY,
            "haiku_available":  False,
        }))
        return {"error": "daily_limit_reached", "haiku_available": False}

    # ── Anthropic API call ────────────────────────────────────────────────────
    try:
        import anthropic  # lazy import — only when actually needed

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        client  = anthropic.AsyncAnthropic(api_key=api_key)

        system_prompt = (
            "You are a data quality classifier for a public data API. "
            "Return JSON only. No prose. No markdown. Raw JSON object only."
        )
        user_message = (
            f"Context: {context}\n\n"
            f"Data: {json.dumps(data, default=str)}\n\n"
            f"Task: {task}"
        )

        response = await client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=500,
            temperature=0.1,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )

        raw_text = response.content[0].text.strip()

        log.info(json.dumps({
            "event":           "haiku_classify_ok",
            "model":           HAIKU_MODEL,
            "count_today":     count,
            "input_tokens":    response.usage.input_tokens,
            "output_tokens":   response.usage.output_tokens,
        }))

        # Strip optional markdown code fence if Haiku wraps output
        if raw_text.startswith("```"):
            lines = raw_text.splitlines()
            raw_text = "\n".join(
                line for line in lines
                if not line.startswith("```")
            ).strip()

        return json.loads(raw_text)

    except Exception as exc:
        log.error(json.dumps({
            "event":           "haiku_classify_error",
            "error":           str(exc),
            "haiku_available": False,
        }))
        return {"error": str(exc), "haiku_available": False}
