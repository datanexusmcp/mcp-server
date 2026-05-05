"""
feedback/agents/bug_listener.py — Redis BLPOP daemon on fb:alerts:immediate.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.6 / Section 11.6 Step 8

Rules (non-negotiable):
  - NEVER checks FEEDBACK_AGENTS_ACTIVE — always runs when started.
  - Fires ntfy.sh HTTP push on every message consumed from fb:alerts:immediate.
  - Prints structured startup JSON to stdout before entering the BLPOP loop.
  - Degrades gracefully when Redis is unavailable (retries with back-off).
  - Degrades gracefully when ntfy.sh is unreachable (logs warning, continues).

Run as:
  python3 -m feedback.agents.bug_listener

Environment variables:
  DATANEXUS_REDIS_URL   — Redis URL (default: redis://localhost:6379)
  NTFY_TOPIC            — ntfy.sh topic name (default: datanexus-bugs)
  NTFY_BASE_URL         — ntfy.sh base URL (default: https://ntfy.sh)
  NTFY_TOKEN            — optional ntfy.sh access token
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import redis as redis_lib

from feedback.config import key_alerts_immediate
from datanexus.core.cache import get_cached

log = logging.getLogger("feedback.agents.bug_listener")

# ── Configuration ──────────────────────────────────────────────────────────────
_REDIS_URL    = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_NTFY_TOPIC   = os.environ.get("NTFY_TOPIC",    "datanexus-bugs")
_NTFY_BASE    = os.environ.get("NTFY_BASE_URL",  "https://ntfy.sh").rstrip("/")
_NTFY_TOKEN   = os.environ.get("NTFY_TOKEN",     "")
_BLPOP_TIMEOUT   = 5    # seconds — short timeout so the loop can check for shutdown
_REDIS_RETRY_SEC = 10   # back-off before retrying Redis connect
_MAX_TITLE_LEN   = 80


def _get_redis() -> Optional[redis_lib.Redis]:
    """Connect to Redis. Returns None on failure."""
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL, decode_responses=True,
            socket_connect_timeout=3, socket_timeout=_BLPOP_TIMEOUT + 2,
        )
        client.ping()
        return client
    except Exception as exc:
        log.warning("bug_listener: Redis connect failed — %s", exc)
        return None


def _fire_ntfy(payload: dict) -> None:
    """POST an alert to ntfy.sh. Swallows all errors."""
    try:
        signal = payload.get("signal", "bug")
        tool   = payload.get("tool_id", "unknown")
        ts     = payload.get("received_at", "")[:10]

        title   = f"[DataNexus] {signal} on {tool} — {ts}"[:_MAX_TITLE_LEN]
        message = payload.get("comment", "") or f"Signal: {signal} | Tool: {tool}"

        headers = {
            "Title":    title,
            "Priority": "high",
            "Tags":     "bug,datanexus",
            "Content-Type": "text/plain",
        }
        if _NTFY_TOKEN:
            headers["Authorization"] = f"Bearer {_NTFY_TOKEN}"

        url = f"{_NTFY_BASE}/{_NTFY_TOPIC}"
        with httpx.Client(timeout=8.0) as client:
            resp = client.post(url, content=message.encode(), headers=headers)
            resp.raise_for_status()

        log.info("bug_listener: ntfy alert sent topic=%s signal=%s", _NTFY_TOPIC, signal)

    except Exception as exc:
        log.warning("bug_listener: ntfy push failed — %s", exc)


def _process_message(raw: str) -> None:
    """
    Decode a raw JSON message, run feedback classification (Phase 4),
    then fire the ntfy alert.

    Classification runs BEFORE send_alert. If it raises or fails for any
    reason, the exception is caught, logged at ERROR, and alert fires anyway —
    classify_feedback must never block alerts.
    """
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"signal": "unknown", "raw": raw[:200]}

    # ── Phase 4: classify_feedback before alert ───────────────────────────────
    try:
        from feedback.models import FeedbackRecord
        from datanexus.agents.feedback_classifier import classify_feedback

        record = FeedbackRecord(
            tool_id=payload.get("tool_id", "T04"),
            query_hash=payload.get("query_hash", ""),
            signal=payload.get("signal", "incorrect_data"),
            comment=payload.get("comment", ""),
            record_id=payload.get("record_id", ""),
        )
        # Fetch the original cached response the feedback was filed against
        cached_response = get_cached(record.tool_id, record.query_hash) or {}
        classification_result = asyncio.run(
            classify_feedback(record, cached_response)
        )
        log.info(json.dumps({
            "event":                  "bug_listener_classification",
            "record_id":              record.record_id,
            "classification_result":  classification_result,
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":  "bug_listener_classification_error",
            "error":  str(exc),
            "action": "continuing to send_alert",
        }))

    # ── Always fire ntfy alert regardless of classification outcome ───────────
    _fire_ntfy(payload)


def run() -> None:
    """
    Main BLPOP loop.  Prints startup JSON, then consumes fb:alerts:immediate.
    Retries Redis connection on failure with _REDIS_RETRY_SEC back-off.
    Never exits on its own — run as a managed process (systemd / supervisor).
    """
    startup = {
        "event":      "startup",
        "service":    "bug_listener",
        "queue":      key_alerts_immediate(),
        "ntfy_topic": _NTFY_TOPIC,
        "redis_url":  _REDIS_URL,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    # Structured startup JSON to stdout (gate requirement)
    print(json.dumps(startup), flush=True)

    log.info("bug_listener starting — queue=%s ntfy_topic=%s",
             key_alerts_immediate(), _NTFY_TOPIC)

    while True:
        r = _get_redis()
        if r is None:
            log.warning("bug_listener: Redis unavailable — retry in %ds", _REDIS_RETRY_SEC)
            time.sleep(_REDIS_RETRY_SEC)
            continue

        log.info("bug_listener: connected to Redis — entering BLPOP loop")
        try:
            while True:
                result = r.blpop(key_alerts_immediate(), timeout=_BLPOP_TIMEOUT)
                if result is None:
                    continue   # timeout — loop back
                _key, raw = result
                log.info("bug_listener: message received len=%d", len(raw))
                _process_message(raw)

        except redis_lib.exceptions.ConnectionError as exc:
            log.warning("bug_listener: Redis connection lost — %s — reconnecting", exc)
            time.sleep(_REDIS_RETRY_SEC)
        except Exception as exc:
            log.exception("bug_listener: unexpected error — %s — continuing", exc)
            time.sleep(2)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    run()
