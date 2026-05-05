"""
feedback/upstream_monitor.py — Schema fingerprinting for upstream API change detection.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.5 / Section 11.6 Step 7

Detects when an upstream API changes its response schema (added/removed/renamed
fields, changed value types) by storing a deterministic fingerprint of the
response structure in Redis and alerting on mismatch.

Key design rules:
  - schema_fingerprint() is deterministic and key-order-independent.
  - Fingerprints capture field names + value types, NOT values themselves.
  - No upstream data is persisted — fingerprints only.
  - Alert published to fb:alerts:immediate on schema change.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import redis as redis_lib

from feedback.config import key_alerts_immediate, key_pause

log = logging.getLogger("feedback.upstream_monitor")

_REDIS_URL     = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_FINGERPRINT_TTL = 30 * 86_400   # 30 days

_redis_client: Optional[redis_lib.Redis] = None


def _get_redis() -> Optional[redis_lib.Redis]:
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
        log.warning("upstream_monitor: Redis unavailable — %s", exc)
        return None


def _set_redis_client(client: Optional[redis_lib.Redis]) -> None:
    global _redis_client
    _redis_client = client


# ── Schema fingerprinting ──────────────────────────────────────────────────────

def _extract_schema(obj: Any, depth: int = 0) -> Any:
    """
    Recursively extract (field-name → type-name) structure from an object.
    Values are replaced with their type names.  Dict keys are sorted.
    Lists are collapsed to their first element's schema (or 'list' if empty).
    Max depth: 5 levels.
    """
    if depth > 5:
        return type(obj).__name__
    if isinstance(obj, dict):
        return {k: _extract_schema(obj[k], depth + 1) for k in sorted(obj)}
    if isinstance(obj, list):
        if not obj:
            return ["list"]
        return [_extract_schema(obj[0], depth + 1)]
    return type(obj).__name__


def schema_fingerprint(response: dict) -> str:
    """
    Return a deterministic 32-hex-char fingerprint of a response's schema.

    Only field names and value types are captured — not values.
    Key-order-independent: {'a':1,'b':2} produces the same fingerprint as
    {'b':2,'a':1}.

    Used to detect upstream API schema changes between polling cycles.
    """
    schema  = _extract_schema(response)
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


# ── Monitoring helpers ─────────────────────────────────────────────────────────

def _fingerprint_key(source_id: str) -> str:
    """Redis key storing the last known fingerprint for a source."""
    return f"upstream_fp:{source_id}"


def check_and_update_fingerprint(source_id: str, response: dict) -> bool:
    """
    Compare the current response schema against the stored fingerprint.

    Returns True  — schema unchanged (or no prior fingerprint stored).
    Returns False — schema change detected; alert published to fb:alerts:immediate.

    Side effects:
      - Updates stored fingerprint on change.
      - Publishes a structured alert JSON to fb:alerts:immediate on change.
    """
    current_fp = schema_fingerprint(response)
    r = _get_redis()

    if r is None:
        return True   # degrade gracefully — assume no change

    key      = _fingerprint_key(source_id)
    stored   = r.get(key)

    # First observation — store and return clean
    if stored is None:
        r.setex(key, _FINGERPRINT_TTL, current_fp)
        log.info("upstream_monitor: initial fingerprint stored source=%s fp=%s",
                 source_id, current_fp)
        return True

    if stored == current_fp:
        return True

    # Schema change detected
    log.warning(
        "upstream_monitor: SCHEMA CHANGE source=%s old=%s new=%s",
        source_id, stored, current_fp,
    )
    alert = json.dumps({
        "event":       "upstream_schema_change",
        "source_id":   source_id,
        "old_fp":      stored,
        "new_fp":      current_fp,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    })
    try:
        r.lpush(key_alerts_immediate(), alert)
        r.setex(key, _FINGERPRINT_TTL, current_fp)
    except Exception as exc:
        log.warning("upstream_monitor: failed to publish alert — %s", exc)

    return False


def get_stored_fingerprint(source_id: str) -> Optional[str]:
    """Return the last stored fingerprint for a source, or None."""
    r = _get_redis()
    if r is None:
        return None
    return r.get(_fingerprint_key(source_id))
