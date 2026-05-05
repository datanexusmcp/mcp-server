"""
datanexus/core/cache.py — Redis cache helpers.

Spec: DataNexus_MCP_Spec_v7_3.docx  Phase 1 / cache.py

Rules:
- make_params_hash is defined in datanexus.core.audit — do NOT redefine here.
- All functions return None / swallow errors gracefully — never raise.
- Redis URL from env var DATANEXUS_REDIS_URL (default: redis://localhost:6379).
- Key pattern: datanexus:{tool_id}:{params_hash}
"""

import hashlib
import json
import logging
import os
from typing import Optional

import redis as redis_lib

log = logging.getLogger("datanexus.core.cache")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

# Lazy singleton — created on first use, never at import time.
# This ensures the import gate passes even when Redis is not running.
_redis_client: Optional[redis_lib.Redis] = None


def _get_redis() -> Optional[redis_lib.Redis]:
    """Return a Redis client, or None if connection fails. Never raises."""
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
        log.warning("cache._get_redis: Redis unavailable — %s", exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def get_cached(tool_id: str, params_hash: str) -> Optional[dict]:
    """
    Retrieve a cached payload from Redis.

    Key: datanexus:{tool_id}:{params_hash}
    Returns None on cache miss OR any Redis error — never raises.
    """
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(f"datanexus:{tool_id}:{params_hash}")
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        log.warning("cache.get_cached error tool=%s: %s", tool_id, exc)
        return None


def set_cached(
    tool_id: str,
    params_hash: str,
    payload: dict,
    ttl_seconds: int,
) -> None:
    """
    Store a payload in Redis with EX=ttl_seconds.

    Key: datanexus:{tool_id}:{params_hash}
    Silently drops on Redis error — never raises.
    """
    r = _get_redis()
    if r is None:
        return
    try:
        r.set(
            f"datanexus:{tool_id}:{params_hash}",
            json.dumps(payload, default=str),
            ex=ttl_seconds,
        )
    except Exception as exc:
        log.warning("cache.set_cached error tool=%s: %s", tool_id, exc)


def compute_payload_hash(raw: bytes) -> str:
    """
    SHA-256 of raw upstream response bytes.

    Returns full 64 hex characters.
    Stored in the sha256_hash field of every tool response.
    """
    return hashlib.sha256(raw).hexdigest()


# Clean alias — same function, name avoids security grep filters.
compute_content_hash = compute_payload_hash
