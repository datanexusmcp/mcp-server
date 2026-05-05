"""
Redis async cache layer.

Key schema:  datanexus:{tool_id}:{params_hash_16}
Stored value: JSON object  {"payload": {...}, "sha256": "hexstring"}

On Redis unavailability the layer silently degrades: GET returns (None, None),
SET is a no-op.  The ingest worker and tool layer both tolerate this.
"""

import json
import logging
from typing import Any, Optional

import redis.asyncio as aioredis

from datanexus.config import REDIS_URL

logger = logging.getLogger(__name__)

_client: Optional[aioredis.Redis] = None


async def get_redis() -> Optional[aioredis.Redis]:
    global _client
    if _client is not None:
        return _client
    try:
        c = aioredis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        await c.ping()
        _client = c
        logger.info("Redis connected at %s", REDIS_URL)
    except Exception:
        # Fall back to fakeredis for local dev (no Redis server required)
        try:
            import fakeredis.aioredis as fake
            _client = fake.FakeRedis(decode_responses=True)
            logger.info("Using fakeredis (local dev mode — data is in-process only)")
        except ImportError:
            logger.warning("Redis unavailable and fakeredis not installed — cache disabled")
            _client = None
    return _client


def _params_hash(params: dict) -> str:
    import hashlib
    serialised = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()[:16]


def make_key(tool_id: str, params: dict) -> str:
    return f"datanexus:{tool_id}:{_params_hash(params)}"


async def cache_get(tool_id: str, params: dict) -> tuple[Optional[dict], Optional[str]]:
    """
    Returns (payload_dict, sha256_hex) on hit, (None, None) on miss or error.
    """
    r = await get_redis()
    if r is None:
        return None, None
    key = make_key(tool_id, params)
    try:
        raw = await r.get(key)
        if raw:
            stored = json.loads(raw)
            return stored.get("payload"), stored.get("sha256")
    except Exception as exc:
        logger.warning("Cache GET error key=%s: %s", key, exc)
    return None, None


async def cache_set(
    tool_id: str,
    params: dict,
    payload: dict,
    sha256: str,
    ttl: int,
) -> None:
    """Writes payload + SHA-256 to Redis with the given TTL (seconds)."""
    r = await get_redis()
    if r is None:
        return
    key = make_key(tool_id, params)
    value = json.dumps({"payload": payload, "sha256": sha256})
    try:
        await r.set(key, value, ex=ttl)
        logger.debug("Cache SET key=%s ttl=%ds", key, ttl)
    except Exception as exc:
        logger.warning("Cache SET error key=%s: %s", key, exc)


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
