"""
datanexus/kev_refresh.py — CISA KEV catalog refresh.

Downloads https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
and stores in Redis as:
  datanexus:kev:catalog    — full catalog JSON (TTL 25h)
  datanexus:kev:fetched_at — ISO timestamp of last successful fetch (TTL 25h)
  datanexus:kev:last_refresh_error — error message if refresh fails (TTL 7d)

Invoked two ways:
  1. Server startup: asyncio.ensure_future(kev_initial_load()) in main.py _lifespan
  2. Daily refresh container: python -m datanexus.kev_refresh  (kev-refresh service)
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import redis as redis_lib

log = logging.getLogger("datanexus.kev_refresh")

KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_REDIS_URL     = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
KEV_KEY        = "datanexus:kev:catalog"
FETCHED_AT_KEY = "datanexus:kev:fetched_at"
LAST_ERROR_KEY = "datanexus:kev:last_refresh_error"
KEV_TTL        = 25 * 3600   # 25 hours — refresh overlap window

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}


def _get_redis() -> Optional[redis_lib.Redis]:
    """Return a Redis client, or None if connection fails. Never raises."""
    try:
        r = redis_lib.Redis.from_url(
            _REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=5,
        )
        r.ping()
        return r
    except Exception as exc:
        log.warning("kev_refresh._get_redis: Redis unavailable — %s", exc)
        return None


def _write_error(msg: str) -> None:
    """Write refresh error to Redis. Never raises."""
    try:
        r = _get_redis()
        if r:
            r.set(LAST_ERROR_KEY, msg[:500], ex=7 * 86400)
    except Exception:
        pass


async def refresh() -> bool:
    """Download KEV catalog and store in Redis. Returns True on success."""
    try:
        async with httpx.AsyncClient(
            headers=_HEADERS,
            timeout=httpx.Timeout(60.0, connect=15.0),
            follow_redirects=True,
        ) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        msg = f"KEV fetch failed: {exc}"
        log.error("kev_refresh: %s", msg)
        _write_error(msg)
        return False

    if "vulnerabilities" not in data:
        msg = f"KEV: unexpected response keys {list(data.keys())}"
        log.error("kev_refresh: %s", msg)
        _write_error(msg)
        return False

    r = _get_redis()
    if r is None:
        log.error("kev_refresh: Redis unavailable, cannot store KEV catalog")
        _write_error("Redis unavailable during store")
        return False

    try:
        now = datetime.now(timezone.utc).isoformat()
        r.set(KEV_KEY, json.dumps(data), ex=KEV_TTL)
        r.set(FETCHED_AT_KEY, now, ex=KEV_TTL)
        r.delete(LAST_ERROR_KEY)
        log.info(
            "kev_refresh: stored %d KEV entries at %s",
            len(data["vulnerabilities"]), now,
        )
        return True
    except Exception as exc:
        msg = f"KEV Redis write failed: {exc}"
        log.error("kev_refresh: %s", msg)
        _write_error(msg)
        return False


async def kev_initial_load() -> None:
    """Called at server startup via asyncio.ensure_future. Swallows all errors."""
    try:
        log.info("kev_refresh: initial load starting")
        await refresh()
    except Exception as exc:
        log.error("kev_refresh: initial load failed — %s", exc)


def main() -> None:
    """Entry point for the kev-refresh docker-compose service."""
    import sys
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    log.info("kev_refresh: running initial refresh on startup")
    success = asyncio.run(refresh())
    if not success:
        log.error("kev_refresh: initial refresh failed — will retry in 24h")

    while True:
        log.info("kev_refresh: sleeping 24h before next refresh")
        time.sleep(24 * 3600)
        log.info("kev_refresh: daily refresh starting")
        asyncio.run(refresh())


if __name__ == "__main__":
    main()
