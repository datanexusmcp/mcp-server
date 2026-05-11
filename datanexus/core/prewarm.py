"""
datanexus/core/prewarm.py — Startup cache pre-warm.

Spec: DataNexus_MCP_Spec_v7_5.docx  Sprint 3 P05

Seeds high-value queries into Redis on server startup so the first real
user request hits the cache rather than the upstream API.

Cache key pattern: cache:{tool_id}:{function_name}:{sha256(param)}
  — distinct from the tool runtime cache (datanexus:{tool_id}:*)
  — checked by the circuit breaker to serve stale data when upstream is down

Errors are always silently swallowed — prewarm must never block startup.
"""

import asyncio
import hashlib
import json
import logging
import os
from typing import List

log = logging.getLogger("datanexus.core.prewarm")

# ── Seed manifest ─────────────────────────────────────────────────────────────

SEED: dict[str, list[tuple[str, str]]] = {
    "T04": [
        ("fetch_nonprofit_by_ein", "13-1788491"),
        ("fetch_nonprofit_by_ein", "23-7363942"),
        ("fetch_nonprofit_by_ein", "04-2103594"),
    ],
    "T10": [
        ("fetch_package_vulnerabilities", "lodash:4.17.21:npm"),
        ("fetch_cve_detail", "CVE-2021-44228"),
        ("fetch_package_licence", "express:4.18.2:npm"),
    ],
}

# TTL for pre-warmed cache entries (4 hours — standard registry data TTL)
_PREWARM_TTL = 14400


def _cache_key(tool_id: str, func_name: str, param: str) -> str:
    h = hashlib.sha256(param.encode()).hexdigest()
    return f"cache:{tool_id}:{func_name}:{h}"


async def _fetch_t04_nonprofit_by_ein(ein: str) -> dict:
    from datanexus.tools.t04 import fetch_nonprofit_by_ein
    return await fetch_nonprofit_by_ein(ein)


async def _fetch_t10_package_vulnerabilities(raw_param: str) -> dict:
    from datanexus.tools.t10 import fetch_package_vulnerabilities
    parts = raw_param.split(":", 2)
    if len(parts) != 3:
        raise ValueError(f"Invalid package param: {raw_param!r} — expected pkg:ver:ecosystem")
    return await fetch_package_vulnerabilities(parts[0], parts[1], parts[2])


async def _fetch_t10_cve_detail(cve_id: str) -> dict:
    from datanexus.tools.t10 import fetch_cve_detail
    return await fetch_cve_detail(cve_id)


async def _fetch_t10_package_licence(raw_param: str) -> dict:
    from datanexus.tools.t10 import fetch_package_licence
    parts = raw_param.split(":", 2)
    if len(parts) != 3:
        raise ValueError(f"Invalid package param: {raw_param!r} — expected pkg:ver:ecosystem")
    return await fetch_package_licence(parts[0], parts[1], parts[2])


_FETCHERS: dict[str, dict[str, any]] = {
    "T04": {
        "fetch_nonprofit_by_ein": _fetch_t04_nonprofit_by_ein,
    },
    "T10": {
        "fetch_package_vulnerabilities": _fetch_t10_package_vulnerabilities,
        "fetch_cve_detail":              _fetch_t10_cve_detail,
        "fetch_package_licence":         _fetch_t10_package_licence,
    },
}


async def _warm_one(r, tool_id: str, func_name: str, param: str) -> None:
    """Fetch one seed entry and write to Redis. Errors are silently swallowed."""
    try:
        fetcher = _FETCHERS.get(tool_id, {}).get(func_name)
        if fetcher is None:
            log.warning("prewarm: no fetcher for %s/%s — skipping", tool_id, func_name)
            return

        result = await fetcher(param)
        key = _cache_key(tool_id, func_name, param)
        await r.set(key, json.dumps(result, default=str), ex=_PREWARM_TTL)
        log.info("prewarm: cached %s", key)
    except Exception as exc:
        log.warning("prewarm: %s/%s(%r) failed — %s", tool_id, func_name, param, exc)


async def prewarm_cache(tool_ids: List[str] | None = None) -> None:
    """
    Pre-warm cache for the given tool IDs (default: all in SEED manifest).

    Errors are always silently swallowed — never block server startup.
    """
    import redis.asyncio as aioredis

    _redis_url = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

    try:
        r = aioredis.from_url(_redis_url, decode_responses=True)
    except Exception as exc:
        log.warning("prewarm: Redis connection failed — skipping prewarm: %s", exc)
        return

    targets = tool_ids if tool_ids is not None else list(SEED.keys())

    tasks = []
    for tool_id in targets:
        entries = SEED.get(tool_id, [])
        for func_name, param in entries:
            tasks.append(_warm_one(r, tool_id, func_name, param))

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as exc:
        log.warning("prewarm: gather error — %s", exc)
    finally:
        try:
            await r.aclose()
        except Exception:
            pass

    log.info("prewarm: completed for tools %s", targets)
