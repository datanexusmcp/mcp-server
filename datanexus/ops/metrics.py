"""
Metric readers for the DataNexus operator dashboard.

All functions accept a redis.asyncio client and return plain dicts.
They are read-only and never write to Redis.

Key patterns consumed:
  datanexus:calls:{tool_id}:{YYYY-MM-DD}   STRING  — INCR daily call counter
  datanexus:sessions:{tool_id}:{YYYY-MM-DD} SET    — unique session IDs per day
  datanexus:stats:{tool_id}               HASH    — fields: hits, misses
  datanexus:feed                           LIST    — last 50 feed entries (JSON)

PostgreSQL table consumed:
  dn_sessions(session_id TEXT PK, created_at TIMESTAMPTZ)
"""

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger("datanexus.ops.metrics")

_ALL_TOOLS = [
    "T01", "T02", "T03", "T04", "T05",
    "T06", "T07", "T08", "T09", "T10",
]
_SCAN_DAYS = 7   # look-back window for repeat-session computation


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _date_range(days: int) -> list[str]:
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=i)).isoformat() for i in range(days)]


async def _scan_keys(r, pattern: str) -> list[str]:
    """SCAN for all keys matching pattern — works with both real Redis and fakeredis."""
    keys: list[str] = []
    cursor = 0
    while True:
        cursor, batch = await r.scan(cursor, match=pattern, count=200)
        keys.extend(batch)
        if cursor == 0:
            break
    return keys


async def get_tool_calls_today(r, tool_id: str) -> int:
    """Total calls for tool_id today."""
    val = await r.get(f"datanexus:calls:{tool_id}:{_today()}")
    return int(val) if val else 0


async def get_tool_sessions_today(r, tool_id: str) -> int:
    """Unique session count for tool_id today."""
    return await r.scard(f"datanexus:sessions:{tool_id}:{_today()}")


async def get_tool_cache_stats(r, tool_id: str) -> dict[str, int]:
    """Return {"hits": N, "misses": N} from the per-tool stats hash."""
    raw = await r.hgetall(f"datanexus:stats:{tool_id}")
    return {
        "hits":   int(raw.get("hits",   0)),
        "misses": int(raw.get("misses", 0)),
    }


async def get_repeat_sessions(r, days: int = _SCAN_DAYS) -> int:
    """
    Count session IDs that appear in unique-session SETs on 2 or more distinct
    calendar dates (any tool).  Scans only the last `days` days.
    """
    dates = _date_range(days)

    # Build {date: set_of_session_ids} across all tools
    sessions_by_date: dict[str, set[str]] = defaultdict(set)
    for d in dates:
        keys = await _scan_keys(r, f"datanexus:sessions:*:{d}")
        for key in keys:
            members = await r.smembers(key)
            sessions_by_date[d].update(members)

    # Count sessions appearing on ≥ 2 different dates
    date_count: dict[str, int] = defaultdict(int)
    for day_sessions in sessions_by_date.values():
        for sid in day_sessions:
            date_count[sid] += 1

    return sum(1 for n in date_count.values() if n >= 2)


async def get_feed(r, max_entries: int = 50) -> list[dict]:
    """Return the last `max_entries` live-feed entries, newest first."""
    raw_entries = await r.lrange("datanexus:feed", 0, max_entries - 1)
    result = []
    for raw in raw_entries:
        try:
            result.append(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            pass
    return result


async def get_grandfathered_count() -> int:
    """
    Count sessions in PostgreSQL created before FREE_TIER_END_DATE.
    Returns -1 when DB is unavailable or FREE_TIER_END_DATE is unset.
    """
    from datanexus.config import FREE_TIER_END_DATE
    if FREE_TIER_END_DATE is None:
        return -1   # -1 signals "all grandfathered" to the dashboard
    try:
        from datanexus.db import _get_pool
        pool = await _get_pool()
        if pool is None:
            return -1
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT count(*) FROM dn_sessions WHERE created_at < $1",
                FREE_TIER_END_DATE,
            )
            return int(row["count"]) if row else 0
    except Exception as exc:
        logger.warning("get_grandfathered_count failed: %s", exc)
        return -1


async def get_all_metrics(r) -> dict[str, Any]:
    """
    Aggregate all dashboard metrics in a single async sweep.
    Returns a dict ready to serialise as JSON.
    """
    today = _today()
    tool_rows = []
    total_calls = 0
    total_sessions = 0
    hit_sum = 0
    miss_sum = 0

    for tool_id in _ALL_TOOLS:
        calls   = await get_tool_calls_today(r, tool_id)
        sessions = await get_tool_sessions_today(r, tool_id)
        stats   = await get_tool_cache_stats(r, tool_id)
        hits    = stats["hits"]
        misses  = stats["misses"]
        total   = hits + misses
        hit_rate = round(hits / total, 4) if total else None

        total_calls   += calls
        total_sessions += sessions
        hit_sum        += hits
        miss_sum       += misses

        tool_rows.append({
            "tool_id":      tool_id,
            "calls_today":  calls,
            "sessions_today": sessions,
            "cache_hits":   hits,
            "cache_misses": misses,
            "hit_rate":     hit_rate,
        })

    all_total = hit_sum + miss_sum
    avg_hit_rate = round(hit_sum / all_total, 4) if all_total else None

    repeat_sessions   = await get_repeat_sessions(r)
    grandfathered     = await get_grandfathered_count()
    feed              = await get_feed(r)
    upstream_health   = await get_upstream_health(r)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "date":         today,
        "tools":        tool_rows,
        "totals": {
            "calls_today":       total_calls,
            "sessions_today":    total_sessions,
            "repeat_sessions_7d": repeat_sessions,
            "avg_hit_rate":      avg_hit_rate,
            "cache_hits":        hit_sum,
            "cache_misses":      miss_sum,
            "grandfathered_sessions": grandfathered,
        },
        "feed":            feed,
        "upstream_health": upstream_health,
        "tool_health":     await get_tool_health(r),
    }


async def get_tool_health(r) -> list[dict]:
    """
    Read smoke test results from Redis (datanexus:smoke:*).
    Returns list of dicts sorted by tool_id then tool name.
    Returns empty list if Redis is unavailable or no smoke data exists.
    """
    if r is None:
        return []
    try:
        keys = await r.keys("datanexus:smoke:*")
        if not keys:
            return []
        results = []
        for key in sorted(keys):
            data = await r.hgetall(key)
            if data:
                tool_name = key.split("datanexus:smoke:")[-1]
                results.append({
                    "tool":          tool_name,
                    "tool_id":       data.get("tool_id", "?"),
                    "status":        data.get("status", "UNKNOWN"),
                    "latency_ms":    int(data.get("latency_ms", 0)),
                    "checked_at":    data.get("checked_at", ""),
                    "ingest_healthy": data.get("ingest_healthy", ""),
                    "checks_passed": data.get("checks_passed", "").split(",") if data.get("checks_passed") else [],
                    "checks_failed": data.get("checks_failed", "").split(",") if data.get("checks_failed") else [],
                    "error":         data.get("error", ""),
                })
        results.sort(key=lambda x: (x["tool_id"], x["tool"]))
        return results
    except Exception as exc:
        import logging
        logging.getLogger("datanexus.ops.metrics").warning(
            "tool_health read failed: %s", exc
        )
        return []


async def get_upstream_health(r) -> list[dict]:
    """
    Read canary results from Redis (datanexus:canary:*).
    Returns a list of dicts sorted by tool_id then source name.
    Returns empty list if Redis is unavailable or no canary data exists.
    """
    if r is None:
        return []
    try:
        keys = await r.keys("datanexus:canary:*")
        if not keys:
            return []
        results = []
        for key in sorted(keys):
            data = await r.hgetall(key)
            if data:
                source = key.split("datanexus:canary:")[-1]
                results.append({
                    "source":     source,
                    "tool_id":    data.get("tool_id", "?"),
                    "status":     data.get("status", "UNKNOWN"),
                    "latency_ms": int(data.get("latency_ms", 0)),
                    "checked_at": data.get("checked_at", ""),
                    "check":      data.get("check", ""),
                    "error":      data.get("error", ""),
                })
        results.sort(key=lambda x: (x["tool_id"], x["source"]))
        return results
    except Exception as exc:
        import logging
        logging.getLogger("datanexus.ops.metrics").warning(
            "upstream_health read failed: %s", exc
        )
        return []
