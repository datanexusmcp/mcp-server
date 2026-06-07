"""
datanexus/core/activation_detector.py — Activation event detector.

Called fire-and-forget from usage_recorder.record_usage() after every INSERT.
Checks each tool call for user activation milestones and writes rows to the
activation_events table.

5 activation levels:
  first_call   — IP's very first tool call ever
  real_query   — non-example, non-test input
  multi_tool   — 3+ distinct tools in a 30-min session
  return_visit — called tools on 2+ calendar days
  power_user   — 10+ calls in a rolling 7-day window

Never raises — all errors are caught and logged at WARNING.
"""

import dataclasses
import json
import logging
import os
from typing import Optional

log = logging.getLogger("datanexus.activation_detector")

# ── Example / test inputs per tool (excluded from real_query detection) ────────

EXAMPLE_INPUTS: dict[str, list[str]] = {
    'T04': ['131837418', 'test', ''],
    'T10': ['CVE-2021-44228', 'react', 'lodash', 'test'],
    'T22': ['test', ''],
    'T07': ['google.com', 'facebook.com', 'test'],
    'T11': ['US6424828', 'US10000000', 'Google', 'test'],
    'T18': ['Lockheed Martin', 'test'],
    'T19': ['test', '1'],
}

# ── Pool singleton ─────────────────────────────────────────────────────────────

_pool = None
_pool_init_attempted = False


async def _get_pool():
    global _pool, _pool_init_attempted
    if _pool_init_attempted:
        return _pool
    _pool_init_attempted = True

    db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()
    if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
        return None

    try:
        import asyncpg
        _pool = await asyncpg.create_pool(
            db_url,
            min_size=1,
            max_size=2,
            command_timeout=5,
        )
        log.info("ActivationDetector: asyncpg pool ready")
    except ImportError:
        _pool = None
    except Exception as exc:
        log.warning("ActivationDetector: pool init failed (non-fatal): %s", exc)
        _pool = None

    return _pool


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class UsageRow:
    client_ip: str
    tool_id: str
    tool_input: dict
    is_smoke: bool
    is_grey: bool


# ── Public API ─────────────────────────────────────────────────────────────────

async def check(row: UsageRow) -> None:
    """
    Check a usage row for activation milestones.  Always returns — never raises.
    """
    ip = row.client_ip
    if not ip or ip == 'unknown':
        return
    if ip.startswith('172.6'):    # Glama tester range
        return
    if row.is_smoke:
        return
    if row.is_grey:
        return

    try:
        pool = await _get_pool()
        if pool is None:
            return
        await _check_activations(pool, row)
    except Exception as exc:
        log.warning("activation_detector.check failed (non-fatal): %s", exc)


# ── Internal checks ────────────────────────────────────────────────────────────

async def _check_activations(pool, row: UsageRow) -> None:
    ip = row.client_ip
    tool_id = row.tool_id
    input_str = json.dumps(row.tool_input).lower()

    async with pool.acquire() as conn:

        # LEVEL 1 — first ever call from this IP
        # Bug 11 fix: dedup by event existence rather than COUNT(*)==1 — the
        # latter is off-by-one whenever earlier rows for this IP were filtered
        # out (is_smoke/is_grey), which let real_query out-fire first_call.
        first_call_logged = await conn.fetchval(
            """SELECT COUNT(*) FROM activation_events
               WHERE client_ip=$1 AND event_type='first_call'""",
            ip,
        )
        if first_call_logged == 0:
            await _log_event(conn, ip, 'first_call', tool_id, row)

        # LEVEL 1b — real query (not example / test input)
        example_inputs = EXAMPLE_INPUTS.get(tool_id, [])
        is_example = any(ex and ex.lower() in input_str for ex in example_inputs)
        if not is_example and len(input_str) > 10:
            await _log_event(conn, ip, 'real_query', tool_id, row)

        # LEVEL 2 — multi-tool session (3+ distinct tools), anchored to session start
        session_rows = await conn.fetch(
            """SELECT tool_id, created_at FROM usage
               WHERE client_ip=$1
                 AND created_at >= NOW() - INTERVAL '30 minutes'
                 AND (is_smoke = false OR is_smoke IS NULL)
                 AND (is_grey  = false OR is_grey  IS NULL)
               ORDER BY created_at ASC""",
            ip,
        )
        distinct_tools = {r['tool_id'] for r in session_rows}
        if len(distinct_tools) >= 3:
            session_start = session_rows[0]['created_at']
            already_logged = await conn.fetchval(
                """SELECT COUNT(*) FROM activation_events
                   WHERE client_ip=$1 AND event_type='multi_tool'
                     AND created_at >= $2""",
                ip, session_start,
            )
            if already_logged == 0:
                await _log_event(
                    conn, ip, 'multi_tool', tool_id, row,
                    metadata={
                        'tools': sorted(distinct_tools),
                        'session_start': session_start.isoformat(),
                    },
                )

        # LEVEL 3 — return visit (calls on 2+ different calendar days),
        # deduped to fire at most once per user per calendar day.
        call_days = await conn.fetch(
            """SELECT DISTINCT DATE(created_at) AS day
               FROM usage
               WHERE client_ip=$1
                 AND (is_smoke = false OR is_smoke IS NULL)
                 AND (is_grey  = false OR is_grey  IS NULL)""",
            ip,
        )
        if len(call_days) >= 2:
            already_today = await conn.fetchval(
                """SELECT COUNT(*) FROM activation_events
                   WHERE client_ip=$1 AND event_type='return_visit'
                     AND DATE(created_at) = CURRENT_DATE""",
                ip,
            )
            if already_today == 0:
                await _log_event(conn, ip, 'return_visit', tool_id, row)

        # LEVEL 4 — power user (crosses 10-call threshold in rolling 7 days)
        week_calls = await conn.fetchval(
            """SELECT COUNT(*) FROM usage
               WHERE client_ip=$1
                 AND created_at >= NOW() - INTERVAL '7 days'
                 AND (is_smoke = false OR is_smoke IS NULL)
                 AND (is_grey  = false OR is_grey  IS NULL)""",
            ip,
        )
        if week_calls == 10:
            await _log_event(conn, ip, 'power_user', tool_id, row)


async def _log_event(
    conn,
    ip: str,
    event_type: str,
    tool_id: str,
    row: UsageRow,
    metadata: Optional[dict] = None,
) -> None:
    await conn.execute(
        """INSERT INTO activation_events
           (client_ip, event_type, tool_id, metadata, created_at)
           VALUES ($1, $2, $3, $4::jsonb, NOW())""",
        ip,
        event_type,
        tool_id,
        json.dumps(metadata or {'input': row.tool_input}),
    )
    log.info("activation: %s from %s on %s", event_type, ip, tool_id)
