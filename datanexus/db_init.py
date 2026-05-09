"""
datanexus/db_init.py — Database table initialisation on container startup.

Creates two tables if they do not already exist:
  sessions  — one row per MCP session seen by @verify_entitlement
  usage     — one row per tool call (inserted by telemetry layer)

Called from main.py via the FastMCP lifespan hook, which fires once before
any tool request is handled.

Fail-safe contract (never blocks server startup):
  - DATANEXUS_DB_URL absent or not a postgresql:// URL → debug-log, return.
  - asyncpg not installed                              → warning-log, return.
  - PostgreSQL unreachable / DDL error                 → warning-log, return.
"""

import logging
import os

log = logging.getLogger("datanexus.db_init")

# Both tables in a single transaction — idempotent via IF NOT EXISTS.
_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT        PRIMARY KEY,
    tool_id     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS usage (
    id          SERIAL      PRIMARY KEY,
    session_id  TEXT        NOT NULL,
    tool_id     TEXT        NOT NULL,
    call_uuid   TEXT        UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
"""


async def init_db() -> None:
    """Create sessions and usage tables if they do not exist.

    Reads DATANEXUS_DB_URL from the environment at call time (not import
    time) so that env vars loaded from .env after module import are visible.

    Never raises — all failure paths log a warning and return so that
    server startup is never blocked by a database issue.
    """
    db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()

    if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
        log.debug(
            "db_init: DATANEXUS_DB_URL is absent or not a postgresql:// URL"
            " — skipping table initialisation"
        )
        return

    try:
        import asyncpg  # optional dependency; absent in local dev without Docker
    except ImportError:
        log.warning(
            "db_init: asyncpg is not installed — skipping table initialisation"
            " (pip install asyncpg to enable)"
        )
        return

    try:
        conn = await asyncpg.connect(db_url)
        try:
            await conn.execute(_DDL)
            log.info(
                "db_init: sessions and usage tables verified / created OK"
            )
        finally:
            await conn.close()
    except Exception as exc:
        log.warning(
            "db_init: PostgreSQL unavailable — skipping table initialisation: %s",
            exc,
        )
