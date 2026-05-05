"""
PostgreSQL session persistence for free-tier grandfathering.

Only activates when DATANEXUS_DB_URL is a postgresql:// URL.
Falls back gracefully (no-op / fail-open) when the DB is unavailable,
so local dev without Docker works without any configuration.

Table schema:
    CREATE TABLE IF NOT EXISTS dn_sessions (
        session_id  TEXT        PRIMARY KEY,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("datanexus.db")

_pool = None          # asyncpg.Pool once connected
_init_attempted = False


async def _get_pool():
    """
    Lazily create the asyncpg connection pool.

    Returns None (silently) when:
      - DATANEXUS_DB_URL is empty or not a postgresql:// URL
      - The database server is unreachable
      - asyncpg is not installed
    """
    global _pool, _init_attempted
    if _init_attempted:
        return _pool

    _init_attempted = True

    from datanexus.config import DB_URL
    if not DB_URL or not DB_URL.startswith(("postgresql://", "postgres://")):
        logger.debug("Session DB disabled — DATANEXUS_DB_URL is not a postgresql:// URL")
        return None

    try:
        import asyncpg  # optional dep; ImportError is handled below
        _pool = await asyncpg.create_pool(
            DB_URL,
            min_size=1,
            max_size=5,
            command_timeout=5,
        )
        async with _pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dn_sessions (
                    session_id  TEXT        PRIMARY KEY,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """)
        logger.info("PostgreSQL connected — dn_sessions table ready")
    except ImportError:
        logger.warning(
            "asyncpg not installed — session persistence disabled "
            "(pip install asyncpg to enable)"
        )
        _pool = None
    except Exception as exc:
        logger.warning("PostgreSQL unavailable — session persistence disabled: %s", exc)
        _pool = None

    return _pool


async def record_session(session_id: str) -> None:
    """
    Insert the session_id with created_at = now() (UTC) if it does not
    already exist.  Idempotent: subsequent calls for the same session_id
    are silently ignored (ON CONFLICT DO NOTHING).
    """
    pool = await _get_pool()
    if pool is None:
        return
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO dn_sessions (session_id) VALUES ($1)"
                " ON CONFLICT DO NOTHING",
                session_id,
            )
    except Exception as exc:
        logger.warning("record_session failed session=%s: %s", session_id, exc)


async def get_session_created_at(session_id: str) -> Optional[datetime]:
    """
    Return the UTC-aware created_at for a session_id, or None when:
      - session not found (was never persisted)
      - DB is unavailable
    """
    pool = await _get_pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT created_at FROM dn_sessions WHERE session_id = $1",
                session_id,
            )
        if row is None:
            return None
        ts = row["created_at"]
        # asyncpg returns timezone-aware datetimes when the column is TIMESTAMPTZ
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except Exception as exc:
        logger.warning("get_session_created_at failed session=%s: %s", session_id, exc)
        return None
