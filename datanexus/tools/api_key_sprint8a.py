"""
datanexus/tools/api_key_sprint8a.py — Sprint 8A

Three API key management tools + _UsageMiddleware.

Tools (sub-server: datanexus-apikeys):
  generate_api_key  — issue a new dnx_... key, store email in DB
  rotate_api_key    — revoke current key, issue replacement
  revoke_api_key    — mark key revoked, invalidate Redis cache

_UsageMiddleware (FastMCP Middleware subclass):
  Intercepts every tool/call, increments per-user monthly Redis counter,
  injects usage fields into the response.  Fails open on Redis unavailability.
"""

import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from pydantic import Field

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

from datanexus.cache import get_redis
from datanexus.core.request_context import api_key_var, call_type_var, client_ip_var, is_organic_var
from payment.config import HARD_LIMIT, NUDGE_AT, WEEK_LIMIT

log = logging.getLogger("datanexus.api_key_sprint8a")

# ── Constants ─────────────────────────────────────────────────────────────────

_COUNTER_TTL      = 864000            # 10 days — weekly key cleanup (TTL refresh on every call)
_KEY_CACHE_TTL    = 300               # 5 minutes
_KEYGEN_DAY_LIMIT = 3
_KEYGEN_TTL       = 25 * 3600        # 25 hours
_KEYED_LIMIT      = 500              # legacy Sprint 8A constant — kept for tool response compat

# Exempt call types — no rate limiting, no organic tracking
_EXEMPT_CALL_TYPES = frozenset({"smoke", "owner", "glama", "smithery", "claude_ai"})

# ── Sub-server ────────────────────────────────────────────────────────────────

api_key_server = FastMCP("datanexus-apikeys")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def build_rate_limit_key(
    user_type: str,
    identifier: str,
    dt: Optional[datetime] = None,
) -> str:
    """
    Build the weekly Redis rate-limit key.
    user_type: "anon" or "key"
    identifier: ip_hash[:16] for anon, key_hash[:16] for registered
    dt: override datetime for testing; uses utcnow() when None
    """
    if dt is None:
        dt = datetime.utcnow()
    week_str = dt.strftime("%G-W%V")   # ISO 8601 Monday-start, e.g. "2026-W22"
    return f"dn:usage:{user_type}:{identifier}:{week_str}"


async def _get_pool():
    """Return asyncpg pool, or None when DB is unconfigured. Never raises."""
    db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()
    if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
        return None
    try:
        import asyncpg
        return await asyncpg.create_pool(db_url, min_size=1, max_size=3, command_timeout=5)
    except Exception as exc:
        log.warning("api_key_sprint8a: DB pool init failed: %s", exc)
        return None


# ── Tools ─────────────────────────────────────────────────────────────────────

@api_key_server.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def generate_api_key(
    email: Annotated[str, Field(description="Email address to associate with the new API key. Used for delivery and repeat-signup lookup. Required.")],
) -> dict:
    """
    Generate a DataNexus API key for the given email address. All users get
    10 free lookups per week — registered users will be notified first when
    paid tiers with higher limits launch. Store the returned key — it is shown
    only once. Pass it as the X-Api-Key header on future requests.
    Rate limit: 3 keys per IP per 24 hours.
    """
    if not email or len(email) > 254 or "@" not in email:
        return {"status": "error", "error_code": "invalid_email", "message": "Valid email address required."}

    client_ip = client_ip_var.get()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    limit_key = f"dn:keygen_limit:{_ip_hash(client_ip)}:{today}"

    r = await get_redis()
    if r:
        try:
            count = await r.incr(limit_key)
            if count == 1:
                await r.expire(limit_key, _KEYGEN_TTL)
            if count > _KEYGEN_DAY_LIMIT:
                return {
                    "status": "error",
                    "error_code": "rate_limit_exceeded",
                    "message": "Maximum 3 API keys may be generated per IP per 24 hours.",
                }
        except Exception as exc:
            log.warning("generate_api_key: Redis rate-limit check failed: %s", exc)

    raw_key = "dnx_" + secrets.token_hex(32)
    key_hash = _hash(raw_key)

    pool = await _get_pool()
    if pool:
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO api_keys (key_hash, email, tier, created_at)
                    VALUES ($1, $2, 'free', NOW())
                    ON CONFLICT (key_hash) DO NOTHING
                    """,
                    key_hash,
                    email,
                )
            await pool.close()
        except Exception as exc:
            log.warning("generate_api_key: DB insert failed: %s", exc)
            return {"status": "error", "error_code": "internal_error", "message": "Key generation failed — please retry."}
    else:
        log.warning("generate_api_key: DB unavailable — key not persisted")
        return {"status": "error", "error_code": "internal_error", "message": "Key generation failed — please retry."}

    if r:
        try:
            cache_key = f"dn:apikey:{key_hash}"
            await r.set(cache_key, "free", ex=_KEY_CACHE_TTL)
        except Exception:
            pass

    log.info("generate_api_key: key issued email=[REDACTED] key=[REDACTED]")
    return {
        "status": "ok",
        "api_key": raw_key,
        "tier": "free",
        "weekly_limit": WEEK_LIMIT,
        "message": "Store this key — it will not be shown again. Pass it as the X-Api-Key header.",
    }


@api_key_server.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False})
async def rotate_api_key(
    current_key: Annotated[str, Field(description="Existing active API key (dnx_...) to revoke and replace. Required.")],
) -> dict:
    """
    ⚠️ DESTRUCTIVE — requires human confirmation before use in automated pipelines.
    Revoke the current API key and issue a replacement. Returns the new key once —
    store it immediately. Pass keys as the X-DataNexus-Key header.
    """
    if not current_key or not current_key.startswith("dnx_"):
        return {"status": "error", "error_code": "invalid_key", "message": "Invalid key format."}

    old_hash = _hash(current_key)

    pool = await _get_pool()
    if not pool:
        return {"status": "error", "error_code": "internal_error", "message": "Rotation failed — please retry."}

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT tier FROM api_keys WHERE key_hash=$1 AND revoked=FALSE", old_hash
            )
            if not row:
                await pool.close()
                return {"status": "error", "error_code": "key_not_found", "message": "Key not found or already revoked."}

            tier = row["tier"]
            new_raw = "dnx_" + secrets.token_hex(32)
            new_hash = _hash(new_raw)

            async with conn.transaction():
                await conn.execute(
                    "UPDATE api_keys SET revoked=TRUE, revoked_at=NOW() WHERE key_hash=$1", old_hash
                )
                await conn.execute(
                    "INSERT INTO api_keys (key_hash, email, tier, created_at) "
                    "SELECT $1, email, $2, NOW() FROM api_keys WHERE key_hash=$3",
                    new_hash, tier, old_hash,
                )
        await pool.close()
    except Exception as exc:
        log.warning("rotate_api_key: DB operation failed: %s", exc)
        return {"status": "error", "error_code": "internal_error", "message": "Rotation failed — please retry."}

    r = await get_redis()
    if r:
        try:
            await r.delete(f"dn:apikey:{old_hash}")
            await r.set(f"dn:apikey:{new_hash}", tier, ex=_KEY_CACHE_TTL)
        except Exception as exc:
            log.warning("rotate_api_key: Redis cache update failed: %s", exc)

    log.info("rotate_api_key: key rotated old=[REDACTED] new=[REDACTED]")
    return {
        "status": "ok",
        "api_key": new_raw,
        "tier": tier,
        "monthly_limit": _KEYED_LIMIT,
        "message": "Old key revoked. Store the new key — it will not be shown again.",
    }


@api_key_server.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False})
async def revoke_api_key(
    key: Annotated[str, Field(description="API key (dnx_...) to permanently revoke. Required.")],
) -> dict:
    """
    ⚠️ DESTRUCTIVE — requires human confirmation before use in automated pipelines.
    Permanently revoke a DataNexus API key. The key will stop working immediately.
    This action cannot be undone — generate a new key if access is needed again.
    """
    if not key or not key.startswith("dnx_"):
        return {"status": "error", "error_code": "invalid_key", "message": "Invalid key format."}

    key_hash = _hash(key)

    pool = await _get_pool()
    if pool:
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE api_keys SET revoked=TRUE, revoked_at=NOW() WHERE key_hash=$1", key_hash
                )
            await pool.close()
        except Exception as exc:
            log.warning("revoke_api_key: DB update failed: %s", exc)
            return {"status": "error", "error_code": "internal_error", "message": "Revocation failed — please retry."}

    r = await get_redis()
    if r:
        try:
            await r.delete(f"dn:apikey:{key_hash}")
        except Exception as exc:
            log.warning("revoke_api_key: Redis DEL failed: %s", exc)

    log.info("revoke_api_key: key revoked key=[REDACTED]")
    return {"status": "revoked"}


# ── _UsageMiddleware ──────────────────────────────────────────────────────────

class _UsageMiddleware(Middleware):
    """
    FastMCP middleware — runs after every tool/call.

    Sprint 8B: weekly ISO bucket, exempt call types, nudge at 8-9, hard limit at 11 (HTTP 200).
    Fails open on Redis unavailability — tool response is returned as-is.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next,
    ) -> ToolResult:
        result = await call_next(context)

        api_key_hash = api_key_var.get()
        client_ip    = client_ip_var.get()
        call_type    = call_type_var.get()
        is_organic   = is_organic_var.get()

        # Exempt call types — no rate limiting, no usage increment
        if call_type in _EXEMPT_CALL_TYPES:
            return result

        # Build weekly Redis key
        if api_key_hash:
            bucket = build_rate_limit_key("key", api_key_hash[:16])
        else:
            bucket = build_rate_limit_key("anon", _ip_hash(client_ip))

        count = 0
        try:
            r = await get_redis()
            if r:
                pipe = r.pipeline()
                pipe.incr(bucket)
                pipe.expire(bucket, _COUNTER_TTL)  # always refresh TTL — pipeline is atomic
                results = await pipe.execute()
                count = results[0]
        except Exception as exc:
            log.warning("_UsageMiddleware: Redis unavailable, rate limiting skipped: %s", exc)
            return result

        # Hard limit — call 11+ returns HTTP 200 with limit_reached dict (not 429)
        # MCP clients show vague "tool failed" on 429; HTTP 200 renders inline in Claude.
        if count >= HARD_LIMIT:
            limit_payload = {
                "status": "limit_reached",
                "message": "You've used your 10 free lookups this week. Register to be notified when higher-limit paid tiers launch.",
                "signup_url": "https://datanexusmcp.com/signup",
                "calls_used": min(count - 1, WEEK_LIMIT),
                "calls_limit": WEEK_LIMIT,
                "reset_in": "7 days rolling",
            }
            return ToolResult(
                content=str(limit_payload),
                structured_content=limit_payload,
            )

        # Notice — calls 1-7: generic free-tier signpost; calls 8-9: remaining count
        rate_info: dict = {}
        if count >= NUDGE_AT:
            remaining = WEEK_LIMIT - count
            rate_info["notice"] = (
                f"{remaining} free lookup{'s' if remaining != 1 else ''} remaining"
                f" · datanexusmcp.com/signup"
            )
        else:
            rate_info["notice"] = "Free tier · datanexusmcp.com/signup"

        if rate_info:
            if result.structured_content:
                result.structured_content.update(rate_info)
            else:
                result = result.model_copy(update={"structured_content": rate_info})

        return result
