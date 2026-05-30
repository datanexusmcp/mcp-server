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
from typing import Optional

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.types import CallToolResult as ToolResult

from datanexus.cache import get_redis
from datanexus.core.request_context import api_key_var, client_ip_var

log = logging.getLogger("datanexus.api_key_sprint8a")

# ── Constants ─────────────────────────────────────────────────────────────────

_ANON_LIMIT       = 100
_KEYED_LIMIT      = 500
_ANON_HINT_AT     = 80
_KEYED_HINT_AT    = 400
_COUNTER_TTL      = 35 * 24 * 3600   # 35 days in seconds
_KEY_CACHE_TTL    = 300               # 5 minutes
_KEYGEN_DAY_LIMIT = 3
_KEYGEN_TTL       = 25 * 3600        # 25 hours

# ── Sub-server ────────────────────────────────────────────────────────────────

api_key_server = FastMCP("datanexus-apikeys")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _next_month_iso() -> str:
    now = datetime.now(timezone.utc)
    first_next = (now.replace(day=1) + timedelta(days=32)).replace(day=1)
    return first_next.strftime("%Y-%m-%d")


def _bucket_key(api_key_hash: Optional[str], client_ip: str) -> str:
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    if api_key_hash:
        return f"dn:usage:key:{api_key_hash}:{month}"
    return f"dn:usage:anon:{_ip_hash(client_ip)}:{month}"


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

@api_key_server.tool()
async def generate_api_key(email: str) -> dict:
    """
    Generate a DataNexus API key for the given email address. Registered users
    receive 500 calls/month instead of 100. Store the returned key — it is shown
    only once. Pass it as the X-DataNexus-Key header on future requests.
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
        "monthly_limit": _KEYED_LIMIT,
        "message": "Store this key — it will not be shown again. Pass it as the X-DataNexus-Key header.",
    }


@api_key_server.tool()
async def rotate_api_key(current_key: str) -> dict:
    """
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


@api_key_server.tool()
async def revoke_api_key(key: str) -> dict:
    """
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

    1. Reads api_key_var / client_ip_var set by ASGI middlewares.
    2. Increments monthly Redis counter (atomic INCR + TTL on first write).
    3. Injects usage fields into every ToolResult.
    4. If PAYMENT_ENABLED=true and count >= limit: returns 429-style ToolResult.
    5. Fails open on Redis unavailability — tool response is returned as-is.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next,
    ) -> ToolResult:
        result = await call_next(context)

        api_key_hash = api_key_var.get()
        client_ip    = client_ip_var.get()

        tier         = "registered" if api_key_hash else "anonymous"
        tier_limit   = _KEYED_LIMIT if tier == "registered" else _ANON_LIMIT
        hint_at      = _KEYED_HINT_AT if tier == "registered" else _ANON_HINT_AT
        bucket       = _bucket_key(api_key_hash, client_ip)

        count = 0
        try:
            r = await get_redis()
            if r:
                pipe = r.pipeline()
                pipe.incr(bucket)
                pipe.ttl(bucket)
                results = await pipe.execute()
                count = results[0]
                if count == 1:
                    await r.expire(bucket, _COUNTER_TTL)
        except Exception as exc:
            log.warning("_UsageMiddleware: Redis unavailable, usage counting skipped: %s", exc)
            return result

        # Per-request read — Railway restarts on env var change, so this is always current
        payment_enabled = os.environ.get("PAYMENT_ENABLED", "false").lower() == "true"

        if payment_enabled and count >= tier_limit:
            from mcp.types import TextContent
            next_month = _next_month_iso()
            error_content = {
                "error": "rate_limit_exceeded",
                "message": f"You've used {count}/{tier_limit} calls this month.",
                "upgrade_url": "https://datanexusmcp.com/upgrade",
                "reset_date": next_month,
                "tier": tier,
            }
            return ToolResult(
                content=[TextContent(type="text", text=str(error_content))],
                structuredContent=error_content,
                isError=True,
            )

        usage_fields: dict = {
            "usage": {
                "calls_this_month": count,
                "limit": tier_limit,
                "tier": tier,
                "reset_date": _next_month_iso(),
            }
        }

        if count >= tier_limit:
            usage_fields["limit_warning"] = (
                f"You've reached your {tier_limit} call limit. "
                "Register/upgrade at datanexusmcp.com/upgrade"
            )
        elif count >= hint_at:
            if tier == "anonymous":
                usage_fields["upgrade_hint"] = (
                    f"You're at {count}/{tier_limit} anonymous calls this month. "
                    "Register a free key for 5x more calls: datanexusmcp.com/key"
                )
            else:
                usage_fields["upgrade_hint"] = (
                    f"You're at {count}/{tier_limit} calls this month. "
                    "Upgrade for unlimited calls: datanexusmcp.com/upgrade"
                )

        if result.structuredContent:
            result.structuredContent.update(usage_fields)
        else:
            result = result.model_copy(update={"structuredContent": usage_fields})

        return result
