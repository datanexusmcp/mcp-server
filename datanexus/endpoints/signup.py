"""
datanexus/endpoints/signup.py — POST /signup handler.

Sprint 8B: email capture → key generation → SendGrid delivery.
Mounted as a Starlette route on FastMCP's underlying ASGI app in main.py.

Flow:
  1. IP-based rate limit (3/IP/24h)
  2. Email validation (email-validator>=2.0, max 255 chars)
  3. Atomic upsert — prevents race condition on concurrent same-email signups
  4. SendGrid delivery
  5. Return {message, email_sent}. Never return raw key in HTTP response.
"""

import hashlib
import httpx
import logging
import os
import secrets
from datetime import datetime, timezone

from starlette.requests import Request
from starlette.responses import JSONResponse

from datanexus.cache import get_redis
from datanexus.core.request_context import client_ip_var

log = logging.getLogger("datanexus.signup")

_SIGNUP_DAY_LIMIT = 3
_SIGNUP_RATE_TTL  = 86400 + 3600   # 25 hours
_KEY_CACHE_TTL    = 300             # 5 minutes


def _ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


async def _get_pool():
    db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()
    if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
        return None
    try:
        import asyncpg
        return await asyncpg.create_pool(db_url, min_size=1, max_size=3, command_timeout=5)
    except Exception as exc:
        log.warning("signup: DB pool init failed: %s", exc)
        return None


async def signup_handler(request: Request) -> JSONResponse:
    client_ip = client_ip_var.get()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rate_key = f"dn:signup:{_ip_hash(client_ip)}:{today}"

    # ── 1. Signup rate limit (3/IP/24h) ──────────────────────────────────────
    r = await get_redis()
    if r:
        try:
            pipe = r.pipeline()
            pipe.incr(rate_key)
            pipe.expire(rate_key, _SIGNUP_RATE_TTL)
            count, _ = await pipe.execute()
            if count > _SIGNUP_DAY_LIMIT:
                return JSONResponse(
                    {"error": "rate_limit_exceeded", "message": "Maximum 3 signups per IP per 24 hours."},
                    status_code=429,
                )
        except Exception as exc:
            log.warning("signup: Redis rate-limit check failed (fail-open): %s", exc)

    # ── 2. Parse and validate email ───────────────────────────────────────────
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    raw_email = (body.get("email") or "").strip()
    if not raw_email or len(raw_email) > 255:
        return JSONResponse({"error": "invalid_email"}, status_code=400)

    try:
        from email_validator import validate_email, EmailNotValidError
        validated = validate_email(raw_email, check_deliverability=False)
        email = validated.normalized
    except Exception:
        return JSONResponse({"error": "invalid_email"}, status_code=400)

    # ── 3. Check for existing key (idempotent signup) ────────────────────────
    pool = await _get_pool()
    if pool is None:
        return JSONResponse({"error": "service_unavailable"}, status_code=503)

    is_re_signup = False
    old_key_hash = None
    raw_key = "dn-" + secrets.token_hex(16)   # "dn-{32 hex chars}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    try:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT key_hash FROM api_keys WHERE email=$1", email
            )
            is_re_signup = existing is not None
            if is_re_signup:
                old_key_hash = existing["key_hash"]

            await conn.execute(
                """
                INSERT INTO api_keys (email, key_hash, created_at, tier, is_active)
                VALUES ($1, $2, NOW(), 'free', TRUE)
                ON CONFLICT (email) DO UPDATE
                  SET key_hash   = EXCLUDED.key_hash,
                      created_at = NOW(),
                      is_active  = TRUE
                """,
                email,
                key_hash,
            )
        await pool.close()
    except Exception as exc:
        log.warning("signup: DB operation failed: %s", exc)
        try:
            await pool.close()
        except Exception:
            pass
        return JSONResponse({"error": "service_unavailable"}, status_code=503)

    # Cache new key hash so _ApiKeyMiddleware picks it up within the TTL window
    # On rotation: also delete old hash from cache so old key stops working immediately
    if r:
        try:
            if is_re_signup and old_key_hash:
                await r.delete(f"dn:apikey:{old_key_hash}")
            await r.set(f"dn:apikey:{key_hash}", "free", ex=_KEY_CACHE_TTL)
        except Exception:
            pass

    # ── 4. Send email via SendGrid ────────────────────────────────────────────
    email_sent = False
    try:
        sg_key = os.environ.get("SENDGRID_API_KEY", "")
        if not sg_key:
            raise RuntimeError("SENDGRID_API_KEY not configured")

        import httpx
        if is_re_signup:
            body_text = (
                f"Your new DataNexus API key: {raw_key}\n\n"
                "Your previous key has been replaced — update any existing integrations.\n\n"
                "To use in Claude:\n"
                "Settings → Connectors → DataNexus → paste key → Save\n\n"
                "Questions? signup@datanexusmcp.com"
            )
        else:
            body_text = (
                f"Your DataNexus API key: {raw_key}\n\n"
                "To use in Claude:\n"
                "Settings → Connectors → DataNexus → paste key → Save\n\n"
                "Questions? signup@datanexusmcp.com"
            )

        payload = {
            "personalizations": [{"to": [{"email": email}]}],
            "from": {"email": "signup@datanexusmcp.com", "name": "DataNexus"},
            "subject": "Your DataNexus API Key",
            "content": [{"type": "text/plain", "value": body_text}],
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.sendgrid.com/v3/mail/send",
                json=payload,
                headers={"Authorization": f"Bearer {sg_key}"},
            )
            resp.raise_for_status()
        email_sent = True

    except Exception as exc:
        log.warning("signup: SendGrid delivery failed (key persisted): %s", exc)

    log.info("signup: email=[REDACTED] re_signup=%s email_sent=%s", is_re_signup, email_sent)

    if email_sent:
        msg = "New key sent — check your inbox. Your previous key has been replaced." if is_re_signup else "Check your inbox"
        return JSONResponse({"message": msg, "email_sent": True, "re_signup": is_re_signup})
    else:
        return JSONResponse({
            "message": "Key saved — email delivery failed. Contact signup@datanexusmcp.com",
            "email_sent": False,
            "re_signup": is_re_signup,
        })
