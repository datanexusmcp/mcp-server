"""
payment/webhook.py — MCPize webhook handler.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10.3 / Phase 5 Step 4

POST /webhooks/mcpize
  - Verifies MCPize HMAC-SHA256 signature on EVERY request.
  - Wrong or missing signature → 401, zero Redis writes.
  - Correct signature → process event, return 200 {"status": "ok"}.

Supported events:
  payment.confirmed       → SET entitlement key (TTL from payload, default 366d)
  subscription.renewed    → EXPIRE entitlement key (extend TTL)
  subscription.lapsed     → DEL entitlement key + SET grace key (TTL = GRACE_TTL)
  subscription.cancelled  → DEL both entitlement key and grace key

Signature format (MCPize standard):
  Header: X-MCPize-Signature: sha256=<hex_hmac_sha256>
  Body:   raw request bytes
  Secret: MCPIZE_WEBHOOK_SECRET env var

If MCPIZE_WEBHOOK_SECRET is unset: signature check is BYPASSED (dev/test only).
In production: MCPIZE_WEBHOOK_SECRET must always be set.

NEVER modify signature verification logic without a human PR.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Optional

import redis as redis_lib
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

import payment.config as _cfg

log = logging.getLogger("payment.webhook")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

app = FastAPI(title="DataNexus MCPize Webhook", version="1.0.0")

# Injectable Redis client for tests
_redis_client: Optional[redis_lib.Redis] = None


def _set_redis_client(client: Optional[redis_lib.Redis]) -> None:
    global _redis_client
    _redis_client = client


def _get_redis() -> Optional[redis_lib.Redis]:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:
        log.warning("payment.webhook: Redis unavailable — %s", exc)
        return None


# ── Signature verification ─────────────────────────────────────────────────────

def _verify_signature(body: bytes, header_value: str, secret: str) -> bool:
    """
    Verify MCPize HMAC-SHA256 webhook signature.

    Expected header format: sha256=<64 hex chars>
    If secret is empty (dev mode): always returns True.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    if not secret:
        # Dev mode — skip verification (ONLY when secret is unconfigured)
        log.warning("payment.webhook: MCPIZE_WEBHOOK_SECRET not set — signature check SKIPPED")
        return True

    if not header_value or not header_value.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, header_value)


# ── Event handlers ─────────────────────────────────────────────────────────────

def _handle_payment_confirmed(r: redis_lib.Redis, data: dict) -> None:
    """
    payment.confirmed — write entitlement key to Redis.
    TTL = payload.ttl_days (default 366) × 86400 seconds.
    """
    tool_id   = data.get("tool_id", "")
    caller_id = data.get("caller_id", "")
    if not tool_id or not caller_id:
        log.warning("payment.webhook: payment.confirmed missing tool_id or caller_id")
        return
    ttl = int(data.get("ttl_days", 366)) * 86_400
    r.setex(_cfg.key_entitlement(tool_id, caller_id), ttl, "1")
    log.info(
        "payment.webhook: entitlement granted tool=%s caller=%s ttl_days=%s",
        tool_id, caller_id, data.get("ttl_days", 366),
    )


def _handle_subscription_renewed(r: redis_lib.Redis, data: dict) -> None:
    """
    subscription.renewed — extend entitlement TTL.
    If key no longer exists, re-create it.
    """
    tool_id   = data.get("tool_id", "")
    caller_id = data.get("caller_id", "")
    if not tool_id or not caller_id:
        return
    ttl = int(data.get("ttl_days", 366)) * 86_400
    ent_key = _cfg.key_entitlement(tool_id, caller_id)
    # SETEX re-creates the key with new TTL whether or not it existed
    r.setex(ent_key, ttl, "1")
    # Remove any lingering grace key
    r.delete(_cfg.key_grace(tool_id, caller_id))
    log.info(
        "payment.webhook: entitlement renewed tool=%s caller=%s ttl_days=%s",
        tool_id, caller_id, data.get("ttl_days", 366),
    )


def _handle_subscription_lapsed(r: redis_lib.Redis, data: dict) -> None:
    """
    subscription.lapsed — remove entitlement, set grace window.
    Grace TTL = payload.grace_days (default 3) × 86400 seconds.
    """
    tool_id   = data.get("tool_id", "")
    caller_id = data.get("caller_id", "")
    if not tool_id or not caller_id:
        return
    r.delete(_cfg.key_entitlement(tool_id, caller_id))
    grace_secs = int(data.get("grace_days", 3)) * 86_400
    r.setex(_cfg.key_grace(tool_id, caller_id), grace_secs, "1")
    log.info(
        "payment.webhook: subscription lapsed tool=%s caller=%s grace_days=%s",
        tool_id, caller_id, data.get("grace_days", 3),
    )


def _handle_subscription_cancelled(r: redis_lib.Redis, data: dict) -> None:
    """
    subscription.cancelled — remove both entitlement and grace keys immediately.
    No grace period on cancellation.
    """
    tool_id   = data.get("tool_id", "")
    caller_id = data.get("caller_id", "")
    if not tool_id or not caller_id:
        return
    r.delete(_cfg.key_entitlement(tool_id, caller_id))
    r.delete(_cfg.key_grace(tool_id, caller_id))
    log.info(
        "payment.webhook: subscription cancelled tool=%s caller=%s",
        tool_id, caller_id,
    )


# ── Route ──────────────────────────────────────────────────────────────────────

@app.post("/webhooks/mcpize")
async def mcpize_webhook(
    request: Request,
    x_mcpize_signature: str = Header(default=""),
) -> JSONResponse:
    """
    MCPize payment webhook receiver.

    Verifies HMAC-SHA256 signature before ANY processing.
    Wrong signature → 401 (zero Redis writes guaranteed).
    """
    body = await request.body()

    # ── Signature verification (gate-keeper — all writes blocked on failure) ──
    secret = _cfg.MCPIZE_WEBHOOK_SECRET
    if not _verify_signature(body, x_mcpize_signature, secret):
        log.warning(
            "payment.webhook: invalid signature — request rejected "
            "sig_header=%r", x_mcpize_signature[:20] if x_mcpize_signature else "missing",
        )
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    # ── Parse body ────────────────────────────────────────────────────────────
    try:
        data  = json.loads(body)
        event = data.get("event", "")
    except (json.JSONDecodeError, ValueError) as exc:
        log.warning("payment.webhook: malformed JSON body — %s", exc)
        raise HTTPException(status_code=400, detail="Malformed JSON body.")

    log.info("payment.webhook: received event=%s", event)

    # ── Dispatch event ────────────────────────────────────────────────────────
    r = _get_redis()
    if r is None:
        log.warning("payment.webhook: Redis unavailable — event=%s not processed", event)
        return JSONResponse({"status": "queued", "note": "Redis unavailable — event not persisted"})

    try:
        if event == "payment.confirmed":
            _handle_payment_confirmed(r, data)
        elif event == "subscription.renewed":
            _handle_subscription_renewed(r, data)
        elif event == "subscription.lapsed":
            _handle_subscription_lapsed(r, data)
        elif event == "subscription.cancelled":
            _handle_subscription_cancelled(r, data)
        else:
            log.info("payment.webhook: unrecognised event=%s — ignored", event)

    except Exception as exc:
        log.exception("payment.webhook: error processing event=%s — %s", event, exc)
        return JSONResponse({"status": "error", "detail": "Processing error."}, status_code=500)

    return JSONResponse({"status": "ok", "event": event})
