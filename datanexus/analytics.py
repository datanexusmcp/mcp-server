# datanexus/analytics.py

import asyncio
import hashlib
import logging
import os
import time
from datetime import date
from typing import Optional

from payment.config import classify_call
from datanexus.core.request_context import api_key_var, client_ip_var

log = logging.getLogger(__name__)

# Lazy import — PostHog only loaded if key is set
_ph = None
_enabled = False


def _get_client():
    global _ph, _enabled
    if _ph is not None:
        return _ph
    key = os.environ.get("POSTHOG_API_KEY", "")
    host = os.environ.get(
        "POSTHOG_HOST", "https://us.i.posthog.com")
    if not key:
        _enabled = False
        return None
    try:
        from posthog import Posthog
        _ph = Posthog(
            project_api_key=key,
            host=host,
            disabled=False,
            # Batch and send async — never blocks
            sync_mode=False,
        )
        _enabled = True
        log.info("PostHog analytics: enabled")
        return _ph
    except Exception as e:
        log.warning(f"PostHog init failed: {e}")
        _enabled = False
        return None


def _anon_id() -> str:
    """
    Daily-rotating anonymous identifier.
    Cannot be linked to any individual.
    Resets every day — no cross-day tracking.
    """
    return hashlib.sha256(
        f"datanexus:{date.today().isoformat()}".encode()
    ).hexdigest()[:16]


def _fire(event: str, properties: dict) -> None:
    """
    Fire PostHog event in background thread.
    Never blocks. Never raises.
    Skipped entirely when DATANEXUS_SMOKE_RUN=1 (smoke/canary test traffic).
    """
    # Exclude smoke test calls from PostHog so organic metrics stay clean.
    # UsageRecorder still writes to PostgreSQL with is_smoke=True.
    if os.environ.get("DATANEXUS_SMOKE_RUN") == "1":
        return

    ph = _get_client()
    if not ph:
        return
    try:
        # Remove any PII that might have crept in
        safe_props = {
            k: v for k, v in properties.items()
            if k not in {
                "ip", "email", "name", "user_id",
                "query", "ein", "npi", "crd",
                "domain", "patent_number"
            }
        }
        ph.capture(
            distinct_id=_anon_id(),
            event=event,
            properties=safe_props,
        )
    except Exception as e:
        log.warning(f"PostHog capture failed: {e}")


async def track_tool_call(
    tool_id: str,
    tool_name: str,
    success: bool,
    latency_ms: int,
    cache_hit: bool,
    error_code: Optional[str] = None,
    ecosystem: Optional[str] = None,
    jurisdiction: Optional[str] = None,
) -> None:
    """
    Track every tool call. Call from tool handlers.
    Runs in background — never awaited by caller.
    """
    client_ip    = client_ip_var.get() or "unknown"
    api_key_hash = api_key_var.get()
    call_type    = classify_call(client_ip, api_key_hash)
    is_organic   = call_type in ("organic", "claude_ai")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _fire, "tool_called", {
        # Tool identity
        "tool_id":      tool_id,
        "tool_name":    tool_name,
        "tool_group":   tool_name.split("_")[0],

        # Outcome
        "success":      success,
        "cache_hit":    cache_hit,
        "latency_ms":   latency_ms,
        "error_code":   error_code or "none",

        # Non-PII context (safe to log)
        "ecosystem":    ecosystem or "none",
        "jurisdiction": jurisdiction or "none",

        # Call origin — use for PostHog filtering (is_organic=true cohort)
        "call_type":    call_type,
        "is_organic":   is_organic,

        # Platform
        "server":       "datanexusmcp.com",
        "date":         date.today().isoformat(),
    })


async def track_tool_error(
    tool_id: str,
    tool_name: str,
    error_code: str,
    error_type: str,
    latency_ms: int,
) -> None:
    """Track errors specifically for error analysis."""
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _fire, "tool_error", {
        "tool_id":    tool_id,
        "tool_name":  tool_name,
        "tool_group": tool_name.split("_")[0],
        "error_code": error_code,
        "error_type": error_type,
        "latency_ms": latency_ms,
        "date":       date.today().isoformat(),
    })


async def track_server_start(tool_count: int) -> None:
    """Track server startup — detects deploy cycles."""
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _fire, "server_started", {
        "tool_count": tool_count,
        "date":       date.today().isoformat(),
    })


def shutdown() -> None:
    """Flush PostHog queue on server shutdown."""
    if _ph:
        try:
            _ph.shutdown()
        except Exception:
            pass
