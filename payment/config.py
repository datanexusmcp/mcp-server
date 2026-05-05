"""
payment/config.py — Single source of truth for all payment configuration.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10.1 / Phase 5 Step 2

Rules (non-negotiable):
  - MCPIZE_ACTIVE defaults False — never enable without explicit env var.
  - MCPIZE_URLS all empty by default — passthrough until URLs are set.
  - ALL Redis entitlement key strings are constructed here.
  - Imported everywhere that needs payment state.

NEVER hardcode payment URLs in tool files — import from here.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

# ── Feature flag ───────────────────────────────────────────────────────────────

# Master payment enforcement switch.
# False  → all tools passthrough, free window active.
# True   → verify_entitlement enforces subscription checks.
# NEVER set to True without also configuring MCPIZE_URLS and MCPIZE_WEBHOOK_SECRET.
MCPIZE_ACTIVE: bool = (
    os.environ.get("MCPIZE_ACTIVE", "false").strip().lower() == "true"
)

# ── MCPize URLs ────────────────────────────────────────────────────────────────

# Subscription / upgrade URL per tool ID.
# Empty string = payment not yet configured for this tool → passthrough.
# Populated when MCPize listing goes live (Phase 5 Gate 3).
MCPIZE_URLS: Dict[str, str] = {
    "T04": os.environ.get("MCPIZE_URL_T04", ""),
    "T10": os.environ.get("MCPIZE_URL_T10", ""),
    # T22 and beyond: add entries here only when the tool is built and
    # registered in main.py.  Pre-populating causes T22 to bleed into
    # the dashboard usage panel and conversion stats before it is live.
}

# ── Webhook secret ─────────────────────────────────────────────────────────────

# HMAC-SHA256 secret shared with MCPize.
# Set as MCPIZE_WEBHOOK_SECRET env var on the Hetzner server.
# If empty: signature verification is skipped in dev/test (never skip in prod).
MCPIZE_WEBHOOK_SECRET: str = os.environ.get("MCPIZE_WEBHOOK_SECRET", "")

# ── TTLs (seconds) ─────────────────────────────────────────────────────────────

ENTITLEMENT_TTL: int = 366 * 86_400   # ~1 year (annual subscription)
GRACE_TTL:       int = 3   * 86_400   # 3-day grace window after lapse
COUNTER_TTL:     int = 35  * 86_400   # telemetry counter retention

FEED_MAX_ENTRIES: int = 50   # datanexus:feed list cap

# ── Section 13 — Haiku daily cap ───────────────────────────────────────────────
# Hard ceiling on Haiku API calls per day across all 4 triggers.
# NEVER set > 100 without a human PR and spec update (CLAUDE.md S13-3).
HAIKU_MAX_CALLS_PER_DAY: int = 100

# ── Redis key constructors ─────────────────────────────────────────────────────
# ALL entitlement/grace Redis key strings are built here and ONLY here.

def key_entitlement(tool_id: str, caller_id: str) -> str:
    """Presence key granting access. datanexus:entitlement:{tool_id}:{caller_id}"""
    return f"datanexus:entitlement:{tool_id}:{caller_id}"


def key_grace(tool_id: str, caller_id: str) -> str:
    """Grace-window key (TTL = GRACE_TTL). datanexus:grace:{tool_id}:{caller_id}"""
    return f"datanexus:grace:{tool_id}:{caller_id}"


def key_calls(tool_id: str, date: str) -> str:
    """Daily call counter. datanexus:calls:{tool_id}:{date}"""
    return f"datanexus:calls:{tool_id}:{date}"


def key_sessions(tool_id: str, date: str) -> str:
    """Daily unique-caller set. datanexus:sessions:{tool_id}:{date}"""
    return f"datanexus:sessions:{tool_id}:{date}"


def key_feed() -> str:
    """Activity feed list (capped at FEED_MAX_ENTRIES). datanexus:feed"""
    return "datanexus:feed"
