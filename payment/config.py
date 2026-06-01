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

import hashlib as _hashlib
import ipaddress as _ipaddress
import os
from typing import Dict, List, Optional

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


# ── Call classification ────────────────────────────────────────────────────────
# Single source of truth for all call-type logic.
# NEVER hardcode these CIDRs or keys in tool files — import from here.

# Full Cloudflare CIDR range used by Glama's quality tester bots.
GLAMA_CIDRS: List[str] = ["172.64.0.0/13"]

# Claude.ai connector IPs (Anthropic infrastructure — real users, proxied).
ANTHROPIC_CIDRS: List[str] = ["160.79.104.0/21"]

# Special API keys — loaded from env vars so they can be rotated without redeploy.
# Defaults are safe sentinel values that classify correctly even without env config.
SMOKE_API_KEY: str = os.environ.get("DATANEXUS_SMOKE_KEY", "dn-smoke-internal")
OWNER_API_KEY: str = os.environ.get("DATANEXUS_OWNER_KEY", "dn-owner-internal")

# Pre-computed hashes — api_key_var holds SHA-256(raw_key), not the raw key itself.
_SMOKE_KEY_HASH: str = _hashlib.sha256(SMOKE_API_KEY.encode()).hexdigest()
_OWNER_KEY_HASH: str = _hashlib.sha256(OWNER_API_KEY.encode()).hexdigest()


def _ip_in_cidrs(ip: str, cidrs: List[str]) -> bool:
    """Return True if ip falls within any of the given CIDR networks."""
    try:
        addr = _ipaddress.ip_address(ip)
        return any(addr in _ipaddress.ip_network(c, strict=False) for c in cidrs)
    except ValueError:
        return False


def classify_call(client_ip: str, api_key_hash: Optional[str]) -> str:
    """
    Classify a tool call by its origin.

    Returns one of: organic | glama | smoke | owner | claude_ai | unknown

    Precedence (highest → lowest):
      1. SMOKE_API_KEY hash match → smoke
      2. OWNER_API_KEY hash match → owner
      3. IP in GLAMA_CIDRS        → glama
      4. IP in ANTHROPIC_CIDRS    → claude_ai  (organic, proxied)
      5. Known non-empty IP       → organic
      6. Unknown/missing IP       → unknown
    """
    if api_key_hash and api_key_hash == _SMOKE_KEY_HASH:
        return "smoke"
    if api_key_hash and api_key_hash == _OWNER_KEY_HASH:
        return "owner"
    if _ip_in_cidrs(client_ip, GLAMA_CIDRS):
        return "glama"
    if _ip_in_cidrs(client_ip, ANTHROPIC_CIDRS):
        return "claude_ai"
    if client_ip and client_ip not in ("unknown", ""):
        return "organic"
    return "unknown"
