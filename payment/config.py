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

# Smithery scanner / proxy IPs.
# Expanded to cover all Cloudflare IPv4 ranges (from cloudflare.com/ips-v4)
# except 172.64.0.0/13 which is already used for GLAMA_CIDRS.
# Smithery uses Cloudflare Workers infrastructure for its scanner.
SMITHERY_CIDRS: List[str] = [
    "162.158.0.0/15",   # primary Cloudflare range (original)
    "104.16.0.0/13",
    "104.24.0.0/14",
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "131.0.72.0/22",
]

# Special API keys — loaded from env vars so they can be rotated without redeploy.
# Defaults are safe sentinel values that classify correctly even without env config.
SMOKE_API_KEY: str = os.environ.get("DATANEXUS_SMOKE_KEY", "dn-smoke-internal")
OWNER_API_KEY: str = os.environ.get("DATANEXUS_OWNER_KEY", "dn-owner-internal")
GLAMA_API_KEY: str = os.environ.get("DATANEXUS_GLAMA_KEY", "dn-glama-internal")

# Sprint 8B: all reserved keys — checked before DB/Redis in _ApiKeyMiddleware.
RESERVED_KEYS: set = {SMOKE_API_KEY, OWNER_API_KEY, GLAMA_API_KEY}

# Anonymous weekly backstop — binding limit is 50/day enforced by _IpCounterMiddleware.
# Anonymous (no valid registered API key) — IP-bucketed.
WEEK_LIMIT: int = 1400          # 200/day × 7 — power users unblocked (pipeline_mcp: 342/week)
NUDGE_AT: int = 1350
HARD_LIMIT: int = 1401          # serve call 1400, hard block at 1401

# Registered (valid API key, tier='free') — key-bucketed.
# No hard ceiling: per-day nudge at 200/day (no hard block) is in _IpCounterMiddleware.
# Weekly ceiling must exceed per-day nudge threshold to avoid false-blocking registered users.
WEEK_LIMIT_REGISTERED: int = 10000
NUDGE_AT_REGISTERED: int = 9900
HARD_LIMIT_REGISTERED: int = 10001


def _ip_in_cidrs(ip: str, cidrs: List[str]) -> bool:
    """Return True if ip falls within any of the given CIDR networks."""
    try:
        addr = _ipaddress.ip_address(ip)
        return any(addr in _ipaddress.ip_network(c, strict=False) for c in cidrs)
    except ValueError:
        return False


def is_glama_ip(ip: str) -> bool:
    return _ip_in_cidrs(ip, GLAMA_CIDRS)


def is_anthropic_ip(ip: str) -> bool:
    return _ip_in_cidrs(ip, ANTHROPIC_CIDRS)


def is_smithery_ip(ip: str) -> bool:
    return _ip_in_cidrs(ip, SMITHERY_CIDRS)


def classify_call(
    client_ip: str,
    api_key: Optional[str],
    key_is_valid: bool = False,
) -> str:
    """
    Classify a tool call by its origin.

    api_key: raw key string (not hash). Reserved keys are matched by value.
    key_is_valid: pre-computed by _ApiKeyMiddleware — do NOT re-validate here.

    Returns one of: smoke | owner | glama | registered | smithery | claude_ai | organic | unknown

    Precedence (highest → lowest):
      1. Reserved key match (smoke/owner/glama)
      2. Valid registered key
      3. IP in GLAMA_CIDRS
      4. IP in SMITHERY_CIDRS
      5. IP in ANTHROPIC_CIDRS
      6. Known non-empty IP → organic
      7. Unknown/missing IP → unknown
    """
    if api_key == SMOKE_API_KEY:    return "smoke"
    if api_key == OWNER_API_KEY:    return "owner"
    if api_key == GLAMA_API_KEY:    return "glama"
    if api_key and key_is_valid:    return "registered"
    if is_glama_ip(client_ip):      return "glama"
    if is_smithery_ip(client_ip):   return "smithery"
    if is_anthropic_ip(client_ip):  return "claude_ai"
    if client_ip not in (None, "", "unknown"): return "organic"
    return "unknown"
