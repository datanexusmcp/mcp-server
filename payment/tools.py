"""
payment/tools.py — report_mcpize_link() MCP tool.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10.4 / Phase 5 Step 5

Three scenarios (evaluated in order):
  1. MCPIZE_ACTIVE=False              → status='free', message='…free window…'
  2. MCPIZE_ACTIVE=True, URL empty    → status='not_configured', message='…not yet listed…'
  3. MCPIZE_ACTIVE=True, URL present  → status='subscription_required', upgrade_url=URL

NEVER modify without a human PR.
"""

from __future__ import annotations

import payment.config as _cfg


def report_mcpize_link(tool_id: str) -> dict:
    """Returns the MCPize subscription status and payment tier for the current DataNexus API key. Read-only. No side effects. Idempotent. Output fields: status (str) — "free", "subscription_required", or "not_configured"; message (str) — human-readable explanation; tool_id (str) — echoes the input; upgrade_url (str) — only present when status="subscription_required". Unknown or test tool_id values always return a structured response, never raise an exception. Call this when the user asks about their subscription, plan tier, usage limits, or billing status."""
    # Scenario 1 — free window
    if not _cfg.MCPIZE_ACTIVE:
        return {
            "status":  "free",
            "message": "This tool is currently in its free window. No subscription required.",
            "tool_id": tool_id,
        }

    url = _cfg.MCPIZE_URLS.get(tool_id, "")

    # Scenario 2 — payment active but tool not yet listed on MCPize
    if not url:
        return {
            "status":  "not_configured",
            "message": "This tool is not yet listed on MCPize. No subscription required at this time.",
            "tool_id": tool_id,
        }

    # Scenario 3 — subscription required
    return {
        "status":      "subscription_required",
        "message":     "A subscription is required to access this tool.",
        "upgrade_url": url,
        "tool_id":     tool_id,
    }
