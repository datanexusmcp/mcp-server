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
    """Check subscription status and access tier for DataNexus tools. Read-only. No side effects. No parameters required. Returns free or paid status, access tier, and upgrade URL during the free window. Call this when a user asks about pricing, subscription status, or access limits. Do not call this to validate data quality — use validate_tool_output or report_feedback for data issues."""
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
