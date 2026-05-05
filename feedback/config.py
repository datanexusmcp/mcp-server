"""
feedback/config.py — All constants and Redis key functions for the feedback system.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.1 / Section 11.6 Step 2

Rules (enforced):
  - FEEDBACK_AGENTS_ACTIVE defaults False — never enable without explicit env var.
  - ALL Redis key strings live here and ONLY here. No key strings in any other file.
  - Key functions are pure (no Redis calls) — they return strings only.
"""

from __future__ import annotations

import os
from typing import FrozenSet

# ── Haiku model (Section 13) ──────────────────────────────────────────────────
# Single source of truth for the Haiku model string.
# NEVER hardcode this string anywhere else — always import HAIKU_MODEL (CLAUDE.md S13-2).
# Update here only when upgrading model versions.
HAIKU_MODEL: str = "claude-haiku-4-5"

# ── Feature flags ──────────────────────────────────────────────────────────────

# Master switch for AI classification agents.
# Set FEEDBACK_AGENTS_ACTIVE=true in the environment to activate.
# When False, classify_record() always returns ('pending', 0.0).
FEEDBACK_AGENTS_ACTIVE: bool = (
    os.environ.get("FEEDBACK_AGENTS_ACTIVE", "").strip().lower() == "true"
)

# ── Tool membership ────────────────────────────────────────────────────────────

# Tools that collect explicit user feedback via report_feedback().
FEEDBACK_ENABLED_TOOLS: FrozenSet[str] = frozenset({"T04", "T10"})

# Tools where only implicit signals are collected (cache hits, error rates).
# report_feedback() rejects these — they do not appear in FEEDBACK_ENABLED_TOOLS.
IMPLICIT_ONLY_TOOLS: FrozenSet[str] = frozenset({"T12", "T13"})

# ── Signal taxonomy ────────────────────────────────────────────────────────────

# Signals that indicate a bug or quality problem.
BUG_SIGNALS: FrozenSet[str] = frozenset({
    "not_useful",
    "incorrect_data",
    "missing_field",
    "hallucination",
    "wrong_entity",
    "stale_data",
    "data_quality",
})

# Signals that indicate positive feedback or a feature request.
IMPROVEMENT_SIGNALS: FrozenSet[str] = frozenset({
    "helpful",
    "very_helpful",
    "feature_request",
    "good_result",
    "saved_time",
})

# Union — every valid signal value.
ALL_SIGNALS: FrozenSet[str] = BUG_SIGNALS | IMPROVEMENT_SIGNALS

# ── Redis TTLs (seconds) ───────────────────────────────────────────────────────

FEEDBACK_TTL:  int = 90  * 86_400   # 90  days — raw feedback records
AUDIT_TTL:     int = 35  * 86_400   # 35  days — audit / telemetry counters
DIGEST_TTL:    int = 180 * 86_400   # 180 days — daily digest items
QUEUE_TTL:     int = 7   * 86_400   # 7   days — classifier work queue entries

# ── Redis key functions ────────────────────────────────────────────────────────
# ALL Redis key strings are constructed here. No other module may hard-code
# a Redis key string. Import and call these functions everywhere else.

def key_feedback(tool_id: str, record_id: str) -> str:
    """Hash key for a single FeedbackRecord.  feedback:{tool_id}:{record_id}"""
    return f"feedback:{tool_id}:{record_id}"


def key_feedback_list(tool_id: str) -> str:
    """Sorted-set key holding all record_ids for a tool, scored by timestamp.
    feedback_list:{tool_id}"""
    return f"feedback_list:{tool_id}"


def key_audit(query_hash: str) -> str:
    """Hash key for a single AuditRecord.  audit:{query_hash}"""
    return f"audit:{query_hash}"


def key_digest(tool_id: str, date: str) -> str:
    """Hash key for the daily DigestItem for a tool.
    digest:{tool_id}:{date}   (date format: YYYY-MM-DD)"""
    return f"digest:{tool_id}:{date}"


def key_classifier_queue() -> str:
    """List key for the classifier work queue (LPUSH / BRPOP).
    classifier:queue"""
    return "classifier:queue"


def key_signal_count(tool_id: str, signal: str, date: str) -> str:
    """Counter key for a specific signal on a given day.
    signal_count:{tool_id}:{signal}:{date}"""
    return f"signal_count:{tool_id}:{signal}:{date}"


def key_bug_count(tool_id: str, date: str) -> str:
    """Counter key for total bug signals for a tool on a given day.
    bug_count:{tool_id}:{date}"""
    return f"bug_count:{tool_id}:{date}"


def key_improvement_count(tool_id: str, date: str) -> str:
    """Counter key for total improvement signals for a tool on a given day.
    improvement_count:{tool_id}:{date}"""
    return f"improvement_count:{tool_id}:{date}"


def key_pending_count(tool_id: str, date: str) -> str:
    """Counter key for pending (unclassified) records for a tool on a given day.
    pending_count:{tool_id}:{date}"""
    return f"pending_count:{tool_id}:{date}"


def key_dedup(tool_id: str, query_hash: str, signal: str) -> str:
    """Dedup window key (TTL = DEDUP_WINDOW_SECS) for identical-feedback suppression.
    fb:dedup:{tool_id}:{query_hash}:{signal}"""
    return f"fb:dedup:{tool_id}:{query_hash}:{signal}"


def key_alerts_immediate() -> str:
    """Redis List key for immediate bug alerts consumed by bug_listener (LPUSH/BLPOP).
    fb:alerts:immediate"""
    return "fb:alerts:immediate"


def key_feedback_queue() -> str:
    """Redis List key for improvement / general feedback queue (LPUSH/BRPOP).
    fb:queue"""
    return "fb:queue"


def key_pause() -> str:
    """Presence key — when this key exists the collector is paused (no new writes).
    fb:pause"""
    return "fb:pause"


# ── Dedup window ──────────────────────────────────────────────────────────────

# Identical tool_id+query_hash+signal within this window → vote increment only.
DEDUP_WINDOW_SECS: int = 60
