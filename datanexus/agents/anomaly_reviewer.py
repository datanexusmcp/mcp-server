"""
datanexus/agents/anomaly_reviewer.py — Haiku Trigger 1: anomaly review.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.3 / Phase 3

Called when the deterministic validator (validator.py) flags an anomaly
that needs a second-opinion classification before deciding whether to
keep, suppress, or flag the affected record.

Rules (CLAUDE.md):
  S13-1: This is Haiku Trigger T1. Do NOT call Anthropic API directly —
         always delegate to haiku_classifier.classify().
  S13-4: Never raises. All exceptions caught. Structured result always returned.

Return shape (exactly 4 keys, always present):
  {
    'action':          'keep' | 'suppress' | 'flag'
    'issue':           str | None
    'confidence':      float   (0.0 – 1.0)
    'haiku_available': bool
  }

When Haiku unavailable (haiku_available=False):
  action='flag', confidence=0.0  — never block the pipeline.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from datanexus.agents.haiku_classifier import classify

log = logging.getLogger("datanexus.agents.anomaly_reviewer")

# Valid action values
_VALID_ACTIONS = frozenset({"keep", "suppress", "flag"})

# Haiku task prompt — instructs the model on the exact JSON shape to return
_TASK_TEMPLATE = (
    "You are reviewing a data anomaly flagged by a deterministic validator. "
    "Decide whether to keep the record as-is, suppress it from results, "
    "or flag it for human review. "
    "Return a JSON object with exactly these keys: "
    "action (one of: keep, suppress, flag), "
    "issue (string describing the problem, or null if none), "
    "confidence (float 0.0–1.0 indicating your certainty). "
    "Example: {{\"action\": \"flag\", \"issue\": \"CVSS vector present but severity level missing\", \"confidence\": 0.85}}"
)


async def review_anomaly(
    tool_id: str,
    field: str,
    value: Any,
    rule_fired: str,
    full_record: dict,
) -> dict:
    """
    Ask Haiku to review a data anomaly and recommend an action.

    Args:
        tool_id:     Tool the anomaly came from ('T04' or 'T10').
        field:       Dotted field path that triggered the rule (e.g. 'severity.level').
        value:       The anomalous value found (e.g. 'UNKNOWN').
        rule_fired:  The validator rule that fired (e.g. 'severity_unknown_with_vector').
        full_record: The complete data record containing the anomaly.

    Returns:
        {'action': str, 'issue': str|None, 'confidence': float, 'haiku_available': bool}
        Never raises.
    """
    context = (
        f"Tool: {tool_id}. "
        f"Field: {field}. "
        f"Anomalous value: {value!r}. "
        f"Validator rule fired: {rule_fired}."
    )

    log.info(json.dumps({
        "event":      "anomaly_review_start",
        "tool_id":    tool_id,
        "field":      field,
        "value":      str(value),
        "rule_fired": rule_fired,
    }))

    try:
        raw = await classify(context, full_record, _TASK_TEMPLATE)
    except Exception as exc:
        # classify() should never raise, but belt-and-suspenders
        log.error(json.dumps({
            "event":      "anomaly_review_classify_exception",
            "tool_id":    tool_id,
            "rule_fired": rule_fired,
            "error":      str(exc),
        }))
        raw = {"error": str(exc), "haiku_available": False}

    # ── Haiku unavailable (daily cap, API error, bad key, etc.) ──────────────
    if not raw or raw.get("haiku_available") is False or "error" in raw:
        result = {
            "action":          "flag",
            "issue":           f"Haiku unavailable — rule: {rule_fired}, field: {field}",
            "confidence":      0.0,
            "haiku_available": False,
        }
        log.info(json.dumps({
            "event":      "anomaly_review_haiku_unavailable",
            "tool_id":    tool_id,
            "rule_fired": rule_fired,
            "result":     result,
        }))
        return result

    # ── Parse and normalise Haiku response ────────────────────────────────────
    action = str(raw.get("action", "flag")).lower()
    if action not in _VALID_ACTIONS:
        log.warning(json.dumps({
            "event":        "anomaly_review_invalid_action",
            "raw_action":   action,
            "defaulting_to": "flag",
        }))
        action = "flag"

    try:
        confidence = float(raw.get("confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))   # clamp to [0, 1]
    except (TypeError, ValueError):
        confidence = 0.0

    issue_raw = raw.get("issue")
    issue = str(issue_raw) if issue_raw is not None else None

    result = {
        "action":          action,
        "issue":           issue,
        "confidence":      confidence,
        "haiku_available": True,
    }

    log.info(json.dumps({
        "event":      "anomaly_review_complete",
        "tool_id":    tool_id,
        "field":      field,
        "rule_fired": rule_fired,
        "result":     result,
    }))

    return result
