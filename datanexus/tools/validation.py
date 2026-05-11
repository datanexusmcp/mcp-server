"""
datanexus/tools/validation.py — MCP tool: validate_tool_output (Section 13).

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.6 / Phase 7

Two-layer validation:
  Layer 1 — deterministic (always runs): datanexus/core/validator.py
  Layer 2 — Haiku AI review (only on ambiguous L1 findings): anomaly_reviewer.py

Consensus rule: feedback_filed=True ONLY when BOTH layers flag the same issue.
Do NOT call this tool recursively.
Do NOT call from inside T04 or T10 handlers.

Return shape (exactly 6 top-level keys):
  {
    'validation':       'pass' | 'issues_found'
    'deterministic':    {'passed': bool, 'issues': list[str]}
    'haiku':            {'passed': bool, 'issues': list[str], 'available': bool}
    'feedback_filed':   bool
    'consensus_issues': list[str]
    'query_hash':       str
  }
"""

from __future__ import annotations

import json
import logging

from datanexus.core.validator import validate_payload
from datanexus.agents.anomaly_reviewer import review_anomaly

log = logging.getLogger("datanexus.tools.validation")

# Issue tokens that are ambiguous enough to warrant Haiku review
# (missing required fields are structural problems, not data quality anomalies)
_HAIKU_WORTHY = frozenset({
    "severity_derived",
    "pysec_deduplicated",
    "malformed_ein",
    "unverified_financials",
    "incomplete_records",
})


def _is_haiku_worthy(issues: list[str]) -> bool:
    """Return True if any issue warrants a Haiku second-opinion."""
    for issue in issues:
        # prefix match (e.g. "pysec_deduplicated:3")
        for token in _HAIKU_WORTHY:
            if issue == token or issue.startswith(token + ":") or issue.startswith(token):
                return True
    return False


async def validate_tool_output(
    tool_id: str,
    query_hash: str,
    response_json: str,
) -> dict:
    """Validate any DataNexus tool response for data quality anomalies. Two-layer validation: deterministic rules (always) + Haiku AI review (only on ambiguous deterministic findings). Auto-files feedback on consensus issues only — both layers must agree before filing. Never blocks — always returns structured result. Verified source: DataNexus internal validator. AI-Ready output. Token-efficient. Two-layer validation architecture. data quality coverage for T04 and T10. Example: validate_tool_output(tool_id='T10', query_hash='3d1697...', response_json=json.dumps(tool_response))"""
    # ── Safe outer wrapper — never raises ────────────────────────────────────
    try:
        return await _validate_inner(tool_id, query_hash, response_json)
    except Exception as exc:
        log.error(json.dumps({
            "event":      "validate_tool_output_exception",
            "tool_id":    tool_id,
            "query_hash": query_hash,
            "error":      str(exc),
        }))
        return {
            "validation":       "error",
            "deterministic":    {"passed": False, "issues": ["internal_error"]},
            "haiku":            {"passed": True,  "issues": [], "available": False},
            "feedback_filed":   False,
            "consensus_issues": [],
            "query_hash":       query_hash,
        }


async def _validate_inner(
    tool_id: str,
    query_hash: str,
    response_json: str,
) -> dict:

    # ── Parse response_json — malformed JSON is a structured result not a raise
    try:
        parsed = json.loads(response_json)
        if not isinstance(parsed, dict):
            parsed = {"_raw": parsed}
    except (json.JSONDecodeError, ValueError) as exc:
        log.warning(json.dumps({
            "event":      "validate_tool_output_json_error",
            "tool_id":    tool_id,
            "query_hash": query_hash,
            "error":      str(exc),
        }))
        return {
            "validation":       "error",
            "deterministic":    {"passed": False, "issues": ["malformed_json"]},
            "haiku":            {"passed": True,  "issues": [], "available": False},
            "feedback_filed":   False,
            "consensus_issues": [],
            "query_hash":       query_hash,
        }

    # ── Layer 1: deterministic validator ─────────────────────────────────────
    cleaned, d_issues = validate_payload(tool_id, parsed)

    d_passed = cleaned is not None and len(d_issues) == 0

    log.info(json.dumps({
        "event":      "validate_layer1",
        "tool_id":    tool_id,
        "query_hash": query_hash,
        "passed":     d_passed,
        "issues":     d_issues,
    }))

    # ── Layer 2: Haiku review (only on ambiguous findings) ────────────────────
    h_issues:    list[str] = []
    h_available: bool      = True
    h_passed:    bool      = True

    if d_issues and _is_haiku_worthy(d_issues):
        try:
            review = await review_anomaly(
                tool_id=tool_id,
                field="response_data",
                value=str(d_issues),
                rule_fired=d_issues[0],
                full_record=cleaned or parsed,
            )
            h_available = review.get("haiku_available", True)
            action      = review.get("action", "keep")
            if action in ("flag", "suppress"):
                h_issues  = [review.get("issue") or d_issues[0]]
                h_passed  = False
        except Exception as exc:
            log.error(json.dumps({
                "event":  "validate_layer2_error",
                "error":  str(exc),
            }))
            h_available = False

    # ── Consensus: both layers must agree ─────────────────────────────────────
    # Layer 1 issues ∩ Layer 2 confirmed → consensus
    consensus_issues: list[str] = []
    feedback_filed = False

    if d_issues and h_issues:
        # Any overlap between what L1 found and what L2 flagged
        consensus_issues = d_issues[:]   # L1 issues confirmed by L2
        # File feedback for each consensus issue
        try:
            from feedback.collector import report_feedback as _file_feedback
            for issue in consensus_issues[:3]:   # cap at 3 to avoid spam
                await _file_feedback(
                    tool_id=tool_id,
                    query_hash=query_hash,
                    signal="data_quality",
                    comment=f"Consensus validation issue: {issue}",
                )
            feedback_filed = True
            log.info(json.dumps({
                "event":           "validate_feedback_filed",
                "tool_id":         tool_id,
                "query_hash":      query_hash,
                "consensus_issues": consensus_issues,
            }))
        except Exception as exc:
            log.error(json.dumps({
                "event":  "validate_feedback_file_error",
                "error":  str(exc),
            }))

    # ── Assemble result ───────────────────────────────────────────────────────
    has_issues = not d_passed or bool(h_issues)
    validation = "issues_found" if has_issues else "pass"

    result = {
        "validation":       validation,
        "deterministic":    {"passed": d_passed,  "issues": d_issues},
        "haiku":            {"passed": h_passed,  "issues": h_issues, "available": h_available},
        "feedback_filed":   feedback_filed,
        "consensus_issues": consensus_issues,
        "query_hash":       query_hash,
    }

    log.info(json.dumps({
        "event":           "validate_tool_output_complete",
        "tool_id":         tool_id,
        "query_hash":      query_hash,
        "validation":      validation,
        "feedback_filed":  feedback_filed,
    }))

    return result
