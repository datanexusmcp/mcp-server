"""
datanexus/agents/feedback_classifier.py — Haiku Trigger 2: feedback classification.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.4 / Phase 4

Most important file in Section 13. Closes the loop between user-reported
feedback and automated data quality triage.

Rules (CLAUDE.md):
  S13-1: This is Haiku Trigger T2. Delegate to haiku_classifier.classify() only.
  S13-4: Never raises. All exceptions caught. Always returns structured result.
  S13-5: FeedbackRecord.classification is ONE-WAY only.
         pending → confirmed | rejected | needs_review.
         NEVER back to pending. Check Redis before every write.

Return shape (exactly 5 keys, always present):
  {
    'classification':   'confirmed' | 'rejected' | 'needs_review'
    'score':            float  (0.0 – 1.0)
    'suggested_fix':    str
    'open_github_issue': bool
    'haiku_available':  bool
  }

Redis writes (ALWAYS, even on Haiku failure):
  HSET feedback:record:{record_id}
    classification  <value>
    score           <value>
    agent_version   <HAIKU_MODEL>

GitHub pending (only when classification='confirmed' AND score >= 0.8):
  HSET datanexus:github:pending:{record_id}
    tool_id, query_hash, signal, comment,
    suggested_fix, score, created_at
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import redis as redis_lib

from feedback.config import HAIKU_MODEL
from feedback.models import FeedbackRecord
from datanexus.agents.haiku_classifier import classify

log = logging.getLogger("datanexus.agents.feedback_classifier")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

# Classifications that lock the record (one-way rule S13-5)
_LOCKED_CLASSIFICATIONS = frozenset({"confirmed", "rejected", "needs_review"})

# Valid output classifications — never 'pending'
_VALID_CLASSIFICATIONS = frozenset({"confirmed", "rejected", "needs_review"})

# Score threshold for opening a GitHub issue
_GITHUB_THRESHOLD = 0.8

_redis_client: redis_lib.Redis | None = None


def _get_redis() -> redis_lib.Redis | None:
    """Return a Redis client. Never raises."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:
        log.warning(json.dumps({
            "event": "feedback_classifier_redis_unavailable",
            "error": str(exc),
        }))
        return None


def _redis_key(record_id: str) -> str:
    """Redis hash key for a feedback record classification state."""
    return f"feedback:record:{record_id}"


def _github_key(record_id: str) -> str:
    """Redis hash key for a pending GitHub issue."""
    return f"datanexus:github:pending:{record_id}"


def _check_current_classification(record_id: str) -> str | None:
    """
    Read the current classification from Redis.
    Returns the classification string, or None if not found / Redis unavailable.
    """
    r = _get_redis()
    if r is None:
        return None
    try:
        return r.hget(_redis_key(record_id), "classification")
    except Exception:
        return None


def _write_redis_classification(
    record_id: str,
    classification: str,
    score: float,
    record: "FeedbackRecord | None" = None,
    suggested_fix: str = "",
) -> None:
    """
    Write classification + full context to Redis so reviewers have everything
    in one place without needing to cross-reference feedback:{tool_id}:{id}.

    Fields always written: classification, score, agent_version.
    Fields written when record is provided: tool_id, signal, comment,
      query_hash, received_at, missing_fields (JSON), suggested_fix.

    Called on EVERY classify_feedback invocation — even on Haiku failure.
    Never raises.
    """
    r = _get_redis()
    if r is None:
        log.warning(json.dumps({
            "event":     "feedback_classifier_redis_write_skip",
            "record_id": record_id,
            "reason":    "Redis unavailable",
        }))
        return
    try:
        mapping: dict = {
            "classification": classification,
            "score":          str(score),
            "agent_version":  HAIKU_MODEL,
        }
        if record is not None:
            mapping.update({
                "tool_id":        record.tool_id,
                "signal":         record.signal,
                "comment":        record.comment or "",
                "query_hash":     record.query_hash,
                "received_at":    record.received_at,
                "missing_fields": json.dumps(record.missing_fields or []),
                "suggested_fix":  suggested_fix,
            })
        r.hset(
            _redis_key(record_id),
            mapping=mapping,
        )
        log.info(json.dumps({
            "event":          "feedback_classifier_redis_written",
            "record_id":      record_id,
            "classification": classification,
            "score":          score,
            "agent_version":  HAIKU_MODEL,
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":     "feedback_classifier_redis_write_error",
            "record_id": record_id,
            "error":     str(exc),
        }))


def _write_github_pending(record: FeedbackRecord, suggested_fix: str, score: float) -> None:
    """
    Write a pending GitHub issue entry to Redis.
    Called only when classification='confirmed' AND score >= _GITHUB_THRESHOLD.
    NOT a GitHub API call — Redis write only.
    Never raises.
    """
    r = _get_redis()
    if r is None:
        return
    try:
        r.hset(
            _github_key(record.record_id),
            mapping={
                "tool_id":       record.tool_id,
                "query_hash":    record.query_hash,
                "signal":        record.signal,
                "comment":       record.comment or "",
                "suggested_fix": suggested_fix,
                "score":         str(score),
                "created_at":    datetime.now(timezone.utc).isoformat(),
            },
        )
        log.info(json.dumps({
            "event":     "github_pending_written",
            "record_id": record.record_id,
            "tool_id":   record.tool_id,
            "score":     score,
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":     "github_pending_write_error",
            "record_id": record.record_id,
            "error":     str(exc),
        }))


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

async def classify_feedback(
    record: FeedbackRecord,
    original_response: dict,
) -> dict:
    """
    Classify a user-submitted feedback record using Haiku.

    Args:
        record:            The FeedbackRecord to classify.
        original_response: The cached tool response that triggered the feedback.

    Returns:
        {'classification': str, 'score': float, 'suggested_fix': str,
         'open_github_issue': bool, 'haiku_available': bool}

    Never raises. Redis write runs on every call.
    """
    # ── S13-5: One-way rule — check before any write ──────────────────────────
    current = _check_current_classification(record.record_id)
    if current in _LOCKED_CLASSIFICATIONS:
        log.warning(json.dumps({
            "event":                  "feedback_already_classified",
            "record_id":              record.record_id,
            "current_classification": current,
            "action":                 "skip — one-way rule S13-5",
        }))
        return {
            "classification":    current,
            "score":             0.0,
            "suggested_fix":     "",
            "open_github_issue": False,
            "haiku_available":   True,
        }

    # ── Build Haiku prompt ────────────────────────────────────────────────────
    context = (
        f"A user reported a data quality issue with tool {record.tool_id}. "
        f"Signal: {record.signal}. "
        f"Comment: {record.comment!r}. "
        f"Missing fields: {record.missing_fields}."
    )
    task = (
        "Classify this feedback report. "
        "Return a JSON object with exactly these keys: "
        "classification (one of: confirmed, rejected, needs_review — NEVER 'pending'), "
        "score (float 0.0-1.0 indicating confidence), "
        "suggested_fix (string describing what should be fixed, or empty string). "
        "Example: {\"classification\": \"confirmed\", \"score\": 0.85, "
        "\"suggested_fix\": \"Derive severity level from CVSS vector when level is UNKNOWN\"}"
    )

    try:
        raw = await classify(context, original_response, task)
    except Exception as exc:
        log.error(json.dumps({
            "event":     "feedback_classifier_classify_exception",
            "record_id": record.record_id,
            "error":     str(exc),
        }))
        raw = {"error": str(exc), "haiku_available": False}

    # ── Haiku unavailable → needs_review (never pending) ─────────────────────
    if not raw or "error" in raw or raw.get("haiku_available") is False:
        classification = "needs_review"
        score          = 0.0
        suggested_fix  = ""
        haiku_available = False

        # Always write to Redis — even on failure
        _write_redis_classification(
            record.record_id, classification, score,
            record=record, suggested_fix="",
        )

        log.info(json.dumps({
            "event":          "feedback_classified",
            "record_id":      record.record_id,
            "classification": classification,
            "haiku_available": haiku_available,
        }))

        return {
            "classification":    classification,
            "score":             score,
            "suggested_fix":     suggested_fix,
            "open_github_issue": False,
            "haiku_available":   haiku_available,
        }

    # ── Parse Haiku response ──────────────────────────────────────────────────
    classification = str(raw.get("classification", "needs_review")).lower()
    if classification not in _VALID_CLASSIFICATIONS:
        log.warning(json.dumps({
            "event":           "feedback_invalid_classification",
            "raw":             classification,
            "defaulting_to":   "needs_review",
        }))
        classification = "needs_review"

    try:
        score = float(raw.get("score", 0.0))
        score = max(0.0, min(1.0, score))
    except (TypeError, ValueError):
        score = 0.0

    suggested_fix = str(raw.get("suggested_fix", "") or "")

    # ── Always write classification to Redis ──────────────────────────────────
    _write_redis_classification(
        record.record_id, classification, score,
        record=record, suggested_fix=suggested_fix,
    )

    # ── GitHub pending: confirmed + score >= 0.8 ──────────────────────────────
    open_github = classification == "confirmed" and score >= _GITHUB_THRESHOLD
    if open_github:
        _write_github_pending(record, suggested_fix, score)

    result = {
        "classification":    classification,
        "score":             score,
        "suggested_fix":     suggested_fix,
        "open_github_issue": open_github,
        "haiku_available":   True,
    }

    log.info(json.dumps({
        "event":             "feedback_classified",
        "record_id":         record.record_id,
        "tool_id":           record.tool_id,
        "signal":            record.signal,
        "classification":    classification,
        "score":             score,
        "open_github_issue": open_github,
        "haiku_available":   True,
    }))

    return result
