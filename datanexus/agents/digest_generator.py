"""
datanexus/agents/digest_generator.py — Haiku Trigger 4: weekly digest.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.6 / Phase 6

Batches ALL feedback records for a tool into ONE Haiku call (cost control)
and produces a DigestItem with data quality score, top issues, suggested
rules, and sprint recommendations.

Rules (CLAUDE.md):
  S13-1: This is Haiku Trigger T4. Delegate to haiku_classifier.classify() only.
  S13-4: Never raises. Always returns structured DigestItem.

Special case — empty records list:
  Return DigestItem with data_quality_score=1.0, top_issues=[].
  Do NOT call Haiku. No Redis write needed (nothing to summarise).

Redis write:
  Key:    datanexus:digest:{tool_id}:{year}-W{week:02d}
  Fields: top_issues, suggested_rules, data_quality_score,
          sprint_recommendations, generated_at
  EXPIRE: 2592000 seconds (30 days)
  Week:   date.today().isocalendar() → (year, week, _)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timezone

import redis as redis_lib

from datanexus.agents.haiku_classifier import classify
from feedback.models import DigestItem, FeedbackRecord

log = logging.getLogger("datanexus.agents.digest_generator")

_REDIS_URL  = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_DIGEST_TTL = 2_592_000   # 30 days in seconds

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
            "event": "digest_generator_redis_unavailable",
            "error": str(exc),
        }))
        return None


def _week_key(tool_id: str) -> str:
    """Redis hash key for the weekly digest: datanexus:digest:{tool_id}:{year}-W{week:02d}"""
    iso = date.today().isocalendar()
    week_str = f"{iso.year}-W{iso.week:02d}"
    return f"datanexus:digest:{tool_id}:{week_str}"


def _write_digest(tool_id: str, item: DigestItem) -> None:
    """Write DigestItem fields to Redis with 30-day TTL. Never raises."""
    r = _get_redis()
    if r is None:
        return
    try:
        key = _week_key(tool_id)
        r.hset(
            key,
            mapping={
                "top_issues":            json.dumps(item.top_issues),
                "suggested_rules":       json.dumps(item.suggested_rules),
                "data_quality_score":    str(item.data_quality_score),
                "sprint_recommendations": json.dumps(item.sprint_recommendations),
                "generated_at":          item.generated_at,
            },
        )
        r.expire(key, _DIGEST_TTL)
        log.info(json.dumps({
            "event":               "digest_written",
            "tool_id":             tool_id,
            "key":                 key,
            "data_quality_score":  item.data_quality_score,
            "top_issues_count":    len(item.top_issues),
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":   "digest_write_error",
            "tool_id": tool_id,
            "error":   str(exc),
        }))


def _safe_float(val, default: float = 1.0) -> float:
    try:
        f = float(val)
        return max(0.0, min(1.0, f))
    except (TypeError, ValueError):
        return default


def _safe_list(val) -> list[str]:
    if isinstance(val, list):
        return [str(x) for x in val]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

async def generate_weekly_digest(
    tool_id: str,
    feedback_records: list[FeedbackRecord],
) -> DigestItem:
    """
    Generate a weekly data quality digest for a tool from its feedback records.

    Batches ALL records into ONE Haiku call (never one call per record).
    Empty records list → returns perfect-score DigestItem without calling Haiku.

    Args:
        tool_id:          Tool to generate digest for ('T04' or 'T10').
        feedback_records: List of FeedbackRecord instances for the period.

    Returns:
        DigestItem with top_issues, data_quality_score, sprint_recommendations.
        Never raises.
    """
    today_str = date.today().isoformat()

    # ── Empty list: score=1.0, no Haiku call ─────────────────────────────────
    if not feedback_records:
        log.info(json.dumps({
            "event":   "digest_empty_records",
            "tool_id": tool_id,
            "action":  "returning perfect score — no Haiku call",
        }))
        return DigestItem(
            tool_id=tool_id,
            date=today_str,
            data_quality_score=1.0,
            top_issues=[],
            suggested_rules=[],
            sprint_recommendations=[],
        )

    # ── Batch all records into ONE Haiku call ─────────────────────────────────
    records_summary = [
        {
            "signal":        r.signal,
            "comment":       r.comment or "",
            "classification": r.classification,
            "score":         r.score,
        }
        for r in feedback_records
    ]

    context = (
        f"Weekly data quality digest for tool {tool_id}. "
        f"Total feedback records: {len(feedback_records)}. "
        f"Bug signals: {sum(1 for r in feedback_records if r.signal in ('incorrect_data','missing_field','stale_data','wrong_entity','data_quality','not_useful'))}. "
        f"Confirmed issues: {sum(1 for r in feedback_records if r.classification == 'confirmed')}."
    )
    task = (
        "Generate a weekly data quality digest. "
        "Return a JSON object with exactly these keys: "
        "top_issues (list of up to 5 strings describing the most common problems), "
        "suggested_rules (list of up to 3 strings for new validator rules to add), "
        "data_quality_score (float 0.0-1.0, where 1.0 = perfect, 0.0 = critical issues), "
        "sprint_recommendations (list of up to 3 actionable sprint items). "
        "Base the score on: confirmed issues lower the score, more records = more weight. "
        "Example: {\"top_issues\": [\"UNKNOWN severity when CVSS vector present\"], "
        "\"suggested_rules\": [\"enforce_cvss_level\"], "
        "\"data_quality_score\": 0.72, "
        "\"sprint_recommendations\": [\"Fix T10 severity derivation in ingest worker\"]}"
    )

    try:
        raw = await classify(context, {"records": records_summary}, task)
    except Exception as exc:
        log.error(json.dumps({
            "event":   "digest_classify_exception",
            "tool_id": tool_id,
            "error":   str(exc),
        }))
        raw = {"error": str(exc), "haiku_available": False}

    # ── Haiku unavailable → degrade gracefully ────────────────────────────────
    if not raw or "error" in raw or raw.get("haiku_available") is False:
        log.warning(json.dumps({
            "event":   "digest_haiku_unavailable",
            "tool_id": tool_id,
        }))
        item = DigestItem(
            tool_id=tool_id,
            date=today_str,
            data_quality_score=0.5,       # unknown — degrade to middle
            top_issues=["Haiku unavailable — manual review recommended"],
            suggested_rules=[],
            sprint_recommendations=[],
        )
        _write_digest(tool_id, item)
        return item

    # ── Parse Haiku response ──────────────────────────────────────────────────
    top_issues            = _safe_list(raw.get("top_issues", []))
    suggested_rules       = _safe_list(raw.get("suggested_rules", []))
    data_quality_score    = _safe_float(raw.get("data_quality_score", 1.0))
    sprint_recommendations = _safe_list(raw.get("sprint_recommendations", []))

    item = DigestItem(
        tool_id=tool_id,
        date=today_str,
        total_count=len(feedback_records),
        data_quality_score=data_quality_score,
        top_issues=top_issues,
        suggested_rules=suggested_rules,
        sprint_recommendations=sprint_recommendations,
    )

    _write_digest(tool_id, item)

    log.info(json.dumps({
        "event":               "digest_generated",
        "tool_id":             tool_id,
        "records_batched":     len(feedback_records),
        "data_quality_score":  data_quality_score,
        "top_issues_count":    len(top_issues),
        "haiku_calls":         1,
    }))

    return item
