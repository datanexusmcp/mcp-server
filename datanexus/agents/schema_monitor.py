"""
datanexus/agents/schema_monitor.py — Haiku Trigger 3: schema change assessment.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.5 / Phase 5

Called when the ingest worker detects a structural change between the
previously-stored schema fingerprint and the newly-fetched payload shape.
Haiku decides whether the change is breaking and what severity to assign.

Rules (CLAUDE.md):
  S13-1: This is Haiku Trigger T3. Delegate to haiku_classifier.classify() only.
  S13-4: Never raises. Always returns structured result.

Return shape (exactly 5 keys, always present):
  {
    'breaking':        bool
    'affected_fields': list[str]
    'severity':        'low' | 'medium' | 'high'
    'recommendation':  str
    'haiku_available': bool
  }

Actions by outcome:
  breaking=True  + severity='high'   → HSET datanexus:schema:alerts:{tool_id}
                                       record_failure(tool_id) × 3 (trip circuit)
  breaking=True  + severity='medium' → HSET datanexus:schema:warnings:{tool_id}
                                       no circuit breaker
  breaking=False (any severity)      → update stored fingerprint in Redis only
  haiku_unavailable                  → breaking=False, severity='low', no actions

Schema fingerprint stored at:
  Redis key: datanexus:schema:fingerprint:{tool_id}
  Value:     JSON string of the schema dict (set of top-level field names)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import redis as redis_lib

from datanexus.agents.haiku_classifier import classify
from datanexus.core.circuit_breaker import record_failure

log = logging.getLogger("datanexus.agents.schema_monitor")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

_VALID_SEVERITIES = frozenset({"low", "medium", "high"})

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
            "event": "schema_monitor_redis_unavailable",
            "error": str(exc),
        }))
        return None


def _fingerprint_key(tool_id: str) -> str:
    return f"datanexus:schema:fingerprint:{tool_id}"

def _alerts_key(tool_id: str) -> str:
    return f"datanexus:schema:alerts:{tool_id}"

def _warnings_key(tool_id: str) -> str:
    return f"datanexus:schema:warnings:{tool_id}"


def _schema_fields(schema: dict) -> set[str]:
    """Extract the set of top-level field names from a schema dict."""
    return set(schema.keys())


def _update_fingerprint(tool_id: str, schema: dict) -> None:
    """Store the current schema fingerprint in Redis. Never raises."""
    r = _get_redis()
    if r is None:
        return
    try:
        fields = sorted(_schema_fields(schema))
        r.set(_fingerprint_key(tool_id), json.dumps(fields))
        log.info(json.dumps({
            "event":   "schema_fingerprint_updated",
            "tool_id": tool_id,
            "fields":  fields,
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":   "schema_fingerprint_update_error",
            "tool_id": tool_id,
            "error":   str(exc),
        }))


def _write_alert(tool_id: str, result: dict) -> None:
    """Write HSET datanexus:schema:alerts:{tool_id}. Never raises."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.hset(
            _alerts_key(tool_id),
            mapping={
                "breaking":         "true",
                "severity":         result.get("severity", "high"),
                "affected_fields":  json.dumps(result.get("affected_fields", [])),
                "recommendation":   result.get("recommendation", ""),
                "detected_at":      datetime.now(timezone.utc).isoformat(),
            },
        )
        log.error(json.dumps({
            "event":           "schema_alert_written",
            "tool_id":         tool_id,
            "affected_fields": result.get("affected_fields", []),
            "recommendation":  result.get("recommendation", ""),
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":   "schema_alert_write_error",
            "tool_id": tool_id,
            "error":   str(exc),
        }))


def _write_warning(tool_id: str, result: dict) -> None:
    """Write HSET datanexus:schema:warnings:{tool_id}. Never raises."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.hset(
            _warnings_key(tool_id),
            mapping={
                "breaking":         "true",
                "severity":         result.get("severity", "medium"),
                "affected_fields":  json.dumps(result.get("affected_fields", [])),
                "recommendation":   result.get("recommendation", ""),
                "detected_at":      datetime.now(timezone.utc).isoformat(),
            },
        )
        log.warning(json.dumps({
            "event":           "schema_warning_written",
            "tool_id":         tool_id,
            "affected_fields": result.get("affected_fields", []),
        }))
    except Exception as exc:
        log.error(json.dumps({
            "event":   "schema_warning_write_error",
            "tool_id": tool_id,
            "error":   str(exc),
        }))


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

async def assess_schema_change(
    tool_id: str,
    old_schema: dict,
    new_schema: dict,
) -> dict:
    """
    Assess whether a schema change between old_schema and new_schema is breaking.

    Args:
        tool_id:    Tool whose schema changed ('T04' or 'T10').
        old_schema: Previously-known schema (dict of field→example).
        new_schema: Newly-observed schema (dict of field→example).

    Returns:
        {'breaking': bool, 'affected_fields': list, 'severity': str,
         'recommendation': str, 'haiku_available': bool}
        Never raises.
    """
    old_fields = _schema_fields(old_schema)
    new_fields  = _schema_fields(new_schema)
    added       = sorted(new_fields - old_fields)
    removed     = sorted(old_fields - new_fields)

    log.info(json.dumps({
        "event":    "schema_assess_start",
        "tool_id":  tool_id,
        "added":    added,
        "removed":  removed,
    }))

    # ── Build Haiku prompt ────────────────────────────────────────────────────
    context = (
        f"Tool: {tool_id}. "
        f"Schema change detected. "
        f"Fields added: {added}. "
        f"Fields removed: {removed}. "
        f"Old field set: {sorted(old_fields)}. "
        f"New field set: {sorted(new_fields)}."
    )
    # Build explicit removed/added context for the prompt
    _removed_str = f"REMOVED fields (were in old, gone from new): {removed}" if removed else "No fields removed."
    _added_str   = f"ADDED fields (new, not in old): {added}" if added else "No fields added."

    task = (
        f"{_removed_str} {_added_str} "
        "Apply these STRICT rules in order — do NOT override them: "
        "RULE 1: If ANY fields were removed → breaking=true, severity='high'. No exceptions. "
        "RULE 2: If fields were only added (none removed) → breaking=false, severity='low'. "
        "RULE 3: If both added and removed → breaking=true, severity='high'. "
        "Return a JSON object with exactly these keys: "
        "breaking (bool), "
        "affected_fields (list of all changed field name strings), "
        "severity (one of: low, medium, high — follow RULE 1/2/3 above), "
        "recommendation (string). "
        "Example for removed field: {\"breaking\": true, \"affected_fields\": [\"required\"], "
        "\"severity\": \"high\", \"recommendation\": \"Removed field may break downstream consumers\"} "
        "Example for added field: {\"breaking\": false, \"affected_fields\": [\"new_field\"], "
        "\"severity\": \"low\", \"recommendation\": \"No action required — additive change only\"}"
    )

    try:
        raw = await classify(context, {"old": old_schema, "new": new_schema}, task)
    except Exception as exc:
        log.error(json.dumps({
            "event":   "schema_monitor_classify_exception",
            "tool_id": tool_id,
            "error":   str(exc),
        }))
        raw = {"error": str(exc), "haiku_available": False}

    # ── Haiku unavailable → safe defaults, no pipeline block ─────────────────
    if not raw or "error" in raw or raw.get("haiku_available") is False:
        result = {
            "breaking":        False,
            "affected_fields": added + removed,
            "severity":        "low",
            "recommendation":  "Haiku unavailable — manual review recommended",
            "haiku_available": False,
        }
        log.warning(json.dumps({
            "event":   "schema_monitor_haiku_unavailable",
            "tool_id": tool_id,
            "result":  result,
        }))
        # Update fingerprint even on Haiku failure (non-breaking default)
        _update_fingerprint(tool_id, new_schema)
        return result

    # ── Parse Haiku response ──────────────────────────────────────────────────
    breaking = bool(raw.get("breaking", False))

    affected_fields = raw.get("affected_fields", [])
    if not isinstance(affected_fields, list):
        affected_fields = []
    affected_fields = [str(f) for f in affected_fields]

    severity = str(raw.get("severity", "low")).lower()
    if severity not in _VALID_SEVERITIES:
        severity = "low"

    recommendation = str(raw.get("recommendation", "") or "")

    # ── Deterministic override: removed fields are ALWAYS breaking + high ─────
    # Haiku may be conservative on field-removal severity. Enforce the spec rule:
    # removed fields can break downstream consumers regardless of field naming.
    if removed and not breaking:
        log.warning(json.dumps({
            "event":    "schema_breaking_override",
            "tool_id":  tool_id,
            "reason":   "removed fields detected — forcing breaking=True, severity=high",
            "removed":  removed,
            "haiku_said_breaking": False,
        }))
        breaking   = True
        severity   = "high"
        recommendation = (
            f"Removed fields {removed} may break downstream consumers. "
            + (recommendation or "Immediate review required.")
        )
    elif removed and severity not in ("medium", "high"):
        # breaking=True but severity too low — elevate for removed fields
        severity = "high"

    result = {
        "breaking":        breaking,
        "affected_fields": affected_fields,
        "severity":        severity,
        "recommendation":  recommendation,
        "haiku_available": True,
    }

    # ── Take action based on outcome ──────────────────────────────────────────
    if breaking and severity == "high":
        # Trip circuit breaker immediately (3 calls to reach threshold)
        _write_alert(tool_id, result)
        for _ in range(3):
            record_failure(tool_id)
        log.error(json.dumps({
            "event":    "schema_breaking_high",
            "tool_id":  tool_id,
            "action":   "alert_written + circuit_tripped × 3",
        }))

    elif breaking and severity == "medium":
        _write_warning(tool_id, result)
        log.warning(json.dumps({
            "event":    "schema_breaking_medium",
            "tool_id":  tool_id,
            "action":   "warning_written",
        }))

    else:
        # Not breaking — update fingerprint only
        _update_fingerprint(tool_id, new_schema)
        log.info(json.dumps({
            "event":    "schema_not_breaking",
            "tool_id":  tool_id,
            "severity": severity,
            "action":   "fingerprint_updated",
        }))

    log.info(json.dumps({
        "event":           "schema_assess_complete",
        "tool_id":         tool_id,
        "breaking":        breaking,
        "severity":        severity,
        "affected_fields": affected_fields,
    }))

    return result
