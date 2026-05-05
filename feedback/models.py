"""
feedback/models.py — Pydantic v2 data models for the feedback system.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.2 / Section 11.6 Step 3

Four models:
  FeedbackInput   — validated inbound signal from report_feedback()
  FeedbackRecord  — persisted record (FeedbackInput + server-side fields)
  AuditRecord     — telemetry record per tool invocation
  DigestItem      — daily rolled-up summary per tool
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from feedback.config import (
    ALL_SIGNALS,
    FEEDBACK_ENABLED_TOOLS,
)


# ══════════════════════════════════════════════════════════════════════════════
# FeedbackInput — validated inbound signal
# ══════════════════════════════════════════════════════════════════════════════

class FeedbackInput(BaseModel):
    """
    Validated inbound feedback from a user or agent via report_feedback().

    Validation rules:
      - tool_id must be in FEEDBACK_ENABLED_TOOLS (currently T04, T10).
      - query_hash must be 16–64 hex characters (links feedback to audit record).
      - signal must be in ALL_SIGNALS (= BUG_SIGNALS | IMPROVEMENT_SIGNALS).
        BUG_SIGNALS:         not_useful, incorrect_data, missing_field,
                             hallucination, wrong_entity, stale_data, data_quality
        IMPROVEMENT_SIGNALS: helpful, very_helpful, feature_request,
                             good_result, saved_time
      - missing_fields is REQUIRED (non-empty list) when signal == 'missing_field'.
      - comment max 1000 chars; stripped on ingress.
    """

    tool_id: str = Field(
        min_length=2,
        max_length=10,
        description="Tool ID — must be in FEEDBACK_ENABLED_TOOLS.",
    )
    query_hash: str = Field(
        min_length=16,
        max_length=64,
        description="Hash returned by the tool call — links feedback to the audit record.",
    )
    signal: str = Field(
        description="Feedback signal — must be in ALL_SIGNALS.",
    )
    comment: str = Field(
        default="",
        max_length=1_000,
        description="Optional free-text comment (max 1000 chars).",
    )
    missing_fields: Optional[List[str]] = Field(
        default=None,
        description="Required when signal == 'missing_field'. List of field names absent from the response.",
    )

    @field_validator("tool_id")
    @classmethod
    def validate_tool_id(cls, v: str) -> str:
        if v not in FEEDBACK_ENABLED_TOOLS:
            raise ValueError(
                f"tool_id '{v}' is not enabled for feedback. "
                f"Enabled tools: {sorted(FEEDBACK_ENABLED_TOOLS)}"
            )
        return v

    @field_validator("signal")
    @classmethod
    def validate_signal(cls, v: str) -> str:
        if v not in ALL_SIGNALS:
            raise ValueError(
                f"signal '{v}' is not valid. "
                f"Valid signals: {sorted(ALL_SIGNALS)}"
            )
        return v

    @field_validator("comment")
    @classmethod
    def strip_comment(cls, v: str) -> str:
        return v.strip()

    @field_validator("missing_fields")
    @classmethod
    def validate_missing_fields_items(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            cleaned = [f.strip() for f in v if f.strip()]
            if not cleaned:
                raise ValueError(
                    "missing_fields must contain at least one non-empty field name."
                )
            return cleaned
        return v

    @model_validator(mode="after")
    def require_missing_fields_for_signal(self) -> "FeedbackInput":
        """missing_fields is required (non-None, non-empty) when signal == 'missing_field'."""
        if self.signal == "missing_field" and not self.missing_fields:
            raise ValueError(
                "missing_fields is required and must be non-empty "
                "when signal is 'missing_field'."
            )
        return self


# ══════════════════════════════════════════════════════════════════════════════
# FeedbackRecord — persisted record
# ══════════════════════════════════════════════════════════════════════════════

class FeedbackRecord(BaseModel):
    """
    Persisted feedback record — FeedbackInput + server-side fields added on write.

    Stored in Redis as a hash at key_feedback(tool_id, record_id).
    Added to the feedback_list sorted set scored by received_at timestamp.
    """

    # --- from FeedbackInput ---
    tool_id:        str
    query_hash:     str
    signal:         str
    comment:        str = ""
    missing_fields: Optional[List[str]] = None

    # --- server-side ---
    record_id:      str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID assigned on write.",
    )
    received_at:    str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of ingestion.",
    )
    classification: str = Field(
        default="pending",
        description="Classifier result: pending | bug | improvement | duplicate | noise.",
    )
    score:          float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Classifier confidence score 0.0–1.0.",
    )
    agent_version:  str = Field(
        default="",
        description="Version of the classifier agent that processed this record.",
    )

    @classmethod
    def from_input(cls, inp: FeedbackInput) -> "FeedbackRecord":
        """Construct a FeedbackRecord from a validated FeedbackInput."""
        return cls(
            tool_id=inp.tool_id,
            query_hash=inp.query_hash,
            signal=inp.signal,
            comment=inp.comment,
            missing_fields=inp.missing_fields,
        )


# ══════════════════════════════════════════════════════════════════════════════
# AuditRecord — per-invocation telemetry
# ══════════════════════════════════════════════════════════════════════════════

class AuditRecord(BaseModel):
    """
    Telemetry record for a single tool invocation.

    Written by AuditContext.__aexit__() via write_audit().
    Stored in Redis as a hash at key_audit(query_hash) with AUDIT_TTL.
    """

    tool_id:          str
    query_hash:       str = Field(min_length=16, max_length=64)
    params_hash:      str = Field(min_length=16, max_length=64)
    schema_version:   str = "1.0"
    ts:               str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    response_time_ms: int  = Field(ge=0)
    cache_hit:        bool = False
    ingest_healthy:   bool = True
    error:            bool = False
    error_type:       str  = ""
    retry_attempt:    int  = Field(default=0, ge=0)


# ══════════════════════════════════════════════════════════════════════════════
# DigestItem — daily rolled-up summary per tool
# ══════════════════════════════════════════════════════════════════════════════

class DigestItem(BaseModel):
    """
    Daily aggregated feedback summary for a tool.

    Generated once per day per tool by the digest worker.
    Stored in Redis at key_digest(tool_id, date) with DIGEST_TTL.

    Section 13 additions (Phase 6): top_issues, suggested_rules,
    data_quality_score, sprint_recommendations added as optional fields
    with defaults so existing tests continue to pass.
    """

    tool_id:          str
    date:             str = Field(
        description="Date string YYYY-MM-DD (UTC).",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    total_count:      int = Field(default=0, ge=0)
    bug_count:        int = Field(default=0, ge=0)
    improvement_count: int = Field(default=0, ge=0)
    pending_count:    int = Field(default=0, ge=0)
    top_signals:      List[str] = Field(
        default_factory=list,
        description="Top 5 signal names by frequency for this day.",
    )
    generated_at:     str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    # ── Section 13 / Phase 6 additions ───────────────────────────────────────
    top_issues:            List[str] = Field(
        default_factory=list,
        description="Top recurring data quality issues identified by Haiku.",
    )
    suggested_rules:       List[str] = Field(
        default_factory=list,
        description="Suggested validator rules to address top issues.",
    )
    data_quality_score:    float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Overall data quality score 0.0–1.0. 1.0 = no issues found.",
    )
    sprint_recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable sprint items generated by the weekly digest.",
    )
