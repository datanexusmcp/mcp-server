"""
feedback/pre_classifier.py — Deterministic pre-classification of feedback records.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.3 / Section 11.6 Step 5

Hard rules (non-negotiable):
  - ZERO Claude API calls at all times — this module is purely rule-based.
  - classify_record() returns ('pending', 0.0) whenever FEEDBACK_AGENTS_ACTIVE=False.
  - classify_missing_field() is key-lookup only — no network, no subprocess.
  - No imports of anthropic, openai, or any LLM client here.

Purpose:
  Screen FeedbackRecords before they reach the AI classification agents
  (Phase 4 Steps 6-10). Catches obvious cases deterministically so the
  agents only process genuinely ambiguous records.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Tuple

from feedback.config import (
    BUG_SIGNALS,
    FEEDBACK_AGENTS_ACTIVE,
    IMPROVEMENT_SIGNALS,
)

if TYPE_CHECKING:
    from feedback.models import FeedbackRecord

# ── Known implemented fields by tool ─────────────────────────────────────────
# classify_missing_field() returns 'already_implemented' for any field in
# the relevant set, and 'needs_human_review' for anything not listed.
#
# Update this map when a tool adds or removes fields — do NOT widen the
# 'already_implemented' set speculatively.

_IMPLEMENTED_FIELDS: dict[str, frozenset[str]] = {
    "T04": frozenset({
        # Standard response envelope
        "query_hash", "schema_version", "data_as_of", "ingest_healthy",
        # Common tool fields
        "status", "tool_id", "source_url", "fetch_timestamp",
        "cache_hit", "sha256_hash", "staleness_notice",
        "markdown_output", "disclaimer",
        # US nonprofit (IRS EO BMF + TEOS)
        "ein", "name", "city", "state", "country",
        "ruling_date", "ntee_code", "org_type",
        "income_amt", "revenue_amt", "asset_amt",
        "form_990_filings", "latest_filing_year",
        "deductibility_code", "subsection_code",
        "activity_codes", "affiliation_code",
        "foundation_code", "classification_code",
        # UK Charity Commission
        "charity_number", "registration_date", "removal_date",
        "activities", "income", "expenditure", "web",
        "source",
    }),
    "T10": frozenset({
        # Standard response envelope
        "query_hash", "schema_version", "data_as_of", "ingest_healthy",
        # Common tool fields
        "status", "tool_id", "source_url", "fetch_timestamp",
        "cache_hit", "sha256_hash", "staleness_notice",
        "markdown_output", "disclaimer",
        # fetch_package_vulnerabilities / fetch_cve_detail
        "cve_id", "description", "cvss_base_score", "cvss_severity",
        "cvss_vector", "published", "last_modified", "references",
        "aliases", "affected", "severity", "fixed_versions",
        # fetch_dependency_graph
        "nodes", "total_deps", "package", "version", "ecosystem",
        # fetch_package_licence
        "licences", "is_default",
        # audit_sbom_vulnerabilities
        "total_components", "total_vulns", "severity_summary",
        "components", "highest_severity", "vuln_count", "cve_ids",
    }),
}


# ── Public API ─────────────────────────────────────────────────────────────────

def classify_missing_field(tool_id: str, field_name: str) -> str:
    """
    Deterministic classifier for 'missing_field' feedback signals.

    Returns:
      'already_implemented'  — the field exists in the tool's response schema.
      'needs_human_review'   — the field is not recognised; needs a human decision.

    No network calls. No Claude calls. Pure key-lookup.

    Args:
      tool_id:    e.g. 'T04', 'T10'
      field_name: the field name the user reported as missing, e.g. 'ein'
    """
    known = _IMPLEMENTED_FIELDS.get(tool_id, frozenset())
    if field_name in known:
        return "already_implemented"
    return "needs_human_review"


def classify_record(record: "FeedbackRecord") -> Tuple[str, float]:
    """
    Pre-classify a FeedbackRecord before it reaches the AI agents.

    When FEEDBACK_AGENTS_ACTIVE=False (default):
      Always returns ('pending', 0.0) — records queue for later processing.

    When FEEDBACK_AGENTS_ACTIVE=True:
      Applies deterministic rule-based heuristics only (no LLM calls):
        - BUG_SIGNALS    → ('bug',         0.8)
        - IMPROVEMENT_SIGNALS → ('improvement', 0.7)
        - Anything else  → ('pending',     0.0)

    The AI agents (Steps 6-10) handle the 'pending' records with confidence
    scores below the acceptance threshold.

    Returns:
      Tuple[classification: str, score: float]
        classification: 'pending' | 'bug' | 'improvement' | 'duplicate' | 'noise'
        score:          0.0–1.0 classifier confidence
    """
    if not FEEDBACK_AGENTS_ACTIVE:
        return ("pending", 0.0)

    signal = getattr(record, "signal", "")

    if signal in BUG_SIGNALS:
        return ("bug", 0.8)

    if signal in IMPROVEMENT_SIGNALS:
        return ("improvement", 0.7)

    return ("pending", 0.0)
