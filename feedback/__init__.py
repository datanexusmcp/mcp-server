"""
feedback — DataNexus Phase 4 Feedback System.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8 + Section 9
Build order: Section 11.6

Sub-packages:
  feedback.agents     — AI classification agents (Phase 4 Steps 6-10)
  feedback.dashboard  — Digest & reporting (Phase 4 Steps 11-13)
  feedback.cli        — Management CLI (Phase 4 Steps 14-15)
  feedback.tests      — Test suite

Core modules:
  feedback.config         — All constants and Redis key functions
  feedback.models         — Pydantic v2 data models
  feedback.audit          — Audit helpers (re-exports datanexus.core.audit)
  feedback.pre_classifier — Deterministic pre-classification (zero Claude calls)
"""
