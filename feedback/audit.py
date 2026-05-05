"""
feedback/audit.py — Audit helpers for the feedback system.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 9.3.3 / Section 11.6 Step 4

Re-exports the four audit primitives from datanexus.core.audit so that
feedback-system code has a single, stable import path that does not
depend directly on the datanexus package layout.

Exports:
  make_params_hash        — deterministic SHA-256 of a params dict (key-order-independent)
  write_audit             — write AuditRecord + telemetry counters to Redis
  AuditContext            — async context manager wrapping a tool call with telemetry
  standard_response_fields — returns the exactly-4-key dict every tool response must include

Rules (from datanexus.core.audit docstring — enforced here too):
  - make_params_hash: NEVER store raw param values — hash only.
  - AuditContext: NEVER suppresses exceptions (returns False from __aexit__).
  - standard_response_fields: returns EXACTLY 4 keys — never add more.
"""

from datanexus.core.audit import (
    AuditContext,
    make_params_hash,
    standard_response_fields,
    write_audit,
)

__all__ = [
    "make_params_hash",
    "write_audit",
    "AuditContext",
    "standard_response_fields",
]
