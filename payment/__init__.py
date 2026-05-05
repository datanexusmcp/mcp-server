"""
payment — DataNexus Phase 5 Payment Infrastructure.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10

Modules:
  payment.config       — MCPIZE_ACTIVE flag, MCPIZE_URLS, Redis key functions
  payment.entitlement  — Full @verify_entitlement decorator (6 conditions + telemetry)
  payment.webhook      — MCPize webhook handler (signature verification + entitlement writes)
  payment.tools        — report_mcpize_link() MCP tool (3 scenarios)
  payment.tests        — Acceptance test suite (10 criteria, Section 10 Table 133)

NEVER modify entitlement.py or webhook.py without a human PR.
(Billing bypass risk — CLAUDE.md Rule #2)
"""
