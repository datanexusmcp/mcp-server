## Retrofits from Sprint 4 eng review (2026-05-17)

### TODO-01: Add _incr_calls() to existing t10.py tools for dashboard visibility
- **What:** Add `_incr_calls("T10")` call to the 5 existing tools in t10.py (fetch_package_vulnerabilities, fetch_cve_detail, fetch_dependency_graph, audit_sbom_vulnerabilities, fetch_package_licence). Currently only track_tool_call() (PostHog) is called; the Redis dashboard counter is missing for T10.
- **Why:** Dashboard shows per-tool call counters for T07 tools but not T10 tools. Adds parity and improves operational visibility without changing behavior.
- **Effort:** ~5 lines per tool (import + one function call). Bundle into any sprint touching t10.py.
- **Depends on:** Nothing. Standalone cleanup.
- **Where to start:** t10.py, import `_incr_calls` from core/cache or define inline same as t07.py.

### TODO-02: Extract validate_canary() as standalone importable function in core/schema.py
- **What:** core/schema.py currently has the canary validation as a Pydantic field_validator on DataNexusResponse AND (after Sprint 4) as an imported standalone function. Clean up so there's one implementation in core/schema.py exposed as `validate_canary(text: str) -> None` that both the Pydantic model and tool files call.
- **Why:** Two implementations of the same logic in the same file. Future pattern change needs one edit.
- **Effort:** 15 minutes. One function, update the Pydantic validator to delegate to it.
- **Depends on:** Sprint 4 DRY fix landing first.
- **Where to start:** core/schema.py, extract `_no_injection` body into `validate_canary()`, call from validator.

## Retrofits from Sprint 4 eng review (2026-05-17)

### TODO-01: Add _incr_calls() to existing t10.py tools for dashboard visibility
What: Add `_incr_calls("T10")` to the 5 existing tools in t10.py. Redis dashboard counter is missing for T10 tools; T07 already has it.
Why: Dashboard parity — T07 shows call counts, T10 doesn't. Trivial fix.
Effort: 5 lines per tool. Bundle into any sprint touching t10.py.
Depends on: Nothing. Standalone.

### TODO-02: Extract validate_canary() as importable function in core/schema.py
What: After Sprint 4's DRY fix, clean up so core/schema.py exposes `validate_canary(text) -> None` as one function that both Pydantic model and tool files call.
Why: Sprint 4 moves from 6 file copies → 1 import. This TODO removes the remaining Pydantic/standalone duplication in schema.py itself.
Effort: 15 min. One function, Pydantic validator delegates to it.
Depends on: Sprint 4 DRY fix landing first.
