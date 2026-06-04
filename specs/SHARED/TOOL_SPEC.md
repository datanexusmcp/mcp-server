# Tool: SHARED — Infrastructure Tools
# Version: 1.0.0
# Last reviewed: 2026-05-10
# Tools: report_feedback, report_mcpize_link, validate_tool_output

### Data sources
- `report_feedback` — internal feedback store (`feedback/` module); no external API
- `report_mcpize_link` — internal payment config (`payment/tools.py`); no external API
- `validate_tool_output` — local Pydantic schema validation; no external API
- ToS: internal only — no upstream ToS applies
- Auth: @verify_entitlement on data tools only; infrastructure tools are unentitled by design

### Signatures
```python
async def report_feedback(
    tool_id: str,
    query_hash: str,
    signal: str,        # "positive" | "negative" | "neutral"
    comment: str = ""
) -> dict               # {"status": "recorded"}

async def report_mcpize_link(tool_id: str = "") -> dict
# Returns: {"status": "free"} or {"upgrade_url": str, "status": "paid"}

async def validate_tool_output(
    tool_id: str,
    output: dict,
    schema_version: str = "1.0"
) -> dict
# Returns: {"valid": bool, "errors": list[str]}
```

**Return fields (report_feedback):** `status`

**Return fields (report_mcpize_link):** `status`, `upgrade_url` (when active)

**Return fields (validate_tool_output):** `valid`, `errors`, `schema_version`,
`tool_id`, `query_hash`

**upstream_fields:** none — all internal

### Hard stops
- `validate_tool_output` MUST NEVER raise an exception — all exceptions caught and logged at ERROR; structured error dict always returned (Rule S13-4)
- `validate_tool_output` MUST NEVER block a tool response — call is best-effort only
- `report_feedback` stores `params_hash` only — NEVER stores query content or returned data
- `report_mcpize_link` MUST NOT be called with customer payment data — upgrade URL only
- `@verify_entitlement` and Stripe billing code: NEVER modify without human PR (Rule D-billing)
- `FeedbackRecord.classification` is one-way: `pending → confirmed | rejected | needs_review` — NEVER transition backwards to `pending` (Rule S13-5)

### Known gaps
- `report_feedback` stub in t04.py Phase 2 — replaced by `feedback.collector.report_feedback` in Phase 4
- `report_mcpize_link` delegates to `payment.tools` — free-window returns `status=free`; upgrade URL active post-Phase 5 billing setup
- `validate_tool_output` schema registry covers T04, T07, T10, T11, T18, T19, T22 only; new tools must register schema before first deploy

### Cache TTL
- None — all three tools are stateless or write-only; caching does not apply

### Acceptance criteria
- `report_feedback("T04", "abc123", "positive")` returns `{"status": "recorded"}` — never raises
- `report_mcpize_link("T04")` returns dict with `status` key — never raises
- `validate_tool_output("T04", {})` returns `{"valid": False, "errors": [...]}` — never raises, never blocks
- `validate_tool_output` with valid T04 output returns `{"valid": True, "errors": []}`
- All three tools return structured dict on any internal error — no exception propagation
- `report_feedback` audit log contains `params_hash` only — no query content, no response data
- Calling `validate_tool_output` with malformed input does not affect the calling tool's response
