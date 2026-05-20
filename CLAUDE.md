# CLAUDE.md — MCP Tool Quality & Security Standard
# Version: 1.1 | April 2026
# Applies to: All MCP server tools in this repository
# Owner: Review required before every deploy

---

## 0. Prime directive

Every tool built from this repository must meet or exceed Glama security score 8.5.
Every tool must run correctly on Claude, Cursor, VS Code (GitHub Copilot), and Windsurf.
No tool ships without passing all gates in Section 7.
When in doubt, fail closed — return an error, never a partial result with hidden failure.

---

## 1. Repository structure (enforce this layout, no exceptions)

```
tools/
  {tool-name}/
    server.py          # FastMCP entrypoint — single file, no sprawl
    validators.py      # All input validation logic lives here
    cache.py           # Redis cache layer
    tests/
      test_schema.py   # Pydantic schema validation tests
      test_injection.py  # Injection and boundary tests
      test_billing.py  # Idempotency and billing tests
      test_load.py     # 500-concurrent load test
    TOOL_SPEC.md       # Upstream API details, ToS confirmation, expansion hard stop
    CHANGELOG.md       # Semantic versioning log
    requirements.txt   # Pinned versions only — no loose constraints
scripts/
  security_review.py  # /security-review skill runner
  load_test.py        # /load-test skill runner
  deploy.sh           # Publisher gate — runs all checks before Hetzner deploy
CLAUDE.md             # This file
```

---

## 2. Technology stack (non-negotiable)

- **Framework**: FastMCP (Python) — no raw JSON-RPC, no custom transport
- **Transport**: Streamable HTTP for all remote tools. stdio only for local dev.
  - SSE is deprecated as of April 2026 — do not use it
- **Auth**: OAuth 2.1 with incremental scope consent for all remote tools
  - API keys in env vars only — never in code, never in config files committed to git
  - Plaintext secrets in config = immediate build failure
- **Cache**: Redis with TTL per tool category (see Section 4)
- **Validation**: Pydantic v2 for all input and output schemas
- **Python version**: 3.11+ minimum
- **Dependencies**: Pin all versions in requirements.txt. Run `pip-audit` before every deploy.

---

## 2b. Tool design principles (Anthropic production guidance, April 2026)

**Group tools around intent, not API endpoints.**
A single `fetch_nonprofit_by_ein` beats `get_organization` + `get_filings` + `get_address` + `merge_result`.
The agent must accomplish a task in one or two calls — not stitch primitives together.
Builder must not add convenience signatures that fragment a workflow into multiple round trips.

**Fewer, well-described tools consistently outperform exhaustive API mirrors.**
Do not wrap the upstream API one-to-one. Each tool signature must map to a professional workflow intent,
not a raw endpoint. If you find yourself creating a tool that only makes sense as a step inside another
tool call — stop. Merge them or cut them.

**When an upstream service requires many distinct operations (wide APIs like T11 Patents, T18 GovCon):**
Expose a thin tool surface that accepts structured intent input and returns only the composed result.
The agent writes one structured query; the tool handles the fan-out internally and returns one clean response.

**Structured error responses so agents can reason about failures:**
```python
# CORRECT — agent can branch on error_code
return {
    "status":        "error",
    "error_code":    "upstream_timeout",  # from defined enum in Section 3.2
    "message":       "Data source temporarily unavailable",
    "retry_after":   30,
    "query_hash":    ctx.query_hash,      # always present — enables feedback
    "ingest_healthy": False,
}

# WRONG — agent cannot reason about this
return {"error": str(e)}
```

Agents that receive structured error codes can retry intelligently, surface the right message to users,
and submit accurate feedback via report_feedback(). Unstructured errors break all three.

---

## 3. Security — hard requirements (non-negotiable)

### 3.1 Input validation (every single parameter, no exceptions)

```python
# REQUIRED pattern for every tool parameter
from pydantic import BaseModel, Field, field_validator
import re

class ToolInput(BaseModel):
    query: str = Field(
        min_length=1,
        max_length=500,
        description="Search query"
    )

    @field_validator('query')
    @classmethod
    def sanitize_query(cls, v):
        # Strip shell metacharacters
        if re.search(r'[;&|`$<>\\]', v):
            raise ValueError("Invalid characters in query")
        # Strip SQL injection patterns
        sql_patterns = r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)\b'
        if re.search(sql_patterns, v, re.IGNORECASE):
            raise ValueError("Invalid query pattern")
        return v.strip()
```

- Every tool parameter goes through a Pydantic model — no raw dict access
- String length limits on every field — no unbounded inputs
- Reject requests with characters outside expected set for that field type
- Log rejected inputs (without echoing them back in the error response)

### 3.2 Error responses — never leak internals

```python
# CORRECT — clean error, no stack trace
return {"error": "upstream_unavailable", "message": "Data source temporarily unavailable", "retry_after": 30}

# WRONG — never do this
return {"error": str(e), "traceback": traceback.format_exc()}
```

Rules:
- Never return raw exception strings
- Never return stack traces
- Never return internal paths, env var names, or upstream API URLs
- Error codes must be from a defined enum — no freeform error strings
- Log full error internally, return clean message externally

### 3.3 Principle of least privilege

- Request read-only tokens wherever read-only is sufficient
- Scope API permissions to the minimum required for the tool's function
- Document in TOOL_SPEC.md exactly which permissions are requested and why
- If upstream API requires write permissions, flag in Gate 1 review (human approval)

### 3.4 Credential management

```bash
# CORRECT — env vars only
export UPSTREAM_API_KEY="your_key_here"

# WRONG — never commit these
API_KEY = "sk-abc123..."  # Hard-coded in source
```

- All secrets via environment variables — `python-dotenv` for local dev, Hetzner secrets for prod
- `.env` files are in `.gitignore` — pre-commit hook verifies this
- `detect-secrets` runs on every commit and blocks if a secret pattern is found
- Rotate all API keys on a 90-day schedule — calendar reminder in TOOL_SPEC.md

### 3.5 Rate limiting (every remote tool, no exceptions)

```python
from fastmcp import FastMCP
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@mcp.tool()
@limiter.limit("60/minute")   # Adjust per tool — document the limit in TOOL_SPEC.md
async def search_tool(query: str) -> dict:
    ...
```

- Default limit: 60 requests/minute per IP
- Burst allowance: 10 requests/second maximum
- Return HTTP 429 with `Retry-After` header on limit breach
- Per-user limits when auth is present (stricter than per-IP)
- Document rate limits in the tool's Glama listing description

### 3.6 Audit logging

```python
import structlog
log = structlog.get_logger()

# Log every tool invocation — never log the actual data returned
log.info("tool_invoked",
    tool_name="trademark_search",
    user_id=user_id,          # hashed, not raw
    query_length=len(query),  # length only, not content
    timestamp=datetime.utcnow().isoformat()
)
```

- Log every invocation with: tool name, hashed user ID, timestamp, response time, success/fail
- Never log actual query content or returned data (PII risk)
- Log format: structured JSON — no freeform strings
- Retention: 30 days minimum

---

## 4. Caching — required for all tools hitting external APIs

```python
import redis
import hashlib
import json

r = redis.Redis(host='localhost', port=6379, db=0)

def cache_key(tool_name: str, params: dict) -> str:
    canonical = json.dumps(params, sort_keys=True)
    return f"{tool_name}:{hashlib.sha256(canonical.encode()).hexdigest()}"

async def cached_call(tool_name: str, params: dict, fetch_fn, ttl: int) -> dict:
    key = cache_key(tool_name, params)
    cached = r.get(key)
    if cached:
        return json.loads(cached)
    result = await fetch_fn(params)
    r.setex(key, ttl, json.dumps(result))
    return result
```

TTL standards by data category:
- Static reference data (standards, legislation text): 24 hours
- Company/trademark registry data: 4 hours
- Real estate / property data: 2 hours
- DNS / domain data: 30 minutes
- Any data the user expects to be live: 5 minutes maximum, document the lag

Cache must be bypassed on explicit user request (`force_refresh=True` parameter).
Cache key must include all parameters that affect the result — no partial keys.

---

## 5. Tool specification standard (every tool needs TOOL_SPEC.md)

```markdown
# Tool: {name}
# Version: 1.0.0
# Last reviewed: YYYY-MM-DD

## Upstream API
- Name:
- URL:
- Auth method:
- Rate limits imposed by upstream:
- ToS commercial use confirmed: YES / NO (link to ToS clause)
- Free tier limits:
- Cost at 1000 calls/day:

## Permissions requested
- [ ] Read-only
- [ ] Write (requires Gate 1 human approval)
- Specific scopes: list them

## Expansion hard stop
The following capabilities are explicitly OUT OF SCOPE for this tool:
- (list what the Builder agent must NOT implement)

## Data freshness
- Cache TTL: X minutes/hours
- Lag disclosed to user: YES / NO
- Staleness risk: describe

## Rate limits (our tool)
- Per IP: 60/minute
- Per user: X/minute
- Burst: 10/second

## Failure modes
- Upstream down: return error code X, message Y
- Rate limit hit: return 429 with retry_after
- Auth failure: return 401, no detail

## Secret rotation due
- Next rotation: YYYY-MM-DD
```

---

## 6. FastMCP implementation template

Every tool must start from this template — not from scratch:

```python
"""
Tool: {name}
Version: 1.0.0
Transport: Streamable HTTP
Auth: OAuth 2.1
"""
from fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator
from validators import sanitize_string  # from validators.py
from cache import cached_call
import structlog
import httpx
import os

log = structlog.get_logger()
mcp = FastMCP("{tool-name}")

UPSTREAM_API_KEY = os.environ.get("UPSTREAM_API_KEY")
if not UPSTREAM_API_KEY:
    raise RuntimeError("UPSTREAM_API_KEY not set — refusing to start")

class SearchInput(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=10, ge=1, le=50)

    @field_validator('query')
    @classmethod
    def validate_query(cls, v):
        return sanitize_string(v)  # centralized validation

@mcp.tool()
async def search(input: SearchInput) -> dict:
    """
    {One-sentence description meeting Glama 6-dimension standard}
    Returns: {describe structure}
    Rate limit: 60/minute per IP
    Data freshness: cached 4 hours
    """
    log.info("tool_invoked", tool="search", query_length=len(input.query))

    try:
        result = await cached_call(
            tool_name="search",
            params=input.model_dump(),
            fetch_fn=_fetch_from_upstream,
            ttl=14400  # 4 hours
        )
        return {"status": "ok", "data": result, "cached": True}

    except httpx.TimeoutException:
        log.error("upstream_timeout", tool="search")
        return {"status": "error", "error": "upstream_timeout", "retry_after": 30}

    except httpx.HTTPStatusError as e:
        log.error("upstream_error", status=e.response.status_code)
        return {"status": "error", "error": "upstream_unavailable"}

    except Exception:
        log.exception("unexpected_error", tool="search")
        return {"status": "error", "error": "internal_error"}

async def _fetch_from_upstream(params: dict) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            "https://api.upstream.com/search",
            params={"q": params["query"], "limit": params["limit"]},
            headers={"Authorization": f"Bearer {UPSTREAM_API_KEY}"}
        )
        response.raise_for_status()
        return response.json()

if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
```

---

## 7. Mandatory gates before deploy (QA agent enforces all of these)

Gate 1 — Policy & Legal (human, ~10 min per tool):
- [ ] ToS of upstream API confirmed for commercial use
- [ ] Expansion hard stop documented in TOOL_SPEC.md
- [ ] No write permissions without explicit approval

Gate 2 — Automated QA (blocks Publisher if any fail):
- [ ] Pydantic schema validation tests pass (100% coverage on input models)
- [ ] Injection tests pass (SQL, shell, path traversal, prompt injection)
- [ ] Billing idempotency test passes (duplicate call = same result, no double-charge)
- [ ] Glama quality score >= 8.5
- [ ] 500-concurrent load test passes with p99 < 2000ms
- [ ] `detect-secrets` scan returns clean
- [ ] `pip-audit` returns no critical CVEs
- [ ] Error response test: no stack traces, no internal paths in any error output
- [ ] Rate limiter test: 429 returned correctly on breach with Retry-After header
- [ ] Cache test: second identical call hits cache, not upstream

Gate 3 — Publisher (human confirmation, ~10 min per tool):
- [ ] Stripe price IDs set in config.py
- [ ] Glama keywords confirmed (6-dimension standard)
- [ ] "Try in Browser" test on Glama passes
- [ ] CHANGELOG.md entry written with semantic version bump
- [ ] Status page updated to include new tool

---

## 8. Skills (Claude Code runs these on demand)

### /security-review
Run before every commit. Checks:
1. No hardcoded secrets (regex scan + detect-secrets)
2. All tool parameters go through Pydantic validator
3. No raw exception strings in any return value
4. Rate limiter decorator present on every @mcp.tool()
5. Audit log.info call present in every @mcp.tool()
6. All httpx calls have timeout= set (max 15s)
7. UPSTREAM_API_KEY loaded from env, not hardcoded
8. No `eval()`, `exec()`, `os.system()`, `subprocess.shell=True` anywhere

Output: PASS / FAIL with line numbers. Block commit on FAIL.

### /load-test
Runs 500 concurrent requests against the tool endpoint.
Accepts: tool name, endpoint URL
Reports: p50, p95, p99 latency, error rate, rate limit trigger count
Threshold: p99 must be < 2000ms, error rate < 0.1%
Block deploy if threshold not met.

### /spec-review
Validates TOOL_SPEC.md is complete:
- ToS confirmation present
- All sections filled
- Expansion hard stop defined
- Secret rotation date set
- Rate limits documented

### /changelog-entry
Generates CHANGELOG.md entry from git diff since last tag.
Format: semantic version bump, list of changes, breaking changes flagged.

---

## 9. Multi-client compatibility (test on all four before listing)

Every tool must be verified working on:
- [ ] Claude Desktop (claude.ai)
- [ ] Cursor
- [ ] VS Code with GitHub Copilot (MCP enabled)
- [ ] Windsurf

Test script: `scripts/multi_client_test.sh` — runs a canonical query against each client config and compares output structure. Any client returning an error = tool not shippable.

---

## 10. Upstream API monitoring

For each tool, set a GitHub Action that:
- Pings the upstream API endpoint daily
- Checks the upstream API's changelog RSS feed weekly
- Opens a GitHub issue automatically if the API returns non-200 or schema changes
- Tags the issue `upstream-change` for triage

Tools that go silent because the upstream changed with no alert are a reputation risk.
This monitoring is non-optional.

---

## 11. What the Builder agent must never do

The Builder agent reads this section first. These are hard stops:

- Never implement capabilities listed in TOOL_SPEC.md expansion hard stop
- Never write to external systems unless Gate 1 has approved write permissions
- Never store user query content in any persistent store
- Never add a dependency not in requirements.txt without running pip-audit first
- Never use `shell=True` in subprocess calls
- Never catch bare `Exception` without re-raising or logging with full context
- Never return HTTP 500 without a structured error body
- Never commit without running /security-review first
- Never change @verify_entitlement or Stripe billing code — those require human PR
- Never use SSE transport — deprecated as of late 2025. Never use stdio for remote tools — local only. Use Streamable HTTP (`mcp.run(transport="streamable-http")`) for all remote tools. This is non-negotiable — Glama and all major MCP clients (Claude, Cursor, Windsurf) are optimised for Streamable HTTP.

### 11.2 Haiku trigger guard

Haiku is called ONLY on the 4 triggers in Section 13.2 of DataNexus_MCP_Spec_v7_6.docx.
Human PR required for any new trigger.

---

## 12. Versioning and maintenance commitment

- Semantic versioning: MAJOR.MINOR.PATCH
  - PATCH: bug fix, no API change
  - MINOR: new optional parameter, backward compatible
  - MAJOR: breaking change — requires advance notice in listing description
- Response to upstream API change: fix within 48 hours or mark tool as deprecated
- Security vulnerability report: fix within 24 hours or take tool offline
- Minimum maintenance window: tools with zero users after 90 days may be archived

---

## 13. Glama 6-dimension tool description standard

Every tool description submitted to Glama must answer these six dimensions:

1. **What it does** — one sentence, verb-first ("Searches", "Returns", "Fetches")
2. **Data source** — name the upstream explicitly ("Uses USPTO TESS API")
3. **Freshness** — state the cache TTL ("Data refreshed every 4 hours")
4. **Rate limit** — state the limit ("60 requests/minute per user")
5. **Auth required** — yes/no and method ("Requires OAuth 2.1 login")
6. **Use case** — who uses this and why ("For brand lawyers verifying trademark conflicts")

Example:
> Searches USPTO TESS for trademark registrations by keyword or owner name. Uses USPTO public API — data refreshed every 4 hours. Rate limit: 60/minute. No auth required. For brand lawyers, Amazon sellers, and compliance teams verifying trademark conflicts before product launch.

---

*This file is the single source of truth for all MCP tool quality standards in this repository.
Any deviation requires a PR with explicit justification and human approval.
Claude Code enforces this file on every build.*

---

## Section 13 — Haiku Validation Rules
## (DataNexus_MCP_Spec_v7_6.docx Section 13)

Rule S13-1: Haiku called ONLY on 4 triggers:
  T1 anomaly_reviewer.review_anomaly()
  T2 feedback_classifier.classify_feedback()
  T3 schema_monitor.assess_schema_change()
  T4 digest_generator.generate_weekly_digest()
  Any new trigger requires human PR + spec update.
  No exceptions.

Rule S13-2: Use HAIKU_MODEL from
  feedback/config.py. Never hardcode the model
  string in any other file. Violation blocks
  commit via /security-review gate.

Rule S13-3: HAIKU_MAX_CALLS_PER_DAY (100) is
  non-negotiable. When limit reached: return
  error dict, log WARNING, never reset or bypass
  the counter. Never set > 100 without human PR.

Rule S13-4: validate_tool_output() never raises
  and never blocks. All exceptions caught and
  logged at ERROR level. Structured error dict
  always returned. Caller always gets a response.

Rule S13-5: FeedbackRecord.classification is
  one-way only. Allowed transitions:
  pending → confirmed | rejected | needs_review.
  NEVER transition backwards to pending.
  feedback_classifier.py enforces this.
  Any code violating this rule must be rejected
  in code review.

## Sprint Discipline — Deploy Rules

Rule D1: Never push to git or deploy to Hetzner
  mid-sprint. Code stays local until ALL smoke
  tests for that tool pass AND operator confirms.
  One tool = one confirmation = one push.
  No batching incomplete tools into a single push.

Rule D2: Never register a tool in main.py on
  Hetzner before its smoke tests pass locally.
  Registration in main.py on Hetzner is the
  final step after confirmation — not during build.

Rule D3: glama.json tool count must be updated
  in the same commit as every tool registration.
  Never let glama.json description fall behind
  the actual registered tool count.

---

## OAuth 2.1 Requirements (Sprint 3)

Hard requirements before MCPIZE_ACTIVE=true:
- Token validation before @verify_entitlement on every paid call
- Tokens in Redis only: oauth:token:{session_id} with 1-hour TTL
- PKCE: S256 required — plain method MUST be rejected
- Token audience MUST be datanexusmcp.com (RFC 8707)
- Unauthenticated requests allowed ONLY when MCPIZE_ACTIVE=false
- MCPize is the AS — DataNexus validates tokens only, never issues them
- Implementation: Sprint 4

Builder hard stops:
- NEVER implement token issuance
- NEVER store tokens in module-level memory
- NEVER accept plain PKCE
- NEVER enforce OAuth when MCPIZE_ACTIVE=false

---

## gstack

Use the `/browse` skill from gstack for all web browsing tasks.
gstack is installed at `~/.claude/skills/gstack`. The `/browse` skill provides a headless Chromium browser with full page rendering, JS execution, and screenshot support — use it instead of any other web fetch or browser tool whenever you need to load a URL, scrape a page, or interact with a web interface.

---

## PostHog Analytics — Privacy Rules

Rule: PostHog events must NEVER include:
  - Query parameters (ein, npi, domain, etc.)
  - User identifiable information
  - Raw tool inputs or outputs
  - IP addresses or session tokens

Allowed properties: tool_id, tool_name, tool_group,
  success, latency_ms, cache_hit, error_code,
  ecosystem, jurisdiction, date.

The anon_id() rotates daily and cannot be
linked to any individual across days.
