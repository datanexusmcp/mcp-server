# DataNexus MCP — Sprint 8 Implementation Prompt
# Focus: Sub-category Taxonomy + Backend Security Depth + Frontend Security Wedge
# Sprint 8A: Global API Key + Soft-Gate Free Tier (implement first)
# Sprint 8B: 7 new/enhanced tools (implement after 8A ships)
# Design docs: SPRINT8A_DESIGN.md (8A) + SPRINT8_DESIGN.md (8B)
# Engineering review: /plan-eng-review 2026-05-30 — D1-D8 (both reviews)
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Last updated: 2026-05-30

═══════════════════════════════════════════════════════
RULE ZERO — READ BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these files completely before writing a single line of code:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
2. /Users/sangeetajagadeesh/OmSaiRam/SPRINT8A_DESIGN.md
   Sprint 8A spec (API key infra). Implement this FIRST.
3. /Users/sangeetajagadeesh/OmSaiRam/SPRINT8_DESIGN.md
   Sprint 8B spec (7 tools). Implement AFTER 8A is tested.
4. /Users/sangeetajagadeesh/OmSaiRam/datanexus/main.py
   Existing middleware stack — you will add _ApiKeyMiddleware
   and register _UsageMiddleware via main.add_middleware().
5. /Users/sangeetajagadeesh/OmSaiRam/datanexus/core/request_context.py
   Contains client_ip_var. You will add api_key_var here.
6. /Users/sangeetajagadeesh/OmSaiRam/datanexus/core/usage_recorder.py
   Contains record_usage(). You will add api_key_hash param.
7. /Users/sangeetajagadeesh/OmSaiRam/datanexus/tools/security_stateful.py
   Contains _parse_sbom(), r.pipeline() pattern, Redis key schema.
   Both will be reused in Sprint 8B.

Confirm pre-read by answering ALL FOUR before any code:

a) What is the exact Redis key format for an anonymous user's
   monthly counter, and what TTL is used — and why 35 days
   instead of 30?

b) _UsageMiddleware must be implemented as what type of class
   (what Python base class), and registered how in main.py?
   Why NOT ASGI BaseHTTPMiddleware?

c) PAYMENT_ENABLED must be read where in the code —
   module level or per-request — and why does it matter
   for Railway deployments?

d) record_usage() will gain a new api_key_hash parameter.
   What is the exact Python signature to add it safely without
   breaking any of the 46 existing call sites?

Do not write any code until I confirm all four.
Type READY only after my confirmation.

═══════════════════════════════════════════════════════
CURRENT STATE
═══════════════════════════════════════════════════════

Live at https://datanexusmcp.com/mcp (46 tools after Sprint 7):

  Existing middleware (datanexus/main.py):
    _ClientIPMiddleware  — pure-ASGI, sets client_ip_var ContextVar
    (no API key middleware yet)

  Tool files (46 tools total):
    nonprofit.py, nonprofit_sprint6.py, nonprofit_sprint7.py (T04)
    security.py, security_sprint6.py, security_stateful.py (T10/T11/T15/T13)
    licence_sprint7.py, cve_sprint7.py (T10 Sprint 7 additions)
    domain.py (T07), compliance.py (T22 partial), legal.py (T11)
    govcon.py (T18), regulatory.py (T19), t04.py, t07.py, t10.py
    t11.py, t18.py, t19.py, t22.py

  Infrastructure already live:
    PostgreSQL (asyncpg): sessions + usage tables (datanexus/db_init.py)
    Redis (aioredis): CVE watch keys, SBOM watch keys, typosquat corpus
    cache.py: get_redis(), get_cached(), set_cached()
    usage_recorder.py: record_usage() — writes every tool call to Postgres

═══════════════════════════════════════════════════════
SPRINT 8A — DO THIS FIRST (API Key Infrastructure)
═══════════════════════════════════════════════════════

Architecture decisions from /plan-eng-review (MANDATORY — do not deviate):

  DECISION 1: _UsageMiddleware = FastMCPMiddleware subclass
    Use: from fastmcp.server.middleware import Middleware as FastMCPMiddleware
    Hook: override on_call_tool(context, call_next) -> ToolResult
    Register: main.add_middleware(Middleware(_UsageMiddleware()))
    NEVER use: BaseHTTPMiddleware or ASGI body buffering
    Reason: BaseHTTPMiddleware breaks asyncio.create_task() contextvar
    propagation used by track_tool_call() in all 46 tools.

  DECISION 2: PAYMENT_ENABLED read per-request
    WRONG:  PAYMENT_ENABLED = os.environ.get("PAYMENT_ENABLED", "false") == "true"  # module level
    RIGHT:  payment_enabled = os.environ.get("PAYMENT_ENABLED", "false").lower() == "true"  # inside on_call_tool
    Reason: Railway injects env vars at container startup. Per-request read
    ensures correct value is used after Railway auto-restart on env var change.
    "No code change needed — Railway restarts on env var change (~30s)."

  DECISION 3: api_key_hash in Postgres usage table
    Add column: api_key_hash TEXT (nullable, default NULL)
    Extend record_usage() with: api_key_hash: str | None = None  (keyword-only)
    Pass it from _UsageMiddleware after computing the hash.

  DECISION 4: Redis pipeline atomic INCR + EXPIRE
    Pattern from security_stateful.py:158 — use r.pipeline()
    Counter key: dn:usage:{tier}:{hash}:{YYYY-MM}
    TTL: 35 days (not 30) — allows keys from late in month M to expire
    naturally after month M+1's key has started. Do NOT set TTL on
    every INCR — only set on first write (check return value of INCR: if == 1).

T1. datanexus/core/request_context.py
    Add: api_key_var: ContextVar[str | None] = ContextVar("api_key", default=None)
    alongside the existing client_ip_var.

T2. datanexus/main.py — _ApiKeyMiddleware (pure-ASGI)
    Pattern: IDENTICAL to _ClientIPMiddleware (same pure-ASGI __call__ pattern)
    - Extract X-DataNexus-Key header
    - SHA-256 hash it (hashlib.sha256(key.encode()).hexdigest())
    - Redis lookup: dn:apikey:{hash} (5-min TTL)
      - If cache miss: Postgres query on api_keys table
      - If found and not revoked: api_key_var.set(hash)
      - If revoked or not found: api_key_var.set(None)
    - If no header: api_key_var.set(None)
    - Redis down: api_key_var.set(None), log WARNING, continue
    Add to middleware=[...] in main.run() AFTER _ClientIPMiddleware.

T3. datanexus/db_init.py — DDL additions
    Add to _DDL string (idempotent — use IF NOT EXISTS):
    ```sql
    CREATE TABLE IF NOT EXISTS api_keys (
        key_hash     TEXT        PRIMARY KEY,
        email        TEXT        NOT NULL,
        tier         TEXT        NOT NULL DEFAULT 'free',
        created_at   TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ,
        revoked_at   TIMESTAMPTZ,
        revoked      BOOLEAN     NOT NULL DEFAULT FALSE
    );
    ALTER TABLE usage ADD COLUMN IF NOT EXISTS api_key_hash TEXT;
    ```

T4. datanexus/core/usage_recorder.py
    Change record_usage() signature to add:
        ..., *, api_key_hash: str | None = None
    (keyword-only with default None — zero changes to existing 46 call sites)
    Pass it in the INSERT statement.

T5. datanexus/tools/api_key_sprint8a.py — NEW FILE
    Three MCP tools in a FastMCP sub-server named "datanexus-apikeys":

    generate_api_key(email: str) -> dict
      - Rate limit: Redis key dn:keygen_limit:{ip_hash}:{YYYY-MM-DD} max 3/day
        TTL 25h. Return error if exceeded.
      - Generate: "dnx_" + secrets.token_hex(32)  (68-char key)
      - Store: SHA-256 hash + email in api_keys table
      - Return: {"api_key": "dnx_...", "message": "Store this key — it will not be shown again."}
      - Redact in AuditContext: pass {"email": email, "key": "[REDACTED]"} not the raw key

    rotate_api_key(current_key: str) -> dict
      - Hash current_key, verify exists + not revoked in DB
      - Mark old key revoked_at=now, revoked=true
      - Invalidate Redis cache: DEL dn:apikey:{old_hash}
      - Generate + store new key (same as generate flow)
      - Return new key once
      - Redact both keys in AuditContext

    revoke_api_key(key: str) -> dict
      - Hash key, set revoked=true in DB
      - DEL dn:apikey:{hash} from Redis cache
      - Return {"status": "revoked"}

T5b. datanexus/tools/api_key_sprint8a.py — _UsageMiddleware class
    class _UsageMiddleware(FastMCPMiddleware):
        async def on_call_tool(self, context, call_next) -> ToolResult:
            result = await call_next(context)

            # Read context vars set by ASGI middleware
            api_key_hash = api_key_var.get()  # str | None
            client_ip    = client_ip_var.get()

            tier       = "registered" if api_key_hash else "anonymous"
            tier_limit = 500 if tier == "registered" else 100
            hint_threshold = 400 if tier == "registered" else 80
            bucket_key = f"dn:usage:{'key' if api_key_hash else 'anon'}:{api_key_hash or hashlib.sha256(client_ip.encode()).hexdigest()[:16]}:{datetime.now().strftime('%Y-%m')}"

            # Redis counter — atomic pipeline
            count = 0
            try:
                r = await get_redis()
                if r:
                    pipe = r.pipeline()
                    pipe.incr(bucket_key)
                    pipe.ttl(bucket_key)
                    results = await pipe.execute()
                    count = results[0]
                    if count == 1:  # first write — set TTL
                        await r.expire(bucket_key, 35 * 24 * 3600)
            except Exception:
                log.warning("_UsageMiddleware: Redis unavailable, usage counting skipped")
                return result  # fail open

            # Per-request env var read
            payment_enabled = os.environ.get("PAYMENT_ENABLED", "false").lower() == "true"

            # Hard gate (future)
            if payment_enabled and count >= tier_limit:
                next_month = (datetime.now().replace(day=1) + timedelta(days=32)).replace(day=1)
                return ToolResult(structured_content={
                    "error": "rate_limit_exceeded",
                    "message": f"You've used {count}/{tier_limit} calls this month.",
                    "upgrade_url": "https://datanexusmcp.com/upgrade",
                    "reset_date": next_month.strftime("%Y-%m-%d"),
                    "tier": tier,
                })

            # Augment result
            usage_fields = {
                "usage": {
                    "calls_this_month": count,
                    "limit": tier_limit,
                    "tier": tier,
                    "reset_date": ...,  # first of next month
                }
            }
            if count >= tier_limit:
                usage_fields["limit_warning"] = f"You've reached your {tier_limit} call limit. Register/upgrade at datanexusmcp.com/upgrade"
            elif count >= hint_threshold:
                usage_fields["upgrade_hint"] = "Register a free API key for 5x more calls: datanexusmcp.com/key" if tier == "anonymous" else "Upgrade for unlimited calls: datanexusmcp.com/upgrade"

            if result.structured_content:
                result.structured_content.update(usage_fields)
            else:
                # structured_content was None — set it
                result = result.model_copy(update={"structured_content": usage_fields})

            return result

T6. datanexus/main.py
    Add imports for _UsageMiddleware and api_key_sprint8a.
    Register: main.add_middleware(Middleware(_UsageMiddleware()))
    Mount: main.mount(api_key_server, namespace="apikeys") or similar.

DEPLOY ORDER for Sprint 8A:
  1. db_init.py changes (T3) — idempotent, safe to deploy first
  2. request_context.py (T1) — adds var, no behavior change
  3. usage_recorder.py (T4) — keyword-only arg, no behavior change
  4. _ApiKeyMiddleware + _UsageMiddleware + api_key tools (T2+T5+T5b+T6)
  5. Railway: PAYMENT_ENABLED not set (defaults to false)

TEST Sprint 8A before 8B:
  - Call any existing tool without X-DataNexus-Key → usage fields appear in response
  - Call generate_api_key("test@example.com") → get dnx_... key
  - Call same tool with X-DataNexus-Key header → tier: "registered", limit: 500
  - Redis down simulation → tools still work, no usage fields

═══════════════════════════════════════════════════════
SPRINT 8B — IMPLEMENT AFTER 8A IS DEPLOYED + TESTED
═══════════════════════════════════════════════════════

Full spec in SPRINT8_DESIGN.md. Summary:

Workstream 1 — Sub-category taxonomy (no new tools):
  - Update README.md section headers with 8 categories
  - Update Glama listing descriptions
  - Create CATEGORIES.md

Workstream 2 — Backend security depth (3 tools):
  - Enhance fetch_dependency_graph in t10.py
    Add cvs_filtered_transitive_deps field (OSV.dev cross-check)
    This is an ENHANCEMENT of an existing tool — NOT a new file
  - audit_sbom_license_policy (new, t10_sprint8.py)
    Reuse _parse_sbom() from security_stateful.py — extract to _sbom_utils.py first
    asyncio.Semaphore(10) for concurrent licence lookups
  - fetch_cve_watch_status (new, t10_sprint8.py)
    watch_ids: list[str] REQUIRED (not optional)
    Reads existing dn:cve_watch:{watch_id} keys
    Cursor: dn:cve_watch:{api_key_hash}:_last_polled
    First call (no cursor): returns last 30 days events

Workstream 3 — Frontend security wedge (4 tools, T20):
  - frontend_security_detect_typosquatting
    Static corpus: data/frontend_corpus.json (curate top-500 from npm)
    Reuse _damerau_levenshtein() from security_sprint6.py
  - frontend_security_audit_manifest
    Direct deps only for BLOCK/CAUTION verdict
    Transitive CVEs in transitive_cve_summary (display only)
    500KB size limit (same as audit_sbom_continuous)
  - frontend_security_audit_ci_pipeline
    Config input REDACTED in AuditContext (security-sensitive)
    500KB size limit
    GitHub Actions: full 5-check suite
    Vercel/Netlify: secrets only
  - frontend_security_fetch_package_risk_brief
    Wraps existing security_fetch_package_risk_brief(ecosystem='npm')
    Adds weekly_downloads (cache 24h) + is_ui_component (static prefixes)

Key reuse from existing code (MANDATORY — do not reimplement):
  datanexus/tools/security_stateful.py:510  _parse_sbom() → extract to _sbom_utils.py
  datanexus/tools/security_sprint6.py:595   _damerau_levenshtein()
  datanexus/tools/security_sprint6.py:200   fetch_package_risk_brief()
  datanexus/tools/_circuit_breakers.py      _osv_breaker, _depsdev_breaker
  datanexus/tools/t07.py:120               _incr_calls() pattern → copy to t10.py (TODO-01)

═══════════════════════════════════════════════════════
TEST FILES TO CREATE
═══════════════════════════════════════════════════════

Sprint 8A:
  datanexus/tests/test_api_key_sprint8a.py (22 test paths)
    Key paths: middleware header extraction, tier logic, Redis fail-open,
    PAYMENT_ENABLED true/false, key generation rate limit, key rotation,
    revocation + cache invalidation, record_usage() no TypeError

Sprint 8B:
  datanexus/tests/test_t10_sprint8.py (15 paths)
  datanexus/tests/test_frontend_sprint8.py (20 paths)
    Critical regression test: ${{ secrets.FOO }} in CI config NOT flagged

═══════════════════════════════════════════════════════
FILES TO TOUCH — SPRINT 8A
═══════════════════════════════════════════════════════

New files:
  datanexus/tools/api_key_sprint8a.py   (tools + _UsageMiddleware class)

Modified files:
  datanexus/main.py                      (add middlewares, import api_key module)
  datanexus/core/request_context.py     (add api_key_var ContextVar)
  datanexus/core/usage_recorder.py      (add api_key_hash param)
  datanexus/db_init.py                  (api_keys DDL + usage column)

Test files:
  datanexus/tests/test_api_key_sprint8a.py

═══════════════════════════════════════════════════════
FILES TO TOUCH — SPRINT 8B
═══════════════════════════════════════════════════════

New files:
  datanexus/tools/_sbom_utils.py        (extract from security_stateful.py)
  datanexus/tools/t10_sprint8.py        (audit_sbom_license_policy, fetch_cve_watch_status)
  datanexus/tools/frontend_sprint8.py   (4 frontend tools)
  data/frontend_corpus.json             (top-500 npm packages, manually curated)
  CATEGORIES.md                         (taxonomy reference)

Modified files:
  datanexus/tools/t10.py                (enhance fetch_dependency_graph + _incr_calls)
  datanexus/tools/security_stateful.py  (import _parse_sbom from _sbom_utils)
  datanexus/main.py                     (register t10_sprint8, frontend_sprint8)
  README.md                             (sub-category taxonomy sections)

Test files:
  datanexus/tests/test_t10_sprint8.py
  datanexus/tests/test_frontend_sprint8.py

═══════════════════════════════════════════════════════
HARDCODED LIMITS — DO NOT CHANGE WITHOUT UPDATING DESIGN DOC
═══════════════════════════════════════════════════════

  Anonymous free tier:       100 calls/month
  Registered free tier:      500 calls/month
  Hint threshold (anon):     80 calls
  Hint threshold (keyed):    400 calls
  Redis TTL monthly counter: 35 days
  Redis TTL api_key cache:   5 minutes (300 seconds)
  Redis TTL keygen limit:    25 hours
  Key generation limit:      3 per IP per 24h
  SBOM size limit:           500,000 bytes (500KB) — same as audit_sbom_continuous
  CI pipeline size limit:    500,000 bytes (500KB)
  IP hash length:            16 hex chars (SHA-256 first 16)
  Key prefix:                "dnx_"
  Key entropy:               32 bytes (secrets.token_hex(32))
  T20 frontend tools prefix: frontend_security_*
  T10 backend tools:         @verify_entitlement("T10")
  T20 frontend tools:        @verify_entitlement("T20")
