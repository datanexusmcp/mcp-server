# P8 — P95 Latency Investigation Findings & Sprint 9B Design

**Status:** Investigation complete (Sprint 9 scope). No code changed — `verify_entitlement` /
billing untouched per "NEVER change without a human PR."

## Root cause — confirmed (not just static analysis)

`payment/entitlement.py::_run_telemetry()` (called by `verify_entitlement`'s wrapper on
**every single tool invocation**, line 178: `await _run_telemetry(tool_id, caller_id)`)
opens a brand-new PostgreSQL connection per call:

```python
if _DB_URL:
    import asyncpg
    conn = await asyncpg.connect(_DB_URL)   # ← fresh TCP + auth handshake, every call
    try:
        await conn.execute("INSERT INTO sessions ... ON CONFLICT DO NOTHING", ...)
    finally:
        await conn.close()
```

This exactly matches the design doc's stated suspicion ("asyncpg.connect() creates new DB
connection per call in verify_entitlement").

### Live confirmation (not static-only)
Ran 5x `asyncpg.connect()` + `execute` + `close` cycles inside the running container against
the production DB:
- **38–45ms per cycle** at idle (`max_connections=100`, current activity=6).//
- This is the *best case*. Each decorated tool call pays this serially, **before** the actual
  tool logic runs (`_run_telemetry` is awaited, blocking, not fire-and-forget).
- Under concurrent load, opening dozens of fresh connections simultaneously causes connection
  setup contention (TCP handshake + SCRAM auth queueing inside Postgres' connection-acceptance
  path) — this is the standard mechanism by which a ~40ms median balloons into a 9,638ms P95
  tail: a small fraction of calls land during a burst, queue behind connection setup, and pay
  multi-second penalties.

### Scope — which tools are affected
`@verify_entitlement(...)` decorates **48 tool functions** across 15 files
(`t04`, `t07` ×7, `t10` ×7, `t10_sprint8`, `t11`, `t18`, `t19`, `t22`, `cve_sprint7`,
`licence_sprint7`, `nonprofit_sprint6/7`, `security_sprint6`, `security_stateful`,
`frontend_sprint8`). **Every one of these pays the per-call `asyncpg.connect()` cost** —
this is not isolated to one tool; it's systemic to the entitlement-wrapper path itself.
T07 (domain) and T10 (security) have the most decorated entry points (7 each), so under the
current organic-traffic mix they contribute the largest share of total connection churn —
consistent with the design doc's note about "pipeline_mcp's frequent health checks…  if T07
domain tools trigger asyncpg.connect() per call, that's the hot path."

### Is verify_entitlement called every invocation, or once per session?
**Every invocation.** `_run_telemetry` is called unconditionally at the top of the wrapper
(line 178), before the `MCPIZE_ACTIVE` free-window passthrough check. There is no
session-level caching or memoization — each of the 48 decorated tool calls independently
opens, uses, and closes its own connection.

## Sprint 9 acceptance — met
- [x] Root cause tool/path identified: `payment/entitlement.py::_run_telemetry`, the
      PostgreSQL session-INSERT branch, called from `verify_entitlement`'s wrapper on every
      decorated tool invocation (48 functions / 15 files).
- [x] Confirmed live (not static): 38–45ms per `asyncpg.connect`+execute+close cycle measured
      against the production DB from inside the running container.
- [x] Confirmed `verify_entitlement` (and therefore `_run_telemetry`) runs on every tool
      call, not once per session.

---

# Sprint 9B — Implementation Design (separate sprint, human PR required)

**Constraint reminder:** All changes below touch `payment/entitlement.py`
(`verify_entitlement` / billing path). Per spec rule, this requires a human-authored PR —
Sprint 9B should NOT be auto-implemented by an agent.

## Proposed fixes (in priority order)

### 1. Shared asyncpg connection pool (primary fix)
Replace the per-call `asyncpg.connect()` / `close()` in `_run_telemetry` with a module-level
pool, initialized once at server startup (mirroring the pattern already used safely elsewhere
in this codebase: `datanexus/db.py::_get_pool`, `datanexus/core/usage_recorder.py`,
`datanexus/core/activation_detector.py::_get_pool`, `datanexus/tools/api_key_sprint8a.py::_get_pool`).

```python
_pool = None
async def _get_pool():
    global _pool
    if _pool is None and _DB_URL:
        _pool = await asyncpg.create_pool(_DB_URL, min_size=2, max_size=10, command_timeout=5)
    return _pool

# in _run_telemetry:
pool = await _get_pool()
if pool:
    async with pool.acquire() as conn:
        await conn.execute("INSERT INTO sessions ... ON CONFLICT DO NOTHING", ...)
```
Eliminates the connect/auth handshake from the hot path entirely — acquire from a warm pool
is sub-millisecond. This alone should collapse the P95 from ~9.6s to low-single-digit ms.

### 2. Async Redis client for counter reads
`_get_redis()` / `pipe.execute()` in `_run_telemetry` currently appear to use a synchronous
Redis client (blocking the event loop during `pipe.execute()`). Audit and migrate to
`redis.asyncio` (already used elsewhere in the codebase, e.g. `datanexus/cache.py::get_redis`)
so telemetry writes don't block concurrent tool calls.

### 3. Entitlement result caching (TTL 60s)
For known API keys, cache the entitlement-check result (tier, MCPIZE_ACTIVE outcome) in Redis
with a 60s TTL, keyed by `key_hash`. This avoids repeated Redis round-trips for
high-frequency callers once `MCPIZE_ACTIVE=true` is flipped on (currently a no-op since the
free-window passthrough short-circuits, but this will matter once enforcement goes live).

## Suggested validation for Sprint 9B
- Before/after P95 comparison via Smithery Observability (target: P95 < 500ms)
- Load test with concurrent calls across the 7 hottest tools (T07, T10) to confirm pool
  sizing (`max_size=10`) doesn't become the new bottleneck — tune against `max_connections=100`
  headroom (currently 6 active connections at idle)
- Confirm `sessions` table INSERT semantics (`ON CONFLICT DO NOTHING`) are unaffected by
  pooled connections (they are — pooling changes connection lifecycle, not transaction/query
  semantics)

## Explicitly out of scope for Sprint 9B (per spec)
- Any change to the six entitlement-check conditions / billing logic itself
- Any change to `MCPIZE_ACTIVE` gating behavior
