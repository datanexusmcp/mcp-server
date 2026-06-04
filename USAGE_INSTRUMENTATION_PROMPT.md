# Task: Usage Instrumentation — Capture Organic Activity + Pass Rate

## Context
Read /Users/sangeetajagadeesh/OmSaiRam/DATANEXUS_CONTEXT_MAY22.md for
full project context before starting.

## Problem
The PostgreSQL usage table exists but has 0 rows — nothing is writing to
it. We have no record of what users searched, whether calls succeeded,
or what errors occurred. Smoke tests pollute PostHog making organic
traffic invisible.

## Goal
After this change, every tool call writes a record to PostgreSQL with:
- which tool was called
- what the user searched (input params)
- did it succeed or fail
- if failed, what error
- how long it took
- the client IP
- whether it was a smoke test (excluded from organic metrics)

---

## Step 1 — Migrate usage table

Run this migration on Hetzner PostgreSQL:

```sql
ALTER TABLE usage ADD COLUMN IF NOT EXISTS client_ip text;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS tool_input jsonb;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS success boolean DEFAULT true;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS error_msg text;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS latency_ms integer;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS is_smoke boolean DEFAULT false;

CREATE INDEX IF NOT EXISTS usage_created_at_idx ON usage(created_at DESC);
CREATE INDEX IF NOT EXISTS usage_tool_id_idx ON usage(tool_id);
CREATE INDEX IF NOT EXISTS usage_client_ip_idx ON usage(client_ip);
```

Add migration to datanexus/db/migrations/004_usage_instrumentation.sql
Run it as part of startup if not already applied (check information_schema).

---

## Step 2 — Find where usage writes should happen

Search the codebase for:
- Where tools are registered and called (main.py, tool handlers)
- Where session_id and call_uuid are currently generated
- Any existing usage insert code that may be silently failing

Look for the pattern where tool execution happens — this is where we
wrap with timing and error capture.

---

## Step 3 — Add UsageRecorder utility

Create datanexus/core/usage_recorder.py:

```python
# datanexus/core/usage_recorder.py

import time
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

class UsageRecorder:
    def __init__(self, db_pool, redis_client=None):
        self.db = db_pool
        self.redis = redis_client
        self.is_smoke = os.environ.get('DATANEXUS_SMOKE_RUN') == '1'

    async def record(
        self,
        tool_id: str,
        session_id: str,
        tool_input: dict,
        client_ip: str,
        success: bool,
        error_msg: str = None,
        latency_ms: int = None
    ):
        # Never raise — usage recording must never block the pipeline
        try:
            await self.db.execute("""
                INSERT INTO usage 
                  (session_id, tool_id, call_uuid, created_at,
                   client_ip, tool_input, success, error_msg,
                   latency_ms, is_smoke)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            """,
                session_id,
                tool_id,
                str(uuid.uuid4()),
                datetime.now(timezone.utc),
                client_ip,
                json.dumps(tool_input),
                success,
                error_msg,
                latency_ms,
                self.is_smoke
            )
        except Exception as e:
            # Log but never raise
            import logging
            logging.getLogger(__name__).warning(
                f"UsageRecorder failed (non-fatal): {e}"
            )
```

---

## Step 4 — Wrap every tool call

In main.py (or wherever tools dispatch), wrap each tool execution:

```python
async def call_tool_with_recording(
    tool_id, tool_fn, tool_input, session_id, client_ip, recorder
):
    start = time.monotonic()
    success = True
    error_msg = None
    try:
        result = await tool_fn(**tool_input)
        return result
    except Exception as e:
        success = False
        error_msg = str(e)[:500]   # cap at 500 chars
        raise
    finally:
        latency_ms = int((time.monotonic() - start) * 1000)
        await recorder.record(
            tool_id=tool_id,
            session_id=session_id,
            tool_input=tool_input,
            client_ip=client_ip,
            success=success,
            error_msg=error_msg,
            latency_ms=latency_ms
        )
```

Extract client_ip from the request context (X-Real-IP header set by
Caddy). Pass it through to the recorder.

---

## Step 5 — Fix smoke test PostHog exclusion

In datanexus/tests/smoke.py, confirm this is set before any tool calls:
```python
os.environ['DATANEXUS_SMOKE_RUN'] = '1'
```

In UsageRecorder.record(), when is_smoke=True:
- Still write to PostgreSQL (useful for test pass rate tracking)
- Skip PostHog event (fixes metric pollution)

In PostHog instrumentation (wherever tool_called event fires):
```python
if os.environ.get('DATANEXUS_SMOKE_RUN') == '1':
    return  # skip PostHog for smoke tests
```

---

## Step 6 — Daily ops dashboard endpoint

Add GET /ops/daily to feedback/dashboard/server.py

Returns JSON with two sections:

### Section A — Tool pass rates (organic only, last 24h)
```sql
SELECT
  tool_id,
  COUNT(*) as total_calls,
  COUNT(*) FILTER (WHERE success = true) as passed,
  COUNT(*) FILTER (WHERE success = false) as failed,
  ROUND(100.0 * COUNT(*) FILTER (WHERE success = true) 
        / COUNT(*), 1) as pass_rate_pct,
  AVG(latency_ms)::int as avg_latency_ms,
  COUNT(DISTINCT client_ip) as unique_ips
FROM usage
WHERE created_at > NOW() - INTERVAL '24 hours'
  AND is_smoke = false
GROUP BY tool_id
ORDER BY total_calls DESC;
```

### Section B — What users searched (organic only, last 24h)
```sql
SELECT
  created_at,
  tool_id,
  client_ip,
  tool_input,
  success,
  error_msg,
  latency_ms
FROM usage
WHERE created_at > NOW() - INTERVAL '24 hours'
  AND is_smoke = false
ORDER BY created_at DESC
LIMIT 200;
```

Endpoint protected by ops IP check (same as existing dashboard).
Response shape:
```json
{
  "generated_at": "2026-05-22T08:00:00Z",
  "window": "last_24h",
  "organic_only": true,
  "tool_summary": [...],
  "recent_calls": [...]
}
```

---

## Step 7 — Add dn-daily alias on Hetzner

Add to ~/.bashrc on Hetzner:
```bash
alias dn-daily='curl -s http://localhost:8101/ops/daily | python3 -m json.tool'
```

So your morning check is just:
```bash
dn-daily
```

---

## Build Order
1. Write migration SQL + apply on startup
2. Create usage_recorder.py
3. Wire recorder into tool dispatch in main.py
4. Fix smoke test PostHog exclusion
5. Add /ops/daily endpoint
6. Add dn-daily alias
7. Deploy

## Gates (in order)
1. Migration: \d usage shows all 6 new columns
2. Recorder: make one manual tool call, check
   SELECT * FROM usage ORDER BY created_at DESC LIMIT 1;
   Must show tool_id, tool_input, success, latency_ms populated
3. Smoke exclusion: run smoke.py, check PostHog —
   no new tool_called events should appear
4. Daily endpoint: curl localhost:8101/ops/daily returns valid JSON
   with tool_summary and recent_calls arrays
5. dn-daily alias: works from Hetzner shell

## Do NOT
- Never let UsageRecorder raise — wrap everything in try/except
- Never log raw API keys that might appear in tool_input
  (add a sanitize_input() step that strips *_key, *_secret fields)
- Never block tool execution if DB is down
- Do not touch Sections 13 Haiku triggers
- Do not modify existing tool logic — only wrap at dispatch layer

## Success
Morning workflow:
  ssh datanexus
  dn-daily
  
Shows: which tools ran, pass rates, what was searched,
any errors — organic traffic only, smoke excluded.
