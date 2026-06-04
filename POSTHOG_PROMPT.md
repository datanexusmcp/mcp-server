# DataNexus MCP — PostHog Analytics Integration
# Add product analytics to all 30 tools
# Understand: which tools agents try, what fails,
# where they drop off, download vs usage gap
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Deploy to: Hetzner 178.104.251.70
# Last updated: May 2026

═══════════════════════════════════════════════════════
WHY POSTHOG
═══════════════════════════════════════════════════════

890 downloads, zero organic usage. PostHog will
reveal exactly what is happening:

- Are agents discovering tools but failing to call?
- Are calls being made but returning errors?
- Which tools get called first and abandoned?
- What is the p99 latency per tool?
- Are there specific error patterns repeating?

PostHog gives session replays, funnels, and
retention analysis — none of which Redis counters
provide. The existing Redis telemetry tracks
counts. PostHog tracks behaviour.

PostHog is free up to 1M events/month.
More than enough for current volume.

═══════════════════════════════════════════════════════
BEFORE WRITING ANY CODE
═══════════════════════════════════════════════════════

Step 1: Sign up at https://posthog.com
  Use dev@datanexusmcp.com
  Choose Cloud (US or EU) — free tier
  Create project: "DataNexus MCP"

Step 2: Get your API key
  Settings → Project → Project API Key
  Looks like: phc_xxxxxxxxxxxxxxxxxxxx
  Also note your host:
    US: https://us.i.posthog.com
    EU: https://eu.i.posthog.com

Step 3: Add to /app/.env on Hetzner:
  ssh datanexus
  echo "POSTHOG_API_KEY=phc_your_key_here" >> /app/.env
  echo "POSTHOG_HOST=https://us.i.posthog.com" >> /app/.env

Step 4: Confirm key is set:
  grep POSTHOG /app/.env
  # Must show both lines

Do not write any code until Steps 1-4 are complete.
Flag me if PostHog signup has any issues.

═══════════════════════════════════════════════════════
PHASE 1 — BUILD POSTHOG CLIENT
═══════════════════════════════════════════════════════

Create: datanexus/analytics.py

This is the single PostHog integration point.
All 30 tools call this — never call PostHog
directly from tool files.

Design principles:
  - NEVER blocks tool execution
  - NEVER raises exceptions to caller
  - NEVER stores PII — no IP addresses,
    no query content, no user identifiers
    beyond a daily-rotating anonymous hash
  - NEVER adds more than 5ms to tool latency
  - Fires events asynchronously in background
  - If PostHog is unreachable: log warning,
    continue silently

```python
# datanexus/analytics.py

import asyncio
import hashlib
import logging
import os
import time
from datetime import date
from typing import Optional

log = logging.getLogger(__name__)

# Lazy import — PostHog only loaded if key is set
_ph = None
_enabled = False

def _get_client():
    global _ph, _enabled
    if _ph is not None:
        return _ph
    key = os.environ.get("POSTHOG_API_KEY", "")
    host = os.environ.get(
        "POSTHOG_HOST", "https://us.i.posthog.com")
    if not key:
        _enabled = False
        return None
    try:
        from posthog import Posthog
        _ph = Posthog(
            project_api_key=key,
            host=host,
            disabled=False,
            # Batch and send async — never blocks
            sync_mode=False,
        )
        _enabled = True
        log.info("PostHog analytics: enabled")
        return _ph
    except Exception as e:
        log.warning(f"PostHog init failed: {e}")
        _enabled = False
        return None

def _anon_id() -> str:
    """
    Daily-rotating anonymous identifier.
    Cannot be linked to any individual.
    Resets every day — no cross-day tracking.
    """
    return hashlib.sha256(
        f"datanexus:{date.today().isoformat()}".encode()
    ).hexdigest()[:16]

def _fire(event: str, properties: dict) -> None:
    """
    Fire PostHog event in background thread.
    Never blocks. Never raises.
    """
    ph = _get_client()
    if not ph:
        return
    try:
        # Remove any PII that might have crept in
        safe_props = {
            k: v for k, v in properties.items()
            if k not in {
                "ip", "email", "name", "user_id",
                "query", "ein", "npi", "crd",
                "domain", "patent_number"
            }
        }
        ph.capture(
            distinct_id=_anon_id(),
            event=event,
            properties=safe_props,
        )
    except Exception as e:
        log.warning(f"PostHog capture failed: {e}")

async def track_tool_call(
    tool_id: str,
    tool_name: str,
    success: bool,
    latency_ms: int,
    cache_hit: bool,
    error_code: Optional[str] = None,
    ecosystem: Optional[str] = None,
    jurisdiction: Optional[str] = None,
) -> None:
    """
    Track every tool call. Call from tool handlers.
    Runs in background — never awaited by caller.
    """
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _fire, "tool_called", {
        # Tool identity
        "tool_id":      tool_id,
        "tool_name":    tool_name,
        "tool_group":   tool_name.split("_")[0],

        # Outcome
        "success":      success,
        "cache_hit":    cache_hit,
        "latency_ms":   latency_ms,
        "error_code":   error_code or "none",

        # Non-PII context (safe to log)
        "ecosystem":    ecosystem or "none",
        "jurisdiction": jurisdiction or "none",

        # Platform
        "server":       "datanexusmcp.com",
        "date":         date.today().isoformat(),
    })

async def track_tool_error(
    tool_id: str,
    tool_name: str,
    error_code: str,
    error_type: str,
    latency_ms: int,
) -> None:
    """Track errors specifically for error analysis."""
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _fire, "tool_error", {
        "tool_id":    tool_id,
        "tool_name":  tool_name,
        "tool_group": tool_name.split("_")[0],
        "error_code": error_code,
        "error_type": error_type,
        "latency_ms": latency_ms,
        "date":       date.today().isoformat(),
    })

async def track_server_start(tool_count: int) -> None:
    """Track server startup — detects deploy cycles."""
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _fire, "server_started", {
        "tool_count": tool_count,
        "date":       date.today().isoformat(),
    })

def shutdown() -> None:
    """Flush PostHog queue on server shutdown."""
    if _ph:
        try:
            _ph.shutdown()
        except Exception:
            pass
```

Gate:
  python3 -c "
  from datanexus.analytics import track_tool_call
  print('analytics import ok')
  "
  Must print 'analytics import ok' with no error.
  (PostHog key not needed for import test)

═══════════════════════════════════════════════════════
PHASE 2 — INSTALL POSTHOG PACKAGE
═══════════════════════════════════════════════════════

Add posthog to requirements.txt:
  echo "posthog>=3.0.0" >> requirements.txt

Verify it installs:
  pip install posthog --break-system-packages
  python3 -c "import posthog; print(posthog.__version__)"

═══════════════════════════════════════════════════════
PHASE 3 — ADD TRACKING TO ALL 30 TOOLS
═══════════════════════════════════════════════════════

For every tool in every sub-server file, add
PostHog tracking. The pattern is identical for
all 30 tools — wrap the existing logic with
timing and track_tool_call at the end.

Files to update:
  datanexus/tools/t04.py  (nonprofit_ tools)
  datanexus/tools/t10.py  (security_ tools)
  datanexus/tools/t22.py  (compliance_ tools)
  datanexus/tools/t07.py  (domain_ tools)
  datanexus/tools/t11.py  (legal_ tools)
  datanexus/tools/t18.py  (govcon_ tools)
  datanexus/tools/t19.py  (regulatory_ tools)

Pattern to apply to EVERY tool function:

```python
# Add at top of each tool file:
from datanexus.analytics import (
    track_tool_call, track_tool_error
)

# Wrap every tool function body:
async def nonprofit_fetch_nonprofit_by_ein(
    ein: str
) -> dict:
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        # ... existing tool logic unchanged ...
        result = { ... }
        _success = True
        _cache_hit = result.get("cache_hit", False)
        return result
    except Exception as e:
        _error_code = getattr(e, "error_code",
            type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T04",
            tool_name="nonprofit_fetch_nonprofit_by_ein",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))
```

Tool ID mapping for tracking:
  nonprofit_*  → tool_id="T04"
  security_*   → tool_id="T10"
  compliance_* → tool_id="T22"
  domain_*     → tool_id="T07"
  legal_*      → tool_id="T11"
  govcon_*     → tool_id="T18"
  regulatory_* → tool_id="T19"

Special parameters to pass for context
(these are NOT PII — just metadata):
  security_fetch_package_vulnerabilities:
    ecosystem=ecosystem parameter value
  legal_fetch_patent_by_number:
    jurisdiction=jurisdiction parameter value
  govcon_search_contract_awards:
    jurisdiction=jurisdiction parameter value

Do NOT pass: ein, npi, crd, domain, patent_number,
  docket_id, vendor_name, or any search query text.
  These could identify individuals or companies.

Also add import time at top of each file
if not already present:
  import time
  import asyncio

Gate per file:
  python3 -c "
  import datanexus.tools.t04 as t
  print('T04 analytics: ok')
  " → prints ok, no error

═══════════════════════════════════════════════════════
PHASE 4 — TRACK SERVER STARTUP
═══════════════════════════════════════════════════════

In datanexus/main.py, add server startup tracking
in the lifespan context manager:

```python
from datanexus.analytics import (
    track_server_start, shutdown as ph_shutdown
)

@asynccontextmanager
async def lifespan(app):
    # ... existing startup code ...
    await db_init()
    # Add this:
    tools = await app.list_tools()
    asyncio.create_task(
        track_server_start(len(tools))
    )
    yield
    # Add this on shutdown:
    ph_shutdown()
```

This fires once per deploy. Shows in PostHog
as a "server_started" event — lets you see
deploy frequency and correlate with usage.

═══════════════════════════════════════════════════════
PHASE 5 — POSTHOG DASHBOARD SETUP
═══════════════════════════════════════════════════════

After deploying to Hetzner, make a test call to
each tool group to seed PostHog with initial data.
Then set up these insights in PostHog UI:

Insight 1 — Tool call volume (line chart):
  Event: tool_called
  Breakdown: tool_name
  Date range: Last 30 days
  → Shows which tools are being called

Insight 2 — Success rate by tool (bar chart):
  Event: tool_called
  Filter: success = true / false
  Breakdown: tool_name
  → Reveals which tools are failing

Insight 3 — Error analysis (table):
  Event: tool_error
  Breakdown: error_code, tool_name
  → Shows what errors agents hit most

Insight 4 — Latency distribution (histogram):
  Event: tool_called
  Property: latency_ms
  Breakdown: tool_group
  → Identifies slow tool groups

Insight 5 — Cache hit rate (bar chart):
  Event: tool_called
  Filter: cache_hit = true / false
  Breakdown: tool_name
  → Shows which tools serve from cache vs live

Insight 6 — Server restart frequency (line):
  Event: server_started
  → Detects deploy patterns and crashes

Save all 6 as a Dashboard: "DataNexus MCP Ops"

═══════════════════════════════════════════════════════
PHASE 6 — DEPLOY TO HETZNER
═══════════════════════════════════════════════════════

Step 1: Commit all changes
  git add datanexus/analytics.py \
           datanexus/tools/t04.py \
           datanexus/tools/t10.py \
           datanexus/tools/t22.py \
           datanexus/tools/t07.py \
           datanexus/tools/t11.py \
           datanexus/tools/t18.py \
           datanexus/tools/t19.py \
           datanexus/main.py \
           requirements.txt
  git commit -m "Add PostHog analytics to all
    30 tools — track calls, errors, latency,
    cache hits. Privacy-safe: no PII captured."
  git push

Step 2: Deploy
  ssh datanexus
  cd /app/datanexus
  git pull
  docker compose build --no-cache datanexus-mcp
  docker compose up -d
  sleep 10
  docker compose ps
  # All 4 containers must be Up

Step 3: Verify PostHog key is loaded
  docker compose exec datanexus-mcp python3 -c "
  import os
  key = os.environ.get('POSTHOG_API_KEY','')
  print('PostHog key set:', bool(key))
  print('Key prefix:', key[:8] if key else 'MISSING')
  "
  PASS if: PostHog key set: True

Step 4: Fire a test event
  docker compose exec datanexus-mcp python3 -c "
  import asyncio
  from datanexus.analytics import track_tool_call
  async def t():
    await track_tool_call(
      tool_id='T04',
      tool_name='nonprofit_fetch_nonprofit_by_ein',
      success=True,
      latency_ms=142,
      cache_hit=False,
    )
    print('Test event fired')
  asyncio.run(t())"

Step 5: Verify event in PostHog
  Go to PostHog → Activity → Live Events
  Should see 'tool_called' event within 30s
  with tool_name=nonprofit_fetch_nonprofit_by_ein

Step 6: Make real tool calls to seed data
  docker compose exec datanexus-mcp python3 -c "
  import asyncio, sys
  sys.path.insert(0, '/app/datanexus')

  async def seed():
      from datanexus.tools.t04 import \
          nonprofit_fetch_nonprofit_by_ein
      from datanexus.tools.t10 import \
          security_fetch_package_vulnerabilities
      from datanexus.tools.t22 import \
          compliance_fetch_npi_provider
      from datanexus.tools.t07 import \
          domain_fetch_domain_rdap
      from datanexus.tools.t11 import \
          legal_fetch_patent_by_number
      from datanexus.tools.t18 import \
          govcon_search_contract_awards
      from datanexus.tools.t19 import \
          regulatory_search_open_rulemakings

      calls = [
          nonprofit_fetch_nonprofit_by_ein(
              '13-1837418'),
          security_fetch_package_vulnerabilities(
              'requests', '2.28.0', 'PyPI'),
          compliance_fetch_npi_provider(
              '1003000126'),
          domain_fetch_domain_rdap('stripe.com'),
          legal_fetch_patent_by_number(
              'EP1000000', 'EP'),
          govcon_search_contract_awards(
              'cybersecurity', '', '', 'US'),
          regulatory_search_open_rulemakings(
              'artificial intelligence', '', 'open'),
      ]
      results = await asyncio.gather(
          *calls, return_exceptions=True)
      for i, r in enumerate(results):
          if isinstance(r, Exception):
              print(f'Call {i}: ERROR {r}')
          else:
              print(f'Call {i}: OK '
                    f'tool={r.get(\"tool_id\")}')
      await asyncio.sleep(2)  # flush PostHog queue
      print('Seed complete')

  asyncio.run(seed())"

  PASS if: 7 calls return OK, no exceptions

═══════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════

Report each as PASS or FAIL:

  □ datanexus/analytics.py created
    Imports cleanly, no PostHog key needed
    for import

  □ posthog>=3.0.0 in requirements.txt

  □ All 7 tool files updated with tracking
    try/finally pattern in every tool function
    import time and asyncio in all files

  □ main.py updated with server_started event
    and ph_shutdown() on lifespan exit

  □ All existing tests still pass:
    pytest feedback/tests/ -v -q
    pytest payment/tests/ -v -q
    Must show 84/84 green

  □ Deployed to Hetzner — 4 containers Up

  □ POSTHOG_API_KEY confirmed in container env

  □ Test event visible in PostHog Live Events

  □ 7 seed calls succeed — all tool groups
    represented in PostHog

  □ 6 PostHog insights created and saved
    to "DataNexus MCP Ops" dashboard

═══════════════════════════════════════════════════════
PRIVACY NOTE — ADD TO CLAUDE.md
═══════════════════════════════════════════════════════

Add this rule to CLAUDE.md in same commit:

Rule: PostHog events must NEVER include:
  - Query parameters (ein, npi, domain, etc.)
  - User identifiable information
  - Raw tool inputs or outputs
  - IP addresses or session tokens
  Allowed: tool_id, tool_name, tool_group,
  success, latency_ms, cache_hit, error_code,
  ecosystem, jurisdiction, date.
  The anon_id() rotates daily and cannot be
  linked to any individual across days.

═══════════════════════════════════════════════════════
WHAT TO LOOK FOR IN POSTHOG AFTER 48 HOURS
═══════════════════════════════════════════════════════

If you see tool_called events with success=False:
  → Tools are being reached but failing
  → Check error_code breakdown

If you see zero tool_called events but
server_started events exist:
  → Agents are connecting but not calling tools
  → Tool descriptions may be unclear
  → search_datanexus_tools routing may be broken

If you see tool_called events only from your
own test calls and nothing organic:
  → Agents are not discovering the server
  → Glama/Smithery listing needs improvement
  → npm package connection may be failing

If you see tool_called events with high
latency_ms (>5000) consistently:
  → Upstream API timeouts are the problem
  → Circuit breaker settings need tuning

This is the data you need to diagnose
890 downloads / zero organic usage.
