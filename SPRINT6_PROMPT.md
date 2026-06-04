# DataNexus MCP — Sprint 6 Implementation Prompt
# Focus: Retention-First — Aggregators + Stateful Anchors
# 6 new tools in 3 groups
# Design doc: sangeetajagadeesh-unknown-design-20260528-195135.md (ENG REVIEWED)
# Engineering review: /plan-eng-review 2026-05-28 — 9 findings, all resolved
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Last updated: 2026-05-28

═══════════════════════════════════════════════════════
RULE ZERO — READ BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these files completely before writing
a single line of code:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
   All rules apply. Non-negotiable.

2. /Users/sangeetajagadeesh/OmSaiRam/SPRINT6_DESIGN.md
   The NEW design. 6 tools, retention rationale,
   all architecture decisions from eng review.
   This file is the authoritative spec for Sprint 6.

3. /Users/sangeetajagadeesh/OmSaiRam/datanexus/main.py
   Understand the lifespan pattern, sub-server
   mount pattern, and namespace conventions.

Confirm pre-read by answering ALL FOUR:

a) The server startup mode is ASGI or WSGI?
   Which line in main.py confirms this?
   (Correct answer changes the scheduler pattern.)

b) fetch_package_risk_brief calls 4 upstreams.
   Should those calls run serially or in parallel?
   What Python pattern is specified?

c) What is the Redis key pattern for the CVE
   watch index SET (not the hash — the SET)?
   What command does the scheduler use to read it?

d) After Sprint 6 is complete, how many total
   tools will be registered in main.py?
   Show arithmetic. Current: 35 tools.
   Sprint 6 adds 6 new tools + 2 new namespaces.

Do not write any code until I confirm all four.
Type READY only after my confirmation.

═══════════════════════════════════════════════════════
CURRENT STATE
═══════════════════════════════════════════════════════

Live at https://datanexusmcp.com/mcp (35 tools):
  nonprofit  (3): fetch_nonprofit_by_ein,
                  search_nonprofits_by_name,
                  fetch_charity_uk
  security   (7): fetch_package_vulnerabilities,
                  fetch_dependency_graph,
                  fetch_cve_detail,
                  audit_sbom_vulnerabilities,
                  fetch_package_licence,
                  fetch_cisa_kev,
                  fetch_cve_epss
  compliance (4): fetch_npi_provider,
                  search_npi_by_name,
                  fetch_finra_broker,
                  check_sam_exclusion
  domain     (7): fetch_domain_rdap, fetch_ssl_certificate_chain,
                  fetch_dns_records, fetch_domain_history,
                  fetch_subdomains, check_email_security,
                  fetch_reverse_ip
  legal      (4): fetch_patent_by_number, search_patents_by_keyword,
                  fetch_patent_citations, fetch_inventor_portfolio
  govcon     (3): search_contract_awards, fetch_vendor_contract_history,
                  fetch_open_solicitations
  regulatory (3): search_open_rulemakings, fetch_docket_details,
                  fetch_federal_register_notices
  Shared     (3): report_feedback, report_mcpize_link, validate_tool_output
  meta       (1): search_datanexus_tools

Server: ASGI / FastMCP async (confirmed in main.py _lifespan).
asyncio.create_task IS supported — do NOT use threading.Thread.
Redis: live on server at dn: namespace prefix.

Dependencies confirmed in requirements.txt:
  fastmcp, pydantic, httpx, redis, asyncpg,
  psycopg2-binary, uvicorn, fastapi, click,
  fakeredis, anthropic, posthog

MISSING — add to requirements.txt BEFORE coding:
  pybreaker>=1.0.0           (circuit breakers — Sprint 4 non-negotiable)
  cyclonedx-python-lib>=4.0  (CycloneDX SBOM parsing)
  spdx-tools>=0.8.0          (SPDX SBOM parsing)

═══════════════════════════════════════════════════════
PRE-WORK — MANDATORY BEFORE ANY NEW TOOL
═══════════════════════════════════════════════════════

Complete ALL of the following before writing any
Sprint 6 tool code. These are blockers, not suggestions.

PRE-1: Add dependencies to requirements.txt
  Add exactly:
    pybreaker>=1.0.0
    cyclonedx-python-lib>=4.0
    spdx-tools>=0.8.0
  Run pip install -r requirements.txt to confirm.

PRE-2: Register NVD API key
  Go to nvd.nist.gov/developers/request-an-api-key
  Free, same-day. Add as NVD_API_KEY to /app/.env
  on Hetzner and to config.py.
  WITHOUT this: daily CVE watch refresh = 100 min.
  WITH this: 10 min. Do NOT ship fetch_cve_watch
  without this key registered.

PRE-3: Refactor 3 existing tool handlers into
  shared utility functions.
  This is required because fetch_package_risk_brief
  calls these tools internally — HTTP self-calls
  are FORBIDDEN (adds 3 network round-trips, creates
  self-dependency on server startup).

  Extract into datanexus/tools/_security_utils.py:
    async def _fetch_vulns(package, ecosystem, version) -> dict
    async def _fetch_licence(package, ecosystem) -> dict

  Extract into datanexus/tools/_maintainer_utils.py:
    async def _fetch_maintainer_history(package, ecosystem) -> dict

  Refactor existing handlers:
    security_fetch_package_vulnerabilities  → thin wrapper → calls _fetch_vulns()
    security_fetch_package_licence          → thin wrapper → calls _fetch_licence()
    fetch_package_maintainer_history (new)  → thin wrapper → calls _fetch_maintainer_history()

  All 3 utility functions must have passing unit tests
  (no MCP server required — mock all HTTP calls)
  BEFORE fetch_package_risk_brief is written.
  Estimate: 90 minutes.

PRE-4: 30-line integration test for fetch_cve_watch
  Write tests/intg/test_cve_watch_intg.py BEFORE
  implementing fetch_cve_watch:
    1. register watch_id="sprint6-test-001", cve_ids=["CVE-2021-44228"]
    2. manually call _run_cve_watch_refresh()
    3. assert Redis key dn:cve_watch:sprint6-test-001 exists
    4. assert last_checked field is updated
    5. assert events field is valid JSON array
    6. assert dn:cve_watch_ids SET contains "sprint6-test-001"
  Only proceed to fetch_cve_watch implementation
  after this test passes on the server.

═══════════════════════════════════════════════════════
BUILD ORDER — STRICT
═══════════════════════════════════════════════════════

Build in this exact order. Each tool must pass
ALL smoke tests before the next tool starts.

  0. PRE-WORK (above) — complete before any code
  1. fetch_package_maintainer_history (Group 3, built first
     because fetch_package_risk_brief depends on it)
  2. fetch_package_risk_brief (Group 1 aggregator)
  3. fetch_nonprofit_full_profile (Group 1 aggregator)
  4. fetch_cve_watch (Group 2 stateful anchor)
  5. audit_sbom_continuous (Group 2 stateful anchor)
  6. detect_typosquatting (Group 3 supply chain)

Build order rationale:
  fetch_package_maintainer_history first — needed
    as a shared utility by the aggregator. Must
    exist before fetch_package_risk_brief is written.
  fetch_package_risk_brief second — flagship aggregator.
    Highest cognitive-load reduction. Stateless.
    Fastest to validate with real calls.
  fetch_nonprofit_full_profile third — ProPublica API,
    stateless. Second aggregator. No scheduler needed.
  fetch_cve_watch fourth — first stateful anchor.
    Requires Redis SET index + scheduler.
    PRE-4 integration test must pass first.
  audit_sbom_continuous fifth — second stateful anchor.
    Requires SBOM parser libs (PRE-1).
  detect_typosquatting last — requires typosquat
    reference list in Redis (scheduler fills it).

═══════════════════════════════════════════════════════
SHARED REQUIREMENTS — ALL SPRINT 6 TOOLS
═══════════════════════════════════════════════════════

Every tool must implement these without exception.

1. File structure:
   datanexus/tools/security_sprint6.py
     → fetch_package_risk_brief
     → fetch_package_maintainer_history
     → detect_typosquatting
   datanexus/tools/nonprofit_sprint6.py
     → fetch_nonprofit_full_profile
   datanexus/tools/security_stateful.py
     → fetch_cve_watch
     → audit_sbom_continuous
   datanexus/tools/_security_utils.py    (PRE-3)
   datanexus/tools/_maintainer_utils.py  (PRE-3)
   datanexus/schedulers.py
     → _cve_refresh_loop()
     → _sbom_refresh_loop()
     → _typosquat_ref_loop()

2. Circuit breakers — MANDATORY on ALL upstream HTTP calls.
   (Sprint 4 non-negotiable constraint.)

   Import pattern:
     import pybreaker
     _nvd_breaker        = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
     _propublica_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
     _depsdev_breaker    = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
     _cisa_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
     _epss_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
     _pypi_stats_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
     _npm_stats_breaker  = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)

   Usage:
     try:
         result = await _depsdev_breaker.call_async(_fetch_depsdev, ...)
         status = "OK"
     except pybreaker.CircuitBreakerError:
         result = None
         status = "CIRCUIT_OPEN"
     except Exception:
         result = None
         status = "ERROR"

   All tool responses MUST include upstream_status dict:
     {"nvd": "OK", "depsdev": "CIRCUIT_OPEN", ...}
   When breaker is CIRCUIT_OPEN: set data field to null,
   still return a verdict based on available data.
   Do NOT return an error when a single upstream is down.

3. asyncio.gather for fetch_package_risk_brief.
   All 4 upstream calls in PARALLEL, not serial:

   vulns, licence, maintainer, depsdev = await asyncio.gather(
       _fetch_vulns(package, ecosystem, resolved_version),
       _fetch_licence(package, ecosystem),
       _fetch_maintainer_history(package, ecosystem),
       _fetch_depsdev(package, ecosystem, resolved_version),
       return_exceptions=True,
   )

   Each coroutine has httpx timeout=8.0 internally.
   If result is an Exception: set field to null,
   mark upstream_status accordingly.
   Build verdict from non-null data only.

4. Redis namespace: all keys use dn: prefix.
   Sprint 6 keys (add to namespace documentation):
     dn:cve_watch:{watch_id}     — Hash (watch data)
     dn:cve_watch_ids            — SET (watch index)
     dn:sbom_watch:{watch_id}    — Hash (SBOM watch data)
     dn:sbom_watch_ids           — SET (SBOM watch index)
     dn:typosquat_ref:{ecosystem}— Sorted set (pkg list)
     dn:scheduler_errors         — List (error log, cap 100)

5. Scheduler registration in main.py _lifespan:
   Add INSIDE _lifespan, after existing asyncio.create_task:

   from datanexus.schedulers import (
       _cve_refresh_loop,
       _sbom_refresh_loop,
       _typosquat_ref_loop,
   )
   asyncio.create_task(_cve_refresh_loop())
   asyncio.create_task(_sbom_refresh_loop())
   asyncio.create_task(_typosquat_ref_loop())

   Scheduler loop pattern (every loop must use this):
   async def _cve_refresh_loop():
       while True:
           try:
               await _run_cve_watch_refresh()
           except Exception as exc:
               await _log_scheduler_error("cve_refresh", str(exc))
           await asyncio.sleep(86400)

   _log_scheduler_error:
   async def _log_scheduler_error(job_name: str, error: str):
       async with redis_client() as r:
           await r.lpush("dn:scheduler_errors",
               f"{job_name}|{error}|{datetime.utcnow().isoformat()}")
           await r.ltrim("dn:scheduler_errors", 0, 99)

6. Watch index SET pattern — NEVER use Redis SCAN:
   On create:
     pipeline: [HSET dn:cve_watch:{watch_id} ..., SADD dn:cve_watch_ids {watch_id}]
   On delete:
     pipeline: [DEL dn:cve_watch:{watch_id}, SREM dn:cve_watch_ids {watch_id}]
   In scheduler:
     watch_ids = await r.smembers("dn:cve_watch_ids")
   On TTL-expired key during refresh:
     call SREM to clean up index, do NOT crash.

7. Glama registration: update glama.json IN THE SAME
   COMMIT as the main.py mount registration. Never
   register a tool in main.py without updating glama.json.

═══════════════════════════════════════════════════════
TOOL SPECS — GROUP 1: AGGREGATORS (ship first)
═══════════════════════════════════════════════════════

── fetch_package_maintainer_history ─────────────────
(Build before fetch_package_risk_brief — it depends on it)

Input:
  package_name: str
  ecosystem: Literal["npm", "pypi", "cargo", "go"]

Utility function location: datanexus/tools/_maintainer_utils.py
  async def _fetch_maintainer_history(package, ecosystem) -> dict

Data sources:
  PyPI: pypi.org/pypi/{name}/json → maintainers array + release timestamps
  npm:  registry.npmjs.org/{name} → maintainers + time map

Account age proxy:
  pypi.org/search/?q=maintainer:{username}
  If non-200 or 0 results: set account_age = "unknown",
  contribute +0.0 to anomaly_score (conservative fallback).
  Do NOT use Libraries.io in Sprint 6.

anomaly_score formula (additive, clamped to 1.0):
  owner_account_age_days < 90  → +0.4
  ownership_transfer_last_90d  → +0.3
  maintainer_count_delta > 1 in 30 days → +0.2
  release_after_6mo_silence    → +0.1

Verdict:
  anomaly_score > 0.7 → maintainer_health = "suspicious"
  anomaly_score 0.3–0.7 → "stale" or "abandoned" (per criteria below)
  anomaly_score < 0.3 → "healthy"
  last release > 18 months ago → "stale"
  no commits in 12 months → "abandoned"
  ownership transfer in last 90 days → "suspicious"
  maintainer account < 90 days old → "suspicious"

Returns: maintainer_count, recent_changes (list),
  ownership_transfers, account_ages,
  anomaly_score (0.0–1.0), maintainer_health,
  upstream_status

Circuit breaker: _pypi_stats_breaker, _npm_stats_breaker

── fetch_package_risk_brief ─────────────────────────

Input:
  package_name: str
  ecosystem: Literal["npm", "pypi", "go", "cargo", "maven"]
  version: str (optional — if omitted, resolve to latest)

Version resolution when omitted:
  PyPI: pypi.org/pypi/{name}/json → info.version
  npm:  registry.npmjs.org/{name} → dist-tags.latest
  Always include resolved_version in response.

Internal calls (parallel, asyncio.gather):
  _fetch_vulns(package, ecosystem, resolved_version)
  _fetch_licence(package, ecosystem)
  _fetch_maintainer_history(package, ecosystem)
  _fetch_depsdev(package, ecosystem, resolved_version)

Deps.dev API URL:
  https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{package}/versions/{version}
  (NOTE: subdomain is api.deps.dev — NOT deps.dev/api)

Verdict decision table (check in order):
  BLOCK if: critical_cve_count >= 1
            OR licence_risk == "INCOMPATIBLE"
  CAUTION if: (critical_cve_count == 0 AND high_cve_count >= 2)
              OR licence_risk == "COPYLEFT"
              OR maintainer_health in ("suspicious", "abandoned")
  SHIP otherwise

Returns:
  verdict: "SHIP" | "CAUTION" | "BLOCK"
  critical_cve_count: int | null
  high_cve_count: int | null
  licence_risk: str | null
  maintainer_health: str | null
  transitive_count: int | null
  resolved_version: str
  upstream_status: dict (all upstreams)
  reasoning: str (one sentence)

Circuit breakers: _nvd_breaker, _depsdev_breaker,
  _pypi_stats_breaker, _npm_stats_breaker

Glama description:
  "Single SHIP/CAUTION/BLOCK verdict for any package.
  Combines CVEs, licence, maintainer health, and
  transitive count in one call."

── fetch_nonprofit_full_profile ─────────────────────

Input:
  ein: str (employer identification number)

Data sources:
  Primary: ProPublica Nonprofit Explorer API
    projects.propublica.org/nonprofits/api/v2/organizations/{ein}.json
  Fallback: IRS e-File bulk download
    irs.gov/charities-non-profits/form-990-series-downloads
    (use if ProPublica returns 404 for a given EIN)

ProPublica field mapping:
  Total revenue:        totrevenue → Part VIII line 12
  Executive comp:       employee array (Schedule J Part II)
  Programme ratio:      totprgmrevnue / totrevenue
  Fundraising:          totfuncexpns / totrevenue (< 35% = healthy)
  Risk flags:           late_tax_period, related_org_flag,
                        YoY revenue delta < -10%
  Reserve months:       netassetsend / (totfuncexpns / 12)

Health score formula (0–100):
  programme_ratio × 40
  + (1 - expense_ratio) × 30
  + revenue_growth_score × 20
  + reserve_months_score × 10
  (all sub-scores 0.0–1.0)

  reserve_months_score = min(reserve_months / 6, 1.0)
  (6+ months of reserves = full score; 0 months = 0)

Returns: financials (revenue, assets, expenses),
  executive_compensation (top 5 by salary),
  risk_flags (list), health_score (0–100),
  programme_ratio, fundraising_sustainability,
  upstream_status

Circuit breaker: _propublica_breaker
When CIRCUIT_OPEN: return upstream_status.propublica=
  "CIRCUIT_OPEN", health_score=null, no error.

Glama description:
  "Complete nonprofit due diligence in one call.
  Revenue trends, executive pay, risk flags, and
  a health score from IRS 990 data."

═══════════════════════════════════════════════════════
TOOL SPECS — GROUP 2: STATEFUL ANCHORS (ship second)
═══════════════════════════════════════════════════════

── fetch_cve_watch ───────────────────────────────────

Input:
  watch_id: str (user-provided, their identity proxy)
  cve_ids: list[str]
  action: Literal["create", "check", "delete"]

Redis schema:
  Key:    dn:cve_watch:{watch_id}
  Type:   Hash
  Fields: created_at, last_checked, cve_ids (JSON array),
          events (JSON array of event dicts)
  TTL:    90 days, refreshed on each check

Watch index (ALWAYS maintain alongside hash):
  Key:   dn:cve_watch_ids
  Type:  SET
  Use:   SADD on create, SREM on delete

Events tracked by scheduler:
  patch_released, exploitation_detected,
  kev_listed, poc_published

On create:
  Store watch in Redis (pipeline: HSET + SADD + EXPIRE)
  Return confirmation + current status of each CVE

On check:
  Return events since last check
  Update last_checked timestamp
  Refresh TTL (90 days from now)
  Return: has_new_events (bool), events (list),
          call_back_in: "24h" (always)

On delete:
  Pipeline: DEL dn:cve_watch:{watch_id} + SREM dn:cve_watch_ids {watch_id}

NOT push: user pulls by calling check.
Do NOT claim push behavior in Glama description.
Glama description:
  "Persistent CVE watchlist. Create once, check anytime
  for new events since your last visit — patch releases,
  KEV listings, PoC publications, exploitation detected."

Scheduler: _cve_refresh_loop() in schedulers.py
  Runs every 24h via asyncio.create_task.
  Reads all watch_ids from SMEMBERS("dn:cve_watch_ids").
  For each watch: calls NVD, CISA KEV, EPSS APIs.
  Appends new events to dn:cve_watch:{watch_id} hash.
  Requires NVD_API_KEY env var (see PRE-2).

NVD rate limits:
  Without API key: 5 req/30s → 100 min per 1,000 lookups
  With API key:    50 req/30s → 10 min per 1,000 lookups

CISA KEV: single bulk JSON download once per daily run.
  json.cisa.gov/cisa/known_exploited_vulnerabilities.json
  No rate limit concern.

EPSS: api.first.org/epss?cve={id}
  One call per CVE ID, same 1,000/day bound.

Circuit breakers: _nvd_breaker, _cisa_breaker, _epss_breaker

── audit_sbom_continuous ────────────────────────────

Input:
  sbom: str (CycloneDX or SPDX JSON string)
  watch_id: str
  action: Literal["register", "check", "deregister"]

INPUT SIZE LIMIT: 500 KB (512,000 bytes).
  Check at handler entry before ANY parsing:
  if len(sbom.encode()) > 512_000:
      return error: "SBOM exceeds 500 KB. For large
      SBOMs, compress or split by component group.
      SBOM URL input is a Sprint 8 candidate."
  Do NOT let oversized SBOMs reach the parser.

SBOM hash: ALWAYS use SHA-256:
  import hashlib
  sbom_hash = hashlib.sha256(sbom.encode()).hexdigest()
  Do NOT use md5 or sha1.

Supported formats:
  CycloneDX 1.4 and 1.5 JSON (cyclonedx-python-lib)
  SPDX 2.3 JSON (spdx-tools)
  Both normalize to PURL format for component_list.

Redis schema:
  Key:    dn:sbom_watch:{watch_id}
  Type:   Hash
  Fields: registered_at, last_audit, sbom_hash,
          component_list (JSON array of PURLs),
          last_audit_results (JSON), new_findings (JSON array)
  TTL:    90 days, refreshed on each check

Watch index (ALWAYS maintain alongside hash):
  Key:   dn:sbom_watch_ids
  Type:  SET
  Use:   SADD on register, SREM on deregister

On register:
  Size check → parse → extract PURLs → store in Redis
  Run initial audit against OSV.dev
  Return: go/no-go signal + critical issues

On check:
  Return new_findings since last_audit
  Update last_audit timestamp
  Refresh TTL

On deregister:
  Pipeline: DEL dn:sbom_watch:{watch_id}
            + SREM dn:sbom_watch_ids {watch_id}

Scheduler: _sbom_refresh_loop() in schedulers.py
  Runs every 7 days via asyncio.create_task.
  Reads all watch_ids from SMEMBERS("dn:sbom_watch_ids").
  Weekly cadence ONLY — new-CVE triggered re-audit
  is a Sprint 8 candidate. Do NOT implement Sprint 8
  behavior in Sprint 6.

Glama description:
  "Persistent SBOM watch. Register once, check anytime
  for new CVEs affecting your dependency snapshot.
  Silent permanent watch — CycloneDX and SPDX supported."

═══════════════════════════════════════════════════════
TOOL SPECS — GROUP 3: SUPPLY CHAIN (ship third)
═══════════════════════════════════════════════════════

── detect_typosquatting ─────────────────────────────

Input:
  package_name: str
  ecosystem: Literal["npm", "pypi", "cargo", "go"]

Method: Damerau-Levenshtein distance ≤ 2 against
  top-10,000 packages in ecosystem.

Top-10k reference list:
  Stored in Redis at dn:typosquat_ref:{ecosystem}
  Type: Sorted set (member=package name, score=download_count)
  TTL: 7 days

Reference list sources:
  PyPI: hugovk/top-pypi-packages dataset on GitHub
        (updated monthly; avoids pypistats.org rate limits)
  npm:  api.npmjs.org/downloads/point/last-month
        (paginated; ~50 requests for top-10k)

Cold start (Redis key missing on first request):
  Fetch synchronously with 30-second timeout.
  Log warning if fetch exceeds 10 seconds.
  If fetch fails or times out:
    return error "Reference list unavailable; retry in 60 seconds."
    Do NOT return partial results. Do NOT serve a
    comparison against fewer than 10,000 packages.

Scheduler: _typosquat_ref_loop() in schedulers.py
  Runs every 7 days via asyncio.create_task.
  DO NOT populate the reference list at server startup.
  Cold start handles first-request population.

anomaly_score per similar package (additive, clamped 1.0):
  new_package_age_days < 30  → +0.5
  download_count < 100       → +0.3
  name_distance == 1         → +0.2

Returns: similar_packages (list), verdict ("SUSPICIOUS"|"CLEAN"),
  upstream_status

Circuit breakers: _pypi_stats_breaker, _npm_stats_breaker

═══════════════════════════════════════════════════════
TEST REQUIREMENTS
═══════════════════════════════════════════════════════

Test plan artifact: sangeetajagadeesh-unknown-eng-review-test-plan-20260528.md
Full test plan location: ~/.gstack/projects/OmNamahaShivaya/

canary.py MUST include before any tool registers:
  canary_nvd()          — GET api.nvd.nist.gov, expect 200
  canary_propublica()   — GET projects.propublica.org/nonprofits/api, expect 200
  canary_depsdev()      — GET api.deps.dev/v3alpha, expect 200
  canary_pypi_json()    — GET pypi.org/pypi/requests/json, expect 200
  canary_npm_registry() — GET registry.npmjs.org/lodash, expect 200

smoke.py MUST pass before main.py registration:
  Group 1:
    smoke_fetch_package_risk_brief() — requests/pypi
      Assert: verdict in ("SHIP","CAUTION","BLOCK"),
              resolved_version non-null,
              upstream_status dict present
    smoke_fetch_package_risk_brief_circuit_open() — mock depsdev down
      Assert: verdict returned (not error),
              upstream_status.depsdev == "CIRCUIT_OPEN",
              transitive_count == null
    smoke_fetch_nonprofit_full_profile() — ein="13-1837418"
      Assert: health_score between 0 and 100,
              executive_compensation list present

  Group 2:
    smoke_fetch_cve_watch_create() — watch_id="smoke-test-001"
      Assert: Redis key dn:cve_watch:smoke-test-001 exists
              dn:cve_watch_ids SET contains "smoke-test-001"
    smoke_fetch_cve_watch_check() — same watch_id
      Assert: has_new_events field present, call_back_in == "24h"
    smoke_fetch_cve_watch_delete() — same watch_id
      Assert: Redis key deleted, removed from SET
    smoke_audit_sbom_continuous_size_limit()
      Assert: 501KB SBOM rejected with correct error message

  Group 3:
    smoke_detect_typosquatting() — "requsets" vs npm registry
      Assert: similar_packages non-empty,
              "requests" appears with distance <= 2
    smoke_detect_typosquatting_cold_start_failure()
      Assert: error "Reference list unavailable; retry in 60 seconds"
              when Redis key missing and fetch times out

Non-negotiable gate: canary.py + smoke.py must
pass locally before ANY tool registers in main.py.
No exceptions. This is CLAUDE.md rule D2/P15-1.

═══════════════════════════════════════════════════════
HARD STOPS — DO NOT BUILD
═══════════════════════════════════════════════════════

1. Do NOT implement push notifications for
   fetch_cve_watch or audit_sbom_continuous.
   Both are PULL-based. Users call check() to get
   updates. Push is a Sprint 8 candidate.

2. Do NOT trigger audit_sbom_continuous re-audit
   when a new CVE is published. Weekly cadence ONLY
   in Sprint 6. New-CVE trigger is Sprint 8.

3. Do NOT use HTTP self-calls inside
   fetch_package_risk_brief. It MUST call the shared
   utility functions directly. Self-calls are forbidden.

4. Do NOT use Redis SCAN to iterate over watches.
   Use SMEMBERS on the index SET. SCAN is forbidden.

5. Do NOT run detect_typosquatting reference list
   population at server startup. Weekly scheduler only.
   Cold start handles first-request population.

6. Do NOT register any Sprint 6 tool in main.py
   without updating glama.json in the same commit.

7. Do NOT use APScheduler for any Sprint 6 scheduler.
   asyncio.create_task loop pattern only (see Shared
   Requirements item 5 above).

═══════════════════════════════════════════════════════
SUCCESS CRITERIA — SPRINT 6
═══════════════════════════════════════════════════════

By end of Sprint 6:

1. RETENTION SIGNAL: At least 1 user calls
   fetch_cve_watch (create) with a watch_id, then
   calls fetch_cve_watch (check) with the SAME
   watch_id on a subsequent calendar day.
   Log both calls with watch_id in server access logs.
   This is the primary Sprint 6 success metric.

2. AGGREGATOR ADOPTION: fetch_package_risk_brief
   generates calls within 7 days of shipping.

3. SUPPLY CHAIN ADOPTION: detect_typosquatting or
   fetch_package_maintainer_history called at least
   5 times in first 14 days.

4. NO REGRESSION: existing tool call counts do not
   drop after Sprint 6 ships.

5. ALL 5 canaries passing.
   ALL smoke tests passing.
   41 total tools registered in main.py.
   glama.json updated in same commit as each mount.

═══════════════════════════════════════════════════════
SPRINT 7 GATE — DO NOT FINALIZE BEFORE JUNE 4
═══════════════════════════════════════════════════════

Sprint 7 scope is determined by June 4 README
reorder data (reorder started May 28):
  If nonprofit >= 20 calls/week despite lower README
    position → expand T04-1 (nonprofit depth)
  If nonprofit drops to < 10 calls/week →
    position-bias confirmed → expand T10-1 stateless
  Either way → T10-5 licence tools always ship

Do NOT finalize Sprint 7 tool list before June 4.
Do NOT build Sprint 7 tools during Sprint 6.

═══════════════════════════════════════════════════════
VISA / PAYMENT CONSTRAINT
═══════════════════════════════════════════════════════

MCPIZE_ACTIVE=false for 60-90 days from now
(through approximately July-August 2026).
All users are on the free window.
Do NOT implement payment gates, subscription checks,
or premium tiers for any Sprint 6 tool.
report_mcpize_link will return status="free" for
all Sprint 6 tool IDs.
