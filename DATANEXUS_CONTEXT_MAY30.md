# DataNexus MCP — Full Project Context
# Last updated: May 30, 2026
# Source 1: DATANEXUS_CONTEXT_MAY24.md updated by Claude Code after Sprint 7 (767 lines)
# Source 2: Operational session May 24-30 (IP classification, analytics, registry, bugs)
# Both sources fully merged — this is the single authoritative context file.

═══════════════════════════════════════════════════════
PRODUCT OVERVIEW
═══════════════════════════════════════════════════════

DataNexus MCP is a remote MCP server delivering
public data intelligence to AI agents.

Server URL:  https://datanexusmcp.com/mcp
Transport:   Streamable HTTP (stateless_http=True, json_response=True)
npm package: @datanexusmcp/mcp-server v2.3.0 (published May 30)
GitHub:      github.com/datanexusmcp/mcp-server
Dashboard:   http://localhost:8101 (SSH tunnel)
             ssh -L 8101:localhost:8101 datanexus -N
Glama:       https://glama.ai/mcp/servers/datanexusmcp/mcp-server
Smithery:    https://smithery.ai/servers/datanexusmcp/mcp-server

═══════════════════════════════════════════════════════
INFRASTRUCTURE
═══════════════════════════════════════════════════════

Server:      Hetzner CAX11, IP 178.104.251.70
OS:          Ubuntu 24.04, Docker 29.4.1
SSH:         ssh datanexus
             Key: ~/.ssh/datanexus2_ed25519
             Full: ssh -i ~/.ssh/datanexus2_ed25519 root@178.104.251.70
             NOTE: old key datanexus_ed25519_new no longer exists
Domain:      datanexusmcp.com (Cloudflare DNS, proxy OFF)
             Cloudflare analytics always zero — use dn-who/dn-daily/PostHog
Email:       dev@datanexusmcp.com
Stack:       Caddy + uvicorn FastMCP 3.3.1 + Redis 7 + PostgreSQL 16
Deploy path: /app/datanexus on server
DB user:     dn (NOT datanexus — was a bug, fixed)
DB tables:   sessions, usage, activation_events
Snapshot:    386464566 (post SSE fix, v2.1.3)

DEPLOY COMMAND (deploy.sh has tilde expansion bug — use directly):
  rsync -avz -e "ssh -F $HOME/.ssh/config" \
    --exclude='.git' --exclude='__pycache__' \
    --exclude='*.pyc' --exclude='.env' --exclude='node_modules' \
    . datanexus:/app/datanexus/
  ssh -F $HOME/.ssh/config datanexus "cd /app/datanexus && \
    docker compose build --no-cache && docker compose up -d"

DOCKER CONTAINERS (7 total):
  datanexus-caddy-1         — TLS + reverse proxy
  datanexus-datanexus-mcp-1 — FastMCP server :8000 + dashboard :8101
  datanexus-redis-1         — cache + sessions + feeds
  datanexus-postgres-1      — usage + sessions + activation_events
  datanexus-daily-digest-1  — Section 13 T4 digest cron
  datanexus-kev-refresh-1   — CISA KEV refresh
  datanexus-bug-listener-1  — Section 13 T2 feedback classifier ✓ LIVE

DOCKER COMMANDS (always run from /app/datanexus):
  cd /app/datanexus
  docker compose ps
  docker compose logs datanexus-mcp --tail 50
  docker compose logs caddy --tail 50
  docker compose logs bug-listener --tail 20
  docker compose restart datanexus-mcp
  docker compose build --no-cache datanexus-mcp
  docker compose up -d

NOTE: All docker compose commands must run from /app/datanexus
      Shortcut: alias dc='cd /app/datanexus && docker compose'

═══════════════════════════════════════════════════════
SERVER ALIASES (available on Hetzner)
═══════════════════════════════════════════════════════

ORIGINAL:
  dn-who        — all-time top external IPs from Caddy logs
  dn-users      — unique users per day
  dn-aborts     — SSE abort timestamps
  dn-ps         — container status
  dn-logs       — MCP server logs
  dn-daily      — organic tool usage last 24h (grey + smoke excluded)
                  curl -s http://localhost:8101/ops/daily | python3 -m json.tool
  dn-returning  — returning users (2+ calendar days)
                  curl -s http://localhost:8101/ops/returning-users | python3 -m json.tool
  dn-activation-events — last 50 activation events (last 7 days)
  dn-funnel     — funnel counts per event_type (all 5 levels, last 30 days)
                  Gate: must return 5 rows even when counts are 0

ADDED May 26:
  dn-who-24h      — top IPs last 24 hours
  dn-who-7d       — top IPs last 7 days
  dn-whois <ip>   — whois + reverse DNS for single IP
  dn-whois-batch  — whois summary for multiple IPs

ADDED May 26-29:
  dn-glama        — Glama quality tester calls by tool
                    filter: client_ip LIKE '172.68.%' (confirmed accurate)
                    455 all-time calls as of May 29
  dn-npm          — npm downloads last day/week/month
  dn-activation   — 14-day organic calls with unique IPs (smoke+Glama free)
  dn-conversion   — returning users with 2+ calls (multi-day)

═══════════════════════════════════════════════════════
USAGE TABLE SCHEMA (PostgreSQL)
═══════════════════════════════════════════════════════

  id          SERIAL PRIMARY KEY
  session_id  TEXT NOT NULL
  tool_id     TEXT NOT NULL
  call_uuid   TEXT UNIQUE NOT NULL
  created_at  TIMESTAMPTZ DEFAULT now()
  client_ip   TEXT
  tool_input  JSONB
  success     BOOLEAN DEFAULT true
  error_msg   TEXT
  latency_ms  INTEGER
  is_smoke    BOOLEAN DEFAULT false
  is_grey     BOOLEAN DEFAULT false

Indexes: usage_pkey, usage_call_uuid_key, usage_client_ip_idx,
         usage_created_at_idx, usage_tool_id_idx

ACTIVATION_EVENTS TABLE (added May 29):
  id, client_ip, event_type, tool_id, session_id, metadata, created_at

5 ACTIVATION LEVELS:
  first_call   — IP's very first tool call ever
  real_query   — non-example, non-test input (len > 10 chars)
  multi_tool   — 3+ distinct tools in 30-min rolling window
  return_visit — called tools on 2nd distinct calendar day
  power_user   — 10+ calls in rolling 7-day window

INSTRUMENTATION STATUS (confirmed May 24 end-to-end):
  HTTP POST /mcp → tool executes → usage row written (is_smoke=false)
  → PostHog tool_called fires — all three at same millisecond. LIVE.
  Smoke tests: is_smoke=true, excluded from PostHog and dn-daily.
  Grey IPs: is_grey=true, excluded from dn-daily and dn-returning.
  NOTE: Grey IPs still get served — only excluded from analytics.

═══════════════════════════════════════════════════════
API KEYS IN /app/.env ON HETZNER
═══════════════════════════════════════════════════════

ANTHROPIC_API_KEY          — live (Haiku validation)
SAM_GOV_API_KEY            — live (T18 + T22)
EPO_CLIENT_ID              — Consumer Key from developers.epo.org
EPO_CLIENT_SECRET          — Consumer Secret
REGULATIONS_GOV_KEY        — live (T19)
POSTHOG_API_KEY            — live (EU cloud)
POSTHOG_HOST               — https://eu.i.posthog.com
DATANEXUS_DB_URL           — postgresql://dn:***@postgres:5432/datanexus
AUTOSCALE_SNAPSHOT_ID      — 386464566
DATANEXUS_SECURITYTRAILS_KEY — needed for domain_fetch_reverse_ip (T07)
DATANEXUS_NVD_API_KEY      — NVD API key (Sprint 6 PRE-2)
                              Without: 100 min per 1,000 CVE lookups
                              With:    10 min per 1,000 CVE lookups
                              Register: nvd.nist.gov/developers/request-an-api-key

CRITICAL: DATANEXUS_DB_URL must be in /app/.env NOT in
docker-compose.yml environment: block.

═══════════════════════════════════════════════════════
FASTMCP CONFIGURATION (updated May 27)
═══════════════════════════════════════════════════════

FastMCP version: 3.3.1 (inside container)
stateless_http=True and json_response=True added to main.run()
  (NOTE: moved from FastMCP() constructor to main.run() per Claude Code)

Problem fixed: GET /mcp returned 406 Not Acceptable
  causing Claude.ai connector to spin forever on sync.
  Fix → returns 405 instead → Claude.ai handles correctly.

Verification:
  curl -X GET https://datanexusmcp.com/mcp
    -H "Accept: text/event-stream" → 405 ✅
  curl -X POST https://datanexusmcp.com/mcp
    -H "Content-Type: application/json" → 200 ✅

═══════════════════════════════════════════════════════
CADDYFILE — CURRENT WORKING VERSION
═══════════════════════════════════════════════════════

datanexusmcp.com {
  @blocked { remote_ip 176.65.148.38 }
  respond @blocked 403

  @ops_ip { remote_ip 178.104.251.70 }
  handle /ops/dashboard* {
    reverse_proxy @ops_ip datanexus-mcp:8101
    respond 403
  }

  handle {
    reverse_proxy datanexus-mcp:8000 {
      flush_interval -1
      header_up X-Real-IP {remote_host}
      transport http {
        versions 1.1
        response_header_timeout 0
        dial_timeout 10s
        keep_alive {
          enabled true
          idle_timeout 300s
          probe_interval 30s
        }
      }
    }
  }
}

NOTE: read_buffer_size, write_buffer_size, max_idle_conns_per_host
NOT supported on this Caddy version — do not add them.
Caddy only logs warn-level — successful requests silent in Caddy logs.
Use uvicorn logs or PostgreSQL usage table for real traffic data.

═══════════════════════════════════════════════════════
LIVE TOOLS — 46 TOTAL (as of May 30, 2026)
═══════════════════════════════════════════════════════

── SPRINTS 1–4 (35 tools) ─────────────────────────────

T04 — Nonprofit (3):
  nonprofit_fetch_nonprofit_by_ein      ← example EIN: 46-5734087
  nonprofit_search_nonprofits_by_name      (changed from 131837418 May 30)
  nonprofit_fetch_charity_uk

T10 — Security (7):
  security_fetch_package_vulnerabilities (batch supported)
  security_fetch_dependency_graph
  security_fetch_cve_detail (includes remediation from OSV)
  security_audit_sbom_vulnerabilities
  security_fetch_package_licence
  security_fetch_cisa_kev
  security_fetch_cve_epss

T22 — Compliance (4):
  compliance_fetch_npi_provider
  compliance_search_npi_by_name
  compliance_fetch_finra_broker
  compliance_check_sam_exclusion

T07 — Domain (7):
  domain_fetch_domain_rdap
  domain_fetch_ssl_certificate_chain
  domain_fetch_dns_records
  domain_fetch_domain_history
  domain_fetch_subdomains
  domain_check_email_security
  domain_fetch_reverse_ip (needs SECURITYTRAILS key)

T11 — Patents (4):
  legal_fetch_patent_by_number
  legal_search_patents_by_keyword
  legal_fetch_patent_citations
  legal_fetch_inventor_portfolio

T18 — GovCon (3):
  govcon_search_contract_awards
  govcon_fetch_vendor_contract_history
  govcon_fetch_open_solicitations

T19 — Regulatory (3):
  regulatory_search_open_rulemakings
  regulatory_fetch_docket_details
  regulatory_fetch_federal_register_notices

Shared (4):
  search_datanexus_tools
  report_feedback
  report_mcpize_link
  validate_tool_output

── SPRINT 6 (6 tools, shipped May 28–29) ──────────────

Files:
  datanexus/tools/security_sprint6.py
  datanexus/tools/nonprofit_sprint6.py
  datanexus/tools/security_stateful.py
  datanexus/tools/_security_utils.py   (shared utilities)
  datanexus/tools/_maintainer_utils.py (shared utilities)

Group 1 — Aggregators:
  security_fetch_package_risk_brief
    SHIP/CAUTION/BLOCK verdict combining CVEs, licence risk,
    maintainer health, transitive dep count. 4 parallel upstreams.
    Verdict: BLOCK if critical CVE or INCOMPATIBLE licence;
             CAUTION if high CVEs/COPYLEFT/suspicious maintainer;
             SHIP otherwise.

  security_fetch_package_maintainer_history
    Maintainer ownership timeline, account age, anomaly score.
    anomaly_score (additive, clamped 1.0):
      owner_account_age < 90d  → +0.4
      ownership_transfer_90d   → +0.3
      maintainer_count_delta   → +0.2
      release_after_6mo_silence → +0.1
    Verdict: suspicious (>0.7), stale/abandoned (0.3–0.7), healthy (<0.3)

  nonprofit_fetch_nonprofit_full_profile
    Full 990 due diligence: financials, exec pay, risk flags,
    health score (0–100), programme ratio, fundraising sustainability.
    Health score: programme_ratio×40 + (1-expense_ratio)×30
                  + revenue_growth_score×20 + reserve_months_score×10
    Source: ProPublica /api/v2/organizations/{ein}.json primary,
            IRS e-File fallback on 404.

Group 2 — Stateful Anchors:
  security_fetch_cve_watch
    Persistent CVE watchlist (create/check/delete).
    Redis: dn:cve_watch:{watch_id} (Hash, 90d TTL)
           dn:cve_watch_ids (SET index — never use SCAN)
    Events: patch_released, exploitation_detected, kev_listed, poc_published
    Scheduler: _cve_refresh_loop() 24h cycle
    SPRINT 6 PRIMARY SUCCESS METRIC: user creates watch, checks next day

  security_audit_sbom_continuous
    Persistent SBOM monitoring (register/check/deregister).
    Redis: dn:sbom_watch:{watch_id} (Hash, 90d TTL)
           dn:sbom_watch_ids (SET index)
    Input limit: 500 KB. Formats: CycloneDX 1.4/1.5, SPDX 2.3 JSON.
    Scheduler: _sbom_refresh_loop() 7-day cycle.

Group 3 — Supply Chain:
  security_detect_typosquatting
    Damerau-Levenshtein distance ≤ 2 vs top-10,000 packages.
    Reference: dn:typosquat_ref:{ecosystem} (Redis ZSET, 7d TTL)
    Cold-start: fetch on first call, fail closed if < 10,000 packages.
    anomaly_score per similar pkg:
      new_pkg_age < 30d → +0.5; downloads < 100 → +0.3; distance==1 → +0.2
    Verdict: SUSPICIOUS or CLEAN

── SPRINT 7 (5 tools, shipped May 29–30) ──────────────

Files:
  datanexus/tools/licence_sprint7.py
  datanexus/tools/cve_sprint7.py
  datanexus/tools/nonprofit_sprint7.py
  datanexus/tools/_circuit_breakers.py  (PRE-0)
  datanexus/tools/_cve_utils.py         (PRE-1)
  datanexus/tools/_licence_compat.py    (PRE-2)
  datanexus/tools/_nonprofit_utils.py   (PRE-3)

Pre-work:
  _circuit_breakers.py — ALL pybreaker singletons centralized here.
    NEVER define pybreaker.CircuitBreaker() in a tool file.
  _cve_utils.py — _fetch_cve_detail_util, _fetch_cisa_kev_util, _fetch_cve_epss_util
  _licence_compat.py — SPDX compatibility table (30+ pairs each direction)
    STATIC_LICENCES dict: top-50 SPDX IDs with risk/obligations/permissions
    All risk levels assume proprietary/commercial use context.
  _nonprofit_utils.py — calculate_health_score() single source of truth

Group 1 — Licence Intelligence:
  security_fetch_licence_analysis
    Input: spdx_id (str)
    Static-first: checks STATIC_LICENCES before any HTTP call.
    Fallback: spdx.org/licenses/{id}.json via _spdx_breaker.
    Unknown ID → DEGRADED (not error): risk_level=UNKNOWN, plain_english=null
    Risk levels: PERMISSIVE, COPYLEFT, STRONG_COPYLEFT, INCOMPATIBLE, UNKNOWN
    AGPL plain_english MUST include "INCOMPATIBLE for proprietary SaaS" (D3)
    upstream_status.spdx_api: "N/A" when served from static bundle.

  security_audit_licence_compatibility
    Input: packages (list[{package_name, ecosystem}]) OR spdx_ids (list[str])
    Mixed input → INVALID_PARAMS. Empty → INVALID_PARAMS. >50 → INVALID_PARAMS.
    Package path: asyncio.Semaphore(10) — prevents 429 at 50 items (D7)
    SPDX-ID path: static bundle only — NO HTTP calls
    Returns: compatibility, conflicts, combined_obligations,
             recommended_action, upstream_status

Group 2 — CVE Aggregator:
  security_fetch_cve_risk_summary
    Input: cve_id validated against ^CVE-\d{4}-\d{4,}$
    Parallel: asyncio.gather + return_exceptions=True
    Degraded nulls (HARD RULE D2):
      kev_listed: null (not false) when CISA unreachable
      epss_score: null (not 0.0) when EPSS unreachable
      patch_available: null (not false) when no allowlist URL match
    Verdict table (FIRST MATCH WINS — D2 fix):
      1. UNKNOWN:          all three null
      2. CRITICAL_EXPLOIT: kev_listed==true OR epss >= 0.7
      3. HIGH_RISK:        cvss >= 9.0 OR (epss >= 0.3 AND cvss >= 7.0)
      4. MODERATE:         cvss >= 4.0
      5. LOW:              otherwise
    patch_available allowlist: github.com/advisories, access.redhat.com,
      security.debian.org, ubuntu.com/security, lists.apache.org,
      msrc.microsoft.com, oracle.com/security-alerts,
      cisco.com/security/advisories, kb.cert.org
    NOTE: nvd.nist.gov NOT in allowlist (informational only)
    P0 smoke: T03-S01 — all-null upstreams → verdict MUST be UNKNOWN not LOW

Group 3 — Nonprofit Depth:
  nonprofit_search_nonprofits_by_category
    Input: category (str), state (str optional 2-letter)
    Category → NTEE map: education→B, healthcare→E, arts→A, environment→C,
      human_services→P, civil_rights→R, international→Q, religion→X,
      science→U, sports→N. Raw single letter A-Z accepted.
    API NOTE: ProPublica /search.json?q={keyword} is working endpoint.
      /nonprofits.json?ntee=&state= → 404. State+NTEE params → 500.
      State filtering done CLIENT-SIDE after API call.
      health_score is null for all search results (no financial fields).
    Max 25 results, truncated=True when more available.

  nonprofit_fetch_nonprofit_financial_trends
    Input: ein (str), years (int default 5, max 10)
    Source: ProPublica /api/v2/organizations/{ein}.json
      (NOT /filings.json — OQ1 resolved May 30)
    Minimum guard: < 2 filings → INSUFFICIENT_DATA (checked FIRST)
    Per-year: reserve_months, programme_ratio, health_score
    CAGR: null if rev_earliest == 0
    trend_direction (first match wins):
      INSUFFICIENT_DATA / VOLATILE / GROWING / STABLE / DECLINING

═══════════════════════════════════════════════════════
SPRINT 7 ENGINEERING REVIEW DECISIONS (D1–D7)
═══════════════════════════════════════════════════════

D1: Utility names: _fetch_licence(), _fetch_vulns() in _security_utils.py
D2: Verdict table: UNKNOWN fires FIRST (step 1). P0 test T03-S01 required.
D3: INCOMPATIBLE context: all risk_levels assume proprietary use.
    AGPL must note open source compatibility.
D4: Circuit breakers: _circuit_breakers.py only. Never per-file instances.
D5: Health score: imported from _nonprofit_utils.py everywhere.
D6: 64 tests passing. P0 regression test T03-S01.
D7: asyncio.Semaphore(10) in audit_licence_compatibility package path.

═══════════════════════════════════════════════════════
REDIS KEY SCHEMA (complete, all sprints)
═══════════════════════════════════════════════════════

CACHE:
  datanexus:T04:{phash}         — nonprofit data (4h TTL)
  datanexus:T10:{phash}         — CVE/SBOM data (1h TTL)
  datanexus:T10:{phash}_archive — stale fallback (24h TTL)
  datanexus:epss:{cve_id}       — EPSS scores (6h TTL)
  datanexus:kev:catalog         — CISA KEV catalog (25h TTL)
  datanexus:kev:fetched_at      — timestamp (25h TTL)

SPRINT 6 STATEFUL:
  dn:cve_watch:{watch_id}       — Hash (90d TTL)
  dn:cve_watch_ids              — SET (permanent)
  dn:sbom_watch:{watch_id}      — Hash (90d TTL)
  dn:sbom_watch_ids             — SET (permanent)
  dn:typosquat_ref:{ecosystem}  — ZSET (7d TTL)
  dn:scheduler_errors           — List (capped 100)

SCHEMA ALERTS:
  datanexus:schema:alerts:T10   — breaking change flag
  datanexus:digest:T10:2026-W19 — weekly digest

CANARY:
  datanexus:canary:sam_gov:last_run — 25h TTL (rate limit guard)

FEEDBACK:
  fb:alerts:immediate           — BLPOP queue (0 pending)

═══════════════════════════════════════════════════════
TEST SUITE STATUS (May 30, 2026)
═══════════════════════════════════════════════════════

64 tests passing (all sprints):
  test_cve_utils.py         — 5 tests (PRE-1)
  test_licence_compat.py    — 16 tests (PRE-2)
  test_nonprofit_utils.py   — 5 tests (PRE-3)
  test_licence_sprint7.py   — 13 tests (Tools 1+2)
  test_cve_sprint7.py       — 11 tests (Tool 3, incl. T03-S01 P0)
  test_nonprofit_sprint7.py — 14 tests (Tools 4+5, incl. live Red Cross)

CI: .github/workflows/ci.yml — PASSING ✅
  Skips smoke.py and canary.py (need live services)
  Skips -k "not integration and not upstream"

CRON ON HETZNER:
  30 * * * * cd /app/datanexus && docker compose
    exec -T datanexus-mcp python3 -m
    datanexus.tests.smoke >> /var/log/datanexus-smoke.log
  0 * * * *  cd /app/datanexus && docker compose
    exec -T datanexus-mcp python3 -m
    datanexus.tests.canary >> /var/log/datanexus-canary.log

RULES:
  P15-1: Every new tool group must add canary+smoke before registering
  P15-2: smoke.py must pass 100% before shipping
  P15-4: When real user reports failure, add regression test before fixing

═══════════════════════════════════════════════════════
SECTION 13 — HAIKU VALIDATION (LIVE)
═══════════════════════════════════════════════════════

4 triggers only (never add more without human PR):
  T1: anomaly_reviewer.review_anomaly()
  T2: feedback_classifier.classify_feedback() — bug_listener LIVE
  T3: schema_monitor.assess_schema_change()
  T4: digest_generator.generate_weekly_digest()

HAIKU_MODEL = "claude-haiku-4-5" (feedback/config.py)
HAIKU_MAX_CALLS_PER_DAY = 100 (payment/config.py)
Cost: ~$0.10/month

KNOWN REDIS KEYS:
  datanexus:schema:alerts:T10 — cvss_score REMOVED from upstream May 5
    severity: high, breaking: true — PENDING fix (30+ days)

RULES: S13-1 through S13-5 (see CLAUDE.md section below)

═══════════════════════════════════════════════════════
POSTHOG ANALYTICS
═══════════════════════════════════════════════════════

Project: DataNexus MCP (EU cloud)
Host:    https://eu.i.posthog.com
Events:  tool_called, tool_error, server_started

Total events: 2,060+
Peak: May 17 (828 events — Glama quality tester)
Organic baseline: 10-20 real tool calls/day (excl. smoke + Glama)

PostHog fires from Hetzner IP (178.104.251.70).
Real user IPs only visible in usage table client_ip field.

═══════════════════════════════════════════════════════
IP CLASSIFICATION (datanexus/core/ip_classifier.py)
═══════════════════════════════════════════════════════

KNOWN LEGIT (never grey):
  173.66.27.4    — Verizon FIOS Washington DC — security auditor
                   Called fetch_package_vulnerabilities on own packages
                   is_grey=false confirmed. 64+ ListTools hits.
                   HIGH VALUE — conversion target
                   Target tools: fetch_cisa_kev, fetch_cve_epss, sbom_audit

  73.241.93.191  — Comcast California residential (hsd1.ca.comcast.net)
                   May 22: T04 MIT EIN 042103594 (1ms cache hit)
                   May 29: T10 PyPI requests CVE check (1ms cache hit)
                   7-day return gap — organic retention confirmed ✓

  160.79.106.35/.36/.37/.38/.39 — Anthropic/Claude.ai infrastructure
                   Real Claude.ai users with DataNexus connector
                   NOTE: analysis conversations calling tools appear here
                   (self-contamination risk — add to KNOWN_INTERNAL filter)

  107.20.6.60    — Amazon EC2 us-east-1
                   138 hits in 7 days, 0 tool executions ever
                   Pure ListTools polling ~every 70 min
                   Not grey — intentional actor, just not executing tools

WATCH LIST:
  77.83.39.x     — Lanedo.net NL (legitimate OSS consultancy)
                   NOTE: May 24 context had as KPROHOST LLC (grey)
                   dn-whois May 26 returned Lanedo.net — possible ASN change
                   Keep on watch list until confirmed
  152.233.x      — RIPE NCC — measurement network, not a user

KNOWN QUALITY TESTERS (exclude from dn-daily):
  172.68.23.75   — Cloudflare/Glama quality tester (27 all-time calls)
  172.68.23.76   — Cloudflare/Glama quality tester (428 all-time calls)
  Total: 455 all-time. dn-glama filter: '172.68.%' confirmed accurate.
  Pattern: ~1 call/second, systematic tool sweep, 5-6 min sessions
  May 29 biggest sweep: 405 calls in 6m51s
  T19 false positive: EPA "climate emissions" → 'system:' injection pattern

KNOWN SCANNERS (is_grey=True):
  66.132.x       — Censys, Inc.
  66.249.x       — Googlebot
  207.90.244.x   — Shodan LLC

GREY_IP_PREFIXES (excluded from dn-daily + dn-returning):
  213.209.159.x  — AS208137 Feo Prest SRL
  79.124.40.x    — AS50360 Tamatiya EOOD
  130.12.180.x   — AS202412 Omegatech LTD
  5.61.209.x     — AS206264 Amarutu Technology
  45.148.10.x    — AS48090 TECHOFF SRV LIMITED
  185.91.127.x   — AS49581 Ferdinand Zink
  109.120.184.x  — AS210644 AEZA GROUP LLC (RU/FI bulletproof)
  80.94.95.x     — AS204428 SS-Net
  149.50.122.x   — AS201814 MEVSPACE via Cogent
  176.65.139.x   — Storm Industries/PFCLOUD-NET NL (bulletproof)
  93.174.93.x    — IP Volume Inc NL (bulletproof)
  2.59.22.x      — Black HOST Ltd AT (bulletproof)
  165.227.x      — DigitalOcean
  64.226.x       — DigitalOcean
  162.243.x      — DigitalOcean
  66.198.225.x   — SKN Subnet & Telecom
  192.253.248.x  — Secure Internet/btcloud.ro
  45.142.154.x   — ALLCLOUD_US IP transit
  45.198.224.x   — VPSVAULT.HOST Seychelles
  212.30.36.x    — GSL Networks/vpnconsumer.com VPN exit nodes

  NOTE: Claude Code prompt for ip_classifier.py update ready from May 26
  SINGLE-HIT POLICY: ignore single-hit IPs unless in usage table

ORGANIC USERS — HISTORICAL:
  117.144.65.213 — Shanghai Mobile, China
                   domain_fetch_domain_history, legal_fetch_patent_citations
                   Hit Bug 1 (CN patent prefix 400)
  222.212.248.29 — ChinaNet Backbone, Chengdu — 6 calls, most active historical
  204.93.227.11  — CacheFly, Leesburg US — older Glama quality tester
  213.33.190.88  — Vimpelcom, Russia — single visit
  216.246.40.79  — CacheFly CDN — T04 call (example EIN copy-paste)

═══════════════════════════════════════════════════════
GLAMA REGISTRY STATUS (May 29-30)
═══════════════════════════════════════════════════════

URL: glama.ai/mcp/servers/datanexusmcp/mcp-server
Profile completion: 92% (one item remaining: No related servers)
Rating: AAA — License A, Quality A, Maintenance A
Glama release: v2.13 (separate from npm v2.3.0)
npm: @datanexusmcp/mcp-server v2.3.0 (published May 30)
glama.json: 46 tools, tools_count=46
README: updated May 30 — Sprint 6+7 documented, new ICP structure
Categories: Security, Government Data, Legal & Compliance

CHECKLIST (May 29):
  ✅ Has a Glama release
  ✅ Server Coherence A
  ✅ Tool Definition Quality A
  ✅ Maintenance A      ← upgraded from B May 27
  ✅ Has permissive license (MIT) A
  ✅ Has README
  ✅ Active usage
  ✅ Has valid glama.json  ← fixed May 25
  ✅ Author verified
  🚫 No related servers  ← only item for 100%

glama.json fixes (May 25):
  - Wrong $schema URL: glama.json → server.json
  - Added: "maintainers": ["datanexusmcp"]
  - Profile 83% → 92%

Maintenance A (May 27) via:
  - CI workflow: .github/workflows/ci.yml PASSING ✅
  - 3 GitHub issues backfilled + closed
  - Commit graph visible (PAT with workflow scope)
  - Auth: PAT with workflow scope OR SSH key preferred

TOOL SCORES (from Glama quality tester):
  report_mcpize_link:          3.0/5.0 B  ← needs improvement
  security_fetch_cve_epss:     4.4/5.0 A
  domain_check_email_security: 4.5/5.0 A
  All others:                  4.7-4.9/5.0 A

GLAMA ANALYTICS (May 23 baseline):
  Search Impressions: 55,000+
  Search Clicks:      62 (0.1% CTR)
  Profile Views:      2,984

COMPETITIVE POSITION (AAA in DataNexus categories):
  Government Data: #1 — only AAA server
  Security: Top 2 AAA
  Legal & Compliance: Top 4 AAA
  No direct AAA competitor covers all three. Only AAA with npm + hosted URL.

OPEN ITEMS:
  - Discord ticket: stale tile description (opened May 25, pending)
  - Related servers: add 3-5 for 100%
    Candidates: FRED MCP, DuckDuckGo MCP, mcp-osv, Brave Search MCP
  - Apply to Glama Connectors (one-click, separate from Servers)
    URL: glama.ai/mcp/connectors

═══════════════════════════════════════════════════════
SMITHERY REGISTRY STATUS (added May 28)
═══════════════════════════════════════════════════════

URL: https://smithery.ai/servers/datanexusmcp/mcp-server
Namespace: datanexusmcp (replaced dev-7bd0)
Published: May 28 2026
Display name: DataNexus MCP
Calls to date: 0 (indexing lag 24-72h)

CLI commands:
  smithery mcp publish <url> -n <namespace>/<name>
  smithery mcp update <id> --name "Display Name"
  smithery mcp update <id> --metadata '{"description":"..."}'
  NOTE: --license flag doesn't exist. License from GitHub repo.
  NOTE: mcp update works on connections not listings — use web UI for
        registry metadata.

═══════════════════════════════════════════════════════
NPM PACKAGE STATUS
═══════════════════════════════════════════════════════

Package: @datanexusmcp/mcp-server v2.3.0
Downloads last month: 2,169 (Apr 27 - May 26)

npm API:
  last-day:   https://api.npmjs.org/downloads/point/last-day/@datanexusmcp/mcp-server
  last-week:  https://api.npmjs.org/downloads/point/last-week/@datanexusmcp/mcp-server
  last-month: https://api.npmjs.org/downloads/point/last-month/@datanexusmcp/mcp-server

dn-npm alias shows all three in one command.

═══════════════════════════════════════════════════════
ACTIVATION ANALYTICS (added May 29)
═══════════════════════════════════════════════════════

FUNNEL STATUS (May 30):
  first_call:    9 unique users  (+4 overnight May 29-30)
  real_query:   10 unique users  ← bug: should be ≤ first_call
  return_visit:  2 unique users
  multi_tool:    0               ← backfill bug
  power_user:    0

RETURN VISIT USERS CONFIRMED:
  160.79.106.37  — Claude.ai infra (backfill artifact — 31 events)
  73.241.93.191  — CA Comcast — MIT EIN + PyPI requests — 7-day gap ✓

KNOWN BUGS IN DETECTOR (Claude Code prompt ready):
  Bug 1: first_call checks existing==1 AFTER write → should check BEFORE (==0)
  Bug 2: return_visit fires every call after day 2 → dedup needed
  Bug 3: multi_tool uses NOW() in backfill → use row's created_at as anchor

EXAMPLE EIN CHANGE (May 29-30):
  OLD: 131837418 (Candid/GuideStar — copy-pasted by evaluators)
  NEW: 46-5734087 (Code for Science & Society — real but obscure)
  Purpose: any 131837418 call = copy-paste tester not organic signal

ACTIVATION RATE: ~6% (target: 25% by end sprint 6)

ORGANIC USAGE (May 22-30 dn-activation):
  May 22:  4 calls, 2 IPs
  May 23:  2 calls, 1 IP
  May 24: 42 calls, 3 IPs  ← best organic day (MN due diligence)
  May 25:  0 calls
  May 26:  6 calls, 1 IP
  May 27: 48 calls, 4 IPs
  May 28:  1 call
  May 30: +4 new first_call users overnight

PostHog 7-day tool breakdown (organic only):
  fetch_nonprofit_by_ein:        26 (#1 — inflated by example EIN)
  fetch_package_vulnerabilities: 12
  search_npi_by_name:            12 (entirely MN user May 24)
  search_nonprofits_by_name:     10
  fetch_cve_detail:               8
  fetch_package_licence:          8
  search_patents_by_keyword:      7

SPRINT 6 PRIMARY SUCCESS METRIC:
  At least 1 user must call fetch_cve_watch create, then check
  on a subsequent calendar day with same watch_id.
  Monitor via dn-returning after June 1.

═══════════════════════════════════════════════════════
UPSTREAM FIXES APPLIED
═══════════════════════════════════════════════════════

cisa_kev (May 25-26): switched to cisagov/kev-data GitHub mirror
  Was: cisa.gov — Akamai blocks Hetzner datacenter IPs (403)
  Now: raw.githubusercontent.com/cisagov/kev-data/main/
       known_exploited_vulnerabilities.json

sam_gov (May 25-26): canary frequency 24h, TTL 86400
  Was: every canary cycle exhausting daily quota (429)

crt_sh (May 25-26): 502 fallback to cached response (DEGRADED not FAIL)
  Root cause: chronic crt.sh hardware instability since Apr 2026

═══════════════════════════════════════════════════════
KNOWN BUGS — PENDING FIXES
═══════════════════════════════════════════════════════

BUG 1 — Patent citations 400 for non-EP patents
  Tool: legal_fetch_patent_citations
  Symptom: CN120586032 → 400 Bad Request
  Cause: tool prepends EP to all patent numbers
  Fix: use patent_number as-is in EPODOC URL
  Status: PENDING — real user (117.144.65.213) hit this

BUG 2 — Sprint 4 smoke test failures
  Tools: fetch_cisa_kev (FIXED May 26), fetch_cve_epss,
    fetch_cve_detail_remediation, fetch_subdomains
  Status: Reassess after Sprint 6 KEV mirror fix

BUG 6 — T10 UNKNOWN severity (30+ days old)
  GHSA-9wx4-h78v-vm56 valid CVSS but severity.level=UNKNOWN
  Haiku: needs_review (0.45). Fix: Section 13.4 Rule 1
  Status: PENDING — human decision needed

BUG 7 — feedback:record missing context fields (3 of 9 fields written)
  Fix prompt: FEEDBACK_RECORD_NTFY_FIX.md (ready)
  Status: PENDING

BUG 8 — ntfy em-dash encoding
  Fix: title.encode('ascii', errors='replace').decode('ascii')
  Status: PENDING (combined with Bug 7)

BUG 9 — Caddy access log not persistent
  Fix prompt: CADDY_ACCESS_LOG_PROMPT.md (ready)
  Status: PENDING

BUG 10 — Smoke test not tagged is_smoke=true (URGENT)
  client_ip='unknown', tool_input={} appearing in dn-daily hourly
  Pattern: T04+T10, 3-5 calls/15s, ~hourly
  Fix: os.environ['DATANEXUS_SMOKE_RUN']='1' at top of smoke.py BEFORE imports
       Fix IP fallback to '127.0.0.1' not 'unknown'
  Status: PENDING — highest priority

BUG 11 — Activation detector 3 bugs
  first_call off-by-one, return_visit no dedup, multi_tool backfill broken
  Claude Code prompt: ready
  Status: PENDING

BUG 12 — T19 injection false positive
  EPA "climate emissions" → "system:" in regulatory text triggers detector
  Fix: tighten regex to injection-style patterns only
  Claude Code prompt: ready
  Status: PENDING

BUG 13 — Panel 2 dashboard smoke inflation
  Missing is_smoke=false + is_grey=false in Panel 2 queries
  Shows T04:48, T07:240 — inflated ~50x. Real: T10:3, T04:3
  Claude Code prompt: ready
  Status: PENDING

═══════════════════════════════════════════════════════
CRITICAL BUGS FIXED (historical)
═══════════════════════════════════════════════════════

SSE FIX (May 14) — flush_interval -1 + HTTP/1.1
FastMCP GET /mcp 406→405 (May 27) — stateless_http/json_response in main.run()
CISA KEV → GitHub mirror (May 25)
SAM.gov canary → 24h (May 25)
crt.sh 502 → cache fallback DEGRADED (May 25)
Circuit breakers centralized (May 30 — Sprint 7 D4)
DB username bug — docker-compose.yml overriding .env
EPO query format — ta all "keywords" (was ti = "keywords")
PatentsView decommissioned Jan 2026 — replaced with EPO
Bug listener not deployed (fixed May 23)
Usage table not writing (fixed May 23)
IP classifier + grey ASN filter (fixed May 24)
OQ1 — ProPublica endpoint: /organizations/{ein}.json not /filings.json

═══════════════════════════════════════════════════════
SPRINT HISTORY
═══════════════════════════════════════════════════════

Sprint 1–2: 26 tools across 7 sub-servers
Sprint 3:   Regrouped into FastMCP mount pattern
Sprint 4:   +9 tools (T10 KEV/EPSS/SBOM, T07 subdomain/email/reverse-ip) → 35
Sprint 6:   +6 tools (aggregators + stateful + supply chain) → 41
Sprint 7:   +5 tools (licence + CVE aggregator + nonprofit depth) → 46
            npm v2.3.0 published, deployed May 30

SPRINT DESIGN NOTE: Do NOT read SPRINT6_DESIGN.md or SPRINT7_DESIGN.md.
They describe earlier plans superseded by the prompts.
Authoritative specs: SPRINT6_PROMPT.md, SPRINT7_PROMPT.md

═══════════════════════════════════════════════════════
SPEC DOCUMENTS
═══════════════════════════════════════════════════════

DataNexus_MCP_Spec_v7_6.docx — CURRENT AUTHORITATIVE
  Sections 1-12: core architecture
  Section 13: Haiku validation (4 triggers)
  Section 14: Sprint 3 plan (7 sub-servers)
  Section 15: Three-layer testing architecture

Sprint 4 spec:
  ~/.gstack/projects/Phase1/
  sangeetajagadeesh-unknown-design-20260516-221059.md

Claude Code prompts in OmSaiRam/:
  SECTION13_PROMPT_v2.md
  SPRINT2_PROMPT.md
  SPRINT3_P10_PROMPT.md
  SPRINT3_P10b_DOCS_PROMPT.md
  SPRINT6_PROMPT.md              ← authoritative (not SPRINT6_DESIGN.md)
  SPRINT7_PROMPT.md              ← authoritative (not SPRINT7_DESIGN.md)
  GLAMA_FIX_PROMPT.md
  POSTHOG_PROMPT.md
  GLAMA_SCORE_PROMPT.md
  CADDY_ACCESS_LOG_PROMPT.md     ← ready, not yet run (Bug 9)
  USAGE_INSTRUMENTATION_PROMPT.md ← DONE May 23
  FEEDBACK_RECORD_NTFY_FIX.md   ← ready (Bugs 7+8)

═══════════════════════════════════════════════════════
CLAUDE.md RULES (KEY ONES)
═══════════════════════════════════════════════════════

D1: Never push to git or deploy to Hetzner
    mid-sprint without operator confirmation
D2: Never register tool in main.py on Hetzner
    before smoke tests pass locally
D3: glama.json tool count updated in same commit
    as every tool registration

S13-1: Haiku called ONLY on 4 triggers
S13-2: Always use HAIKU_MODEL from config.py
S13-3: HAIKU_MAX_CALLS_PER_DAY=100 non-negotiable
S13-4: validate_tool_output never raises
S13-5: FeedbackRecord.classification one-way only

P15-1: Every new tool group must add canary+smoke before registering
P15-2: smoke.py must pass 100% before shipping
P15-4: When real user reports failure, add regression test before fixing

SPRINT 7 HARD STOPS:
  — Never define pybreaker.CircuitBreaker() in a tool file
  — kev_listed/epss_score/patch_available degrade to null, never false/0.0
  — nvd.nist.gov NOT a valid patch confirmation URL
  — Semaphore(10) on audit_licence_compatibility package path
  — glama.json updated in same commit as main.py tool registration

═══════════════════════════════════════════════════════
MONETISATION STATUS
═══════════════════════════════════════════════════════

MCPIZE_ACTIVE=false through ~July-August 2026
FEEDBACK_AGENTS_ACTIVE=false
All Sprint 6 and Sprint 7 tools are free.
Infrastructure: ~$6.19/month Hetzner
Haiku cost: ~$0.10/month
Current revenue: $0
T12 Sanctions: DEFERRED to Sprint 5+ (needs legal entity first)

PLANNED PRICING:
  Free:        $0    — 500 calls/month, all 46 tools, email required
  Pro:         $29/month — 5,000 calls/month
  Team:        $99/month — 25,000 calls/month
  Enterprise:  $499/month — unlimited + SLA

API KEY STRATEGY (not yet implemented — priority next sprint):
  Purpose 1: Identity — email capture (most important NOW)
  Purpose 2: Usage signal — per-user attribution
  Purpose 3: Monetization gate (later)
  Soft nudge before hard gate:
    Return in response: "Free tier — sign up at datanexusmcp.com"

90-DAY REVISED TARGETS:
  Day 30: 10 email signups, activation rate 6% → 15%
  Day 60: 5 user conversations, 1 paying customer
  Day 90: 3-5 paying customers, $87-$495 MRR

═══════════════════════════════════════════════════════
CLAUDE CONNECTORS DIRECTORY OPPORTUNITY
═══════════════════════════════════════════════════════

Anthropic Connectors Directory:
  Submit: claude.ai/connectors/submit
  Size:   375+ integrations May 2026
  Impact: zero-friction one-click for Claude Pro/Team users
  Status: Not yet applied — apply after activation rate improved

Glama Connectors (separate from Glama Servers):
  URL:    glama.ai/mcp/connectors (3,565 remote connectors)
  Impact: one-click via Glama Gateway, no URL pasting
  Status: DataNexus in Servers ✓, NOT in Connectors yet
  Action: submit at glama.ai/mcp/connectors

═══════════════════════════════════════════════════════
PRIORITY TODO LIST (May 30, 2026)
═══════════════════════════════════════════════════════

URGENT (do today):
  1. Fix smoke test is_smoke tagging (Bug 10) — prompt ready
  2. Fix Panel 2 dashboard smoke filter (Bug 13) — prompt ready
  3. Fix activation detector bugs (Bug 11) — prompt ready

HIGH (this week):
  4. Fix T19 injection false positive (Bug 12) — prompt ready
  5. Fix tool descriptions for low Glama scores (report_mcpize_link 3.0)
  6. Add related servers on Glama (reach 100% — Bugs 3 pending Discord)
  7. Apply to Glama Connectors section
  8. Update ip_classifier.py grey blocklist (10 new ASNs from May 26)
     Claude Code prompt: ready

NEXT SPRINT:
  9. API key signup flow + email capture (identity + monetization)
  10. Cross-tool suggestions (welcome resource + next-step nudges)
  11. Apply to Anthropic Connectors Directory
  12. Fix patent citations 400 non-EP (Bug 1)
  13. Add SECURITYTRAILS_KEY for domain_fetch_reverse_ip
  14. Monitor Sprint 6 stateful anchors for return visit metric
  15. Check dn-returning June 1+ for Sprint 7 nonprofit adoption

PENDING:
  16. Feedback record missing fields + ntfy (Bugs 7+8) — prompt ready
  17. Caddy access log persistent (Bug 9) — prompt ready
  18. T10 UNKNOWN severity human decision (Bug 6)
  19. Reassess Sprint 4 smoke failures (Bug 2)

═══════════════════════════════════════════════════════
MORNING CHECKLIST (15 min daily)
═══════════════════════════════════════════════════════

ssh datanexus
cd /app/datanexus

dn-daily          — watch for client_ip='unknown' tool_input={} (Bug 10)
dn-who-24h        — new IPs, classify anything 5+ hits
dn-funnel         — activation funnel trend (all 5 levels)
dn-returning      — returning users (Sprint 6 stateful metric)
dn-activation     — 14-day organic call trend
dn-glama          — Glama tester activity (172.68.%)
dn-npm            — npm downloads

Watch for:
  173.66.27.4 making tool calls (DC auditor conversion)
  107.20.6.60 executing tools (AWS EC2 poller)
  fetch_cve_watch create → return visit (Sprint 6 primary metric)
  New Smithery IPs appearing
  client_ip='unknown' tool_input={} — smoke bug still active

Check Glama: glama.ai/mcp/servers/datanexusmcp/mcp-server
  Profile: 92% (add related servers for 100%)
  Tile description: pending Discord re-index

═══════════════════════════════════════════════════════
HOW TO START A NEW CHAT SESSION
═══════════════════════════════════════════════════════

Paste this at the start of new conversation:

"Read /Users/sangeetajagadeesh/OmSaiRam/DATANEXUS_CONTEXT_MAY30.md
for full project context. Summarise current state in one paragraph
to confirm you have it, then help me with: [your task]"

NOTE: Rename this file to DATANEXUS_CONTEXT_MAY30.md on your Mac.
      Update the HOW TO START section in future updates accordingly.
