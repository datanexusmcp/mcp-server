# DataNexus MCP — Full Project Context
# Last updated: May 24, 2026
# Use this file to start a new chat session without losing context

═══════════════════════════════════════════════════════
PRODUCT OVERVIEW
═══════════════════════════════════════════════════════

DataNexus MCP is a remote MCP server delivering
public data intelligence to AI agents.

Server URL:  https://datanexusmcp.com/mcp
Transport:   Streamable HTTP
npm package: @datanexusmcp/mcp-server v2.2.1
GitHub:      github.com/datanexusmcp/mcp-server
Dashboard:   http://localhost:8101 (SSH tunnel)
             ssh -L 8101:localhost:8101 datanexus -N

═══════════════════════════════════════════════════════
INFRASTRUCTURE
═══════════════════════════════════════════════════════

Server:      Hetzner CAX11, IP 178.104.251.70
OS:          Ubuntu 24.04, Docker 29.4.1
SSH:         ssh datanexus
             Key: ~/.ssh/datanexus_ed25519_new
             Full: ssh -i ~/.ssh/datanexus_ed25519_new root@178.104.251.70
Domain:      datanexusmcp.com (Cloudflare DNS, proxy OFF)
             NOTE: Cloudflare analytics always zero for datanexusmcp.com
             because proxy is OFF — traffic goes direct to Hetzner.
             Use dn-who / dn-daily / PostHog for real analytics.
Email:       dev@datanexusmcp.com
Stack:       Caddy + uvicorn FastMCP + Redis 7 + PostgreSQL 16
Deploy path: /app/datanexus on server
DB user:     dn (NOT datanexus — was a bug, fixed)
DB tables:   sessions, usage (11 columns — see schema below)
Snapshot:    386464566 (post SSE fix, v2.1.3 — CURRENT)

DOCKER CONTAINERS (7 total as of May 24):
  datanexus-caddy-1         — TLS + reverse proxy
  datanexus-datanexus-mcp-1 — FastMCP server :8000 + dashboard :8101
  datanexus-redis-1         — cache + sessions + feeds
  datanexus-postgres-1      — usage + sessions tables
  datanexus-daily-digest-1  — Section 13 T4 digest cron
  datanexus-kev-refresh-1   — CISA KEV refresh
  datanexus-bug-listener-1  — Section 13 T2 feedback classifier ✓ NEW

DOCKER COMMANDS (always run from /app/datanexus):
  cd /app/datanexus
  docker compose ps
  docker compose logs datanexus-mcp --tail 50
  docker compose logs caddy --tail 50
  docker compose logs bug-listener --tail 20
  docker compose restart datanexus-mcp
  docker compose build --no-cache datanexus-mcp
  docker compose up -d

SERVER ALIASES (available on Hetzner):
  dn-who        — top external IPs with geo lookup
  dn-users      — unique users per day
  dn-aborts     — SSE abort timestamps
  dn-ps         — container status
  dn-logs       — MCP server logs
  dn-crtsh      — check crt.sh status
  dn-daily      — organic tool usage last 24h (grey IPs excluded)
                  curl -s http://localhost:8101/ops/daily | python3 -m json.tool
  dn-returning  — returning users (2+ calendar days) ⏳ data pending
                  curl -s http://localhost:8101/ops/returning-users | python3 -m json.tool
  dn-activation-events — last 50 activation events (last 7 days)
  dn-funnel            — funnel counts per event_type (all 5 levels, last 30 days)
                         Gate: must return 5 rows even when counts are 0

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
  is_grey     BOOLEAN DEFAULT false  ← NEW May 24

Indexes: usage_pkey, usage_call_uuid_key, usage_client_ip_idx,
         usage_created_at_idx, usage_tool_id_idx

INSTRUMENTATION STATUS (confirmed May 24 end-to-end):
  HTTP POST /mcp → tool executes → usage row written (is_smoke=false)
  → PostHog tool_called fires — all three at same millisecond. LIVE.
  Smoke tests: is_smoke=true, excluded from PostHog and dn-daily.
  Grey IPs: is_grey=true, excluded from dn-daily and dn-returning.

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

CRITICAL: DATANEXUS_DB_URL must be in /app/.env NOT in
docker-compose.yml environment: block. Past bug: it was
hardcoded in docker-compose.yml with wrong username
(datanexus instead of dn) which overrode .env.

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

NOTE: read_buffer_size, write_buffer_size,
max_idle_conns_per_host are NOT supported by
the Caddy version on Hetzner — do not add them.

CADDY LOGGING NOTE: Caddy only logs warn-level entries by default.
Successful requests are silent in Caddy logs — only failures appear.
All successful requests visible only via uvicorn logs (as 172.18.0.x)
or PostgreSQL usage table (with real client_ip via X-Real-IP).
Caddy persistent access log prompt: CADDY_ACCESS_LOG_PROMPT.md (pending)

═══════════════════════════════════════════════════════
LIVE TOOLS — CURRENT STATE
═══════════════════════════════════════════════════════

Total: 30+ tools across 7+ sub-servers

SPRINT 1 (T04 — Nonprofit):
  nonprofit_fetch_nonprofit_by_ein
  nonprofit_search_nonprofits_by_name
  nonprofit_fetch_charity_uk

SPRINT 1 (T10 — Security):
  security_fetch_package_vulnerabilities (batch supported)
  security_fetch_dependency_graph
  security_fetch_cve_detail (now includes remediation)
  security_audit_sbom_vulnerabilities
  security_fetch_package_licence

SPRINT 4 NEW (T10 additions):
  security_fetch_cisa_kev        — CISA KEV catalog lookup
  security_fetch_cve_epss        — EPSS exploit probability
  security_fetch_cve_detail_remediation — CVE + fix versions

SPRINT 2 (T22 — Compliance):
  compliance_fetch_npi_provider
  compliance_search_npi_by_name
  compliance_fetch_finra_broker
  compliance_check_sam_exclusion

SPRINT 2 (T07 — Domain):
  domain_fetch_domain_rdap
  domain_fetch_ssl_certificate_chain
  domain_fetch_dns_records
  domain_fetch_domain_history

SPRINT 4 NEW (T07 additions):
  domain_fetch_subdomains        — CT log subdomain enum
  domain_check_email_security    — SPF/DMARC/DKIM scoring
  domain_fetch_reverse_ip        — co-hosted domains (needs SECURITYTRAILS key)

SPRINT 2 (T11 — Patents):
  legal_fetch_patent_by_number
  legal_search_patents_by_keyword
  legal_fetch_patent_citations
  legal_fetch_inventor_portfolio

SPRINT 2 (T18 — GovCon):
  govcon_search_contract_awards
  govcon_fetch_vendor_contract_history
  govcon_fetch_open_solicitations

SPRINT 2 (T19 — Regulatory):
  regulatory_search_open_rulemakings
  regulatory_fetch_docket_details
  regulatory_fetch_federal_register_notices

SHARED:
  search_datanexus_tools         — meta-tool, find right tool
  report_feedback                — data quality reporting
  report_mcpize_link             — subscription status
  validate_tool_output           — two-layer validation

═══════════════════════════════════════════════════════
SECTION 13 — HAIKU VALIDATION (LIVE)
═══════════════════════════════════════════════════════

4 triggers only (never add more without human PR):
  T1: anomaly_reviewer.review_anomaly()
  T2: feedback_classifier.classify_feedback() ✓ bug_listener NOW LIVE
  T3: schema_monitor.assess_schema_change()
  T4: digest_generator.generate_weekly_digest()

HAIKU_MODEL = "claude-haiku-4-5" (feedback/config.py)
HAIKU_MAX_CALLS_PER_DAY = 100 (payment/config.py)
Cost: ~$0.10/month at current volume

FEEDBACK LOOP STATUS (confirmed May 23):
  bug_listener deployed as docker service — runs BLPOP on fb:alerts:immediate
  Backlog of 4 pending records (from May 3) processed on startup:
    T10 b8a3aea7 → needs_review (score 0.45) — UNKNOWN severity bug
    T04 test records → scores 0.62, 0.45 — below 0.8 GitHub threshold
  feedback:record:{id} writes only 3 fields — fix prompt pending:
    (classification, score, agent_version — missing context fields)
  ntfy em-dash encoding bug — push alerts not working, fix prompt pending

KNOWN REDIS KEYS:
  datanexus:schema:alerts:T10 — breaking change detected May 5
    cvss_score field REMOVED from upstream — 20 days unactioned
    affected_fields: ["cvss_score"]
    severity: high, breaking: true
  datanexus:digest:T10:2026-W19 — weekly digest generated May 4
    data_quality_score: 0.75
    top_issues: UNKNOWN severity, missing fixed_version, CVE lag
  fb:alerts:immediate — queue drained, 0 pending

═══════════════════════════════════════════════════════
SECTION 15 — THREE-LAYER TESTING (LIVE)
═══════════════════════════════════════════════════════

Layer 1: 84 unit tests (pytest) — run on every commit
Layer 2: Upstream canary (datanexus/tests/canary.py)
         Runs hourly at :00 via cron
         14 upstream sources checked
Layer 3: Tool smoke tests (datanexus/tests/smoke.py)
         Runs hourly at :30 via cron
         All 30 tools with known-good inputs

CURRENT SMOKE STATUS (May 19):
  PASS: 29, FAIL: 6, DEGRADED: 1, SKIP: 3
  FAIL causes:
    - fetch_cisa_kev, fetch_cve_epss,
      fetch_cve_detail_remediation,
      fetch_subdomains — Sprint 4 bugs pending fix
    - fetch_ssl_certificate_chain,
      fetch_domain_history — crt.sh upstream issue
  DEGRADED: check_sam_exclusion (SAM.gov slow)
  SKIP: report_feedback, report_mcpize_link
        (not in meta module), fetch_finra_broker (gated)

Rule P15-4: when a real user reports a failure,
add regression smoke test BEFORE fixing the bug.

CRON ON HETZNER:
  30 * * * * cd /app/datanexus && docker compose
    exec -T datanexus-mcp python3 -m
    datanexus.tests.smoke >> /var/log/datanexus-smoke.log
  0 * * * *  cd /app/datanexus && docker compose
    exec -T datanexus-mcp python3 -m
    datanexus.tests.canary >> /var/log/datanexus-canary.log

═══════════════════════════════════════════════════════
POSTHOG ANALYTICS
═══════════════════════════════════════════════════════

Project: DataNexus MCP (EU cloud)
Host:    https://eu.i.posthog.com
Events:  tool_called, tool_error, server_started

CONFIRMED WORKING (May 24 end-to-end test):
  curl POST /mcp → usage table row + PostHog event
  at exact same millisecond. Both pipelines live.

Total events to date: 2,060+
Peak: May 17 (828 events — Glama quality tester)
Current organic: 2-3 real tool calls/day
  (200+ bot connections do ListTools only — not tool executions)

Smoke test exclusion: DATANEXUS_SMOKE_RUN=1 confirmed working.
Smoke calls excluded from PostHog and dn-daily.

PostHog PostHog fires from Hetzner IP (178.104.251.70).
Real user IPs only visible in usage table client_ip field.

═══════════════════════════════════════════════════════
IP CLASSIFICATION (datanexus/core/ip_classifier.py)
═══════════════════════════════════════════════════════

KNOWN LEGIT IPs:
  173.66.27.4    — Verizon Business / Laurel MD
                   Security auditor — scanned @datanexusmcp/mcp-server
                   and @modelcontextprotocol/server-sequential-thinking
                   Result: clean (vulns: []) — good signal for trust
  73.241.93.191  — US organic — looked up MIT EIN (04-2103594)
  160.79.106.35/.36/.37/.38 — Google LLC / Anthropic Claude.ai infra
  107.20.6.60 — Amazon EC2 us-east-1
    - 138 hits in 7 days, 0 tool executions
    - Pure ListTools only — automated polling ~every 70 min
    - Likely MCP aggregator, crawler, or misconfigured agent
    - Not grey (intentional actor) but not a real user
    - Add to dn-daily exclusion? Low priority — not inflating metrics
      since dn-daily only counts tool executions anyway
    - WATCH: if tool calls appear, reassess immediately

WATCH_LIST (not grey — monitored):
  77.83.39.x     — Lanedo.net NL — legitimate OSS consultancy, watching
                   (prev. misidentified as KPROHOST LLC / AS214940)
  152.233.x      — RIPE NCC — measurement network, not a real user

KNOWN SCANNERS (is_grey=True, logged at INFO — visible in future dn-scanners):
  66.132.x       — Censys, Inc. — internet-wide security scanner
  66.249.x       — Googlebot

GREY_IP_PREFIXES (excluded from dn-daily + dn-returning):
Last updated: May 26 2026 via dn-whois-batch

  Original entries (confirmed May 24):
  AS208137 Feo Prest SRL         213.209.159.x
  AS50360  Tamatiya EOOD          79.124.40.x
  AS202412 Omegatech LTD          130.12.180.x
  AS206264 Amarutu Technology     5.61.209.x
  AS48090  TECHOFF SRV LIMITED    45.148.10.x
  AS49581  Ferdinand Zink         185.91.127.x
  AS210644 AEZA GROUP LLC         109.120.184.x
  AS204428 SS-Net                 80.94.95.x
  AS201814 MEVSPACE               149.50.122.x

  Added May 26 2026 via dn-whois-batch:
  176.65.139.x   — Storm Industries / PFCLOUD-NET NL — bulletproof host
  93.174.93.x    — IP Volume Inc NL — bulletproof host, chronic abuse
  2.59.22.x      — Black HOST Ltd AT — bulletproof host
  165.227.x      — DigitalOcean — datacenter bot range
  64.226.x       — DigitalOcean — datacenter bot range

NOTE: Grey IPs still get served — only excluded from analytics.
      Most bots do ListTools only, no actual tool execution.
      77.83.39.x removed from grey list May 26 — reclassified to WATCH_LIST.

═══════════════════════════════════════════════════════
GLAMA STATUS
═══════════════════════════════════════════════════════

Listing: glama.ai/mcp/servers/datanexusmcp/mcp-server
Profile completion: 58%+ (improving)
Scores: License A, Quality A, Maintenance B
Glama release: v2.13 (separate from npm v2.2.1)

ANALYTICS (as of May 23):
  Search Impressions: 55,000+
  Search Clicks:      62 (0.1% CTR — PROBLEM)
  Profile Views:      2,984
  Tool Calls:         0 (via Glama Try in Browser)
  Copy MCP URL:       not tracked — enhancement request sent to Glama

ROOT CAUSE of low CTR: glama.json description stale
PENDING FIX: update glama.json description to:
  "CISA KEV · CVE EPSS · SBOM audit · patent
  search · nonprofit 990 · government contracts
  · subdomain enumeration · email security
  scoring. 30+ tools, zero install, one URL."
Glama tile description stale — Discord ticket opened May 25 2026
glama.json fix pushed and verified. Awaiting forced re-index from Glama team.
Follow up if not resolved by May 28.

npm package: @datanexusmcp/mcp-server v2.2.1

═══════════════════════════════════════════════════════
ORGANIC USERS CONFIRMED
═══════════════════════════════════════════════════════

Since SSE fix (May 14, 17:30 UTC):

173.66.27.4 — Verizon Business / Laurel MD (HIGH VALUE)
  - Security auditor profile (beltway / contractor)
  - Called fetch_package_vulnerabilities on:
    @datanexusmcp/mcp-server@2.2.1 → clean ✓
    @modelcontextprotocol/server-sequential-thinking → clean ✓
  - Previously failed SSE connection (node client)
  - Now successfully using HTTP transport
  - WATCH: likely returning — dn-returning will show when data matures

73.241.93.191 — US organic
  - fetch_nonprofit_by_ein: EIN 04-2103594 (MIT)
  - Cache hit, 1ms latency

117.144.65.213 — Shanghai Mobile, China
  - Repeat user, 5+ visits
  - Called: domain_fetch_domain_history,
    legal_fetch_patent_citations (CN120586032)
  - Patent citations bug hit: 400 Bad Request
    (EP prefix incorrectly prepended to CN patent)

222.212.248.29 — ChinaNet Backbone, Chengdu, China
  - 6 calls, most active historical user
  - New user as of May 17

204.93.227.11 — CacheFly, Leesburg US
  - Glama quality tester
  - Triggered Quality score A

160.79.106.35/.36 — Google/Anthropic
  - Claude.ai infrastructure
  - Real Claude users have DataNexus as connector

213.33.190.88 — Vimpelcom, Russia
  - Single visit

═══════════════════════════════════════════════════════
FIXES (May 27, 2026)
═══════════════════════════════════════════════════════

FIX — FastMCP GET /mcp 406 → 405 (Claude.ai connector sync)
  File: datanexus/main.py
  Cause: FastMCP 3.3.1 removed stateless_http/json_response from FastMCP()
    constructor — passing them there raises TypeError and crashes the server.
    FastMCP was falling back to non-stateless mode, returning 406 Not
    Acceptable on GET /mcp instead of 405, causing Claude.ai connector to
    spin forever on sync.
  Fix: removed stateless_http=True, json_response=True from FastMCP()
    constructor; added both params to main.run() call instead (correct
    location in FastMCP 3.3.1 — accepted via **transport_kwargs).
  Gates: GET /mcp → 405 ✓  POST /mcp initialize → 200 ✓  import ok ✓

PRE-SPRINT-6 FIXES (May 25, 2026)
═══════════════════════════════════════════════════════

FIX 1 — cisa_kev upstream changed to GitHub mirror
  File: datanexus/kev_refresh.py + datanexus/tests/canary.py
  Cause: cisa.gov Akamai CDN blocks all Hetzner datacenter IPs (403)
  Fix: switched KEV_URL to:
    https://raw.githubusercontent.com/cisagov/kev-data/main/
    known_exploited_vulnerabilities.json
  Mirror is officially maintained by CISA (cisagov org on GitHub)
  JSON schema is identical — all parsing logic unchanged

FIX 2 — sam_gov canary frequency reduced to 24h
  File: datanexus/tests/canary.py
  Cause: hourly canary exhausted SAM.gov 1,000 req/day quota (429s)
  Fix Part A: T22_TTL already 86400 — no change needed
  Fix Part B: added _CANARY_INTERVALS = {"sam_gov": 24}
    canary now runs once per 24h tracked via Redis
    key: datanexus:canary:sam_gov:last_run (TTL 25h)
    if within 24h window, returns SKIP (not FAIL)
    run is recorded even on 429 to protect remaining quota

FIX 3 — crt.sh 502 fallback to cache with DEGRADED status
  Files: datanexus/tools/t07.py + datanexus/tests/canary.py
  Cause: crt.sh hardware degraded since April 2026 (chronic 502s)
  Fix in t07.py:
    - _fetch_crt_sh timeout reduced to 5s (fail fast on 502)
    - _fetch_crt_sh raises HTTPStatusError explicitly on 502/503
    - fetch_ssl_certificate_chain: catches HTTPStatusError 502/503,
      serves phash+"_archive" cache with source_note field
    - fetch_domain_history: same fallback pattern
    - fetch_subdomains: serves domain+"_archive" on 502
    - All three tools now write _archive on success (TTL = T07_TTL * 6)
  Fix in canary.py:
    - canary_crt_sh returns DEGRADED (not FAIL) for 502/503
    - Tool response includes source_note about cached data

FIX 4 — glama.json maintainers field added
  File: glama.json
  Added: "$schema": "https://glama.ai/mcp/schemas/server.json"
  Added: "maintainers": ["datanexusmcp"]
  Added: "tools_count": 35 (verified against main.py: 35 total)
  Note: "datanexusmcp" is GitHub org username (not personal account)
  MANUAL STEP REQUIRED: go to glama.ai → DataNexus listing → Claim

═══════════════════════════════════════════════════════
KNOWN BUGS — PENDING FIXES
═══════════════════════════════════════════════════════

BUG 1 — Patent citations 400 for non-EP patents
  Tool: legal_fetch_patent_citations
  Symptom: CN120586032 → 400 Bad Request
  Cause: tool prepends EP to all patent numbers
    building URL /epodoc/EPCN120586032/citations
    instead of /epodoc/CN120586032/citations
  Fix: use patent_number as-is in EPODOC URL
  Status: PENDING — real user hit this

BUG 2 — Sprint 4 tools failing smoke tests
  Tools: fetch_cisa_kev, fetch_cve_epss,
    fetch_cve_detail_remediation, fetch_subdomains
  Status: PENDING

BUG 3 — glama.json description stale
  Shows "10 tools" and old description
  Status: PENDING — fix CTR from 0.1%

BUG 4 — Smoke test telemetry
  Status: FIXED — DATANEXUS_SMOKE_RUN=1 confirmed working
  Smoke calls excluded from PostHog + dn-daily ✓

BUG 5 — crt.sh upstream intermittent
  fetch_ssl_certificate_chain and
  fetch_domain_history return ingest_healthy=false
  Status: UPSTREAM — not our code

BUG 6 — T10 UNKNOWN severity (20 days old)
  GHSA-9wx4-h78v-vm56 and GHSA-gc5v-m9x4-r6x2
  have valid CVSS vectors but severity.level = UNKNOWN
  Haiku classified as needs_review (score 0.45)
  Fix spec: Section 13.4 Rule 1 — derive from CVSS vector
  Status: PENDING — needs human decision then Claude Code fix

BUG 7 — feedback:record missing context fields
  feedback_classifier writes only 3 fields to feedback:record:{id}
  Missing: tool_id, signal, comment, suggested_fix,
           missing_fields, received_at, query_hash
  Fix prompt: ready (combined with ntfy bug below)
  Status: PENDING

BUG 8 — ntfy em-dash encoding
  _fire_ntfy() fails with ascii codec on em-dash in title
  Push alerts not working
  Fix: title.encode('ascii', errors='replace').decode('ascii')
  Status: PENDING (combined with Bug 7 prompt)

BUG 9 — Caddy access log not persistent
  Successful requests invisible in Caddy logs
  Only failures logged (warn level)
  Fix prompt: CADDY_ACCESS_LOG_PROMPT.md (ready)
  Status: PENDING

═══════════════════════════════════════════════════════
CRITICAL BUGS FIXED (historical)
═══════════════════════════════════════════════════════

SSE FIX (May 14) — Most important fix ever
  Caddy was dropping GET /mcp SSE connections
  in ~2ms with "context canceled"
  Fix: flush_interval -1 + HTTP/1.1 upstream
  Impact: went from 890 downloads/0 usage to
  confirmed organic users within 24 hours

DB USERNAME BUG
  docker-compose.yml had DATANEXUS_DB_URL with
  username "datanexus" in environment: block
  overriding .env which had correct "dn" user
  Fix: removed from docker-compose.yml environment

EPO QUERY FORMAT
  legal_search_patents_by_keyword returned 404
  Wrong format: ti = "keywords"
  Correct CQL: ta all "keywords"
  Fixed and confirmed working

PatentsView decommissioned Jan 2026
  Replaced with EPO as primary, WIPO fallback
  301 redirects eliminated

crt.sh timeout
  Increased httpx timeout to 30 seconds
  domain_fetch_domain_history now returns data

BUG LISTENER NOT DEPLOYED (fixed May 23)
  bug_listener.py existed but was never added to
  docker-compose.yml — feedback queue sat pending
  for 20 days. Now running as dedicated container.

USAGE TABLE NOT WRITING (fixed May 23)
  usage table existed with 0 rows — pool init was
  silently failing. Fixed and confirmed live with
  end-to-end millisecond-matched test May 24.

IP CLASSIFIER + GREY ASN FILTER (fixed May 24)
  dn-daily now excludes grey hosting IPs.
  is_grey column added to usage table.
  ip_classifier.py with KNOWN_LEGIT + GREY_IP_PREFIXES live.

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
  (7 new T10+T07 security/domain tools)

Claude Code prompts in OmSaiRam/:
  SECTION13_PROMPT_v2.md
  SPRINT2_PROMPT.md
  SPRINT3_P10_PROMPT.md
  SPRINT3_P10b_DOCS_PROMPT.md
  GLAMA_FIX_PROMPT.md
  POSTHOG_PROMPT.md
  GLAMA_SCORE_PROMPT.md
  CADDY_ACCESS_LOG_PROMPT.md        ← ready, not yet run
  USAGE_INSTRUMENTATION_PROMPT.md   ← DONE May 23
  FEEDBACK_RECORD_NTFY_FIX.md       ← ready (bugs 7+8)

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

P15-1: Every new tool group must add canary
       and smoke entries before registering
P15-2: smoke.py must pass 100% before shipping
P15-3: Known-good inputs must be stable facts
P15-4: When real user reports failure, add
       regression smoke test before fixing

═══════════════════════════════════════════════════════
MONETISATION STATUS
═══════════════════════════════════════════════════════

MCPIZE_ACTIVE=false (free window active)
FEEDBACK_AGENTS_ACTIVE=false
Infrastructure: ~$6.19/month Hetzner
Haiku cost: ~$0.10/month
Phase 2 (Day 60): flip MCPIZE_ACTIVE=true
T12 Sanctions: DEFERRED to Sprint 5+
  (needs legal entity established first)

═══════════════════════════════════════════════════════
ACTIVATION ANALYTICS (added May 29 2026)
═══════════════════════════════════════════════════════

activation_events TABLE (PostgreSQL):
  id          SERIAL PRIMARY KEY
  client_ip   TEXT NOT NULL
  event_type  TEXT NOT NULL   (5 values — see below)
  tool_id     TEXT
  session_id  TEXT
  metadata    JSONB
  created_at  TIMESTAMPTZ DEFAULT NOW()

  Migration: datanexus/core/db_migrations/add_activation_events.sql
  Run: cd /app/datanexus && docker compose exec postgres \
         psql -U dn datanexus -f /migrations/add_activation_events.sql

5 ACTIVATION LEVELS:
  first_call   — IP's very first tool call ever
  real_query   — non-example, non-test input (len > 10 chars,
                 not in EXAMPLE_INPUTS for that tool_id)
  multi_tool   — 3+ distinct tools used in 30-min rolling window
  return_visit — called tools on 2nd distinct calendar day
  power_user   — 10+ calls in a rolling 7-day window

HOW IT WORKS:
  activation_detector.check() called (awaited) from
  usage_recorder.record_usage() after every INSERT.
  Fire-and-forget — never raises, never blocks tool call.
  Grey IPs, smoke tests, and Glama tester range (172.6.x)
  are skipped before any DB query.
  EXAMPLE_INPUTS per tool are excluded from real_query detection.

FILES:
  datanexus/core/activation_detector.py  — detector logic + pool
  datanexus/core/usage_recorder.py       — hook (await check after INSERT)
  datanexus/core/db_migrations/add_activation_events.sql
  datanexus/scripts/backfill_activation.py  — one-time history replay
  feedback/dashboard/server.py           — /api/summary activation_funnel
                                           + HTML funnel panel

SERVER ALIASES (add to ~/.bashrc on Hetzner):
  dn-activation-events  — last 50 activation events (7-day window)
  dn-funnel             — funnel counts per event_type (all 5 levels)

DASHBOARD:
  GET /api/summary includes:
    summary.activation_funnel.first_call
    summary.activation_funnel.real_query
    summary.activation_funnel.multi_tool
    summary.activation_funnel.return_visit
    summary.activation_funnel.power_user
    summary.activation_funnel.conversion_rate  (real_query/first_call %)
  latest_activations: last 10 activation_events rows

BACKFILL:
  Run once after migration to populate from existing usage history:
    docker compose exec datanexus-mcp \
      python3 -m datanexus.scripts.backfill_activation
  Expected: 173.66.27.4 → first_call + real_query
            160.79.106.x → first_call
            MN due diligence user → multi_tool

═══════════════════════════════════════════════════════
PRIORITY TODO LIST
═══════════════════════════════════════════════════════

IMMEDIATE (fix before next user hits them):
  1. Fix patent citations 400 (CN patent prefix bug) — Bug 1
  2. Fix glama.json description (0.1% CTR killer) — Bug 3
  3. Fix Sprint 4 smoke failures (4 tools failing) — Bug 2
  4. Fix feedback:record missing fields + ntfy — Bugs 7+8
     (prompt ready: FEEDBACK_RECORD_NTFY_FIX.md)
  5. Run CADDY_ACCESS_LOG_PROMPT.md — Bug 9

SHORT TERM (this week):
  6. Add SECURITYTRAILS_KEY to .env for
     domain_fetch_reverse_ip
  7. Run GLAMA_SCORE_PROMPT.md to improve
     tool description scores from 3.3-4.6 to 4.5+
  8. Decide on T10 UNKNOWN severity fix (Bug 6)
     — Haiku said needs_review, human decision needed

MORNING CHECKLIST (15 min daily):
  ssh datanexus
  dn-daily          — organic tool calls + pass rates
  dn-who            — new IPs, watch for 173.66.27.4 return
  dn-returning      — returning users (data matures ~May 27)
  Check PostHog EU  — tool_called events
  Monitor Glama CTR — target 2%+ from 0.1%

═══════════════════════════════════════════════════════
HOW TO START A NEW CHAT SESSION
═══════════════════════════════════════════════════════

Paste this at the start of new conversation:

"Read /Users/sangeetajagadeesh/OmSaiRam/
DATANEXUS_CONTEXT_MAY24.md for full project
context. Summarise current state in one
paragraph to confirm you have it, then
help me with: [your task]"
