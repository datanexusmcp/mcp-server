# DataNexus MCP — Full Project Context
# Last updated: May 30, 2026
# Use this file to start a new chat session without losing context

═══════════════════════════════════════════════════════
PRODUCT OVERVIEW
═══════════════════════════════════════════════════════

DataNexus MCP is a remote MCP server delivering
public data intelligence to AI agents.

Server URL:  https://datanexusmcp.com/mcp
Transport:   Streamable HTTP
npm package: @datanexusmcp/mcp-server v2.3.0
GitHub:      github.com/datanexusmcp/mcp-server
Dashboard:   http://localhost:8101 (SSH tunnel)
             ssh -L 8101:localhost:8101 datanexus -N

═══════════════════════════════════════════════════════
INFRASTRUCTURE
═══════════════════════════════════════════════════════

Server:      Hetzner CAX11, IP 178.104.251.70
OS:          Ubuntu 24.04, Docker 29.4.1
SSH:         ssh datanexus
             Key: ~/.ssh/datanexus2_ed25519
             Full: ssh -i ~/.ssh/datanexus2_ed25519 root@178.104.251.70
Domain:      datanexusmcp.com (Cloudflare DNS, proxy OFF)
             NOTE: Cloudflare analytics always zero for datanexusmcp.com
             because proxy is OFF — traffic goes direct to Hetzner.
             Use dn-who / dn-daily / PostHog for real analytics.
Email:       dev@datanexusmcp.com
Stack:       Caddy + uvicorn FastMCP + Redis 7 + PostgreSQL 16
Deploy path: /app/datanexus on server
DB user:     dn (NOT datanexus — was a bug, fixed)
DB tables:   sessions, usage (11 columns), activation_events
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
  datanexus-postgres-1      — usage + sessions + activation_events tables
  datanexus-daily-digest-1  — Section 13 T4 digest cron
  datanexus-kev-refresh-1   — CISA KEV refresh
  datanexus-bug-listener-1  — Section 13 T2 feedback classifier

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
  dn-daily      — organic tool usage last 24h (grey IPs excluded)
                  curl -s http://localhost:8101/ops/daily | python3 -m json.tool
  dn-returning  — returning users (2+ calendar days)
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
  is_grey     BOOLEAN DEFAULT false

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
DATANEXUS_NVD_API_KEY      — NVD API key (Sprint 6 PRE-2)
                              Without: 100 min per 1,000 CVE lookups
                              With:    10 min per 1,000 CVE lookups
                              Register: nvd.nist.gov/developers/request-an-api-key

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

═══════════════════════════════════════════════════════
LIVE TOOLS — CURRENT STATE (46 total as of May 30, 2026)
═══════════════════════════════════════════════════════

── SPRINTS 1–4 (35 tools, shipped before May 28) ──────

T04 — Nonprofit (3):
  nonprofit_fetch_nonprofit_by_ein
  nonprofit_search_nonprofits_by_name
  nonprofit_fetch_charity_uk

T10 — Security (7):
  security_fetch_package_vulnerabilities (batch supported)
  security_fetch_dependency_graph
  security_fetch_cve_detail (includes remediation from OSV)
  security_audit_sbom_vulnerabilities
  security_fetch_package_licence
  security_fetch_cisa_kev        — CISA KEV catalog lookup
  security_fetch_cve_epss        — EPSS exploit probability

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
  domain_fetch_subdomains        — CT log subdomain enum
  domain_check_email_security    — SPF/DMARC/DKIM scoring
  domain_fetch_reverse_ip        — co-hosted domains (needs SECURITYTRAILS key)

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
    maintainer health, and transitive dep count in one parallel call.
    Calls 4 upstreams via asyncio.gather: OSV.dev, deps.dev,
    PyPI/npm registry, maintainer history.
    Verdict: BLOCK if critical CVE or INCOMPATIBLE licence;
             CAUTION if high CVEs/COPYLEFT/suspicious maintainer;
             SHIP otherwise.

  security_fetch_package_maintainer_history
    Maintainer ownership timeline, account age, anomaly score.
    anomaly_score additive formula (clamped 1.0):
      owner_account_age < 90d  → +0.4
      ownership_transfer_90d   → +0.3
      maintainer_count_delta   → +0.2
      release_after_6mo_silence → +0.1
    Verdict: suspicious (>0.7), stale/abandoned (0.3–0.7), healthy (<0.3)

  nonprofit_fetch_nonprofit_full_profile
    Full 990 due diligence: financials, exec pay, risk flags,
    health score (0–100), programme ratio, fundraising sustainability.
    Health score formula:
      programme_ratio × 40 + (1 - expense_ratio) × 30
      + revenue_growth_score × 20 + reserve_months_score × 10
    Source: ProPublica primary, IRS e-File fallback on 404.

Group 2 — Stateful Anchors:
  security_fetch_cve_watch
    Persistent CVE watchlist (create/check/delete).
    Redis: dn:cve_watch:{watch_id} (Hash, 90-day TTL)
           dn:cve_watch_ids (SET index — never use SCAN)
    Events tracked: patch_released, exploitation_detected,
                    kev_listed, poc_published
    Scheduler: _cve_refresh_loop() — 24h cycle, asyncio.create_task
    PULL-based only — no push notifications.

  security_audit_sbom_continuous
    Persistent SBOM monitoring (register/check/deregister).
    Redis: dn:sbom_watch:{watch_id} (Hash, 90-day TTL)
           dn:sbom_watch_ids (SET index)
    Input limit: 500 KB checked before parsing.
    Formats: CycloneDX 1.4/1.5, SPDX 2.3 JSON.
    Scheduler: _sbom_refresh_loop() — 7-day cycle.

Group 3 — Supply Chain:
  security_detect_typosquatting
    Damerau-Levenshtein distance ≤ 2 vs top-10,000 packages.
    Reference list: dn:typosquat_ref:{ecosystem} (Redis ZSET, 7-day TTL)
    Sources: hugovk/top-pypi-packages (PyPI), npm download API
    Cold-start: fetch on first call (30s timeout), fail closed
                if < 10,000 packages available.
    anomaly_score per similar pkg:
      new_pkg_age < 30d → +0.5
      downloads < 100   → +0.3
      distance == 1     → +0.2
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

Pre-work changes:
  _circuit_breakers.py  — ALL pybreaker singletons centralized here.
    Never define pybreaker.CircuitBreaker() in a tool file.
    Sprint 6 files (_security_utils.py, _maintainer_utils.py,
    nonprofit_sprint6.py, security_sprint6.py) updated to import from here.
    Reason: two separate instances on the same upstream = no shared
    failure state = circuit never opens during an outage.

  _cve_utils.py  — Core HTTP utilities extracted from t10.py Sprint 4 handlers.
    _fetch_cve_detail_util(cve_id) → {cvss_score, references, configurations}
    _fetch_cisa_kev_util(cve_id)   → {kev_listed: bool}
    _fetch_cve_epss_util(cve_id)   → {epss_score: float}
    Sprint 4 handlers remain unchanged — they still call these internally.

  _licence_compat.py  — Hand-coded SPDX compatibility table.
    get_compatibility(A, B) → "COMPATIBLE" | "CONFLICT" | "UNKNOWN"
    Symmetric. Covers 30+ CONFLICT pairs, 30+ COMPATIBLE pairs.
    STATIC_LICENCES dict: metadata for top-50 SPDX IDs
    (risk_level, obligations, permissions, limitations, osi_approved, fsf_libre, tldr).
    All risk levels assume proprietary/commercial use context.

  _nonprofit_utils.py  — calculate_health_score() extracted from nonprofit_sprint6.py.
    Single source of truth — imported by Sprint 6 and Sprint 7 tools.
    Formula: programme_ratio×40 + (1-expense_ratio)×30
             + revenue_growth_score×20 + reserve_months_score×10
    Returns None if totrevenue == 0.
    OQ1 note: ProPublica filings endpoint is /api/v2/organizations/{ein}.json
    (NOT /filings.json — that 404s). Returns pre-computed fields in
    filings_with_data. No raw 990 JSON parsing needed.

Group 1 — Licence Intelligence:
  security_fetch_licence_analysis
    Input: spdx_id (str)
    Static-first: checks STATIC_LICENCES bundle before any HTTP call.
    Fallback: spdx.org/licenses/{id}.json via _spdx_breaker.
    Unknown ID → DEGRADED (not error): risk_level=UNKNOWN, plain_english=null
    Risk levels (proprietary/commercial context):
      PERMISSIVE: MIT, Apache-2.0, BSD-*, ISC — attribution only
      COPYLEFT: LGPL-*, MPL-2.0 — share-alike for modified files
      STRONG_COPYLEFT: GPL-* — share-alike for ALL derivative works
      INCOMPATIBLE: AGPL-3.0 (proprietary SaaS) — cannot use in closed services
      UNKNOWN: unrecognized SPDX ID
    AGPL plain_english and tldr MUST include "INCOMPATIBLE for proprietary SaaS"
    and "Compatible with open source projects" (D3 requirement).
    upstream_status.spdx_api: "N/A" when served from static bundle.

  security_audit_licence_compatibility
    Input: packages (list[{package_name, ecosystem}]) OR spdx_ids (list[str])
    Mixed input → INVALID_PARAMS. Empty list → INVALID_PARAMS. >50 → INVALID_PARAMS.
    Package path: resolves SPDX IDs via _fetch_licence() from _security_utils.py
      Concurrency: asyncio.Semaphore(10) — prevents 429 from PyPI/npm at 50 items
      Partial failure: continue with resolved subset, list failures in upstream_status
    SPDX-ID path: static bundle only — NO HTTP calls
    Returns: compatibility (COMPATIBLE/CONFLICT/UNKNOWN),
             conflicts (list[{licence_a, licence_b, reason, package}]),
             combined_obligations (deduped union),
             recommended_action (first-match template),
             upstream_status.spdx_api + upstream_status.failed_packages

Group 2 — CVE Aggregator:
  security_fetch_cve_risk_summary
    Input: cve_id (str) — validated against ^CVE-\d{4}-\d{4,}$
    Parallel calls via asyncio.gather + return_exceptions=True:
      _fetch_cve_detail_util → cvss_score, references, configurations
      _fetch_cisa_kev_util   → kev_listed
      _fetch_cve_epss_util   → epss_score
    Degraded nulls (HARD RULE):
      kev_listed: null  (not false) when CISA unreachable
      epss_score: null  (not 0.0) when EPSS unreachable
      patch_available: null (not false) when no allowlist URL match
    Verdict table (evaluate IN ORDER — FIRST MATCH WINS, D2 fix):
      1. UNKNOWN:          all three null (all upstreams down)
      2. CRITICAL_EXPLOIT: kev_listed==true OR epss >= 0.7
      3. HIGH_RISK:        cvss >= 9.0 OR (epss >= 0.3 AND cvss >= 7.0)
      4. MODERATE:         cvss >= 4.0
      5. LOW:              otherwise (at least one non-null)
    patch_available: True if NVD references include vendor advisory domain.
      nvd.nist.gov NOT in allowlist (informational only).
      Allowlist: github.com/advisories, access.redhat.com, security.debian.org,
        ubuntu.com/security, lists.apache.org, msrc.microsoft.com,
        oracle.com/security-alerts, cisco.com/security/advisories, kb.cert.org
    upstream_status: {nvd, cisa, epss} each "OK"|"ERROR"|"CIRCUIT_OPEN"
    P0 smoke test T03-S01: all-null upstreams → verdict MUST be "UNKNOWN" not "LOW"

Group 3 — Nonprofit Depth:
  nonprofit_search_nonprofits_by_category
    Input: category (str), state (str, optional, 2-letter)
    Category → NTEE: education→B, healthcare→E, arts→A, environment→C,
      human_services→P, civil_rights→R, international→Q, religion→X,
      science→U, sports→N. Raw single letter A–Z accepted directly.
    API NOTE: ProPublica /search.json?q={keyword} is the working endpoint.
      /nonprofits.json?ntee=&state= → 404. State+NTEE params → 500.
      State filtering done client-side after API call.
      Financial fields (totrevenue etc.) NOT returned by search endpoint
      → health_score is null for all search results.
    Max 25 results, truncated=True when more available.
    Source: ProPublica Nonprofit Explorer /search.json

  nonprofit_fetch_nonprofit_financial_trends
    Input: ein (str), years (int, default 5, max 10)
    Source: ProPublica /api/v2/organizations/{ein}.json
      (NOT /filings.json — OQ1 resolved May 30)
    Slices `years` most recent filings from filings_with_data.
    Minimum guard: < 2 filings → INSUFFICIENT_DATA (checked FIRST).
    Per-year: reserve_months = net_assets / (expenses/12), null if expenses==0
              programme_ratio = totprgmrevnue / totrevenue, null if revenue==0
              health_score via calculate_health_score() from _nonprofit_utils.py
    CAGR: ((rev_latest / rev_earliest) ^ (1/n_years)) - 1
          null if rev_earliest == 0
    trend_direction (IN ORDER — first match wins):
      INSUFFICIENT_DATA: < 2 filings
      VOLATILE: consecutive filings with opposite-sign change_pct, both >20%
      GROWING: CAGR > 5%
      STABLE: -5% ≤ CAGR ≤ 5%
      DECLINING: CAGR < -5%

═══════════════════════════════════════════════════════
SPRINT 7 ENGINEERING REVIEW DECISIONS (D1–D7)
═══════════════════════════════════════════════════════

D1 Utility names: actual names are _fetch_licence(), _fetch_vulns()
   in _security_utils.py. No _licence.py file.

D2 Verdict table: UNKNOWN fires FIRST (step 1) before LOW (step 5).
   REGRESSION TEST T03-S01 is P0 — no ship until it passes.

D3 INCOMPATIBLE context: all risk_levels assume proprietary use.
   AGPL plain_english + tldr must note open source compatibility.

D4 Circuit breakers: create _circuit_breakers.py and import
   from there everywhere. Never define new instances per-file.

D5 Health score: PRE-3 updated Sprint 6 nonprofit_sprint6.py
   to import calculate_health_score from _nonprofit_utils.py.

D6 Tests: P0 regression test T03-S01. 64 tests total passing.

D7 Concurrency: asyncio.Semaphore(10) in audit_licence_compatibility
   package-name path. Prevents 429 at 50-item inputs.

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
  dn:cve_watch:{watch_id}       — Hash (watch data, 90d TTL)
  dn:cve_watch_ids              — SET (watch index, permanent)
  dn:sbom_watch:{watch_id}      — Hash (SBOM data, 90d TTL)
  dn:sbom_watch_ids             — SET (SBOM index, permanent)
  dn:typosquat_ref:{ecosystem}  — ZSET (pkg reference, 7d TTL)
  dn:scheduler_errors           — List (error log, capped 100)

SCHEMA ALERTS:
  datanexus:schema:alerts:T10   — breaking change flag
  datanexus:digest:T10:2026-W19 — weekly digest

CANARY:
  datanexus:canary:sam_gov:last_run — 25h TTL (rate limit guard)

═══════════════════════════════════════════════════════
TEST SUITE STATUS (May 30, 2026)
═══════════════════════════════════════════════════════

64 tests passing (all Sprint 6 + Sprint 7):

  test_cve_utils.py         — 5 tests (PRE-1 utilities)
  test_licence_compat.py    — 16 tests (PRE-2 compatibility table)
  test_nonprofit_utils.py   — 5 tests (PRE-3 health score)
  test_licence_sprint7.py   — 13 tests (Tools 1 + 2)
  test_cve_sprint7.py       — 11 tests (Tool 3 incl. T03-S01 P0)
  test_nonprofit_sprint7.py — 14 tests (Tools 4 + 5, incl. live Red Cross)

Three-layer testing architecture (from spec Section 15):
  Layer 1: pytest unit tests — run on every commit
  Layer 2: datanexus/tests/canary.py — hourly at :00 via cron
  Layer 3: datanexus/tests/smoke.py  — hourly at :30 via cron

CRON ON HETZNER:
  30 * * * * cd /app/datanexus && docker compose
    exec -T datanexus-mcp python3 -m
    datanexus.tests.smoke >> /var/log/datanexus-smoke.log
  0 * * * *  cd /app/datanexus && docker compose
    exec -T datanexus-mcp python3 -m
    datanexus.tests.canary >> /var/log/datanexus-canary.log

RULES:
  P15-1: Every new tool group must add canary and smoke entries before registering
  P15-2: smoke.py must pass 100% before shipping
  P15-4: When real user reports failure, add regression smoke test before fixing bug

═══════════════════════════════════════════════════════
SECTION 13 — HAIKU VALIDATION (LIVE)
═══════════════════════════════════════════════════════

4 triggers only (never add more without human PR):
  T1: anomaly_reviewer.review_anomaly()
  T2: feedback_classifier.classify_feedback() — bug_listener live
  T3: schema_monitor.assess_schema_change()
  T4: digest_generator.generate_weekly_digest()

HAIKU_MODEL = "claude-haiku-4-5" (feedback/config.py)
HAIKU_MAX_CALLS_PER_DAY = 100 (payment/config.py)
Cost: ~$0.10/month at current volume

FEEDBACK LOOP STATUS:
  bug_listener deployed — runs BLPOP on fb:alerts:immediate
  fb:alerts:immediate — queue drained, 0 pending

KNOWN REDIS KEYS:
  datanexus:schema:alerts:T10 — breaking change detected May 5
    cvss_score field REMOVED from upstream — PENDING fix
    affected_fields: ["cvss_score"]
    severity: high, breaking: true

RULES:
  S13-1: Haiku called ONLY on 4 triggers
  S13-2: Always use HAIKU_MODEL from config.py
  S13-3: HAIKU_MAX_CALLS_PER_DAY=100 non-negotiable
  S13-4: validate_tool_output never raises
  S13-5: FeedbackRecord.classification one-way only

═══════════════════════════════════════════════════════
POSTHOG ANALYTICS
═══════════════════════════════════════════════════════

Project: DataNexus MCP (EU cloud)
Host:    https://eu.i.posthog.com
Events:  tool_called, tool_error, server_started

Total events to date: 2,060+
Peak: May 17 (828 events — Glama quality tester)
Current organic: 2-3 real tool calls/day

PostHog fires from Hetzner IP (178.104.251.70).
Real user IPs only visible in usage table client_ip field.

═══════════════════════════════════════════════════════
IP CLASSIFICATION (datanexus/core/ip_classifier.py)
═══════════════════════════════════════════════════════

KNOWN LEGIT IPs:
  173.66.27.4    — Verizon Business / Laurel MD
                   Security auditor — scanned packages
  73.241.93.191  — US organic — looked up MIT EIN
  160.79.106.35/.36/.37/.38 — Google LLC / Anthropic Claude.ai infra
  107.20.6.60    — Amazon EC2 us-east-1 (ListTools only, no executions)

WATCH_LIST:
  77.83.39.x     — Lanedo.net NL — legitimate OSS consultancy
  152.233.x      — RIPE NCC — measurement network

KNOWN SCANNERS (is_grey=True):
  66.132.x       — Censys, Inc.
  66.249.x       — Googlebot

GREY_IP_PREFIXES (excluded from dn-daily + dn-returning):
  213.209.159.x, 79.124.40.x, 130.12.180.x, 5.61.209.x
  45.148.10.x, 185.91.127.x, 109.120.184.x, 80.94.95.x
  149.50.122.x, 176.65.139.x, 93.174.93.x, 2.59.22.x
  165.227.x, 64.226.x

dn-glama: 172.68.23.75/76 — 455 calls all-time

═══════════════════════════════════════════════════════
GLAMA STATUS
═══════════════════════════════════════════════════════

Listing:  glama.ai/mcp/servers/datanexusmcp/mcp-server
npm:      @datanexusmcp/mcp-server v2.3.0 (published May 30)
glama.json: 46 tools, tools_count=46
README:   updated May 30 — Sprint 6 + Sprint 7 documented

═══════════════════════════════════════════════════════
ORGANIC USERS CONFIRMED
═══════════════════════════════════════════════════════

173.66.27.4 — Verizon Business / Laurel MD (HIGH VALUE)
  Security auditor, called fetch_package_vulnerabilities on own packages

73.241.93.191 — US organic
  fetch_nonprofit_by_ein: EIN 04-2103594 (MIT)

117.144.65.213 — Shanghai Mobile, China
  domain_fetch_domain_history, legal_fetch_patent_citations (CN120586032)
  Patent citations bug hit (CN prefix bug — see known bugs)

222.212.248.29 — ChinaNet Backbone, Chengdu — 6 calls
160.79.106.35/.36 — Google/Anthropic Claude.ai users

SPRINT 6 RETURN METRIC (primary success criterion):
  At least 1 user must call fetch_cve_watch create, then check
  on a subsequent calendar day with the same watch_id.
  dn-returning confirms when data matures.

═══════════════════════════════════════════════════════
ACTIVATION ANALYTICS (added May 29, 2026)
═══════════════════════════════════════════════════════

activation_events TABLE (PostgreSQL):
  id, client_ip, event_type, tool_id, session_id, metadata, created_at

5 ACTIVATION LEVELS:
  first_call   — IP's very first tool call ever
  real_query   — non-example, non-test input (len > 10 chars)
  multi_tool   — 3+ distinct tools in 30-min rolling window
  return_visit — called tools on 2nd distinct calendar day
  power_user   — 10+ calls in rolling 7-day window

DASHBOARD: GET /api/summary includes activation_funnel counts

═══════════════════════════════════════════════════════
KNOWN BUGS — PENDING FIXES
═══════════════════════════════════════════════════════

BUG 1 — Patent citations 400 for non-EP patents
  Tool: legal_fetch_patent_citations
  Symptom: CN120586032 → 400 Bad Request
  Cause: tool prepends EP to all patent numbers
  Fix: use patent_number as-is in EPODOC URL
  Status: PENDING — real user hit this

BUG 2 — Sprint 4 smoke test failures
  Tools: fetch_cisa_kev, fetch_cve_epss,
    fetch_cve_detail_remediation, fetch_subdomains
  Note: CISA KEV migrated to GitHub mirror in Sprint 6
  Status: PENDING — reassess after Sprint 6 fix

BUG 6 — T10 UNKNOWN severity (30+ days old)
  GHSA-9wx4-h78v-vm56 has valid CVSS but severity.level=UNKNOWN
  Fix: derive from CVSS vector (Section 13 Rule 1)
  Status: PENDING — needs human decision

BUG 7 — feedback:record missing context fields
  feedback_classifier writes only 3 of 9 expected fields
  Status: PENDING

BUG 8 — ntfy em-dash encoding
  _fire_ntfy() fails on em-dash in title
  Fix: title.encode('ascii', errors='replace').decode('ascii')
  Status: PENDING

BUG 9 — Caddy access log not persistent
  Status: PENDING (CADDY_ACCESS_LOG_PROMPT.md ready)

═══════════════════════════════════════════════════════
CRITICAL BUGS FIXED (historical)
═══════════════════════════════════════════════════════

SSE FIX (May 14) — flush_interval -1 + HTTP/1.1
FastMCP GET /mcp 406→405 fix (May 27) — stateless_http/json_response
  moved from FastMCP() constructor to main.run()
CISA KEV → GitHub mirror (May 25) — cisa.gov blocks Hetzner IPs
SAM.gov canary → 24h frequency (May 25) — quota exhaustion fix
crt.sh 502 → cache fallback DEGRADED (May 25)
Circuit breakers centralized (May 30 — Sprint 7 D4)

═══════════════════════════════════════════════════════
SPRINT HISTORY
═══════════════════════════════════════════════════════

Sprint 1–2: 26 tools across 7 sub-servers
Sprint 3:   Regrouped into FastMCP mount pattern
Sprint 4:   +9 tools (T10 KEV/EPSS/SBOM, T07 subdomain/email/reverse-ip)
            Total: 35 tools
Sprint 6:   +6 tools (aggregators + stateful anchors + supply chain)
            41 tools. Key files: security_sprint6.py,
            nonprofit_sprint6.py, security_stateful.py,
            _security_utils.py, _maintainer_utils.py, schedulers.py
Sprint 7:   +5 tools (licence intelligence + CVE aggregator + nonprofit depth)
            46 tools. Key files: licence_sprint7.py, cve_sprint7.py,
            nonprofit_sprint7.py. Pre-work: _circuit_breakers.py,
            _cve_utils.py, _licence_compat.py, _nonprofit_utils.py
            npm v2.3.0 published, deployed May 30.

SPRINT DESIGN NOTE: Sprint 6 and Sprint 7 were re-planned.
  Do not read SPRINT6_DESIGN.md or SPRINT7_DESIGN.md —
  they describe earlier plans superseded by the prompts.
  Authoritative specs: SPRINT6_PROMPT.md, SPRINT7_PROMPT.md

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
P15-4: When real user reports failure, add
       regression smoke test before fixing

SPRINT 7 HARD STOPS (additional):
  — Never define pybreaker.CircuitBreaker() in a tool file
  — kev_listed/epss_score/patch_available degrade to null, never false/0.0
  — nvd.nist.gov NOT a valid patch confirmation URL
  — Semaphore(10) on audit_licence_compatibility package path
  — glama.json updated in same commit as main.py tool registration

═══════════════════════════════════════════════════════
MONETISATION STATUS
═══════════════════════════════════════════════════════

MCPIZE_ACTIVE=false through ~July-August 2026
All Sprint 6 and Sprint 7 tools are free.
Infrastructure: ~$6.19/month Hetzner
Haiku cost: ~$0.10/month

═══════════════════════════════════════════════════════
PRIORITY TODO LIST (as of May 30, 2026)
═══════════════════════════════════════════════════════

IMMEDIATE:
  1. Fix patent citations 400 (CN patent prefix bug) — Bug 1
  2. Reassess Sprint 4 smoke failures post-KEV mirror fix — Bug 2
  3. Fix feedback:record missing fields + ntfy — Bugs 7+8
  4. Run CADDY_ACCESS_LOG_PROMPT.md — Bug 9

SHORT TERM:
  5. Add SECURITYTRAILS_KEY to .env for domain_fetch_reverse_ip
  6. Decide T10 UNKNOWN severity fix — Bug 6 (Haiku: needs_review)
  7. Monitor Sprint 6 stateful anchors for return visit (primary success metric)
  8. Check dn-returning after June 1 for Sprint 7 nonprofit tool adoption

MORNING CHECKLIST (15 min daily):
  ssh datanexus
  dn-daily          — organic tool calls + pass rates
  dn-who            — new IPs, watch for 173.66.27.4 return
  dn-returning      — returning users (Sprint 6 stateful anchor metric)
  dn-funnel         — activation funnel counts
  Check PostHog EU  — tool_called events

═══════════════════════════════════════════════════════
HOW TO START A NEW CHAT SESSION
═══════════════════════════════════════════════════════

Paste this at the start of new conversation:

"Read /Users/sangeetajagadeesh/OmSaiRam/
DATANEXUS_CONTEXT_MAY24.md for full project
context. Summarise current state in one
paragraph to confirm you have it, then
help me with: [your task]"
