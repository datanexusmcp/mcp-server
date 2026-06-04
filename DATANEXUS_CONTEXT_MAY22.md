# DataNexus MCP — Full Project Context
# Last updated: May 22, 2026
# Use this file to start a new chat session without losing context

═══════════════════════════════════════════════════════
PRODUCT OVERVIEW
═══════════════════════════════════════════════════════

DataNexus MCP is a remote MCP server delivering
public data intelligence to AI agents.

Server URL:  https://datanexusmcp.com/mcp
Transport:   Streamable HTTP
npm package: @datanexusmcp/mcp-server v2.1.3
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
Email:       dev@datanexusmcp.com
Stack:       Caddy + uvicorn FastMCP + Redis 7 + PostgreSQL 16
Deploy path: /app/datanexus on server
DB user:     dn (NOT datanexus — was a bug, fixed)
DB tables:   sessions, usage (auto-created on startup)
Snapshot:    386464566 (post SSE fix, v2.1.3 — CURRENT)

DOCKER COMMANDS (always run from /app/datanexus):
  cd /app/datanexus
  docker compose ps
  docker compose logs datanexus-mcp --tail 50
  docker compose logs caddy --tail 50
  docker compose restart datanexus-mcp
  docker compose build --no-cache datanexus-mcp
  docker compose up -d

SERVER ALIASES (available on Hetzner):
  dn-who      — top external IPs with geo lookup
  dn-users    — unique users per day
  dn-aborts   — SSE abort timestamps
  dn-ps       — container status
  dn-logs     — MCP server logs
  dn-crtsh    — check crt.sh status

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
  T2: feedback_classifier.classify_feedback()
  T3: schema_monitor.assess_schema_change()
  T4: digest_generator.generate_weekly_digest()

HAIKU_MAX_CALLS_PER_DAY = 100 (payment/config.py)
HAIKU_MODEL = "claude-haiku-4-5" (feedback/config.py)
Cost: ~$0.10/month at current volume

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
SECTION 16 — USAGE INSTRUMENTATION (LIVE, May 22)
═══════════════════════════════════════════════════════

usage table now captures:
  client_ip, tool_input, success, error_msg, 
  latency_ms, is_smoke

Daily ops check: dn-daily (curl localhost:8101/ops/daily)
Smoke tests excluded from PostHog: DATANEXUS_SMOKE_RUN=1

═══════════════════════════════════════════════════════
POSTHOG ANALYTICS
═══════════════════════════════════════════════════════

Project: DataNexus MCP (EU cloud)
Host:    https://eu.i.posthog.com
Events:  tool_called, tool_error, server_started

Total events to date: 2,060+
Peak: May 17 (828 events — Glama quality tester)
Current: ~140/day (smoke tests + organic)

IMPORTANT: PostHog events fire from Hetzner server
(IP 178.104.251.70) not from user's IP.
Distinguish organic by time — calls at unexpected
hours or for tools you did not personally test.

SMOKE TEST EXCLUSION: smoke tests set
os.environ['DATANEXUS_SMOKE_RUN'] = '1'
which skips PostHog and Redis telemetry.
(Pending fix — may not be implemented yet)

═══════════════════════════════════════════════════════
GLAMA STATUS
═══════════════════════════════════════════════════════

Listing: glama.ai/mcp/servers/datanexusmcp/mcp-server
Profile completion: 58%+ (improving)
Scores: License A, Quality A, Maintenance B

ANALYTICS (last 30 days as of May 21):
  Search Impressions: 47,061
  Search Clicks:      62 (0.1% CTR — PROBLEM)
  Profile Views:      2,736
  Tool Calls:         0 (via Glama Try in Browser)

ROOT CAUSE of low CTR: glama.json description
still shows old stale text:
  "Provides AI-ready access to US/UK nonprofit
  data and OSS vulnerability intelligence via
  MCP, with 10 tools and no API key required."

PENDING FIX: update glama.json description to:
  "CISA KEV · CVE EPSS · SBOM audit · patent
  search · nonprofit 990 · government contracts
  · subdomain enumeration · email security
  scoring. 30+ tools, zero install, one URL."

Build & Release: successful — Quality score A
npm package: @datanexusmcp/mcp-server v2.1.3

═══════════════════════════════════════════════════════
ORGANIC USERS CONFIRMED
═══════════════════════════════════════════════════════

Since SSE fix (May 14, 17:30 UTC):

117.144.65.213 — Shanghai Mobile, China
  - Repeat user, 5+ visits
  - Called: domain_fetch_domain_history,
    legal_fetch_patent_citations (CN120586032)
  - Patent citations bug hit: 400 Bad Request
    (EP prefix incorrectly prepended to CN patent)

222.212.248.29 — ChinaNet Backbone, Chengdu, China
  - 6 calls, most active user
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

BUG 4 — Smoke test telemetry not excluded
  Smoke test calls inflate dashboard metrics
  Fix: DATANEXUS_SMOKE_RUN env var
  Status: PENDING

BUG 5 — crt.sh upstream intermittent
  fetch_ssl_certificate_chain and
  fetch_domain_history return ingest_healthy=false
  when crt.sh returns empty array
  Status: UPSTREAM — not our code

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
Infrastructure: ~$6.09/month Hetzner
Haiku cost: ~$0.10/month
Phase 2 (Day 60): flip MCPIZE_ACTIVE=true
T12 Sanctions: DEFERRED to Sprint 5+
  (needs legal entity established first)

═══════════════════════════════════════════════════════
PRIORITY TODO LIST
═══════════════════════════════════════════════════════

IMMEDIATE (fix before next user hits them):
  1. Fix patent citations 400 (CN patent prefix bug)
  2. Fix glama.json description (0.1% CTR killer)
  3. Fix Sprint 4 smoke failures (4 tools failing)

SHORT TERM (this week):
  4. Exclude smoke test calls from telemetry
  5. Add SECURITYTRAILS_KEY to .env for
     domain_fetch_reverse_ip
  6. Run GLAMA_SCORE_PROMPT.md to improve
     tool description scores from 3.3-4.6 to 4.5+
  7. Verify cron is running:
     crontab -l | grep -E "smoke|canary"

ONGOING:
  8. Check dn-who daily for new users
  9. Check PostHog for tool_called events
  10. Monitor Glama CTR — target 2%+ from 0.1%

═══════════════════════════════════════════════════════
HOW TO START A NEW CHAT SESSION
═══════════════════════════════════════════════════════

Paste this at the start of new conversation:

"Read /Users/sangeetajagadeesh/OmSaiRam/
DATANEXUS_CONTEXT_MAY22.md for full project
context. Summarise current state in one
paragraph to confirm you have it, then
help me with: [your task]"

