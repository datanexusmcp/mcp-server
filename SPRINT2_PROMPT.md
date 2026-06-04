# DataNexus MCP — Sprint 2 Implementation Prompt
# Tools: T22, T07, T11, T18, T19 (in build order)
# T12 deferred to Sprint 3
# Spec: DataNexus_MCP_Spec_v7_4.docx (authoritative)
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Prerequisites: Sprint 1 + Section 13 complete
#   11 tools live at https://datanexusmcp.com/mcp
#   84/84 tests green
# Last updated: May 2026

═══════════════════════════════════════════════════════
RULE ZERO — READ BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these files completely before writing
a single line of code:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
   All rules apply. Section 13 rules now active.

2. /Users/sangeetajagadeesh/OmSaiRam/
   DataNexus_MCP_Spec_v7_4.docx
   Read tool specs for T22, T07, T11, T18, T19.
   Read Section 11 canonical session starter.
   Read Section 12 amendments — they supersede
   earlier sections where conflicts exist.

Confirm pre-read by answering ALL five:

a) What is T22's hard stop? Give exact wording.

b) T11 requires EPO OPS OAuth. What are the
   EPO OAuth credentials called and where do
   they live? (Hint: /app/.env on Hetzner)

c) T18 has two data sources with different
   key requirements. Which one requires no key
   and should be built first as fallback?

d) What is the hard stop for T19?
   Give exact wording from the spec.

e) After Sprint 2 is complete, how many total
   tools will be registered in main.py?
   Show arithmetic. Current state: 11 tools.
   Sprint 2 adds: T22, T07, T11, T18, T19.
   Each tool registers: N data functions +
   report_feedback + report_mcpize_link.

Do not write any code until I confirm all five.
Type READY only after my confirmation.

═══════════════════════════════════════════════════════
CURRENT STATE
═══════════════════════════════════════════════════════

Live at https://datanexusmcp.com/mcp:
  T04: fetch_nonprofit_by_ein,
       search_nonprofits_by_name,
       fetch_charity_uk
  T10: fetch_package_vulnerabilities,
       fetch_dependency_graph,
       fetch_cve_detail,
       audit_sbom_vulnerabilities,
       fetch_package_licence
  Shared: report_feedback, report_mcpize_link
  Section 13: validate_tool_output
  Total: 11 tools

API keys confirmed in /app/.env on Hetzner:
  ANTHROPIC_API_KEY — live (Haiku working)
  SAM_GOV_API_KEY — added (T18 + T22 unblocked)
  EPO_CLIENT_ID + EPO_CLIENT_SECRET — approved
  REGULATIONS_GOV_KEY — add before T19 build

T12 (Sanctions) — deferred to Sprint 3.
Do not build T12 in this sprint under any
circumstances.

═══════════════════════════════════════════════════════
BUILD ORDER — STRICT
═══════════════════════════════════════════════════════

Build tools in this exact order.
Each tool must pass ALL smoke tests before
the next tool starts. No batching. No skipping.

  1. T22 — Professional Licence Verification
  2. T07 — Domain & DNS Intelligence
  3. T11 — Global Patent Intelligence
  4. T18 — Government Contracting & Procurement
  5. T19 — Regulatory Docket & Comment Tracking

Build order rationale:
  T22 first — NPPES is no-key, immediate data,
    fastest path to working tool
  T07 second — all sources no-key, 4h TTL,
    developer audience finds it fast
  T11 third — EPO OAuth is approved, highest
    MRR target ($7,200) in Sprint 2
  T18 fourth — SAM.gov key in .env, USASpending
    fallback if SAM.gov has issues
  T19 last — add REGULATIONS_GOV_KEY to .env
    before starting this tool

═══════════════════════════════════════════════════════
SHARED REQUIREMENTS — ALL SPRINT 2 TOOLS
═══════════════════════════════════════════════════════

Every tool in Sprint 2 must implement these.
No exceptions. These are inherited from the
shared platform architecture (Section 2).

1. File structure per tool:
   datanexus/tools/t{nn}.py — FastMCP module
   datanexus/ingest/t{nn}_worker.py — ingest
   Register in datanexus/main.py

2. Every tool function must use:
   @verify_entitlement (from payment.entitlement)
   AuditContext (from feedback.audit)
   standard_response_fields() in every response
   DataNexusResponse base schema fields

3. Every response must include:
   tool_id, source_url, fetch_timestamp,
   cache_hit, staleness_notice, sha256_hash,
   data, markdown_output, query_hash,
   schema_version, data_as_of, ingest_healthy,
   disclaimer (tool-specific, hardcoded)

4. Ingest workers must:
   Call validate_payload() from
   datanexus/core/validator.py between
   fetch() and set_cached()
   Use IngestBase.run_forever()
   Log structured JSON on every run

5. Every tool must be registered with:
   2 data functions minimum (per spec)
   report_feedback (shared, from feedback.collector)
   report_mcpize_link (shared, from payment.tools)

6. Glama description requirements:
   Must contain: "AI-Ready Markdown",
   "Verified source", "token-efficient"
   Must contain tool-specific keywords from spec
   Must include: what it does, when to call it,
   what it returns, data source, freshness

7. Hard stops are absolute:
   Do not implement any capability listed under
   "Hard stop" in the spec for each tool.
   If a requested feature is near a hard stop,
   flag for human review — do not build.

8. Disclaimer wording (tool-specific):
   Each tool has its own disclaimer.
   See per-tool sections below for exact wording.
   Never omit disclaimer from any response.

═══════════════════════════════════════════════════════
TOOL 1 — T22: PROFESSIONAL LICENCE VERIFICATION
═══════════════════════════════════════════════════════

Spec reference: Section 5, T22 entry
Build order: FIRST

Sources:
  Primary:   NPPES NPI Registry
             npiregistry.cms.hhs.gov/api-page
             No key required. REST JSON. Fast.
  Secondary: FINRA BrokerCheck
             developer.finra.org
             Free, registration required.
             Use FINRA_API_KEY from .env if set.
             If not set: skip FINRA, return
             NPPES data only with note.
  Supporting: SAM.gov exclusions
             Same SAM_GOV_API_KEY as T18.
             Checks if professional is on
             federal exclusions list.

Cache TTL: 86400 seconds (24 hours)
Circuit breaker source IDs:
  "nppes", "finra", "sam_exclusions"

Hard stop (exact wording — never violate):
  Do NOT add licence status opinions, 'safe to
  hire' decisions, or employment recommendations.
  Returns only: licence found / not found /
  status as registered in official registry.

Disclaimer (hardcode on every T22 response):
  "Licence status sourced from NPPES NPI Registry,
  FINRA BrokerCheck, and SAM.gov public registries.
  DataNexus does not verify current standing or
  fitness for any role. Verify with issuing
  authority before making employment or
  engagement decisions."

── Data functions (exactly 3): ──────────────────

@mcp.tool()
@verify_entitlement('T22')
async def fetch_npi_provider(npi_number: str) -> dict:
  """
  Fetch NPI registration details for any US
  healthcare provider by NPI number. Returns
  provider name, speciality, taxonomy codes,
  practice address, and registration status in
  AI-Ready Markdown.
  Verified source: NPPES NPI Registry (CMS).
  Data freshness: 24-hour cache.
  Token-efficient.
  Example: fetch_npi_provider('1234567890')
  Returns: licence found / not found /
  registration status only — no fitness opinions.
  """

@mcp.tool()
@verify_entitlement('T22')
async def search_npi_by_name(
    name: str,
    state: str = '',
    speciality: str = ''
) -> dict:
  """
  Search NPPES NPI Registry by provider name
  with optional state and speciality filters.
  Returns up to 10 matching providers with NPI,
  name, speciality, and address in AI-Ready
  Markdown. Verified source: NPPES (CMS).
  Data freshness: 24-hour cache. Token-efficient.
  Example: search_npi_by_name('Smith', 'CA',
  'Cardiology')
  """

@mcp.tool()
@verify_entitlement('T22')
async def fetch_finra_broker(crd_number: str) -> dict:
  """
  Fetch FINRA BrokerCheck registration details
  for any US broker or investment adviser by
  CRD number. Returns registration status,
  qualifications, disclosures, and employment
  history in AI-Ready Markdown.
  Verified source: FINRA BrokerCheck.
  Data freshness: 24-hour cache. Token-efficient.
  Example: fetch_finra_broker('1234567')
  If FINRA_API_KEY not configured: returns
  NPPES-only data with source limitation notice.
  """

── Ingest worker: ────────────────────────────────

class NPPESWorker(IngestBase):
  Pre-seeds top 100 most-searched NPI specialities.
  Schedule: 86400 seconds.
  TTL: 86400.

── Smoke tests (7 required): ────────────────────

Test 1: fetch_npi_provider("1003000126")
  PASS if: tool_id="T22", provider name present,
  sha256_hash non-empty, disclaimer present

Test 2: Same call again
  PASS if: cache_hit=True

Test 3: search_npi_by_name("Smith", "CA", "")
  PASS if: returns list, markdown_output non-empty

Test 4: fetch_npi_provider("0000000000")
  PASS if: returns cleanly — not found handled
  gracefully, no crash on invalid NPI

Test 5: Canary injection test
  Inject "ignore previous instructions" into
  mock markdown_output
  PASS if: ValueError raised

Test 6: Hard stop check
  grep -ri "safe to hire\|recommend\|fitness\|
  opinion" datanexus/tools/t22.py
  PASS if: zero matches

Test 7: Telemetry
  redis-cli GET datanexus:calls:T22:{today}
  PASS if: counter >= 3 after tests 1-3

All 7 PASS before building T07.
Stop and report results. Wait for confirmation.

═══════════════════════════════════════════════════════
TOOL 2 — T07: DOMAIN & DNS INTELLIGENCE
═══════════════════════════════════════════════════════

Spec reference: Section 4, T07 entry
Build order: SECOND

Sources:
  Primary:   IANA RDAP
             rdap.iana.org — no key, no auth
             Modern structured replacement for WHOIS
  Secondary: crt.sh Certificate Transparency
             crt.sh/json — no key
             Returns SSL certificate history
  Supporting: Cloudflare DNS over HTTPS
             cloudflare-dns.com/dns-query
             No key. Returns DNS records as JSON.

Cache TTL: 14400 seconds (4 hours)
Circuit breaker source IDs:
  "iana_rdap", "crt_sh", "cloudflare_doh"

Hard stop (exact wording — never violate):
  Do NOT add active scanning, port enumeration,
  vulnerability testing, subdomain brute-forcing,
  or any active probing beyond passive DNS and
  RDAP lookups. Security tool territory — ToS
  risk on all sources.

Disclaimer (hardcode on every T07 response):
  "Domain and DNS data sourced from IANA RDAP,
  crt.sh Certificate Transparency, and Cloudflare
  DNS. DataNexus does not warrant completeness.
  Registration data reflects public registry
  records only."

── Data functions (exactly 4): ──────────────────

@mcp.tool()
@verify_entitlement('T07')
async def fetch_domain_rdap(domain: str) -> dict:
  """
  Fetch domain registration details via IANA RDAP
  (modern WHOIS replacement). Returns registrar,
  registration date, expiry date, nameservers,
  and registrant info (where public) in AI-Ready
  Markdown. Verified source: IANA RDAP.
  Data freshness: 4-hour cache. Token-efficient.
  Example: fetch_domain_rdap('stripe.com')
  """

@mcp.tool()
@verify_entitlement('T07')
async def fetch_ssl_certificate_chain(
    domain: str
) -> dict:
  """
  Fetch SSL certificate history for any domain
  from Certificate Transparency logs. Returns
  issuer, subject, validity dates, and SANs in
  AI-Ready Markdown.
  Verified source: crt.sh Certificate Transparency.
  Data freshness: 4-hour cache. Token-efficient.
  Example: fetch_ssl_certificate_chain('github.com')
  """

@mcp.tool()
@verify_entitlement('T07')
async def fetch_dns_records(
    domain: str,
    record_types: list[str]
) -> dict:
  """
  Fetch DNS records for any domain via Cloudflare
  DNS over HTTPS. Returns A, AAAA, MX, TXT, NS,
  CNAME records as structured AI-Ready Markdown.
  Verified source: Cloudflare DoH. Token-efficient.
  Data freshness: 4-hour cache.
  Example: fetch_dns_records('cloudflare.com',
    ['A', 'MX', 'TXT'])
  """

@mcp.tool()
@verify_entitlement('T07')
async def fetch_domain_history(domain: str) -> dict:
  """
  Fetch historical SSL certificate issuance
  for a domain from Certificate Transparency logs.
  Useful for detecting domain hijacking or
  unexpected certificate issuance.
  Verified source: crt.sh. Token-efficient.
  Data freshness: 4-hour cache.
  Example: fetch_domain_history('example.com')
  """

── Smoke tests (6 required): ────────────────────

Test 1: fetch_domain_rdap("stripe.com")
  PASS if: registrar present, expiry date present,
  sha256_hash non-empty, disclaimer present

Test 2: fetch_ssl_certificate_chain("github.com")
  PASS if: certificate data returned,
  issuer present, markdown_output non-empty

Test 3: fetch_dns_records("cloudflare.com",
  ["A", "MX", "TXT"])
  PASS if: returns records for at least 2 types

Test 4: fetch_domain_rdap("thisdoesnotexist99999.com")
  PASS if: returns cleanly — not found handled
  gracefully, no crash

Test 5: Hard stop check
  grep -ri "scan\|port\|nmap\|enumerate\|brute"
  datanexus/tools/t07.py
  PASS if: zero matches

Test 6: Telemetry
  redis-cli GET datanexus:calls:T07:{today}
  PASS if: counter >= 3 after tests 1-3

All 6 PASS before building T11.
Stop and report results. Wait for confirmation.

═══════════════════════════════════════════════════════
TOOL 3 — T11: GLOBAL PATENT INTELLIGENCE
═══════════════════════════════════════════════════════

Spec reference: Section 5, T11 entry
Build order: THIRD

Sources:
  Primary:   EPO OPS API (OAuth)
             ops.epo.org/3.2/rest-services
             EPO_CLIENT_ID + EPO_CLIENT_SECRET
             in /app/.env — confirmed approved
  Secondary: USPTO PatentsView API (no key)
             patentsview.org/api/patents/query
  Supporting: WIPO PATENTSCOPE API (no key)
             patentscope.wipo.int/search/api

Cache TTL: 86400 seconds (24 hours)
Circuit breaker source IDs:
  "epo_ops", "uspto_patentsview", "wipo_patentscope"

EPO OAuth implementation:
  Token endpoint:
    ops.epo.org/3.2/auth/accesstoken
  Request token with:
    grant_type=client_credentials
    client_id=EPO_CLIENT_ID
    client_secret=EPO_CLIENT_SECRET
  Token expires in 20 minutes — refresh before
  expiry. Cache token in Redis:
    datanexus:epo:token:{expiry_ts}
  Never hardcode credentials. Read from env only.

Free tier limit: 4GB/month data transfer.
  Monitor with:
    datanexus:epo:bytes_used:{month_iso}
  If > 3.8GB: circuit breaker trips EPO source,
  fallback to USPTO only, alert ops.

Hard stop (exact wording — never violate):
  Do NOT add patent valuation, licensing fee
  estimates, infringement opinions, or any
  statement about whether a patent is valid or
  enforceable. Legal advice territory.

Disclaimer (hardcode on every T11 response):
  "Patent data sourced from EPO OPS, USPTO
  PatentsView, and WIPO PATENTSCOPE. DataNexus
  does not provide patent valuation, infringement
  analysis, or legal opinions. Verify data with
  official patent office records before any
  legal or commercial decision."

── Data functions (exactly 4): ──────────────────

@mcp.tool()
@verify_entitlement('T11')
async def fetch_patent_by_number(
    patent_number: str,
    jurisdiction: str = 'EP'
) -> dict:
  """
  Fetch full patent details by patent number from
  EPO OPS, USPTO, or WIPO. Returns title, abstract,
  claims summary, filing date, inventors, assignees,
  and citation count in AI-Ready Markdown.
  Verified source: EPO OPS + USPTO PatentsView.
  Data freshness: 24-hour cache. Token-efficient.
  jurisdiction: 'EP' (EPO), 'US' (USPTO),
    'WO' (WIPO PCT). Default: 'EP'.
  Example: fetch_patent_by_number('EP1000000', 'EP')
  """

@mcp.tool()
@verify_entitlement('T11')
async def search_patents_by_keyword(
    keywords: str,
    jurisdiction: str = 'EP',
    date_from: str = ''
) -> dict:
  """
  Search patents by keyword across EPO, USPTO,
  or WIPO. Returns up to 10 matching patents with
  title, abstract excerpt, filing date, and
  assignee in AI-Ready Markdown.
  Verified source: EPO OPS + USPTO PatentsView.
  Data freshness: 24-hour cache. Token-efficient.
  Example: search_patents_by_keyword(
    'neural network image classification', 'US',
    '2020-01-01')
  """

@mcp.tool()
@verify_entitlement('T11')
async def fetch_patent_citations(
    patent_number: str,
    jurisdiction: str = 'EP'
) -> dict:
  """
  Fetch forward and backward citations for a
  patent. Returns citing patents, cited patents,
  and citation count in AI-Ready Markdown.
  Useful for prior art research and technology
  landscape analysis.
  Verified source: EPO OPS. Token-efficient.
  Data freshness: 24-hour cache.
  Example: fetch_patent_citations('EP1000000','EP')
  """

@mcp.tool()
@verify_entitlement('T11')
async def fetch_inventor_portfolio(
    inventor_name: str,
    assignee: str = ''
) -> dict:
  """
  Fetch patent portfolio for an inventor or
  assignee. Returns list of patents with filing
  dates, jurisdictions, and technology domains
  in AI-Ready Markdown.
  Verified source: EPO OPS + USPTO PatentsView.
  Data freshness: 24-hour cache. Token-efficient.
  Example: fetch_inventor_portfolio(
    'John Smith', 'Apple Inc')
  """

── Smoke tests (7 required): ────────────────────

Test 1: fetch_patent_by_number("EP1000000", "EP")
  PASS if: title present, sha256_hash non-empty,
  disclaimer present, EPO OAuth used successfully

Test 2: Same call again
  PASS if: cache_hit=True

Test 3: search_patents_by_keyword(
  "machine learning", "US", "")
  PASS if: returns list of patents,
  markdown_output non-empty

Test 4: EPO token caching
  redis-cli KEYS "datanexus:epo:token:*"
  PASS if: at least 1 key present after test 1

Test 5: fetch_patent_by_number("US10000000", "US")
  PASS if: USPTO data returned (different source
  from test 1), no crash

Test 6: Hard stop check
  grep -ri "valuation\|infringement\|
  licensing fee\|valid patent\|enforceable"
  datanexus/tools/t11.py
  PASS if: zero matches

Test 7: EPO fallback
  Temporarily set EPO_CLIENT_ID=invalid
  search_patents_by_keyword("test", "EP", "")
  PASS if: returns USPTO data with source
  limitation notice, no crash, circuit breaker
  logs EPO failure
  Restore real EPO credentials after test

All 7 PASS before building T18.
Stop and report results. Wait for confirmation.

═══════════════════════════════════════════════════════
TOOL 4 — T18: GOVERNMENT CONTRACTING & PROCUREMENT
═══════════════════════════════════════════════════════

Spec reference: Section 5, T18 entry
Build order: FOURTH

Sources:
  Primary:   USASpending.gov API (no key)
             api.usaspending.gov
             Build this first — no key needed,
             immediate data, good fallback
  Secondary: SAM.gov API (SAM_GOV_API_KEY in .env)
             api.sam.gov/prod/opportunities/v2
  Supporting: EU TED API (no key)
             ted.europa.eu/api/swagger-ui
  Supporting: UK Find-a-Tender (no key)
             find-tender.service.gov.uk/api

Cache TTL: 14400 seconds (4 hours)
Circuit breaker source IDs:
  "usaspending", "sam_gov", "eu_ted",
  "uk_find_a_tender"

Hard stop (exact wording — never violate):
  Do NOT add procurement strategy advice, bid
  scoring, win probability estimates, or any
  consulting recommendations. Do NOT add
  classified contract data.

Disclaimer (hardcode on every T18 response):
  "Contract data sourced from USASpending.gov,
  SAM.gov, EU TED, and UK Find-a-Tender public
  databases. DataNexus does not provide
  procurement strategy advice or bid consulting.
  Verify award data with contracting authority
  before any business decision."

── Data functions (exactly 3): ──────────────────

@mcp.tool()
@verify_entitlement('T18')
async def search_contract_awards(
    keyword: str,
    agency: str = '',
    date_from: str = '',
    jurisdiction: str = 'US'
) -> dict:
  """
  Search government contract awards by keyword,
  agency, and date range. Returns award amounts,
  incumbent vendors, contract types, and NAICS
  codes in AI-Ready Markdown.
  Verified source: USASpending.gov + SAM.gov
  (US) · EU TED (EU) · Find-a-Tender (UK).
  Data freshness: 4-hour cache. Token-efficient.
  jurisdiction: 'US', 'EU', 'UK'. Default: 'US'.
  Example: search_contract_awards(
    'cybersecurity', 'Department of Defense',
    '2024-01-01', 'US')
  """

@mcp.tool()
@verify_entitlement('T18')
async def fetch_vendor_contract_history(
    vendor_name: str,
    jurisdiction: str = 'US'
) -> dict:
  """
  Fetch contract award history for a specific
  vendor. Returns total awards, top agencies,
  contract types, and recent awards in AI-Ready
  Markdown. Useful for competitive intelligence
  and incumbent research.
  Verified source: USASpending.gov.
  Data freshness: 4-hour cache. Token-efficient.
  Example: fetch_vendor_contract_history(
    'Booz Allen Hamilton', 'US')
  """

@mcp.tool()
@verify_entitlement('T18')
async def fetch_open_solicitations(
    keyword: str,
    agency: str = '',
    jurisdiction: str = 'US'
) -> dict:
  """
  Fetch currently open contract solicitations
  and bid opportunities matching a keyword.
  Returns solicitation title, agency, deadline,
  estimated value, and NAICS in AI-Ready Markdown.
  Verified source: SAM.gov (US) · EU TED (EU)
  · Find-a-Tender (UK). Token-efficient.
  Data freshness: 4-hour cache.
  Example: fetch_open_solicitations(
    'cloud services', 'GSA', 'US')
  """

── Smoke tests (6 required): ────────────────────

Test 1: search_contract_awards(
  "cybersecurity", "", "", "US")
  PASS if: returns awards data, NAICS codes
  present, sha256_hash non-empty, disclaimer
  present

Test 2: fetch_vendor_contract_history(
  "Booz Allen Hamilton", "US")
  PASS if: award history returned,
  markdown_output non-empty

Test 3: search_contract_awards(
  "information technology", "", "", "US")
  PASS if: cache_hit=False first call,
  USASpending data returned

Test 4: fetch_open_solicitations(
  "cloud", "", "US")
  PASS if: solicitations returned or empty
  list handled gracefully

Test 5: Hard stop check
  grep -ri "strategy\|bid score\|win prob\|
  consulting\|recommend" datanexus/tools/t18.py
  PASS if: zero matches

Test 6: Telemetry
  redis-cli GET datanexus:calls:T18:{today}
  PASS if: counter >= 3 after tests 1-3

All 6 PASS before building T19.
Stop and report results. Wait for confirmation.

═══════════════════════════════════════════════════════
TOOL 5 — T19: REGULATORY DOCKET & COMMENT TRACKING
═══════════════════════════════════════════════════════

Spec reference: Section 5, T19 entry
Build order: FIFTH (LAST in Sprint 2)

BLOCKING REQUIREMENT: Before starting T19,
confirm REGULATIONS_GOV_KEY is in /app/.env
on Hetzner server. If not set:
  ssh datanexus
  nano /app/.env
  Add: REGULATIONS_GOV_KEY=your_key_here
  docker compose restart datanexus-mcp
Do not build T19 without this key.
Flag me if key is missing.

Sources:
  Primary:   Regulations.gov API
             api.regulations.gov
             REGULATIONS_GOV_KEY required
             Free tier: 1,000 req/day
  Secondary: Federal Register API (no key)
             federalregister.gov/api/v1
  Supporting: EU Have Your Say (no key)
             ec.europa.eu/info/law/better-
             regulation/have-your-say/api_en

Cache TTL: 14400 seconds (4 hours)
  Rate limit awareness: Regulations.gov 1,000
  req/day — ingest worker must batch efficiently.
  Schedule ingest at 6-hour intervals, not 4h,
  to stay within daily limit.

Circuit breaker source IDs:
  "regulations_gov", "federal_register",
  "eu_have_your_say"

Hard stop (exact wording — never violate):
  Do NOT add regulatory interpretation, compliance
  advice, or any statement about what a rule means
  for a specific business. Do NOT add 'what this
  rule means for your business' analysis.
  Legal advisory territory.

Disclaimer (hardcode on every T19 response):
  "Regulatory data sourced from Regulations.gov,
  Federal Register, and EU Have Your Say public
  APIs. DataNexus does not provide regulatory
  interpretation or compliance advice. Consult
  qualified regulatory counsel before acting on
  any regulatory information."

── Data functions (exactly 3): ──────────────────

@mcp.tool()
@verify_entitlement('T19')
async def search_open_rulemakings(
    keyword: str,
    agency: str = '',
    status: str = 'open'
) -> dict:
  """
  Search open rulemakings and comment periods
  on Regulations.gov and Federal Register.
  Returns docket title, agency, comment deadline,
  docket ID, and document count in AI-Ready
  Markdown. Verified source: Regulations.gov
  + Federal Register API. Token-efficient.
  Data freshness: 4-hour cache.
  status: 'open', 'closed', 'all'. Default: 'open'
  Example: search_open_rulemakings(
    'artificial intelligence', 'FTC', 'open')
  """

@mcp.tool()
@verify_entitlement('T19')
async def fetch_docket_details(
    docket_id: str
) -> dict:
  """
  Fetch full details for a specific regulatory
  docket by ID. Returns title, agency, status,
  comment period dates, number of comments, and
  related documents in AI-Ready Markdown.
  Verified source: Regulations.gov.
  Data freshness: 4-hour cache. Token-efficient.
  Example: fetch_docket_details('FDA-2023-N-0001')
  """

@mcp.tool()
@verify_entitlement('T19')
async def fetch_federal_register_notices(
    agency: str,
    keyword: str = '',
    date_from: str = ''
) -> dict:
  """
  Fetch recent Federal Register notices and
  rules for an agency. Returns document type,
  title, publication date, effective date, and
  CFR citations in AI-Ready Markdown.
  Verified source: Federal Register API (no key).
  Data freshness: 4-hour cache. Token-efficient.
  Example: fetch_federal_register_notices(
    'SEC', 'crypto', '2024-01-01')
  """

── Smoke tests (6 required): ────────────────────

Test 1: search_open_rulemakings(
  "artificial intelligence", "", "open")
  PASS if: dockets returned, comment deadline
  present, sha256_hash non-empty, disclaimer
  present

Test 2: Same call again
  PASS if: cache_hit=True

Test 3: fetch_docket_details("FDA-2023-N-0001")
  PASS if: docket data returned or not-found
  handled gracefully — no crash on unknown ID

Test 4: fetch_federal_register_notices(
  "SEC", "cryptocurrency", "2024-01-01")
  PASS if: Federal Register API called
  (different source from test 1), data returned

Test 5: Hard stop check
  grep -ri "interpret\|compliance advice\|
  means for your business\|legal opinion"
  datanexus/tools/t19.py
  PASS if: zero matches

Test 6: Rate limit awareness
  Confirm ingest worker schedules at 21600s
  (6 hours) not 14400s (4 hours) to stay within
  Regulations.gov 1,000 req/day free tier.
  grep "schedule_seconds.*21600\|21600.*schedule"
  datanexus/ingest/t19_worker.py
  PASS if: 21600 present (or equivalent
  calculation showing awareness of rate limit)

All 6 PASS before final deployment.
Stop and report results. Wait for confirmation.

═══════════════════════════════════════════════════════
FINAL PHASE — DEPLOY + VERIFY ALL SPRINT 2 TOOLS
═══════════════════════════════════════════════════════

After all 5 tools pass their smoke tests:

Step 1: Update validator.py with Sprint 2 rules
  Add T22, T07, T11, T18, T19 to required_fields:
    T22: ['npi_number'] or ['name']
    T07: ['domain']
    T11: ['patent_number'] or ['keywords']
    T18: ['keyword']
    T19: ['keyword'] or ['docket_id']
  Add tool-specific validation rules where
  deterministic checks are possible:
    T22: NPI must be 10 digits
    T07: domain must contain at least one dot
    T11: patent number format check per jurisdiction
    T18: date_from must be valid ISO date if present
    T19: status must be 'open'|'closed'|'all'

Step 2: Single commit for Sprint 2
  git add -A
  git commit -m "Sprint 2: T22, T07, T11, T18,
  T19 — professional licences, DNS, patents,
  GovCon, regulatory dockets"

Step 3: Deploy to Hetzner
  ssh datanexus && cd /app/datanexus
  git pull
  docker compose build --no-cache datanexus-mcp
  docker compose up -d
  Confirm all 4 containers Up.

Step 4: Verify tool count
  curl -s -X POST https://datanexusmcp.com/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,
         "method":"initialize",
         "params":{"protocolVersion":"2024-11-05",
         "capabilities":{},
         "clientInfo":{"name":"test",
         "version":"1.0"}}}'
  Note the session ID from response headers.
  Then call tools/list with session ID.
  PASS if: total tools = 26
  Arithmetic:
    Sprint 1: 11 tools
    T22: 3 data + 2 shared = 5 new
    T07: 4 data + 2 shared = 6 new
    T11: 4 data + 2 shared = 6 new (EPO)
    T18: 3 data + 2 shared = 5 new
    T19: 3 data + 2 shared = 5 new
    Wait — report_feedback and report_mcpize_link
    are SHARED tools already registered once.
    Do NOT register them again per tool.
    Each new tool adds only its data functions.
    Correct arithmetic:
      11 existing + 3 + 4 + 4 + 3 + 3 = 28
    But validate_tool_output is also shared.
    Confirm exact count from main.py and report.

Step 5: Run existing tests — no regressions
  docker compose exec datanexus-mcp \
    pytest feedback/tests/ -v --tb=short
  docker compose exec datanexus-mcp \
    pytest payment/tests/ -v --tb=short
  Must show 84/84 green. Zero failures.

Step 6: Update registries
  Bump package.json version (patch increment)
  npm publish @datanexus/mcp-server
  Update glama.json with T22, T07, T11, T18,
  T19 tool entries.
  Each entry must contain required keywords:
    "AI-Ready Markdown", "Verified source",
    "token-efficient"
  Plus tool-specific Glama keywords from spec.

Step 7: Live end-to-end test per tool
  □ fetch_npi_provider("1003000126") — T22 live
  □ fetch_domain_rdap("stripe.com") — T07 live
  □ fetch_patent_by_number("EP1000000","EP") — T11
  □ search_contract_awards("cyber","","","US") — T18
  □ search_open_rulemakings("AI","","open") — T19

═══════════════════════════════════════════════════════
FINAL REPORT TABLE
═══════════════════════════════════════════════════════

Report this when Sprint 2 is complete:

Tool | Smoke tests | Live test | Status
-----+-------------+-----------+-------
T22  | 7/7         | PASS/FAIL | done/fail
T07  | 6/6         | PASS/FAIL | done/fail
T11  | 7/7         | PASS/FAIL | done/fail
T18  | 6/6         | PASS/FAIL | done/fail
T19  | 6/6         | PASS/FAIL | done/fail

Tests: feedback {n}/61 · payment {n}/23
Total tools in main.py: {n}
npm publish: PASS/FAIL version {x.x.x}
glama.json updated: PASS/FAIL
All containers Up: PASS/FAIL

Sprint 2 complete ONLY when:
  All 5 tools pass all smoke tests
  All 5 live tests PASS
  84/84 existing tests green
  npm published
  glama.json updated

Stop. Do not begin Sprint 3 (T12 + remaining
tools) until I give explicit go-ahead.

═══════════════════════════════════════════════════════
HARD BOUNDARIES — SPRINT 2
═══════════════════════════════════════════════════════

Do NOT build T12 (Sanctions) — deferred Sprint 3.
Do NOT build T08, T09, T20, T21 — not in scope.
Do NOT change @verify_entitlement or payment/.
Do NOT modify tests that currently pass.
Do NOT add a 5th Haiku trigger.
Do NOT implement capabilities listed under
  "Hard stop" for any tool.
Build exactly what is specified. Nothing more.
