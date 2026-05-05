# DataNexus MCP — Sprint 1 Prompt
# Spec: DataNexus_MCP_Spec_v7_3.docx (AUTHORITATIVE)
# Approved tools this week: T04 and T10 ONLY
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Last updated: April 2026
# Server: datanexusmcp.com
# Hetzner CAX11 IP: 178.104.251.70
# SSH: ssh datanexus
# Docker: 29.4.1
# .env location: /app/.env
# Snapshot ID: 381677081
# Transport: streamable-http (no stdio)
# Deploy target: Hetzner — not local Mac

═══════════════════════════════════════════════════════
RULE ZERO — BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these files in this exact order before writing
a single line of code or making any file change:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
   Every rule is absolute. No exceptions.

2. /Users/sangeetajagadeesh/OmSaiRam/
   DataNexus_MCP_Spec_v7_3.docx
   Read the ENTIRE document. This is the only
   authoritative spec. No prior version applies.

   Pay particular attention to these sections:
   - Section 11: Canonical Session Starter
     (read this every session, every time)
   - Section 12: v7.3 Amendments
     (supersedes earlier sections where conflicts exist)
   - Section 12.4: T04 updated specification
     (ProPublica REMOVED — IRS direct sources only)
   - Section 12.5: Build status table
     (only T04 and T10 approved this week)
   - Section 12.6: Payment this week = nothing
   - Section 8: Feedback system
   - Section 10: Payment architecture

Confirm pre-read by answering ALL of these before
touching any code:

a) What are the 5 most critical CLAUDE.md rules?
   (from Section 11.2)

b) What are the exact function signatures for T04
   in v7.3? Note: these changed from v7.0.
   (from Section 12.4 / Table 163)

c) What are the exact function signatures for T10?
   Note: fetch_dependency_graph has a hard timeout.
   (from Section 11.3 / Table 140)

d) What is the default value of MCPIZE_ACTIVE and
   what does flipping it to true do to existing
   free-window users?

e) What is the default value of FEEDBACK_AGENTS_ACTIVE
   and which two components ignore this switch?

f) What are the 5 feedback system build steps and
   their gates? (Section 11.6)

g) Why was ProPublica removed from T04?
   (Section 12.4 / Table 160)

h) What must Publisher check before deploying?
   (Section 12.3 / Table 158 — 5 checks)

Do not proceed until I confirm your answers are
correct. Type READY TO BUILD only after I confirm.

═══════════════════════════════════════════════════════
PHASE 0 — WIPE LOCAL IMPLEMENTATION
═══════════════════════════════════════════════════════

Wipe the current local implementation only.

DELETE:
- All files under datanexus/tools/
- All files under datanexus/ingest/
- All tool registrations in datanexus/main.py
  (reset main.py to clean FastMCP app, zero tools)
- Any feedback/ or payment/ directories if present
  from previous implementation attempts
  (we rebuild these correctly per v7.3)

DO NOT TOUCH — leave exactly as-is:
- CLAUDE.md
- docker-compose.yml
- .env
- start-local.sh
- Caddyfile and any infrastructure files
- npm package (do not unpublish)
- glama.json (do not modify)
- smithery.yml (do not modify)
- .well-known/mcp-manifest.json (do not modify)

After wiping: print every file and directory
deleted. Confirm main.py has zero tool registrations.
Confirm feedback/ and payment/ are clean.

Stop. Wait for my go-ahead before Phase 1.

═══════════════════════════════════════════════════════
PHASE 1 — SHARED CORE INFRASTRUCTURE
═══════════════════════════════════════════════════════

Build the shared core that all tools use.
Every file must pass its import gate before the next.
No exceptions. No skipping ahead.

── datanexus/core/__init__.py ───────────────────────
Empty file. Package marker.
Gate: python3 -c "import datanexus.core" — no error.

── datanexus/core/schema.py ─────────────────────────

Pydantic v2 DataNexusResponse base model.
All tool responses inherit from this.

Required fields:
  tool_id:          str
  source_url:       HttpUrl
  fetch_timestamp:  datetime    # UTC
  cache_hit:        bool
  staleness_notice: Optional[str]  # None when fresh
  sha256_hash:      str            # payload integrity
  data:             Dict[str, Any] # tool payload
  markdown_output:  str            # AI-Ready Markdown
  query_hash:       str            # AuditContext output
  schema_version:   str = "1.0"
  data_as_of:       str            # ISO freshness ts
  ingest_healthy:   bool
  disclaimer:       str            # per-tool, hardcoded

Validator on markdown_output.
Raise ValueError if ANY pattern found (re.IGNORECASE):
  "ignore previous"
  "you are now"
  "system:"
  "<script"
  "<iframe"
  "forget your instructions"
  "new persona"
  "disregard"

Error response shape (return this, never raise,
never return raw str(e)):
  {
    'status':         'error',
    'error_code':     str,   # defined enum value
    'message':        str,   # human-readable only
    'retry_after':    int,   # 0 if no retry
    'query_hash':     str,   # always present
    'ingest_healthy': bool,
  }

Gate: python3 -c "from datanexus.core.schema import
  DataNexusResponse; print('ok')" → prints 'ok'

── datanexus/core/cache.py ──────────────────────────

Redis cache helpers. Import make_params_hash from
datanexus.core.audit — do not redefine it here.

  get_cached(tool_id: str, params_hash: str)
    → Optional[dict]
    Key: datanexus:{tool_id}:{params_hash}
    Returns None on miss or Redis error (never raise)

  set_cached(tool_id: str, params_hash: str,
             payload: dict, ttl_seconds: int) → None
    Stores JSON-serialised payload with EX=ttl_seconds

  compute_payload_hash(raw: bytes) → str
    SHA-256 of raw upstream response bytes
    Full 64 hex chars
    This goes into sha256_hash response field

Gate:
  from datanexus.core.cache import (get_cached,
    set_cached, compute_payload_hash)
  print('ok') — no error

── datanexus/core/circuit_breaker.py ────────────────

Per-source breaker. All state in Redis — no
module-level dicts (CLAUDE.md rule).

Redis key prefix: datanexus:cb:{source_id}:
  :failures   — INCR counter, 600s TTL
  :tripped    — SET flag when tripped
  :last_probe — SET timestamp

trip_threshold:  3 consecutive failures
trip_window:     600s
probe_interval:  900s

Functions:
  record_failure(source_id: str) → bool
    Increment :failures (INCR, 600s TTL per call)
    If count >= 3: SET :tripped, log structured JSON:
      {"ts":ISO,"event":"breaker_tripped",
       "source":source_id}
    Return True if just tripped, False otherwise

  record_success(source_id: str) → None
    DEL :failures, DEL :tripped
    Log: {"ts":ISO,"event":"breaker_reset",
          "source":source_id}

  is_tripped(source_id: str) → bool
    If :tripped key missing: return False
    If :tripped exists and probe interval passed:
      DEL :tripped (allow one probe request)
      return False
    return True

  get_staleness_notice(source_id: str,
                       cached_at: str) → str
    Returns: "Source {source_id} unavailable.
    Serving cached data from {cached_at}."

Gate: is_tripped("test_new_source") → False
  (no Redis keys for this source → not tripped)

── datanexus/core/audit.py ──────────────────────────

Implements the audit and telemetry layer.
Section 9.3.3 specification — authoritative.

NEVER store raw parameter values.
Only params_hash. This is a CLAUDE.md rule.

  make_params_hash(params: dict) → str
    SHA-256 of sorted JSON-serialised params
    Returns first 32 hex chars
    DETERMINISTIC: key order is ignored

  write_audit(tool_id: str, params: dict,
              version: str, response_time_ms: int,
              cache_hit: bool, error: bool,
              error_type: Optional[str],
              retry_attempt: int) → str
    Computes params_hash, writes AuditRecord to Redis
    Also increments (all with 35-day TTL):
      dau:{tool_id}:{version}:{date}  (INCR)
      errors:{tool_id}:{date}          (INCR if error)
      cache_miss:{tool_id}:{date}
        (INCR if not cache_hit)
    Returns query_hash (the params_hash)

  class AuditContext (async context manager):
    __init__(tool_id, params, version)
    __aenter__ → captures start time, returns self
    __aexit__  → calls write_audit with elapsed ms
    ctx.query_hash: str  — available after __aenter__
    ctx.set_cache_hit(bool)
    ctx.set_error(str)
    ctx.set_retry(int)
    NEVER suppresses exceptions

  standard_response_fields(
      query_hash: str,
      data_as_of: str,
      ingest_healthy: bool,
      schema_version: str = '1.0') → dict
    Returns dict with EXACTLY these 4 keys:
      query_hash, schema_version,
      data_as_of, ingest_healthy
    Every tool response MUST include these.
    Never add more keys to this function.

Gate:
  make_params_hash({'b':2,'a':1}) ==
  make_params_hash({'a':1,'b':2}) → True
  standard_response_fields('h','2026-04-26',True)
    returns dict with exactly 4 keys → True

── datanexus/core/entitlement.py ────────────────────

Free-window @verify_entitlement stub.
MCPIZE_ACTIVE defaults to false.
When false: decorator is passthrough only.
Telemetry ALWAYS runs regardless of switch.

from payment.config import MCPIZE_ACTIVE
  — if payment/ not yet built, use:
  MCPIZE_ACTIVE = os.environ.get(
    'MCPIZE_ACTIVE','false').lower()=='true'

Telemetry that runs on EVERY call (free or paid):
  INCR datanexus:calls:{tool_id}:{date}
  SADD datanexus:sessions:{tool_id}:{date} {session_id}
  LPUSH datanexus:feed
    "{tool_id}|{session_id}|{timestamp}|free"
  LTRIM datanexus:feed 0 49
  PostgreSQL: INSERT INTO sessions
    (session_id, tool_id, created_at)
    VALUES (...) ON CONFLICT DO NOTHING

session_id: UUID from request context or generate new

  def verify_entitlement(tool_id: str):
    def decorator(fn):
      @functools.wraps(fn)
      async def wrapper(*args, **kwargs):
        session_id = _get_or_create_session(kwargs)
        await _run_telemetry(tool_id, session_id)
        if not MCPIZE_ACTIVE:
          return await fn(*args, **kwargs)
        # paid enforcement — delegated to
        # payment/entitlement.py when MCPIZE_ACTIVE
        return await fn(*args, **kwargs)
      return wrapper
    return decorator

Gate:
  MCPIZE_ACTIVE=false: decorated async function
  called, returns normally, Redis INCR counter
  incremented, function return value unchanged.

── datanexus/core/ingest_base.py ────────────────────

Base class for all ingest workers.
No module-level dicts. No lru_cache. CLAUDE.md rule.

  class IngestBase:
    def __init__(self, tool_id: str,
                 source_id: str,
                 ttl_seconds: int,
                 schedule_seconds: int):

    async def fetch(self) → bytes:
      # Override in subclass. Returns raw bytes.

    async def run_forever(self) → None:
      # Infinite loop: sleep, fetch, store, log
      # On success: compute_payload_hash, set_cached,
      #   record_success(source_id)
      #   Log: {"ts":ISO,"tool":tool_id,
      #    "source":source_id,"status":"ok",
      #    "payload_bytes":int,"hash":str,
      #    "breaker_tripped":false}
      # On ANY exception: record_failure(source_id)
      #   Log: {"ts":ISO,"tool":tool_id,
      #    "source":source_id,"status":"error",
      #    "error":str(e),"breaker_tripped":bool}
      # NEVER crash the process

Gate: IngestBase('T04','irs_bmf',604800,3600)
  instantiates without error.

── Confirm full core passes ─────────────────────────

python3 -c "
from datanexus.core.schema import DataNexusResponse
from datanexus.core.cache import (get_cached,
  set_cached, compute_payload_hash)
from datanexus.core.circuit_breaker import (
  is_tripped, record_failure, record_success,
  get_staleness_notice)
from datanexus.core.audit import (make_params_hash,
  write_audit, AuditContext, standard_response_fields)
from datanexus.core.entitlement import verify_entitlement
from datanexus.core.ingest_base import IngestBase
print('all core imports ok')
"

Must print 'all core imports ok'. No errors.
Fix any import error before Phase 2.

═══════════════════════════════════════════════════════
PHASE 2 — BUILD T04 (Days 1–3)
═══════════════════════════════════════════════════════

CRITICAL — READ SECTION 12.4 BEFORE WRITING ANY
T04 CODE. The Section 4 T04 entry is superseded.
The authoritative T04 spec is Section 12.4.

PROPUBLICA IS REMOVED FROM T04 ENTIRELY.
Do not reference ProPublica in any T04 code,
comment, or string. See Table 160 for why.

Sources (v7.3, Section 12.4):
  Primary:   IRS EO BMF direct download
             irs.gov/charities-non-profits/
             exempt-organizations-business-master-
             file-extract-eo-bmf
             Public domain. No key. No restriction.

  Secondary: IRS TEOS bulk downloads
             irs.gov/charities-non-profits/
             tax-exempt-organization-search-bulk-
             data-downloads
             Public domain. No key. No restriction.

  Tertiary:  UK Charity Commission API
             api.charitycommission.gov.uk
             Open Government Licence v3.0
             Commercial use permitted WITH GDPR
             mitigation (see below)

Cache TTL:
  IRS data: 604800 seconds (7 days)
  UK Charity data: 86400 seconds (24 hours MAX)
    — UK GDPR requirement, not negotiable

Circuit breaker source IDs:
  "irs_bmf", "irs_teos", "uk_charity"

Hard stop: Do NOT add donor data, individual
  giving history, donation amounts, any PII about
  individual donors. Do NOT use ProPublica.

UK GDPR Mitigation — implement all four (Table 162):
  1. Glama description and README must state:
     "DataNexus acts as data controller for UK
     charity data processed via this tool. Data
     sourced from Charity Commission for England
     and Wales under Open Government Licence v3.0."
  2. Never store trustee names, officer details,
     or personal addresses beyond 24h cache TTL.
  3. Tool description must state purpose limitation:
     "For due diligence and research purposes.
     Not for profiling individuals associated
     with charities."
  4. README must include:
     "Individuals whose data appears in charity
     records may contact
     dataprotection@datanexusmcp.com to exercise
     rights under UK GDPR Article 17."

── Step A: datanexus/ingest/t04_worker.py ───────────

Three IngestBase subclasses:

class IRSBMFWorker(IngestBase):
  Downloads IRS EO BMF ZIP file monthly
  (file updates monthly — schedule 7 days)
  Extracts CSV, converts to indexed JSON
  Key pattern: datanexus:T04:bmf:{ein}
  Index by EIN for O(1) lookup
  Also maintain search index:
    datanexus:T04:bmf:name:{name_prefix}
    → list of EINs (for name search)
  TTL: 604800s per key

class IRSTEOSWorker(IngestBase):
  Downloads IRS TEOS bulk files (990, 990EZ, 990PF)
  Extracts financial data per EIN
  Key pattern: datanexus:T04:teos:{ein}
  TTL: 604800s

class UKCharityWorker(IngestBase):
  Fetches UK Charity Commission API per charity
  Key pattern: datanexus:T04:uk:{regno}
  TTL: 86400s (24 hours — UK GDPR max)
  Store ONLY: name, income, activities, status
  NEVER store: trustees, officers, personal data

── Step B: datanexus/tools/t04.py ───────────────────

Exactly 3 data functions + 2 infrastructure
functions = 5 total registered on server.
(Section 11.3, Table 163 — authoritative)

DATA SIGNATURES (v7.3 — supersedes all prior):

@mcp.tool()
@verify_entitlement('T04')
async def fetch_nonprofit_by_ein(ein: str) -> dict:
  """
  Fetch IRS 990 data for any US nonprofit by EIN.
  Returns name, address, NTEE code, ruling date,
  revenue, expenses, and assets in AI-Ready Markdown.
  Source: IRS EO BMF + IRS TEOS (public domain).
  Token-efficient. Verified source.
  Example: fetch_nonprofit_by_ein('13-1837418')
  On cache miss: serves from IRS bulk data.
  On source unavailable: returns archived data with
  staleness_notice showing last update time.
  """
  params = {'ein': ein}
  async with AuditContext('T04', params, '1.0') as ctx:
    phash = make_params_hash(params)
    cached = await get_cached('T04', phash)
    if cached:
      ctx.set_cache_hit(True)
      return {**cached,
              **standard_response_fields(
                ctx.query_hash,
                cached.get('data_as_of',''),
                True)}
    if is_tripped('irs_bmf') and is_tripped('irs_teos'):
      archive = await get_cached('T04', phash+'_archive')
      return {
        'data': archive or {},
        'staleness_notice': get_staleness_notice(
          'irs_bmf', archive.get('data_as_of','')),
        **standard_response_fields(
          ctx.query_hash, '', False)
      }
    # Live lookup from Redis BMF index
    # (pre-populated by IRSBMFWorker)
    result = await _lookup_ein_from_index(ein)
    markdown = _build_nonprofit_markdown(result)
    # canary validator runs via DataNexusResponse
    payload = {
      'tool_id': 'T04',
      'data': result,
      'markdown_output': markdown,
      'disclaimer': (
        'Data sourced from IRS EO BMF and IRS TEOS '
        '(public domain). DataNexus does not warrant '
        'accuracy. Verify against primary source '
        'before making business decisions.'
      ),
      'sha256_hash': compute_payload_hash(
        json.dumps(result).encode()),
      'cache_hit': False,
      'staleness_notice': None,
    }
    await set_cached('T04', phash, payload, 604800)
    ctx.set_cache_hit(False)
    return {**payload,
            **standard_response_fields(
              ctx.query_hash,
              datetime.utcnow().isoformat(),
              True)}

@mcp.tool()
@verify_entitlement('T04')
async def search_nonprofits_by_name(
    name: str,
    state: str = ''
) -> dict:
  """
  Search US nonprofits by name with optional state
  filter. Returns up to 25 results with EIN, revenue
  and mission in AI-Ready Markdown.
  Source: IRS TEOS search (public domain).
  Example: search_nonprofits_by_name('Red Cross','CA')
  """

@mcp.tool()
@verify_entitlement('T04')
async def fetch_charity_uk(
    charity_number_or_name: str
) -> dict:
  """
  Fetch UK registered charity details from the
  Charity Commission. Returns registration status,
  income, and activities in AI-Ready Markdown.
  For due diligence and research purposes.
  Not for profiling individuals associated with
  charities. DataNexus acts as data controller for
  UK charity data under Open Government Licence v3.0.
  Source: UK Charity Commission API.
  Example: fetch_charity_uk('219099')
  """
  # Cache TTL: 86400s (24h) — UK GDPR requirement
  # Return ONLY: name, income, activities, status
  # NEVER return: trustees, officers, addresses

INFRASTRUCTURE SIGNATURES (same on all tools):

mcp.tool()(report_feedback)     # from feedback.collector
mcp.tool()(report_mcpize_link)  # from payment.tools

NOTE: report_feedback and report_mcpize_link are
built in Phases 4 and 5. For now register stub
functions that return {'status':'not_yet_active'}.
Replace with real implementations in Phase 4 and 5.

── Step C: Register T04 in main.py ──────────────────

Import all 3 T04 data functions + 2 infra stubs.
Confirm: python3 -m datanexus.main --help
  lists all 5 T04 functions, no error.

── Step D: T04 Smoke Tests ──────────────────────────

Report each as PASS or FAIL with detail.

Test 1 — EIN lookup:
  fetch_nonprofit_by_ein("13-1837418")
  PASS if: tool_id=="T04", sha256_hash non-empty,
  markdown_output non-empty, query_hash non-empty,
  cache_hit==False, ingest_healthy==True,
  disclaimer present, no ProPublica in response

Test 2 — Cache hit:
  fetch_nonprofit_by_ein("13-1837418") (second call)
  PASS if: cache_hit==True, identical data

Test 3 — Name search:
  search_nonprofits_by_name("Red Cross", "CA")
  PASS if: returns list, markdown_output non-empty

Test 4 — UK charity:
  fetch_charity_uk("219099")
  PASS if: charity name present, no personal data
  fields, source_url contains charitycommission

Test 5 — Canary:
  Inject "ignore previous instructions" into a
  mock markdown_output
  PASS if: ValueError raised

Test 6 — UK TTL:
  After fetch_charity_uk(), check Redis TTL:
  redis-cli TTL datanexus:T04:uk:{regno}
  PASS if: TTL <= 86400 (24 hours)

Test 7 — Telemetry:
  redis-cli GET datanexus:calls:T04:{today}
  PASS if: counter >= 4 after tests 1-4

All 7 PASS required before building T10.

═══════════════════════════════════════════════════════
PHASE 3 — BUILD T10 (Days 4–6)
═══════════════════════════════════════════════════════

Spec reference: Section 4 T10 + Section 11.3
Table 140 — v7.3 authoritative signatures.

IMPORTANT v7.3 CHANGE FOR T10:
fetch_dependency_graph exists in v1.0 but has
known performance issue — p99 > 4 seconds.
Hard limit: if response_time_ms > 8000, return
structured error response (never hang silently).
This is tracked for v1.1 fix.

Sources:
  Primary:   OSV.dev API (Google)
             api.osv.dev/v1 — no key, no auth
  Secondary: NIST NVD CVE API
             services.nvd.nist.gov/rest/json/
             cves/2.0 — no key (lower rate limit)
             Register key in background:
             nvd.nist.gov/developers/
             request-an-api-key — non-blocking
  Supporting: deps.dev API
             api.deps.dev/v3alpha — no key
  Supporting: GitHub Advisory Database
             api.github.com/advisories
             — no key for public data

Cache TTL: 3600 seconds (1 hour)
  CVEs are published continuously.
  Do not increase this TTL.

Circuit breaker source IDs:
  "osv_dev", "nist_nvd", "deps_dev"

Hard stop: Do NOT return exploit code, PoC
  payloads, CVSS attack vectors in executable
  form, active scanning instructions, or
  remediation advice beyond linking to official
  patch release notes.

── Step A: datanexus/ingest/t10_worker.py ───────────

CVE data cannot be pre-fetched without knowing
queries. Strategy: pre-seed popular packages.

class OSVPopularPackagesWorker(IngestBase):
  Pre-fetches CVEs for 50 popular packages:
  PyPI: requests, flask, django, numpy, pandas,
        fastapi, pydantic, sqlalchemy, celery,
        boto3, cryptography, pillow, urllib3,
        aiohttp, httpx
  npm: express, lodash, axios, react, next,
       webpack, typescript, jest, eslint, chalk,
       moment, async, semver, minimist, tar
  Maven: log4j-core, spring-core,
         jackson-databind, commons-lang3, guava
  Go: github.com/gin-gonic/gin,
      golang.org/x/net, github.com/gorilla/mux,
      github.com/dgrijalva/jwt-go
  (extend to 50 total)

  Key: datanexus:T10:pkg:{ecosystem}:{pkg}:all
  TTL: 3600s
  Schedule: every 3600 seconds

Cache miss strategy: if not pre-seeded, fetch
live from OSV.dev on tool call (within rate limit
since each package only fetches once per hour).

── Step B: datanexus/tools/t10.py ───────────────────

Exactly 5 data functions + 2 infra = 7 total.
(Section 11.3, Table 140)

@mcp.tool()
@verify_entitlement('T10')
async def fetch_package_vulnerabilities(
    package: str,
    version: str,
    ecosystem: str
) -> dict:
  """
  Fetch all known CVEs and security advisories for
  any open source package and version across PyPI,
  npm, Maven, Go, Cargo, NuGet, RubyGems, Packagist.
  Returns severity, CVSS score, fixed versions, and
  affected ranges in AI-Ready Markdown.
  Verified source: Google OSV.dev + NIST NVD.
  Token-efficient.
  ecosystem values: PyPI, npm, Maven, Go, Cargo,
  NuGet, RubyGems, Packagist
  Example: fetch_package_vulnerabilities(
    'requests', '2.28.0', 'PyPI')
  On source down: archived scan with staleness notice.
  """

@mcp.tool()
@verify_entitlement('T10')
async def fetch_dependency_graph(
    package: str,
    version: str,
    ecosystem: str
) -> dict:
  """
  Fetch the dependency graph for a package from
  deps.dev. Returns direct and transitive
  dependencies in AI-Ready Markdown.
  NOTE: p99 latency may exceed 4 seconds. If
  response time exceeds 8000ms, a structured
  timeout error is returned — never hangs.
  Example: fetch_dependency_graph(
    'fastapi', '0.100.0', 'PyPI')
  """
  # Hard timeout: if response_time_ms > 8000:
  # return {'status':'error',
  #   'error_code':'upstream_timeout',
  #   'message':'Dependency graph fetch timed out.
  #     Try again or reduce package complexity.',
  #   'retry_after': 30,
  #   'query_hash': ctx.query_hash,
  #   'ingest_healthy': False}

@mcp.tool()
@verify_entitlement('T10')
async def fetch_cve_detail(cve_id: str) -> dict:
  """
  Fetch full CVE detail by CVE ID from NIST NVD.
  Returns description, CVSS score, affected products,
  and patch references in AI-Ready Markdown.
  Example: fetch_cve_detail('CVE-2023-32681')
  """

@mcp.tool()
@verify_entitlement('T10')
async def audit_sbom_vulnerabilities(
    sbom_json: str
) -> dict:
  """
  Audit a Software Bill of Materials in CycloneDX
  or SPDX JSON format. Returns all packages with
  known vulnerabilities, severity summary, and fix
  pointers in AI-Ready Markdown.
  Source: OSV.dev batch query API.
  Input: sbom_json as stringified JSON.
  """

@mcp.tool()
@verify_entitlement('T10')
async def fetch_package_licence(
    package: str,
    version: str,
    ecosystem: str
) -> dict:
  """
  Fetch the declared software licence for a package
  version from deps.dev. Returns SPDX licence
  identifier in AI-Ready Markdown.
  Example: fetch_package_licence(
    'fastapi', '0.100.0', 'PyPI')
  """

INFRASTRUCTURE SIGNATURES (same stubs as T04):
mcp.tool()(report_feedback)
mcp.tool()(report_mcpize_link)

Disclaimer for all T10 responses:
"Vulnerability data sourced from Google OSV.dev
and NIST NVD. DataNexus does not warrant
completeness. Verify with your security team
before making decisions."

── Step C: Register T10 in main.py ──────────────────

Import all 5 T10 data + 2 infra.
Total tools in main.py now: T04 (5) + T10 (7) = 12.
Confirm with: python3 -m datanexus.main --help

── Step D: T10 Smoke Tests ──────────────────────────

Test 1 — Known vulnerability:
  fetch_package_vulnerabilities(
    "requests", "2.28.0", "PyPI")
  PASS if: CVE data returned, CVSS score present,
  sha256_hash non-empty, cache_hit==False first call

Test 2 — Cache hit + TTL:
  Same call again
  PASS if: cache_hit==True
  redis-cli TTL datanexus:T10:pkg:PyPI:requests:all
  PASS if: TTL between 1 and 3600

Test 3 — CVE detail:
  fetch_cve_detail("CVE-2023-32681")
  PASS if: description present, CVSS score present,
  markdown_output non-empty

Test 4 — Safe package:
  fetch_package_vulnerabilities(
    "certifi", "2023.7.22", "PyPI")
  PASS if: response returned, no crash on zero vulns,
  ingest_healthy==True

Test 5 — Licence:
  fetch_package_licence("fastapi", "0.100.0", "PyPI")
  PASS if: licence identifier present (MIT or Apache)

Test 6 — Timeout error:
  Mock deps.dev to delay > 8000ms
  PASS if: returns structured error with
  error_code=='upstream_timeout', never hangs

Test 7 — Hard stop grep:
  grep -ri "exploit\|payload\|proof.of.concept\|
    PoC\|attack vector code" datanexus/tools/t10.py
  PASS if: zero matches

All 7 PASS required before Phase 4.

═══════════════════════════════════════════════════════
PHASE 4 — FEEDBACK SYSTEM (Section 8 + Section 9)
═══════════════════════════════════════════════════════

Build the feedback system exactly as Section 8
specifies. Build order from Section 11.6 / Table 148.
Do not skip steps. Do not reorder.

Each step must pass its gate before the next begins.

Step 1: feedback/__init__.py + 4 sub-package inits
  Gate: python3 -c "import feedback" — no error

Step 2: feedback/config.py
  FEEDBACK_AGENTS_ACTIVE defaults false.
  ALL Redis key_*() functions defined here.
  No Redis key strings anywhere else.
  FEEDBACK_ENABLED_TOOLS = {'T04', 'T10'}
    — T22 excluded (privacy — personal identifiers)
  IMPLICIT_ONLY_TOOLS = {'T12','T13','T22'}
  BUG_SIGNALS = {'tool_down','schema_error',
    'returns_empty_unexpectedly','ingest_stale'}
  IMPROVEMENT_SIGNALS = {'missing_field',
    'not_useful','too_slow','wrong_result',
    'unclear_response'}
  Gate: python3 -c "from feedback.config import
    FEEDBACK_AGENTS_ACTIVE; print(
    FEEDBACK_AGENTS_ACTIVE)" → False

Step 3: feedback/models.py
  FeedbackInput, FeedbackRecord,
  AuditRecord, DigestItem
  Gate:
    FeedbackInput(tool_id='T99',...) → ValidationError
    FeedbackInput(signal='missing_field',
      missing_fields=None,...) → ValidationError

Step 4: feedback/audit.py
  Exports make_params_hash, write_audit,
  AuditContext, standard_response_fields
  Gate:
    make_params_hash({'b':2,'a':1}) ==
    make_params_hash({'a':1,'b':2}) → True
    standard_response_fields('h','ts',True)
      returns dict with exactly 4 keys → True

Step 5: feedback/pre_classifier.py
  Deterministic. Zero Claude API calls.
  Gate:
    classify_missing_field('T04','ein') ==
      'already_implemented'
    classify_missing_field('T04','xyz_unknown_99')
      == 'needs_human_review'

Steps 6-14: Build remaining feedback files per
Section 9.4 full build order.
Key requirements:
  - report_feedback() ALWAYS returns
    {'status':'recorded'} — even on reject/throttle
  - bug_listener.py NEVER checks
    FEEDBACK_AGENTS_ACTIVE
  - master.py EXITS IMMEDIATELY if
    FEEDBACK_AGENTS_ACTIVE=false
  - tool_worker.py loads ONLY its own TOOL_SPEC.md
    — never another tool's spec

Step 15: Replace T04 + T10 infra stubs
  Replace stub report_feedback with real:
    from feedback.collector import report_feedback
    mcp.tool()(report_feedback)

Full acceptance criteria (Table 110 / Section 9.6):
  □ FEEDBACK_AGENTS_ACTIVE=false: master exits <1s
  □ 100 identical report_feedback() calls
    → 1 entry + vote_count=100
  □ BUG_SIGNAL → fb:alerts:immediate, not fb:queue
  □ Every T04 + T10 response has query_hash,
    schema_version, data_as_of, ingest_healthy
  □ privacy_hash('1.2.3.4') on day D !=
    privacy_hash('1.2.3.4') on day D+1
  □ pytest feedback/tests/ -v — all pass

═══════════════════════════════════════════════════════
PHASE 5 — PAYMENT INFRASTRUCTURE (Section 10)
═══════════════════════════════════════════════════════

Build after feedback Steps 1-5 complete.
payment/entitlement.py imports from feedback.audit.

Build order from Section 11.7 / Table 149:

Step 1: payment/__init__.py
  Gate: python3 -c "import payment" — no error

Step 2: payment/config.py
  MCPIZE_ACTIVE defaults false
  MCPIZE_URLS dict — key per tool ID, all empty str
  Gate: python3 -c "from payment.config import
    MCPIZE_ACTIVE; print(MCPIZE_ACTIVE)" → False

Step 3: payment/entitlement.py
  Full @verify_entitlement implementation
  (replaces core/entitlement.py stub)
  6 check conditions per Table 116:
    free window, no URL, valid entitlement,
    grace, no entitlement, Redis error (fail open)
  Gate: all 3 gate conditions in Table 149 Step 3

Step 4: payment/webhook.py
  POST /webhooks/mcpize
  Verify MCPize signature on EVERY request (Table 126)
  Handles: payment.confirmed, subscription.renewed,
    subscription.lapsed, subscription.cancelled
  Gate: wrong signature → 401, zero Redis writes
    payment.confirmed → Redis key written

Step 5: payment/tools.py
  report_mcpize_link() MCP tool
  Gate: all 3 scenarios in Table 149 Step 5

Step 6: payment/tests/test_payment.py
  All 10 acceptance criteria (Table 133)
  Gate: pytest payment/tests/ -v — all pass

Replace T04 + T10 infra stubs with real:
  from payment.tools import report_mcpize_link
  mcp.tool()(report_mcpize_link)

Update datanexus/tools/t04.py and t10.py to import
@verify_entitlement from payment.entitlement instead
of datanexus.core.entitlement.

═══════════════════════════════════════════════════════
PHASE 6 — DASHBOARD (Section 12.8)
═══════════════════════════════════════════════════════

Dashboard covers TWO areas per Section 12.8:
1. Feedback intelligence (Section 8.8)
2. Usage and adoption (new in v7.3)

Build feedback/dashboard/server.py to include
both panels as specified in Tables 171-172:

Usage panels (new in v7.3):
  - Agent status banner (FEEDBACK_AGENTS_ACTIVE +
    MCPIZE_ACTIVE state)
  - Usage summary row (total calls, unique callers,
    DAU 7-day trend, peak hour)
  - Per-tool adoption table (DAU today, DAU 7d avg,
    DAU trend, error rate, cache hit ratio, p99)
  - Conversion funnel (only when MCPIZE_ACTIVE=true)
  - Top query patterns (privacy-safe aggregate only)

Implement get_usage_summary() per Table 172.
Implement get_conversion_stats() per Table 172.

Dashboard ships at Gate 1 (first paying subscriber).
Before Gate 1: endpoint exists, shows free window
banner, minimal data. This is correct behaviour.

Serve dashboard at: http://localhost:8101

Gate: GET http://localhost:8101 → 200 HTML
  Contains agent status banner.
  GET http://localhost:8101/api/summary → JSON
  with 'summary' and 'tools' keys.

═══════════════════════════════════════════════════════
PHASE 7 — CLAUDE DESKTOP INTEGRATION
═══════════════════════════════════════════════════════

File: ~/Library/Application Support/Claude/
      claude_desktop_config.json

Content:
{
  "mcpServers": {
    "datanexus": {
      "command": "python",
      "args": ["-m", "datanexus.main"],
      "cwd": "/Users/sangeetajagadeesh/OmSaiRam",
      "env": {
        "DATANEXUS_REDIS_URL": "redis://localhost:6379",
        "DATANEXUS_DB_URL":
          "postgresql://dn:password@localhost:5432/datanexus",
        "DATANEXUS_ENV": "local",
        "MCPIZE_ACTIVE": "false",
        "FEEDBACK_AGENTS_ACTIVE": "false"
      }
    }
  }
}

Update start-local.sh:
  1. Start Redis if not running
  2. Start PostgreSQL if not running
  3. Confirm both healthy
  4. Start IRSBMFWorker as background process
  5. Start IRSTEOSWorker as background process
  6. Start UKCharityWorker as background process
  7. Start OSVPopularPackagesWorker as background
  8. Start bug_listener as background process
  9. uvicorn datanexus.main:app on port 8000
  10. Serve dashboard on port 8101
  11. Print:
      "DataNexus MCP — T04 + T10 live"
      "Tools: 12 registered (5 T04 + 7 T10)"
      "Dashboard: http://localhost:8101"
      "Test T04: fetch_nonprofit_by_ein '13-1837418'"
      "Test T10: fetch_package_vulnerabilities
               'requests' '2.28.0' 'PyPI'"

═══════════════════════════════════════════════════════
PHASE 8 — REGISTRY UPDATE
═══════════════════════════════════════════════════════

npm, Glama, Smithery already published.
Update only — do not republish from scratch.

1. Bump package.json version (1.x.x → next patch)
   npm publish @datanexus/mcp-server

2. Update glama.json:
   - Add T10 entries if missing
   - Update T04 entries:
     Remove ProPublica references
     Add IRS EO BMF and IRS TEOS as sources
     Add UK GDPR purpose limitation statement
   - Verify all T04 and T10 descriptions contain:
     "AI-Ready Markdown", "Verified source",
     "token-efficient"
   - Target Glama quality score ≥8.5/10

3. Update .well-known/mcp-manifest.json
   with current T04 (v7.3 signatures) and T10

═══════════════════════════════════════════════════════
PHASE 9 — FINAL VERIFICATION CHECKLIST
═══════════════════════════════════════════════════════

Report each as PASS or FAIL with detail.
Stop on any FAIL. Fix before marking complete.

Infrastructure:
□ All core imports pass in one python3 -c call
□ make_params_hash is deterministic (key order safe)
□ Redis INCR counters increment on every tool call
□ Circuit breaker: 3 failures → tripped, probe → reset

T04:
□ fetch_nonprofit_by_ein("13-1837418") returns
  in Claude Desktop — no ProPublica in response
□ cache_hit==True on second identical call
□ UK charity TTL <= 86400 in Redis
□ Canary validator raises ValueError on injection

T10:
□ fetch_package_vulnerabilities("requests",
  "2.28.0", "PyPI") returns CVE data
□ cache_hit==True on second call, TTL ~3600
□ fetch_dependency_graph returns timeout error
  if > 8000ms (not a hang)
□ Hard stop grep: zero matches for exploit/PoC/etc

Feedback:
□ pytest feedback/tests/ -v — ALL PASS
□ report_feedback() returns {'status':'recorded'}
  regardless of input
□ FEEDBACK_AGENTS_ACTIVE=false: master exits <1s
□ 100 identical calls → 1 queue entry, vote_count=100

Payment:
□ pytest payment/tests/ -v — ALL PASS
□ MCPIZE_ACTIVE=false: @verify_entitlement passthrough
□ Webhook: wrong signature → 401, no Redis write

Dashboard:
□ GET localhost:8101 → 200, agent status banner shown
□ GET localhost:8101/api/summary → JSON with
  'summary' and 'tools' keys

Registry:
□ npm install: npx -y @datanexus/mcp-server works
□ glama.json has no ProPublica reference in T04
□ T04 Glama description has UK GDPR statement

All 22 boxes green = Sprint 1 complete.
Report completion. Stop.
Do not begin T22 or any other tool.
Wait for my explicit go-ahead for Sprint 2.

═══════════════════════════════════════════════════════
HARD BOUNDARY
═══════════════════════════════════════════════════════

Only T04 and T10 are APPROVED this week.
(Section 12.5, Table 166)

If any agent or pipeline step attempts to build
T22, T01, T07, or any other tool, stop immediately
and flag me. Do not build AWAITING REVIEW tools
under any circumstances.

Section 12 supersedes all earlier sections where
conflicts exist. If you find a contradiction between
Section 12 and Sections 1-11, Section 12 wins.
