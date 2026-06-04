# DataNexus MCP — Sprint 7 Implementation Prompt
# Focus: Aggregator-First Licence + CVE Intelligence + Nonprofit Trends
# 5 new tools in 3 groups + 5 pre-work files
# Design doc: SPRINT7_DESIGN.md (ENG REVIEWED — 7 findings, all resolved)
# Engineering review: /plan-eng-review 2026-05-29 — D1-D7
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Last updated: 2026-05-29

═══════════════════════════════════════════════════════
RULE ZERO — READ BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these files completely before writing
a single line of code:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
2. /Users/sangeetajagadeesh/OmSaiRam/SPRINT7_DESIGN.md
   Authoritative Sprint 7 spec with all eng-review fixes.
3. /Users/sangeetajagadeesh/OmSaiRam/datanexus/tools/_security_utils.py
   Sprint 6 utility functions you will call directly.
4. /Users/sangeetajagadeesh/OmSaiRam/datanexus/tools/nonprofit_sprint6.py
   Sprint 6 nonprofit code you will refactor in PRE-3.

Confirm pre-read by answering ALL FOUR:

a) In the fetch_cve_risk_summary verdict table, which
   verdict fires FIRST: UNKNOWN or LOW? And why?

b) audit_licence_compatibility uses asyncio.Semaphore.
   What is the limit and why (what does it prevent)?

c) _circuit_breakers.py does not exist yet. Where must
   ALL existing Sprint 6 breaker instances be moved to,
   and which Sprint 7 pre-work step creates the file?

d) After Sprint 7 ships, how many tools total are in
   main.py? Current: 41 (35 Sprint 4 + 6 Sprint 6).
   Sprint 7 adds 5.

Do not write any code until I confirm all four.
Type READY only after my confirmation.

═══════════════════════════════════════════════════════
CURRENT STATE
═══════════════════════════════════════════════════════

Live at https://datanexusmcp.com/mcp (41 tools after Sprint 6):
  nonprofit_sprint6 (2): fetch_nonprofit_full_profile,
                         (fetch_nonprofit_by_ein etc still in nonprofit.py)
  security_sprint6  (3): fetch_package_risk_brief,
                         fetch_package_maintainer_history,
                         detect_typosquatting
  security_stateful (2): fetch_cve_watch,
                         audit_sbom_continuous
  + 34 Sprint 1-4 tools (see datanexus/main.py header)

Utility files from Sprint 6 (THESE EXIST — read them):
  datanexus/tools/_security_utils.py
    _fetch_vulns(package, ecosystem, version) -> dict
    _fetch_licence(package, ecosystem) -> dict       ← audit_licence_compatibility uses this
    _fetch_depsdev(package, ecosystem, version) -> dict
    _resolve_version(package, ecosystem) -> str|None
  datanexus/tools/_maintainer_utils.py
    _fetch_maintainer_history(package, ecosystem) -> dict

Files that DO NOT EXIST yet (pre-work creates them):
  datanexus/tools/_circuit_breakers.py   ← PRE-0 (new — eng review D4)
  datanexus/tools/_cve_utils.py          ← PRE-1
  datanexus/tools/_licence_compat.py     ← PRE-2
  datanexus/tools/_nonprofit_utils.py    ← PRE-3
  (also requires: ProPublica API response verified in PRE-4)

═══════════════════════════════════════════════════════
PRE-WORK — ALL FIVE ITEMS BEFORE ANY SPRINT 7 TOOL
═══════════════════════════════════════════════════════

Complete in ORDER. Each item must have passing tests
before the next item starts.

PRE-0: Create datanexus/tools/_circuit_breakers.py
  (Engineering review D4 — circuit breakers MUST be singletons)
  All pybreaker instances in ONE file. Sprint 6 AND Sprint 7
  tool files ALL import from here. Two separate instances on
  the same upstream = no shared failure state = circuit never
  opens during an outage.

  ```python
  # datanexus/tools/_circuit_breakers.py
  import pybreaker
  _propublica_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _nvd_breaker        = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _cisa_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _epss_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _spdx_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _pypi_stats_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _npm_stats_breaker  = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  _depsdev_breaker    = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
  ```

  Update ALL Sprint 6 files that currently define their own
  pybreaker instances to import from _circuit_breakers.py:
    security_sprint6.py, security_stateful.py, nonprofit_sprint6.py,
    _security_utils.py (if it defines any), _maintainer_utils.py (if any)

  Verification: `python -c "from datanexus.tools._circuit_breakers import _propublica_breaker; print('ok')"`

PRE-1: Extract datanexus/tools/_cve_utils.py
  Read the Sprint 4 security handlers (security.py or wherever
  fetch_cve_detail, fetch_cisa_kev, fetch_cve_epss live).
  Extract the core HTTP logic into:
    async def _fetch_cve_detail_util(cve_id: str) -> dict
    async def _fetch_cisa_kev_util(cve_id: str) -> dict
    async def _fetch_cve_epss_util(cve_id: str) -> dict
  These import from _circuit_breakers.py (not define new ones).
  Sprint 4 handlers remain unchanged — they call these utilities.

  Unit tests (mock HTTP):
    test_cve_detail_util_returns_cvss_score
    test_cisa_kev_util_returns_bool_field
    test_cve_epss_util_returns_float_0_to_1
  All 3 must pass before fetch_cve_risk_summary is written.

PRE-2: Build datanexus/tools/_licence_compat.py
  Hand-coded Python dict. Symmetric lookup required:
    get_compatibility(A, B) == get_compatibility(B, A)

  CONFLICT pairs (must cover these at minimum):
    ("GPL-2.0-only", "Apache-2.0")      # ASF position 2007
    ("GPL-3.0-only", "Apache-2.0")      # ASF position 2007
    ("AGPL-3.0-or-later", "MIT")        # in proprietary SaaS context
    ("AGPL-3.0-or-later", "Apache-2.0")
    ("GPL-2.0-only", "GPL-3.0-only")    # version incompatibility
    ("EUPL-1.1", "GPL-3.0-only")

  COMPATIBLE pairs (must cover these at minimum):
    ("MIT", "Apache-2.0"), ("MIT", "BSD-2-Clause"), ("MIT", "BSD-3-Clause"),
    ("MIT", "ISC"), ("MIT", "MIT"), ("Apache-2.0", "BSD-2-Clause"),
    ("Apache-2.0", "BSD-3-Clause"), ("LGPL-2.1-or-later", "GPL-2.0-or-later")

  UNKNOWN: everything else → "UNKNOWN"

  Unit tests:
    test_gpl3_apache_is_conflict
    test_mit_apache_is_compatible
    test_unknown_pair_returns_unknown
    test_symmetric_lookup (get_compatibility(A,B) == get_compatibility(B,A))

PRE-3: Build datanexus/tools/_nonprofit_utils.py AND update Sprint 6
  (Engineering review D5 — single source of truth, no duplicate formula)

  Step 3a: Extract calculate_health_score() from nonprofit_sprint6.py
  to _nonprofit_utils.py:
    def calculate_health_score(totrevenue: float, totfuncexpns: float,
                               totprgmrevnue: float, netassetsend: float) -> float | None
  Formula (from Sprint 6 spec):
    programme_ratio × 40 + (1 - expense_ratio) × 30
    + revenue_growth_score × 20 + reserve_months_score × 10
    reserve_months = netassetsend / (totfuncexpns / 12)
    reserve_months_score = min(reserve_months / 6, 1.0)
    Returns None if totrevenue == 0

  Step 3b: Update nonprofit_sprint6.py::fetch_nonprofit_full_profile to
  import calculate_health_score from _nonprofit_utils.py.
  It must NOT define or use its own inline formula.

  Unit tests:
    test_health_score_formula_correct (verify the weights sum to 100)
    test_health_score_zero_revenue_returns_none
    test_sprint6_refactor_still_works (call fetch_nonprofit_full_profile
      with mock data; assert health_score unchanged after refactor)

PRE-4: Verify OQ1 — ProPublica multi-year API response shape
  Run:
    curl "https://projects.propublica.org/nonprofits/api/v2/organizations/131837418/filings.json"
  Read the JSON. Answer: does it return year-by-year totals directly, or
  raw IRS 990 JSON that needs field extraction?

  If raw 990 JSON → add to _nonprofit_utils.py:
    async def _parse_990_annual_fields(filing: dict) -> dict
    Returns: {year, total_revenue, total_expenses, totprgmrevnue, netassetsend}

  If pre-computed fields → no extra function needed.
  Document the answer in a comment at the top of _nonprofit_utils.py.

═══════════════════════════════════════════════════════
BUILD ORDER — STRICT
═══════════════════════════════════════════════════════

  0. PRE-0 through PRE-4 (above) — all before any tool
  1. fetch_licence_analysis (needs PRE-2; _spdx_breaker from _circuit_breakers.py)
  2. audit_licence_compatibility (needs PRE-2, _fetch_licence from _security_utils.py)
  3. fetch_cve_risk_summary (needs PRE-1; _nvd_breaker, _cisa_breaker, _epss_breaker)
  4. search_nonprofits_by_category (needs PRE-3; June 4 gate — see below)
  5. fetch_nonprofit_financial_trends (needs PRE-3, PRE-4; June 4 gate)

  ⚠️ JUNE 4 GATE: Do NOT start tools 4-5 until you (the human) confirm the
  June 4 README reorder data. If nonprofit < 10 calls/week: skip both
  nonprofit tools. If >= 20: ship both. Decision is the human's.

Each tool must pass ALL smoke tests before the next tool starts.

═══════════════════════════════════════════════════════
SHARED REQUIREMENTS — ALL SPRINT 7 TOOLS
═══════════════════════════════════════════════════════

All Sprint 6 shared requirements still apply (asyncio.gather,
glama.json in same commit as mount, canary+smoke before registration,
no HTTP self-calls, etc.). Sprint 7 additions:

1. Import circuit breakers from _circuit_breakers.py:
   from datanexus.tools._circuit_breakers import (
       _propublica_breaker, _nvd_breaker, _cisa_breaker,
       _epss_breaker, _spdx_breaker
   )
   Never define a new pybreaker.CircuitBreaker() in a Sprint 7 tool file.

2. upstream_status shape — all tools must include this field:
   {"source_name": "OK" | "ERROR" | "CIRCUIT_OPEN" | "N/A"}
   "N/A" = no HTTP call made (static bundle hit).

3. Degraded null vs false — strictly enforced:
   kev_listed: null  (not false) when CISA unreachable
   epss_score: null  (not 0.0) when EPSS unreachable
   patch_available: null (not false) when no allowlist URL match
   null = "could not determine" / false = "checked, confirmed no"

4. Glama.json updated in SAME commit as main.py mount registration.

═══════════════════════════════════════════════════════
TOOL SPECS — GROUP 1: LICENCE INTELLIGENCE
═══════════════════════════════════════════════════════

── fetch_licence_analysis ────────────────────────────

Input: spdx_id (str) — e.g., "MIT", "GPL-3.0-only", "AGPL-3.0-or-later"

Source resolution (STATIC-FIRST — mandatory):
  1. Check _licence_compat.py static bundle. If spdx_id found →
     return immediately with upstream_status.spdx_api = "N/A"
  2. Not in bundle → call spdx.org/licenses/{id}.json
     upstream_status.spdx_api = "OK" | "ERROR" | "CIRCUIT_OPEN"
     Circuit breaker: _spdx_breaker from _circuit_breakers.py

Unknown SPDX ID (not in bundle AND API 404 or CIRCUIT_OPEN):
  Return DEGRADED response (NOT an error):
    risk_level="UNKNOWN", plain_english=null, obligations=[],
    permissions=[], limitations=[], osi_approved=null, fsf_libre=null,
    tldr="Licence identifier not recognized. Verify at spdx.org/licenses."

⚠️ CONTEXT ASSUMPTION (engineering review D3):
  ALL risk_level values assume proprietary/commercial use.
  This is the most conservative interpretation.
  For context-dependent licences (AGPL-3.0):
    plain_english MUST include: "INCOMPATIBLE for proprietary SaaS.
    Compatible with open source projects — see SPDX for details."
    tldr MUST include: "INCOMPATIBLE for proprietary/commercial use."

risk_level boundaries:
  PERMISSIVE:      MIT, Apache-2.0, BSD-*, ISC — attribution only
  COPYLEFT:        LGPL-*, MPL-2.0 — share-alike for modified files
  STRONG_COPYLEFT: GPL-* — share-alike for ALL derivative works
  INCOMPATIBLE:    AGPL-3.0 (proprietary SaaS), GPL-2.0-only in Apache project
  UNKNOWN:         ID not recognized

Returns:
  plain_english, risk_level, obligations, permissions, limitations,
  osi_approved, fsf_libre, tldr, upstream_status

Canary: canary_spdx_api() — GET spdx.org/licenses/MIT.json, expect 200

Smoke (all must pass before registration):
  smoke_fetch_licence_analysis_mit()
    → risk_level="PERMISSIVE", upstream_status.spdx_api="N/A"
  smoke_fetch_licence_analysis_gpl3()
    → risk_level="STRONG_COPYLEFT"
  smoke_fetch_licence_analysis_agpl()
    → risk_level="INCOMPATIBLE", plain_english contains "proprietary"
  smoke_fetch_licence_analysis_unknown()
    → risk_level="UNKNOWN", plain_english=null

── audit_licence_compatibility ───────────────────────

Input (mutually exclusive — mixed → INVALID_PARAMS):
  packages: list[{package_name: str, ecosystem: str}]  OR
  spdx_ids: list[str]
  Max 50 items either path. Empty list → INVALID_PARAMS.

Package-name path (with concurrency limit — eng review D7):
  ```python
  sem = asyncio.Semaphore(10)  # prevents 429 from PyPI/npm at 50 items

  async def _resolve_one(p):
      async with sem:
          return await _fetch_licence(p["package_name"], p["ecosystem"])

  spdx_ids_resolved = await asyncio.gather(
      *[_resolve_one(p) for p in packages],
      return_exceptions=True,
  )
  ```
  Import _fetch_licence from datanexus.tools._security_utils
  Partial failure: continue with resolved subset; list failures in
  upstream_status.failed_packages. Do NOT error the whole call.

SPDX-ID path:
  Look up each ID in _licence_compat.py ONLY. NO network calls.
  upstream_status.spdx_api = "N/A"

Compatibility from _licence_compat.py:
  CONFLICT | COMPATIBLE | UNKNOWN

recommended_action (first match):
  CONFLICT → "Remove or replace {pkg} ({licence}), or obtain commercial licence."
  COMPATIBLE + COPYLEFT present → "Compatible. {pkg} uses {licence} — comply with share-alike."
  COMPATIBLE + all PERMISSIVE → "All compatible. Attribution only."
  UNKNOWN → "Compatibility undetermined for {a} + {b}. Consult legal."

Returns:
  compatibility, conflicts, combined_obligations, recommended_action,
  upstream_status: {spdx_api: "N/A"|"OK"|"ERROR"|"CIRCUIT_OPEN",
                    failed_packages: list[str]}

Smoke:
  smoke_audit_licence_compat_packages_compatible() → COMPATIBLE
  smoke_audit_licence_compat_conflict() — spdx_ids=["GPL-3.0-only","Apache-2.0"] → CONFLICT
  smoke_audit_licence_compat_no_http() — spdx_ids path → upstream_status.spdx_api="N/A"
  smoke_audit_licence_compat_max_limit() — 51 packages → INVALID_PARAMS
  smoke_audit_licence_compat_mixed_input() → INVALID_PARAMS

═══════════════════════════════════════════════════════
TOOL SPECS — GROUP 2: CVE AGGREGATOR
═══════════════════════════════════════════════════════

── fetch_cve_risk_summary ────────────────────────────

Input: cve_id (str)
Validation: must match ^CVE-\d{4}-\d{4,}$ → INVALID_PARAMS on mismatch.

Internal parallel calls (from _cve_utils.py):
  cve_detail, kev_status, epss = await asyncio.gather(
      _fetch_cve_detail_util(cve_id),
      _fetch_cisa_kev_util(cve_id),
      _fetch_cve_epss_util(cve_id),
      return_exceptions=True,
  )

Degraded values when upstream unavailable:
  kev_listed: null (NOT false)
  epss_score: null (NOT 0.0)
  cvss_score: null
  patch_available: null

⚠️ VERDICT TABLE (eng review D2 fix — EVALUATE IN ORDER, FIRST MATCH WINS):
  1. UNKNOWN: kev_listed IS null AND epss_score IS null AND cvss_score IS null
     (all upstreams down — UNKNOWN, not LOW; LOW means "checked, low risk")
  2. CRITICAL_EXPLOIT: kev_listed == true OR epss_score >= 0.7
  3. HIGH_RISK: cvss_score >= 9.0 OR (epss_score >= 0.3 AND cvss_score >= 7.0)
  4. MODERATE: cvss_score >= 4.0
  5. LOW: otherwise (at least one input non-null, no higher threshold met)

patch_available derivation:
  Parse NVD references for URLs matching ALLOWLIST → patch_available=true
  No match → patch_available=null (NOT false)
  nvd.nist.gov is NOT in allowlist (informational, not patch confirmation)
  Allowlist:
    github.com/advisories, github.com/*/security
    access.redhat.com, security.debian.org, ubuntu.com/security
    lists.apache.org, msrc.microsoft.com, portal.msrc.microsoft.com
    support.microsoft.com/*/security, oracle.com/security-alerts
    cisco.com/security/advisories, kb.cert.org
    tools.cisco.com/security/center

Returns:
  verdict, epss_score, kev_listed, cvss_score, patch_available,
  affected_ecosystems, tldr, upstream_status

Smoke:
  ⚠️ T03-S01 IS A P0 BLOCKER — do NOT register until this passes:
  smoke_cve_risk_summary_all_null_returns_unknown()
    Mock NVD + CISA + EPSS all raise CircuitBreakerError.
    Assert: verdict == "UNKNOWN"  (NOT "LOW")
    This test proves D2 fix is correctly implemented.

  smoke_cve_risk_summary_critical_exploit_kev()
    Mock kev_listed=true → verdict="CRITICAL_EXPLOIT"
  smoke_cve_risk_summary_high_risk_cvss()
    Mock cvss_score=9.5, kev=false, epss=0.1 → verdict="HIGH_RISK"
  smoke_cve_risk_summary_invalid_id()
    cve_id="not-a-cve" → INVALID_PARAMS
  smoke_cve_risk_summary_partial_upstream_down()
    Mock NVD down, CISA+EPSS OK → verdict returned (not error)
    upstream_status.nvd="CIRCUIT_OPEN"
  smoke_cve_risk_summary_patch_available()
    Mock NVD refs include github.com/advisories URL → patch_available=true
  smoke_cve_risk_summary_no_allowlist_match()
    Mock NVD refs include only nvd.nist.gov → patch_available=null

═══════════════════════════════════════════════════════
TOOL SPECS — GROUP 3: NONPROFIT DEPTH
═══════════════════════════════════════════════════════

⚠️ JUNE 4 GATE: Do NOT build tools 4 or 5 until the human
confirms June 4 README reorder data.
  If nonprofit >= 20 calls/week: build both.
  If < 10: skip both, Sprint 7 is security-only.

── search_nonprofits_by_category ─────────────────────

Input: category (str), state (str, optional, 2-letter)

Category → NTEE code:
  education→B, healthcare→E, arts→A, environment→C, human_services→P,
  civil_rights→R, international→Q, religion→X, science→U, sports→N
  Raw single letter A-Z: accepted directly (bypass name lookup)
  Unrecognized → INVALID_PARAMS listing valid names. DO NOT fuzzy-match.

Source: ProPublica /api/v2/nonprofits?state={state}&ntee={ntee}
  Max 25 results per call. Include result_count + truncated fields.

health_score per result:
  Call calculate_health_score() from _nonprofit_utils.py (NOT inline).
  Missing fields for a specific org → health_score=null for that item.

Circuit breaker: _propublica_breaker from _circuit_breakers.py

Smoke:
  smoke_search_nonprofits_education_ca() → list non-empty
  smoke_search_nonprofits_raw_ntee_code() — category="B" → same result
  smoke_search_nonprofits_invalid_category() → INVALID_PARAMS
  smoke_search_nonprofits_empty_category() → INVALID_PARAMS
  smoke_search_nonprofits_truncated() — mock 30 results → 25 returned + truncated=true

── fetch_nonprofit_financial_trends ──────────────────

⚠️ Also requires OQ1 resolved (PRE-4 must be complete).

Input: ein (str), years (int, optional, default 5, max 10)

Source: ProPublica /api/v2/organizations/{ein}/filings.json
  Take `years` most recent filings. CAGR uses first and last of selected.

Minimum data guard (INSUFFICIENT_DATA — check FIRST):
  If fewer than 2 filings: return
    trend_direction="INSUFFICIENT_DATA", cagr=null,
    all trend lists=[], message="Fewer than 2 Form 990 filings available."
  DO NOT attempt CAGR with < 2 data points.

Per-year calculations:
  reserve_months = net_assets / (total_expenses / 12)
    If total_expenses == 0: reserve_months = null (not divide-by-zero)
  programme_ratio = totprgmrevnue / totrevenue
    If totrevenue == 0: programme_ratio = null
  health_score: call calculate_health_score() from _nonprofit_utils.py

trend_direction (EVALUATE IN ORDER — first match wins):
  1. INSUFFICIENT_DATA: < 2 selected filings
  2. VOLATILE: any two CONSECUTIVE filings with opposite-sign change_pct
     AND both absolute values exceed 20%
  3. GROWING: CAGR > 5%
  4. STABLE: -5% ≤ CAGR ≤ 5%
  5. DECLINING: CAGR < -5%

CAGR formula: ((revenue_latest / revenue_earliest) ^ (1/n_years)) - 1
  n_years = latest_year - earliest_year of selected filings
  revenue_earliest == 0 → cagr = null

Circuit breaker: _propublica_breaker from _circuit_breakers.py

Smoke:
  smoke_nonprofit_trends_insufficient_data()
    EIN with 1 filing → trend_direction="INSUFFICIENT_DATA", cagr=null
  smoke_nonprofit_trends_growing()
    Mock CAGR=8% → trend_direction="GROWING"
  smoke_nonprofit_trends_zero_expenses()
    Mock totfuncexpns=0 → reserve_months=null (no crash)
  smoke_nonprofit_trends_real_ein()
    ein="13-1837418" (Red Cross) → revenue_trend non-empty

═══════════════════════════════════════════════════════
TEST REQUIREMENTS
═══════════════════════════════════════════════════════

Full test plan: sangeetajagadeesh-unknown-eng-review-test-plan-Sprint7-20260529.md
(in ~/.gstack/projects/OmNamahaShivaya/)

canary.py BEFORE any Sprint 7 tool registers:
  canary_spdx_api() — GET spdx.org/licenses/MIT.json, expect 200

⚠️ P0 BLOCKER before fetch_cve_risk_summary registers:
  T03-S01: all-null upstreams → verdict="UNKNOWN" (NOT "LOW")
  This is the D2 regression test. No registration until it passes.

Non-negotiable: canary.py + smoke.py must pass locally
before ANY Sprint 7 tool registers in main.py.

═══════════════════════════════════════════════════════
HARD STOPS — DO NOT BUILD
═══════════════════════════════════════════════════════

1. Never define a new pybreaker.CircuitBreaker() inside a
   Sprint 7 tool file. All imports come from _circuit_breakers.py.

2. Never use false as the degraded value for kev_listed,
   epss_score, or patch_available. null means "could not check."

3. Never use nvd.nist.gov as a patch_available confirmation URL.
   It is informational, not a patch source.

4. Never fire >10 concurrent _fetch_licence() HTTP calls in
   audit_licence_compatibility. Use Semaphore(10).

5. Never skip the June 4 gate for nonprofit tools 4-5.
   Decision requires the human to read the data.

6. Never register any Sprint 7 tool in main.py without
   updating glama.json in the same commit.

7. Never start tool implementation before the required
   pre-work for that tool passes unit tests.

═══════════════════════════════════════════════════════
SUCCESS CRITERIA — SPRINT 7
═══════════════════════════════════════════════════════

1. Licence follow-through: 1+ call to fetch_licence_analysis
   or audit_licence_compatibility within 7 days of shipping.

2. CVE aggregator: fetch_cve_risk_summary called 5+ times
   in first 14 days.

3. Nonprofit discovery (if shipped): search_nonprofits_by_category
   called 3+ times in first 14 days.

4. No regression: existing tool call counts unchanged.

5. Return rate holds: 2+ out of next 5 visitors return.

6. 46 total tools in main.py (41 + 5).
   glama.json updated in same commit as each mount.

═══════════════════════════════════════════════════════
ENGINEERING REVIEW DECISIONS (D1-D7)
Reference: plan-eng-review 2026-05-29
═══════════════════════════════════════════════════════

D1 Utility names: actual names are _fetch_licence(), _fetch_vulns()
   in _security_utils.py (not _fetch_licence_util etc). No _licence.py.

D2 Verdict table: UNKNOWN fires FIRST (step 1) before LOW (step 5).
   REGRESSION TEST T03-S01 is P0 — no ship until it passes.

D3 INCOMPATIBLE context: all risk_levels assume proprietary use.
   AGPL plain_english + tldr must note open source compatibility.

D4 Circuit breakers: create _circuit_breakers.py (PRE-0) and import
   from there everywhere. Never define new instances per-file.

D5 Health score: PRE-3 must also update Sprint 6 nonprofit_sprint6.py
   to import calculate_health_score from _nonprofit_utils.py.

D6 Tests: P0 regression test T03-S01. Full test plan in gstack dir.

D7 Concurrency: asyncio.Semaphore(10) in audit_licence_compatibility
   package-name path. Prevents 429 at 50-item inputs.

═══════════════════════════════════════════════════════
VISA / PAYMENT CONSTRAINT
═══════════════════════════════════════════════════════

MCPIZE_ACTIVE=false through ~July-August 2026.
All Sprint 7 tools are free. No payment gates.
