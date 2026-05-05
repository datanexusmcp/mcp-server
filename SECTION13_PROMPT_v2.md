# DataNexus MCP — Section 13 Implementation Prompt
# Haiku Validation Architecture
# Spec: DataNexus_MCP_Spec_v7_4.docx (AUTHORITATIVE — all 13 sections)
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Prerequisites: Sprint 1 complete, 84/84 tests green
# Tool description fixes complete (10 tools registered, Glama score ~9.0)
# Server live at https://datanexusmcp.com/mcp
# Last updated: May 2026

═══════════════════════════════════════════════════════
RULE ZERO — READ BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these two files completely before writing
a single line of code:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
   Every rule is absolute. No exceptions.

2. /Users/sangeetajagadeesh/OmSaiRam/
   DataNexus_MCP_Spec_v7_4.docx
   Read Section 13 in full.
   Sections 1-12 remain authoritative for all
   prior decisions. Section 13 adds new content
   only — it does not supersede Sections 1-12.

Confirm pre-read by answering ALL six before
touching any file:

a) Name the 4 Haiku triggers and the exact file
   that handles each one.

b) What is HAIKU_MAX_CALLS_PER_DAY, where is it
   defined, and what happens when it is reached?

c) Give the exact return shape of
   validate_tool_output() when issues are found.
   Include all top-level keys.

d) What specific production gap does
   feedback_classifier.py close?
   What was broken before and what does it fix?

e) What two things must happen in the SAME commit
   as the Section 13 code? (Section 13.12)

f) How many total tools will be registered in
   main.py after Section 13 is complete?
   Current state: 10 tools.
   Show your arithmetic.

Do not write any code until I confirm all six
answers. Type READY only after my confirmation.

═══════════════════════════════════════════════════════
CURRENT STATE — READ THIS BEFORE PHASE 0
═══════════════════════════════════════════════════════

Sprint 1 complete:
  - T04: 3 data tools
  - T10: 5 data tools
  - Shared: report_feedback + report_mcpize_link
  - Total: 10 tools registered in main.py
  - 84/84 tests green (61 feedback + 23 payment)
  - Live at https://datanexusmcp.com/mcp

Known production issues already fixed:
  - Tool description duplicates removed
  - Host allowlist removed (was blocking agents)

Known production issues NOT yet fixed:
  - T10 Bug 1: severity.level = UNKNOWN when
    CVSS vector is present
  - T10 Bug 2: PYSEC records not deduplicated
    against GHSA records sharing CVE alias
  Fix these in Phase 0 before Section 13 build.

Section 13 adds:
  - datanexus/core/validator.py (Layer 1)
  - datanexus/agents/haiku_classifier.py
  - datanexus/agents/anomaly_reviewer.py
  - datanexus/agents/feedback_classifier.py
  - datanexus/agents/schema_monitor.py
  - datanexus/agents/digest_generator.py
  - validate_tool_output() in main.py
  - Updates to bug_listener.py
  - Updates to feedback/dashboard/server.py
  - Updates to CLAUDE.md
  - Redeploy to Hetzner

═══════════════════════════════════════════════════════
PHASE 0 — FIX TWO KNOWN T10 PRODUCTION BUGS
═══════════════════════════════════════════════════════

Fix in datanexus/tools/t10.py response formatter.
Deterministic fixes — no Haiku needed.

Bug 1 — severity_level_from_vector:
  When building vulnerability list, if any record
  has severity.level == 'UNKNOWN' or missing AND
  cvss_vector field is present:
  Derive level from CVSS base score:
    0.0 = NONE, 0.1-3.9 = LOW, 4.0-6.9 = MEDIUM
    7.0-8.9 = HIGH, 9.0-10.0 = CRITICAL
  Mutate record in place. Log correction JSON.

Bug 2 — deduplicate_by_cve_alias:
  For each PYSEC record: check if any GHSA shares
  a CVE alias. If yes: remove PYSEC, keep GHSA.
  Log every suppression as structured JSON.

After fixing both:
  docker compose build --no-cache datanexus-mcp
  docker compose up -d datanexus-mcp

Gate — all 3 PASS before Phase 1:
  □ fetch_package_vulnerabilities("requests",
    "2.28.0", "PyPI") — no UNKNOWN severity
    when CVSS vector present
  □ No duplicate PYSEC/GHSA pairs for same CVE
  □ docker compose logs shows fix log lines

═══════════════════════════════════════════════════════
PHASE 1 — LAYER 1: DETERMINISTIC VALIDATOR
═══════════════════════════════════════════════════════

Build: datanexus/core/validator.py

Single function:
  validate_payload(tool_id: str, raw_data: dict)
    -> tuple[dict | None, list[str]]
  Returns (cleaned_data, issues_list)
  cleaned_data is None ONLY for Rule General-1.
  Never raises. Catches all exceptions.

Called from IngestBase.run_forever() AFTER fetch()
and BEFORE set_cached(). Update IngestBase now:
  raw_data = json.loads(raw_bytes)
  cleaned, issues = validate_payload(
    self.tool_id, raw_data)
  if cleaned is None:
    record_failure(self.source_id)
    continue  # do not cache
  if issues:
    log.info(json.dumps({"validation_issues":issues}))
  await set_cached(...)

T10 rules:
  T10-1: severity_level_from_vector
    Same logic as Phase 0 — ingest-time version.
    Append 'severity_derived' to issues.
  T10-2: deduplicate_by_cve_alias
    Same logic as Phase 0 — ingest-time version.
    Append 'pysec_deduplicated:{count}' to issues.
  T10-3: flag_incomplete_records
    If vuln has empty summary AND missing severity:
    Add incomplete=True. Do not suppress.
    Append 'incomplete_records:{count}' to issues.

T04 rules:
  T04-1: validate_ein_format
    EIN must match r'^\d{2}-\d{7}$'
    Add malformed_ein=True. Append 'malformed_ein'.
  T04-2: validate_financial_figures
    revenue and expenses must be int or float.
    Add unverified_financials=True if not.

General rules (all tools):
  General-1: non_empty_response
    If raw_data is None or empty:
    Return (None, ['upstream_empty'])
  General-2: required_fields_present
    T04 required: ['name']
    T10 required: ['package', 'ecosystem']
    Append 'missing_required:{field}' to issues.

Gate — all 4 PASS before Phase 2:
  □ validate_payload('T10', mock_UNKNOWN_vuln)
    returns tuple with derived severity and
    'severity_derived' in issues
  □ validate_payload('T04', {'revenue':'n/a',
    'name':'Test'}) → 'unverified_financials'
    in issues
  □ validate_payload('T10', {}) →
    (None, ['upstream_empty'])
  □ from datanexus.core.validator import
    validate_payload → imports cleanly

═══════════════════════════════════════════════════════
PHASE 2 — HAIKU CLASSIFIER
═══════════════════════════════════════════════════════

Build: datanexus/agents/haiku_classifier.py

  async def classify(
      context: str, data: dict, task: str
  ) -> dict:

Rules:
  Use HAIKU_MODEL from feedback/config.py always.
  Never hardcode model string. CLAUDE.md rule.
  Temperature: 0.1. Max tokens: 500.
  System prompt: "You are a data quality classifier
  for a public data API. Return JSON only.
  No prose. No markdown. Raw JSON object only."

  Daily cap — runs BEFORE every Haiku call:
    today_key = f"haiku:calls:{date.today()}"
    count = await redis.incr(today_key)
    await redis.expire(today_key, 86400)
    if count > HAIKU_MAX_CALLS_PER_DAY:
      return {'error':'daily_limit_reached',
              'haiku_available':False}

  Add to payment/config.py:
    HAIKU_MAX_CALLS_PER_DAY = 100

  On ANY API error: return
    {'error': str(e), 'haiku_available': False}
  Never raise. Never block.

Gate — all 3 PASS before Phase 3:
  □ classify('test',{},'test') → dict with no
    'error' key when API key is valid
  □ redis-cli SET haiku:calls:{today} 101 then
    classify() → {'error':'daily_limit_reached',
    'haiku_available':False}
    redis-cli DEL haiku:calls:{today}
  □ Invalid API key → returns error dict,
    no exception propagated

═══════════════════════════════════════════════════════
PHASE 3 — ANOMALY REVIEWER (TRIGGER 1)
═══════════════════════════════════════════════════════

Build: datanexus/agents/anomaly_reviewer.py

  async def review_anomaly(
      tool_id: str, field: str, value: Any,
      rule_fired: str, full_record: dict
  ) -> dict:

Returns exactly:
  {'action': 'keep'|'suppress'|'flag',
   'issue': str|None,
   'confidence': float,
   'haiku_available': bool}

If haiku_available=False: default action='flag',
confidence=0.0. Never block pipeline.

Log every call as structured JSON.

Gate — all 4 PASS before Phase 4:
  □ review_anomaly('T10','severity.level',
    'UNKNOWN','severity_unknown_with_vector',
    mock_record) → dict with 'action' key
  □ Returns 'confidence' key (float)
  □ Returns 'haiku_available' key (bool)
  □ When Haiku unavailable: action='flag',
    no exception raised

═══════════════════════════════════════════════════════
PHASE 4 — FEEDBACK CLASSIFIER (TRIGGER 2)
═══════════════════════════════════════════════════════

Build: datanexus/agents/feedback_classifier.py
Most important file in Section 13.

  async def classify_feedback(
      record: FeedbackRecord,
      original_response: dict
  ) -> dict:

Returns exactly:
  {'classification': 'confirmed'|'rejected'|
                     'needs_review',
   'score': float,
   'suggested_fix': str,
   'open_github_issue': bool,
   'haiku_available': bool}

Critical behaviours:

  1. NEVER return classification='pending'.
     haiku_available=False → 'needs_review'.

  2. Always update FeedbackRecord in Redis:
     HSET feedback:record:{record.record_id}
       classification {result}
       score {score}
       agent_version {HAIKU_MODEL}
     Run on EVERY call, even if Haiku fails.

  3. One-way rule (CLAUDE.md S13-5):
     Check current classification first.
     If already confirmed|rejected|needs_review:
     Log warning and return without overwriting.

  4. If confirmed AND score >= 0.8:
     open_github_issue = True
     HSET datanexus:github:pending:{record_id}
       tool_id, query_hash, signal, comment,
       suggested_fix, score, created_at

Update bug_listener.py — after BLPOP pull,
BEFORE send_alert():
  cached = await get_cached(record.tool_id,
    record.query_hash) or {}
  result = await classify_feedback(record, cached)
  log result as JSON
  then call send_alert() as normal
  If classify_feedback raises: catch, log ERROR,
  continue to send_alert() — never block alerts.

Gate — all 5 PASS before Phase 5:
  □ classify_feedback(mock_record, mock_response)
    → classification != 'pending'
  □ HGETALL feedback:record:{id} → classification
    field present and not 'pending'
  □ confirmed + score >= 0.8 →
    KEYS datanexus:github:pending:* shows key
  □ haiku_unavailable → classification=
    'needs_review', Redis still updated
  □ record already 'confirmed' → second call
    does NOT overwrite, logs warning

═══════════════════════════════════════════════════════
PHASE 5 — SCHEMA MONITOR (TRIGGER 3)
═══════════════════════════════════════════════════════

Build: datanexus/agents/schema_monitor.py

  async def assess_schema_change(
      tool_id: str,
      old_schema: dict,
      new_schema: dict
  ) -> dict:

Returns exactly:
  {'breaking': bool,
   'affected_fields': list[str],
   'severity': 'low'|'medium'|'high',
   'recommendation': str,
   'haiku_available': bool}

Actions:
  breaking + high → HSET datanexus:schema:
    alerts:{tool_id}, record_failure × 3
  breaking + medium → HSET datanexus:schema:
    warnings:{tool_id}, no circuit breaker
  not breaking → update stored fingerprint only
  haiku_unavailable → breaking=False, severity='low'

Gate — all 3 PASS before Phase 6:
  □ new optional field → breaking=False,
    severity='low', no circuit breaker
  □ removed required field → breaking=True,
    schema:alerts:{tool_id} key written
  □ haiku_unavailable → breaking=False,
    no circuit breaker

═══════════════════════════════════════════════════════
PHASE 6 — DIGEST GENERATOR (TRIGGER 4)
═══════════════════════════════════════════════════════

Build: datanexus/agents/digest_generator.py

  async def generate_weekly_digest(
      tool_id: str,
      feedback_records: list[FeedbackRecord]
  ) -> DigestItem:

If empty list: return DigestItem with
  data_quality_score=1.0, top_issues=[].
  Do NOT call Haiku.

Batch ALL records into ONE Haiku call.
Write to Redis: HSET datanexus:digest:
  {tool_id}:{week_iso} with all DigestItem fields.
EXPIRE: 2592000 (30 days).
Week format: f"{year}-W{week:02d}"

Gate — all 3 PASS before Phase 7:
  □ generate_weekly_digest('T10', [r1,r2,r3])
    → DigestItem, top_issues non-empty,
    score between 0.0 and 1.0
  □ HGETALL datanexus:digest:T10:{week} → data
  □ Empty list → score=1.0, top_issues=[],
    NO Haiku call in logs

═══════════════════════════════════════════════════════
PHASE 7 — MCP TOOL: validate_tool_output
═══════════════════════════════════════════════════════

Build: datanexus/tools/validation.py
Register in: datanexus/main.py

@mcp.tool()
async def validate_tool_output(
    tool_id: str,
    query_hash: str,
    response_json: str
) -> dict:
  """
  Validate any DataNexus tool response for data
  quality anomalies. Two-layer validation:
  deterministic rules (always) + Haiku AI review
  (only on ambiguous deterministic findings).
  Auto-files feedback on consensus issues only —
  both layers must agree before filing.
  Never blocks — always returns structured result.
  Verified source: DataNexus internal validator.
  AI-Ready output. Token-efficient.
  Example: validate_tool_output(
    tool_id='T10',
    query_hash='3d1697...',
    response_json=json.dumps(tool_response))
  """
  # Parse, validate Layer 1, call Layer 2 if needed
  # Consensus required before report_feedback()
  # Always return:
  return {
    'validation':       'pass'|'issues_found',
    'deterministic':    {'passed':bool,'issues':[]},
    'haiku':            {'passed':bool,'issues':[],
                         'available':bool},
    'feedback_filed':   bool,
    'consensus_issues': list[str],
    'query_hash':       query_hash
  }

Do NOT call validate_tool_output recursively.
Do NOT call from inside T04 or T10 handlers.
Register in main.py. Total tools: 10 + 1 = 11.

Gate — all 4 PASS before Phase 8:
  □ validate_tool_output('T10', 'hash',
    json.dumps(mock_with_UNKNOWN_severity))
    → validation='issues_found', query_hash='hash'
  □ validate_tool_output('T04', 'hash2',
    json.dumps(clean_response))
    → validation='pass', feedback_filed=False
  □ validate_tool_output('T10', 'hash3',
    'not valid json {{{{')
    → structured dict with 'validation' key,
    no exception raised
  □ python3 -m datanexus.main --help lists
    11 tools including validate_tool_output

═══════════════════════════════════════════════════════
PHASE 8 — DASHBOARD UPDATE
═══════════════════════════════════════════════════════

Update feedback/dashboard/server.py.
Add 4 elements. Do not modify existing panels.

1. Weekly digest card per tool:
   Read HGETALL datanexus:digest:{tool_id}:{week}
   Show: data_quality_score (coloured), top_issues
   (max 5), sprint_recommendations (max 3).
   If missing: "First digest generates Saturday 00:00 UTC"

2. Haiku call counter:
   Read GET haiku:calls:{today}
   Show {count}/{HAIKU_MAX_CALLS_PER_DAY}
   green<80, amber 80-99, red=100

3. Pending GitHub issues:
   KEYS datanexus:github:pending:* → count
   "Review and open on GitHub manually"

4. Validation coverage: static placeholder text
   "Tracking starts when agents call
   validate_tool_output()"

Add to /api/summary response:
  haiku_calls_today: int
  haiku_daily_limit: int
  pending_github_issues: int
  digest_available: bool

Gate — all 3 PASS before Phase 9:
  □ GET localhost:8101 → 200, body contains
    'haiku' or 'data quality' (case-insensitive)
  □ GET localhost:8101/api/summary → JSON with
    haiku_calls_today AND pending_github_issues
  □ haiku_calls_today is int >= 0

═══════════════════════════════════════════════════════
PHASE 9 — CLAUDE.MD UPDATE
═══════════════════════════════════════════════════════

Update CLAUDE.md in repo root.
SAME COMMIT as Section 13 code. Non-negotiable.

Append to CLAUDE.md:

## Section 13 — Haiku Validation Rules

Rule S13-1: Haiku called ONLY on 4 triggers:
  T1 anomaly_reviewer.review_anomaly()
  T2 feedback_classifier.classify_feedback()
  T3 schema_monitor.assess_schema_change()
  T4 digest_generator.generate_weekly_digest()
  Any new trigger requires human PR + spec update.

Rule S13-2: Use HAIKU_MODEL from feedback/config.py.
  Never hardcode the model string anywhere else.

Rule S13-3: HAIKU_MAX_CALLS_PER_DAY (100) is
  non-negotiable. Never reset or bypass the counter.
  Never set > 100 without human PR.

Rule S13-4: validate_tool_output() never raises.
  All exceptions caught, logged at ERROR, structured
  error dict returned. Caller always gets response.

Rule S13-5: FeedbackRecord.classification is
  one-way only: pending → confirmed|rejected|
  needs_review. NEVER back to pending.

Also add to Section 11.2:
  "Haiku called ONLY on 4 triggers in Section 13.2.
  Human PR required for any new trigger."

Gate — all 3 PASS before Phase 10:
  □ grep 'HAIKU_MAX_CALLS_PER_DAY' CLAUDE.md → match
  □ grep 'Section 13' CLAUDE.md → match
  □ grep 'one-way\|S13-5' CLAUDE.md → match

═══════════════════════════════════════════════════════
PHASE 10 — UPDATE MAIN.PY COMMENT BLOCK
═══════════════════════════════════════════════════════

Add near top of main.py after imports:

# ── SECTION 13 ADDITIONS (v7.4) ─────────────────
# validate_tool_output: added in Section 13
#   See: DataNexus_MCP_Spec_v7_4.docx Section 13.6
#
# Haiku triggers — exactly 4, no others permitted:
#   T1: anomaly_reviewer.review_anomaly()
#   T2: feedback_classifier.classify_feedback()
#   T3: schema_monitor.assess_schema_change()
#   T4: digest_generator.generate_weekly_digest()
#
# Tool count after Section 13: 11 total
#   T04: fetch_nonprofit_by_ein,
#        search_nonprofits_by_name, fetch_charity_uk
#   T10: fetch_package_vulnerabilities,
#        fetch_dependency_graph, fetch_cve_detail,
#        audit_sbom_vulnerabilities,
#        fetch_package_licence
#   Shared: report_feedback, report_mcpize_link
#   New:    validate_tool_output
# ─────────────────────────────────────────────────

Gate:
  □ Comment block present in main.py
  □ Tool count shows 11
  □ All 11 tool names listed correctly

═══════════════════════════════════════════════════════
PHASE 11 — DEPLOY + FULL VERIFICATION
═══════════════════════════════════════════════════════

Step 1: Single commit with ALL Section 13 changes
  git add -A
  git commit -m "Section 13: Haiku Validation
  Architecture — validator, 4 Haiku agents,
  validate_tool_output, dashboard, CLAUDE.md"

  Must include ALL of these files in one commit:
  datanexus/core/validator.py
  datanexus/agents/haiku_classifier.py
  datanexus/agents/anomaly_reviewer.py
  datanexus/agents/feedback_classifier.py
  datanexus/agents/schema_monitor.py
  datanexus/agents/digest_generator.py
  datanexus/tools/validation.py
  datanexus/main.py (updated — 11 tools)
  datanexus/core/ingest_base.py (updated)
  datanexus/agents/bug_listener.py (updated)
  feedback/dashboard/server.py (updated)
  CLAUDE.md (updated with S13 rules)

Step 2: Deploy to Hetzner
  ssh datanexus && cd /app/datanexus
  git pull
  docker compose build --no-cache datanexus-mcp
  docker compose up -d
  Confirm all 4 containers Up.

Step 3: Existing tests must still pass
  docker compose exec datanexus-mcp \
    pytest feedback/tests/ -v
  docker compose exec datanexus-mcp \
    pytest payment/tests/ -v
  Must show 84/84 green. Zero regressions.

Step 4: All 10 acceptance criteria (Section 13.11)
  □ AC-01: validate_payload('T10', mock_UNKNOWN)
    returns derived severity, 'severity_derived'
    in issues
  □ AC-02: haiku:calls:{today} = 100 → classify()
    returns daily_limit_reached. Reset key.
  □ AC-03: invalid API key → review_anomaly()
    returns haiku_available=False, action='flag'
  □ AC-04: File incorrect_data for T10 query_hash.
    Within 60s: classification != 'pending',
    score > 0.0
  □ AC-05: KEYS datanexus:github:pending:*
    shows key if score >= 0.8 from AC-04
  □ AC-06: assess_schema_change — new optional
    field → breaking=False, no circuit breaker
  □ AC-07: assess_schema_change — removed field
    → breaking=True, schema:alerts key written
  □ AC-08: generate_weekly_digest with 3 records
    → top_issues non-empty, Redis key written
  □ AC-09: validate_tool_output with bad JSON
    → structured dict returned, no exception
  □ AC-10: /api/summary contains
    haiku_calls_today AND pending_github_issues

Step 5: Update npm and registries
  Bump package.json patch version
  npm publish @datanexus/mcp-server
  Add validate_tool_output to glama.json with:
    "AI-Ready", "Verified source",
    "token-efficient", "data quality validation"

═══════════════════════════════════════════════════════
FINAL REPORT
═══════════════════════════════════════════════════════

Phase | PASS/FAIL | Notes
------+-----------+-------
0  T10 bug fixes
1  validator.py
2  haiku_classifier.py
3  anomaly_reviewer.py
4  feedback_classifier.py
5  schema_monitor.py
6  digest_generator.py
7  validate_tool_output
8  dashboard update
9  CLAUDE.md update
10 main.py comment
11 deploy + verification

Tests: feedback {n}/61 · payment {n}/23
AC-01 through AC-10: each PASS/FAIL
Final tool count: {n} in main.py

Section 13 complete ONLY when:
  All 12 phase gates PASS
  All 10 acceptance criteria PASS
  84/84 existing tests green
  11 tools registered in main.py
  All in one commit

Stop. Wait for Sprint 2 go-ahead.
Do not build T22 or any Sprint 2 tool.

═══════════════════════════════════════════════════════
SCOPE BOUNDARY
═══════════════════════════════════════════════════════

Do NOT add a 5th Haiku trigger without human PR.
Do NOT call Haiku from T04/T10 handlers directly.
Do NOT build Sprint 2 tools.
Do NOT change @verify_entitlement or payment/ code.
Do NOT modify tests that currently pass.
Build exactly what Section 13 specifies. No more.
