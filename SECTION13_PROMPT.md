# DataNexus MCP — Section 13 Implementation Prompt
# Haiku Validation Architecture
# Spec: DataNexus_MCP_Spec_v7_4_Section13.docx
# Directory: /Users/sangeetajagadeesh/OmSaiRam
# Prerequisites: Sprint 1 complete (84/84 tests green, T04+T10 live)
# Last updated: May 2026

═══════════════════════════════════════════════════════
RULE ZERO — READ BEFORE ANY CODE
═══════════════════════════════════════════════════════

Read these files completely before writing a single line:

1. /Users/sangeetajagadeesh/OmSaiRam/CLAUDE.md
2. /Users/sangeetajagadeesh/OmSaiRam/DataNexus_MCP_Spec_v7_4_Section13.docx
   Focus on Section 13 entirely.
   Sections 1-12 are unchanged from v7.3.

Confirm pre-read by answering ALL of these:

a) What are the 4 triggers that justify a Haiku call?
   Name each trigger and the file that handles it.

b) What is HAIKU_MAX_CALLS_PER_DAY and where is it defined?

c) What does validate_tool_output() return when it finds
   issues? Give the exact response shape.

d) What does feedback_classifier.py do that closes a gap
   identified in production? Be specific about what
   was broken before and what it fixes.

e) What are the two things that must happen in the same
   commit as the Section 13 build?
   (Hint: Section 13.12)

f) After Section 13 is built, how many total tools are
   registered in main.py?

Do not write any code until I confirm your answers.
Type READY TO BUILD only after my confirmation.

═══════════════════════════════════════════════════════
CONTEXT — CURRENT STATE
═══════════════════════════════════════════════════════

Sprint 1 is complete:
- T04 (5 tools) + T10 (7 tools) = 12 registered
- 84/84 tests green (61 feedback + 23 payment)
- Live at https://datanexusmcp.com/mcp
- Feedback pipeline working: fb:alerts:immediate confirmed
- Known production issue: FeedbackRecord.classification
  stays at 'pending' forever — Section 13 fixes this

Two T10 data quality bugs found in production
(filed via feedback pipeline):
  Bug 1: severity.level = UNKNOWN when CVSS vector present
  Bug 2: PYSEC duplicate records not deduplicated vs GHSA

These bugs are the motivation for Section 13.
validator.py (Layer 1) fixes them deterministically.
Haiku (Layer 2) handles the ambiguous cases validator
cannot auto-fix.

═══════════════════════════════════════════════════════
PHASE 0 — FIX THE TWO KNOWN T10 BUGS FIRST
═══════════════════════════════════════════════════════

Before building any Section 13 file, fix the two known
T10 production bugs. These are deterministic fixes —
no Haiku needed. They belong in the T10 response
formatter, not in validator.py (which is built later).

Bug 1 fix — severity_level_from_vector:
  In datanexus/tools/t10.py response formatter:
  When building vulnerability list, if any record has
  severity.level == 'UNKNOWN' or missing AND
  cvss_vector is present — derive level from base score:
    score 0.0       = NONE
    score 0.1-3.9   = LOW
    score 4.0-6.9   = MEDIUM
    score 7.0-8.9   = HIGH
    score 9.0-10.0  = CRITICAL
  Apply derived level. Log correction as structured JSON.

Bug 2 fix — deduplicate_by_cve_alias:
  In datanexus/tools/t10.py response formatter:
  After fetching vulnerability list, deduplicate:
  For each PYSEC record: check if any GHSA record
  shares a CVE alias. If yes: suppress PYSEC,
  keep GHSA (GHSA has more complete data).
  Log suppression: {"suppressed": "PYSEC-id",
    "kept": "GHSA-id", "shared_alias": "CVE-id"}

After fixing:
  □ Redeploy to Hetzner
  □ Re-run: fetch_package_vulnerabilities(
      "requests", "2.28.0", "PyPI")
  □ Verify: no UNKNOWN severity when CVSS present
  □ Verify: no duplicate PYSEC/GHSA pairs
  □ Report both as PASS before Phase 1

═══════════════════════════════════════════════════════
PHASE 1 — LAYER 1: DETERMINISTIC VALIDATOR
═══════════════════════════════════════════════════════

Build: datanexus/core/validator.py

Single function:
  validate_payload(tool_id: str, raw_data: dict)
    -> tuple[dict, list[str]]
  Returns: (cleaned_data, issues_list)
  Never raises. Never blocks. Catches all exceptions.

Called from: IngestBase.run_forever() AFTER fetch()
and BEFORE set_cached(). This is mandatory placement.
Every ingest cycle validates before caching.

T10 rules (implement all three):

  Rule 1 — severity_level_from_vector
    If any vuln in raw_data has severity.level ==
    'UNKNOWN' or missing AND cvss_vector present:
    Derive level from score using table above.
    Mutate record in-place. Append 'severity_derived'
    to issues_list.
    NOTE: This rule overlaps with the Bug 1 fix in
    Phase 0. The Phase 0 fix is in the tool formatter
    (query-time). This rule is in the ingest validator
    (cache-time). Both are needed — different layers.

  Rule 2 — deduplicate_by_cve_alias
    Suppress PYSEC records that share a CVE alias
    with a GHSA record. Keep GHSA.
    Append 'pysec_deduplicated:{count}' to issues_list
    if any suppressed.

  Rule 3 — flag_incomplete_records
    If any vuln has empty summary AND missing severity:
    Add incomplete=True to that record.
    Do NOT suppress — flag only.
    Append 'incomplete_records:{count}' to issues_list.

T04 rules (implement both):

  Rule 1 — validate_ein_format
    EIN must match regex r'^\d{2}-\d{7}$'
    If not: add malformed_ein=True to record.
    Append 'malformed_ein' to issues_list.

  Rule 2 — validate_financial_figures
    Revenue and expenses fields must be numeric
    (int or float).
    If string or null when field is present:
    Add unverified_financials=True.
    Append 'unverified_financials' to issues_list.

General rules (all tools):

  Rule 1 — non_empty_response
    If data dict is empty dict or None:
    Do NOT cache.
    Return (None, ['upstream_empty'])
    Caller must handle None cleaned_data by returning
    error response instead of caching.

  Rule 2 — required_fields_present
    T04 required: ['ein', 'name']
    T10 required: ['package', 'ecosystem', 'vulns']
    If any missing: append 'missing_required:{field}'
    to issues_list.

Update IngestBase.run_forever() to call
validate_payload() between fetch() and set_cached():
  raw = await self.fetch()
  cleaned, issues = validate_payload(self.tool_id, raw)
  if cleaned is None:
    record_failure(self.source_id)
    continue
  if issues:
    log as structured JSON: {"ts":ISO,"tool":tool_id,
      "validation_issues":issues}
  set_cached(self.tool_id, params_hash, cleaned, ttl)

Gate:
  validate_payload('T10', mock_vuln_with_UNKNOWN_severity
    _and_cvss_vector) returns:
    - cleaned_data with severity.level != 'UNKNOWN'
    - issues_list contains 'severity_derived'

  validate_payload('T04', {'revenue': 'n/a', 'ein':
    '123456789'}) returns:
    - issues_list contains 'malformed_ein'
    - issues_list contains 'unverified_financials'

  validate_payload('T10', {}) returns (None,
    ['upstream_empty'])

Report all 3 gate results before Phase 2.

═══════════════════════════════════════════════════════
PHASE 2 — HAIKU CLASSIFIER (ENTRY POINT)
═══════════════════════════════════════════════════════

Build: datanexus/agents/haiku_classifier.py

Single function:
  async def classify(
      context: str,
      data: dict,
      task: str
  ) -> dict:

Rules:
  - Use HAIKU_MODEL constant from feedback/config.py
    Never hardcode the model string.
  - Temperature: 0.1 — deterministic, not creative
  - Max tokens: 500 — keep responses tight
  - System prompt (identical for all 4 triggers):
    "You are a data quality classifier for a public
    data API. Return JSON only. No prose. No markdown.
    Raw JSON object only. No code fences."

  - Daily cap enforcement BEFORE every Haiku call:
    today_key = f'haiku:calls:{date.today().isoformat()}'
    count = await redis.incr(today_key)
    await redis.expire(today_key, 86400)
    if count > HAIKU_MAX_CALLS_PER_DAY:
      log.warning('Haiku daily limit — deterministic
        fallback')
      return {'error': 'daily_limit_reached',
              'haiku_available': False}

  - On ANY API error or exception:
    return {'error': str(e), 'haiku_available': False}
    Never raise. Never block.

Add to payment/config.py:
  HAIKU_MAX_CALLS_PER_DAY: int = 100

Gate:
  □ With valid Haiku API key: classify('test', {},
    'test') returns dict with no 'error' key
  □ With counter at 101: returns
    {'error': 'daily_limit_reached',
     'haiku_available': False}
  □ With invalid API key: returns
    {'error': str(e), 'haiku_available': False}
    — no exception propagated

Report all 3 gate results before Phase 3.

═══════════════════════════════════════════════════════
PHASE 3 — TRIGGER 1: ANOMALY REVIEWER
═══════════════════════════════════════════════════════

Build: datanexus/agents/anomaly_reviewer.py

Called by: validator.py when a rule fires but
auto-fix is ambiguous. NOT called for every rule —
only when the correct action cannot be determined
deterministically.

  async def review_anomaly(
      tool_id: str,
      field: str,
      value: Any,
      rule_fired: str,
      full_record: dict
  ) -> dict:

Returns:
  {
    'action':          'keep' | 'suppress' | 'flag',
    'issue':           str | None,
    'confidence':      float (0.0-1.0),
    'haiku_available': bool
  }

Behaviour:
  - If haiku_classifier returns error:
    default action = 'flag', confidence = 0.0
  - If haiku_classifier returns result:
    parse action, issue, confidence from response
  - Log every call as structured JSON:
    {"ts":ISO,"trigger":"anomaly_review",
     "tool":tool_id,"field":field,
     "rule":rule_fired,"action":action,
     "confidence":confidence}

Gate:
  review_anomaly('T10', 'severity.level', 'UNKNOWN',
    'severity_unknown_with_vector', mock_vuln_record)
  □ Returns dict with 'action' key present
  □ Returns dict with 'confidence' key present
  □ Returns dict with 'haiku_available' key present
  □ When Haiku unavailable: action='flag',
    pipeline not blocked

Report all 4 gate results before Phase 4.

═══════════════════════════════════════════════════════
PHASE 4 — TRIGGER 2: FEEDBACK CLASSIFIER
═══════════════════════════════════════════════════════

Build: datanexus/agents/feedback_classifier.py

THIS IS THE MOST IMPORTANT FILE IN SECTION 13.
It closes the gap where FeedbackRecord.classification
stays 'pending' forever with score=0.0.

  async def classify_feedback(
      record: FeedbackRecord,
      original_response: dict
  ) -> dict:

Returns:
  {
    'classification':   'confirmed' | 'rejected' |
                        'needs_review',
    'score':            float (0.0-1.0),
    'suggested_fix':    str,
    'open_github_issue': bool,
    'haiku_available':  bool
  }

Behaviour:
  - If haiku_classifier returns error:
    return {'classification': 'needs_review',
            'score': 0.0, 'haiku_available': False, ...}
    Never leave as 'pending' — escalate to needs_review.

  - If confirmed AND score >= 0.8:
    open_github_issue = True
    Write to Redis:
      HSET datanexus:github:pending:{record.record_id}
        tool_id    {record.tool_id}
        query_hash {record.query_hash}
        signal     {record.signal}
        comment    {record.comment}
        suggested_fix {suggested_fix}
        score      {score}
        ts         {ISO timestamp}
    This is NOT an actual GitHub API call —
    just write to Redis. Human opens the actual
    GitHub issue from this data.

  - Update FeedbackRecord in Redis:
    HSET feedback:record:{record.record_id}
      classification {result.classification}
      score          {result.score}
      agent_version  {HAIKU_MODEL}
    This must happen on EVERY call — even if
    haiku_available=False. Never leave 'pending'.

Update bug_listener.py:
  After BLPOP pull and before send_alert():
  Call classify_feedback(record, original_response)
  where original_response is fetched from Redis cache
  using record.query_hash to look up the tool response.
  If original_response not found in cache:
    call classify_feedback(record, {}) —
    Haiku works with partial context.

One-way reclassification rule (CLAUDE.md):
  classification may ONLY move:
    pending → confirmed | rejected | needs_review
  NEVER move confirmed → pending.
  NEVER move rejected → pending.

Gate:
  □ classify_feedback(mock_incorrect_data_record,
      mock_t10_response_with_unknown_severity)
    returns classification != 'pending'
  □ FeedbackRecord in Redis: classification field
    updated, no longer 'pending'
  □ With confirmed + score >= 0.8: Redis key
    datanexus:github:pending:{record_id} written
  □ With haiku_unavailable: still returns
    classification='needs_review', not 'pending'

Report all 4 gate results before Phase 5.

═══════════════════════════════════════════════════════
PHASE 5 — TRIGGER 3: SCHEMA MONITOR
═══════════════════════════════════════════════════════

Build: datanexus/agents/schema_monitor.py

  async def assess_schema_change(
      tool_id: str,
      old_schema: dict,
      new_schema: dict
  ) -> dict:

Returns:
  {
    'breaking':         bool,
    'affected_fields':  list[str],
    'severity':         'low' | 'medium' | 'high',
    'recommendation':   str,
    'haiku_available':  bool
  }

Actions based on result:
  breaking=True + severity='high':
    HSET datanexus:schema:alerts:{tool_id}
      detected_at {ISO}
      affected_fields {json.dumps(affected_fields)}
      recommendation {recommendation}
    Trigger circuit breaker for that source:
      record_failure(source_id) × 3
      (trips breaker immediately)
    Log to ops alert channel.

  breaking=True + severity='medium':
    HSET datanexus:schema:warnings:{tool_id}
      detected_at {ISO}
      affected_fields {json.dumps(affected_fields)}
    Flag cache as stale:
      DEL datanexus:T{nn}:* pattern for that tool
    Do not trip circuit breaker.

  not breaking (any severity):
    Update stored fingerprint in Redis.
    No alert. No disruption.

  haiku_available=False:
    Default to breaking=False, severity='low'.
    Log warning. Never block ingest on Haiku failure.

Gate:
  □ assess_schema_change('T10',
      {'vulns': [], 'total': 0},
      {'vulns': [], 'total': 0, 'new_optional': ''})
    returns breaking=False, severity='low'
    No circuit breaker triggered.

  □ assess_schema_change('T10',
      {'vulns': [], 'total': 0, 'summary': ''},
      {'vulns': [], 'total': 0})
    (removed required field)
    returns breaking=True, severity='high'
    datanexus:schema:alerts:T10 key written.

  □ haiku_unavailable: returns breaking=False,
    severity='low', haiku_available=False.
    No circuit breaker triggered.

Report all 3 gate results before Phase 6.

═══════════════════════════════════════════════════════
PHASE 6 — TRIGGER 4: DIGEST GENERATOR
═══════════════════════════════════════════════════════

Build: datanexus/agents/digest_generator.py

  async def generate_weekly_digest(
      tool_id: str,
      feedback_records: list[FeedbackRecord]
  ) -> DigestItem:

Rules:
  - If feedback_records is empty:
    return empty DigestItem with data_quality_score=1.0
    Do not call Haiku on empty input.
  - Batch ALL records into a SINGLE Haiku call —
    not one call per record. Cost control.
  - Input to Haiku: tool_id + serialised records list
    + instruction to find patterns and generate rules
  - Write result to Redis:
    HSET datanexus:digest:{tool_id}:{week_iso}
      top_issues          {json.dumps(top_issues)}
      suggested_rules     {json.dumps(suggested_rules)}
      data_quality_score  {score}
      sprint_recommendations {json.dumps(recs)}
      generated_at        {ISO}
    Expire: 30 days

  Week ISO format: date.today().isocalendar()
    → f"{year}-W{week:02d}"
    Example: "2026-W18"

Schedule: Saturday 00:00 UTC.
Add cron entry to /etc/cron.d/datanexus-feedback
  on Hetzner server:
  0 0 * * 6  app  python3 -m
    feedback.agents.digest_generator
    --tool T04
  0 5 * * 6  app  python3 -m
    feedback.agents.digest_generator
    --tool T10

Gate:
  □ generate_weekly_digest('T10',
      [mock_record_1, mock_record_2, mock_record_3])
    returns DigestItem with non-empty top_issues
  □ Redis key datanexus:digest:T10:{week_iso} written
  □ generate_weekly_digest('T10', []) returns
    DigestItem with data_quality_score=1.0,
    top_issues=[] — no Haiku called

Report all 3 gate results before Phase 7.

═══════════════════════════════════════════════════════
PHASE 7 — MCP TOOL: validate_tool_output
═══════════════════════════════════════════════════════

Build: register in datanexus/tools/validation.py
then import and register in main.py.

@mcp.tool()
async def validate_tool_output(
    tool_id: str,
    query_hash: str,
    response_json: str
) -> dict:
  """
  Validate a DataNexus tool response for data quality
  anomalies. Call this after any tool call to
  automatically detect and report issues.
  Returns validation result and auto-files feedback
  if anomalies detected by both layers.
  Never blocks — always returns even if validation
  finds issues or response_json is malformed.
  Example: validate_tool_output(
    tool_id='T10',
    query_hash='3d1697...',
    response_json=json.dumps(tool_response))
  Verified source: DataNexus internal validator.
  AI-Ready Markdown output. Token-efficient.
  """
  # Step 1: Parse response_json
  #   On parse error: return structured error,
  #   never raise
  # Step 2: Run Layer 1 (validator.py)
  #   cleaned, issues = validate_payload(tool_id,data)
  # Step 3: If Layer 1 issues and action ambiguous:
  #   call anomaly_reviewer.review_anomaly()
  # Step 4: If both Layer 1 AND Layer 2 flag issue:
  #   auto-call report_feedback() with:
  #     signal = 'incorrect_data'
  #     missing_fields = flagged_fields_list
  #     comment = f"Auto-detected: {consensus_issues}"
  #     query_hash = query_hash
  #   This is a consensus requirement —
  #   Layer 1 alone or Layer 2 alone does not
  #   auto-file. Both must agree.
  # Step 5: Always return:
  return {
    'validation':        'pass' | 'issues_found',
    'deterministic': {
      'passed': bool,
      'issues': []
    },
    'haiku': {
      'passed':    bool,
      'issues':    [],
      'available': bool
    },
    'feedback_filed': bool,
    'consensus_issues': [],
    'query_hash': query_hash
  }

Register in main.py.
Total tools after: T04 (5) + T10 (7) +
  validate_tool_output (1) = 13.

Glama description (required — contributes to score):
  "Validate any DataNexus tool response for data
  quality anomalies. Two-layer validation: deterministic
  rules + Haiku AI review. Auto-files feedback on
  confirmed issues. Never blocks tool workflow.
  Returns structured validation report.
  Token-efficient. AI-Ready output."

Hard stop for this tool:
  Do NOT call validate_tool_output recursively.
  Do NOT call validate_tool_output from inside
  any other tool handler.
  This tool is for external agent use only.

Gate:
  □ validate_tool_output('T10', 'test_hash',
      json.dumps(mock_response_with_UNKNOWN_severity))
    returns validation='issues_found',
    deterministic.issues non-empty,
    query_hash='test_hash'
  □ validate_tool_output('T04', 'hash2',
      json.dumps(clean_response))
    returns validation='pass',
    feedback_filed=False
  □ validate_tool_output('T10', 'hash3',
      'not valid json')
    returns structured error dict — never raises
  □ python3 -m datanexus.main --help lists
    13 tools. validate_tool_output present.

Report all 4 gate results before Phase 8.

═══════════════════════════════════════════════════════
PHASE 8 — UPDATE BUG LISTENER
═══════════════════════════════════════════════════════

Update datanexus/agents/bug_listener.py (existing file):

After BLPOP pull, BEFORE send_alert():
  1. Parse record from pulled payload
  2. Attempt to fetch original tool response from
     Redis cache using query_hash:
     cached = get_cached(record.tool_id,
       record.query_hash)
     If not found: use empty dict {}
  3. Call:
     result = await classify_feedback(
       record, cached or {})
  4. Log result as structured JSON
  5. Then call send_alert() as before

This is a non-breaking change — send_alert() still
fires on every BUG_SIGNAL. classify_feedback() is
called in addition, not instead.

If classify_feedback() raises for any reason:
  catch, log, continue to send_alert().
  Never let feedback classification block alerts.

Gate:
  □ File feedback with signal=incorrect_data
    for T10's known query_hash from production
  □ Check: docker compose logs datanexus-mcp
    --tail 30 | grep classify_feedback
    Must show structured log entry
  □ Check: FeedbackRecord in Redis:
    docker compose exec redis redis-cli HGETALL
    feedback:record:{record_id}
    classification must not be 'pending'
  □ send_alert() still fires (check ntfy.sh
    or stdout log for alert delivery)

Report all 4 gate results before Phase 9.

═══════════════════════════════════════════════════════
PHASE 9 — DASHBOARD UPDATE
═══════════════════════════════════════════════════════

Update feedback/dashboard/server.py to add
4 new panel elements from Section 13.8:

1. Weekly digest card (per active tool):
   Read: datanexus:digest:{tool_id}:{week_iso}
   Show: data_quality_score, top_issues list,
   sprint_recommendations list.
   If key missing: show "First digest generates
   Saturday 00:00 UTC — {days} days away"

2. Haiku call counter:
   Read: haiku:calls:{today}
   Show: {count}/{HAIKU_MAX_CALLS_PER_DAY}
   Style: green when < 80, amber when 80-99,
   red when at limit.

3. Pending GitHub issues:
   Read: KEYS datanexus:github:pending:*
   Show: count of pending issue drafts
   with note: "Open these on GitHub manually"

4. Validation coverage:
   Not tracked yet — show "Tracking starts when
   agents call validate_tool_output()"
   (Placeholder — no Redis key for this yet)

Update /api/summary endpoint to include:
  'haiku_calls_today':      int,
  'haiku_daily_limit':      int (HAIKU_MAX_CALLS_PER_DAY),
  'pending_github_issues':  int,
  'digest_available':       bool (per tool)

Gate:
  □ GET http://localhost:8101 returns 200
    Page contains 'haiku' or 'data quality'
    in HTML body
  □ GET http://localhost:8101/api/summary
    returns JSON containing keys:
    haiku_calls_today, pending_github_issues
  □ haiku_calls_today is an integer (0 or more)

Report all 3 gate results before Phase 10.

═══════════════════════════════════════════════════════
PHASE 10 — CLAUDE.MD UPDATE
═══════════════════════════════════════════════════════

Add these 4 rules to CLAUDE.md in repo root.
This update happens in the SAME COMMIT as the
Section 13 code. Non-negotiable.

Append to existing CLAUDE.md under a new section:
## Section 13 — Haiku Validation Rules

Rule 1:
Haiku is called ONLY on the 4 triggers defined in
Section 13.2 of the spec. Any new Haiku call requires
a human PR and a Section 13 update. No exceptions.

Rule 2:
Always use HAIKU_MODEL constant from feedback/config.py.
Never hardcode the model string (e.g.
'claude-haiku-4-5-20251001') in any file other than
feedback/config.py.

Rule 3:
HAIKU_MAX_CALLS_PER_DAY (100) enforcement is
non-negotiable. When daily limit is reached: use
deterministic fallback, log warning at WARNING level,
never bypass the counter by resetting it or skipping
the check.

Rule 4:
validate_tool_output() must never raise and never
block. Any exception inside it must be caught, logged
at ERROR level, and the function must return a
structured error dict. The calling agent must always
receive a response.

Rule 5:
FeedbackRecord.classification is one-way only.
It may move: pending → confirmed | rejected |
needs_review. It may NEVER move back to pending from
any other state. feedback_classifier.py enforces this.

Gate:
  □ grep 'HAIKU_MAX_CALLS_PER_DAY' CLAUDE.md
    returns a match
  □ grep 'Section 13' CLAUDE.md returns a match
  □ grep 'haiku_available' CLAUDE.md or
    grep 'four triggers' CLAUDE.md returns a match

Report all 3 gate results before Phase 11.

═══════════════════════════════════════════════════════
PHASE 11 — SECTION 11 CROSS-REFERENCE UPDATE
═══════════════════════════════════════════════════════

Update the canonical session starter (Section 11 in
the spec). Since the spec is a Word document and
Claude Code cannot edit it directly, instead update
the SPRINT1_PROMPT.md or any Claude Code session
README to reflect these additions. Document them as
comments in main.py:

Add to datanexus/main.py as a comment block:

# ── SECTION 13 ADDITIONS ──────────────────────────
# validate_tool_output: NEW in v7.4
#   Agents call after any tool response to check
#   data quality. Returns structured validation report.
#   See: DataNexus_MCP_Spec_v7_4_Section13.docx
#
# Haiku triggers (4 only — no others permitted):
#   T1: anomaly_reviewer.review_anomaly()
#   T2: feedback_classifier.classify_feedback()
#   T3: schema_monitor.assess_schema_change()
#   T4: digest_generator.generate_weekly_digest()
#
# Total tools registered: 13
#   T04: 5 (fetch_nonprofit_by_ein,
#          search_nonprofits_by_name,
#          fetch_charity_uk,
#          report_feedback,
#          report_mcpize_link)
#   T10: 7 (fetch_package_vulnerabilities,
#          fetch_dependency_graph,
#          fetch_cve_detail,
#          audit_sbom_vulnerabilities,
#          fetch_package_licence,
#          report_feedback,
#          report_mcpize_link)
#   New: validate_tool_output (1)
# ─────────────────────────────────────────────────

Gate:
  □ Comment block present in main.py
  □ Tool count in comment matches actual registered
    tools in main.py (13)

═══════════════════════════════════════════════════════
PHASE 12 — FULL DEPLOYMENT AND VERIFICATION
═══════════════════════════════════════════════════════

Deploy to Hetzner and run full acceptance criteria.

Step 1: Redeploy
  cd /app/datanexus
  docker compose build --no-cache
  docker compose up -d
  Confirm all 4 containers Up.

Step 2: Add cron entries on server
  ssh datanexus
  cat >> /etc/cron.d/datanexus-feedback << 'EOF'
  # Weekly digest — Saturdays
  0 0 * * 6  root  cd /app/datanexus && docker compose exec datanexus-mcp python3 -m feedback.agents.digest_generator --tool T04
  0 5 * * 6  root  cd /app/datanexus && docker compose exec datanexus-mcp python3 -m feedback.agents.digest_generator --tool T10
  EOF

Step 3: Run all 10 acceptance criteria (Section 13.11)

□ AC-01 Deterministic validator
  validate_payload('T10', mock_UNKNOWN_severity_with
  _cvss) returns severity_derived in issues.

□ AC-02 Haiku daily cap
  Manually set haiku:calls:{today} to 100 in Redis.
  Next classify() returns daily_limit_reached.
  redis-cli SET haiku:calls:{today} 100
  Then call classify — verify limit respected.
  Reset: redis-cli DEL haiku:calls:{today}

□ AC-03 Anomaly reviewer fallback
  Set ANTHROPIC_API_KEY to invalid value temporarily.
  review_anomaly() returns haiku_available=False,
  action='flag'. Pipeline not blocked.
  Restore key after test.

□ AC-04 Feedback classification closes loop
  File feedback with signal=incorrect_data.
  Within 60 seconds: check FeedbackRecord in Redis.
  classification must not be 'pending'.

□ AC-05 GitHub issue queued on high confidence
  Check: redis-cli KEYS datanexus:github:pending:*
  If previous tests produced confirmed + score >= 0.8:
  at least 1 key exists.

□ AC-06 Schema change benign
  Call assess_schema_change('T10',
    {'vulns':[],'total':0},
    {'vulns':[],'total':0,'new_field':''})
  Returns breaking=False. No circuit breaker.

□ AC-07 Schema change breaking
  Call assess_schema_change('T10',
    {'vulns':[],'total':0,'required_field':''},
    {'vulns':[],'total':0})
  Returns breaking=True, severity in response.
  datanexus:schema:alerts:T10 key written.

□ AC-08 Digest generation
  Call generate_weekly_digest('T10', [r1, r2])
  Returns DigestItem. top_issues non-empty.
  Redis key datanexus:digest:T10:{week_iso} exists.

□ AC-09 validate_tool_output never blocks
  Call with response_json='not valid json'
  Returns structured error dict. Never raises.
  docker compose logs shows no uncaught exception.

□ AC-10 Dashboard panel
  GET http://localhost:8101/api/summary
  Response JSON contains:
    haiku_calls_today (int)
    pending_github_issues (int)

Step 4: Run existing tests — must still all pass
  pytest feedback/tests/ -v
  pytest payment/tests/ -v
  Both must show all green. Zero regressions.

Step 5: Update npm package
  Bump package.json version (patch increment)
  npm publish @datanexus/mcp-server
  Update glama.json to add validate_tool_output
  tool entry with required keywords:
    "AI-Ready Markdown", "Verified source",
    "token-efficient", "data quality validation"

═══════════════════════════════════════════════════════
FINAL REPORT
═══════════════════════════════════════════════════════

After all phases complete, report:

Phase completion summary:
  □ Phase 0 — T10 bug fixes: PASS/FAIL
  □ Phase 1 — validator.py: PASS/FAIL
  □ Phase 2 — haiku_classifier.py: PASS/FAIL
  □ Phase 3 — anomaly_reviewer.py: PASS/FAIL
  □ Phase 4 — feedback_classifier.py: PASS/FAIL
  □ Phase 5 — schema_monitor.py: PASS/FAIL
  □ Phase 6 — digest_generator.py: PASS/FAIL
  □ Phase 7 — validate_tool_output tool: PASS/FAIL
  □ Phase 8 — bug_listener update: PASS/FAIL
  □ Phase 9 — dashboard update: PASS/FAIL
  □ Phase 10 — CLAUDE.md update: PASS/FAIL
  □ Phase 11 — Section 11 comment: PASS/FAIL
  □ Phase 12 — deployment + 10 AC: PASS/FAIL

Existing tests:
  □ pytest feedback/tests/: {n}/61 pass
  □ pytest payment/tests/: {n}/23 pass

Final tool count:
  □ 13 tools registered in main.py

Section 13 is complete ONLY when:
  - All 13 phase gates are PASS
  - All 10 acceptance criteria are PASS
  - 84/84 existing tests still green
  - 13 tools registered in main.py
  - CLAUDE.md updated with Section 13 rules

Stop. Report completion. Wait for Sprint 2
go-ahead. Do not begin T22 or any Sprint 2
tool until I give explicit go-ahead.

═══════════════════════════════════════════════════════
SCOPE BOUNDARY — ABSOLUTE
═══════════════════════════════════════════════════════

Section 13 scope is exactly what is defined above.

Do NOT:
  - Add a 5th Haiku trigger without human PR
  - Call Haiku from inside T04 or T10 tool handlers
  - Call Haiku from IngestBase directly
  - Add any machine learning or model calls beyond
    the 4 triggers defined in Section 13.2
  - Build any Sprint 2 tools (T22, T07, T12, etc.)
  - Change @verify_entitlement or payment code
  - Modify any feedback test that currently passes

Build Section 13 exactly as specified. Nothing more.
