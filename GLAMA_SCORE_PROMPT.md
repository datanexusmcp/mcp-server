# DataNexus MCP — Glama Tool Score Improvement
# Target: raise all 30 tools from 3.3-4.6 → 4.5+
# Current average: 3.93 / 5.0
# Source: Glama score page May 15 2026
# Directory: /Users/sangeetajagadeesh/OmSaiRam

═══════════════════════════════════════════════════════
WHAT GLAMA MEASURES — READ THIS FIRST
═══════════════════════════════════════════════════════

Glama scores tool descriptions on 5 dimensions.
Every tool fails on the same 4 patterns.
Fix all 4 patterns in every tool description.

DIMENSION 1 — Side effects / read-only disclosure
  Every tool must explicitly state:
  "Read-only. No side effects. Idempotent."
  Glama penalises any tool that does not say this.

DIMENSION 2 — Parameter completeness
  Every parameter must be explained beyond its
  schema type. Include:
  - Format (e.g. "ISO 8601 date: 2024-01-31")
  - Valid values (e.g. "US, EU, or UK")
  - Whether optional or required
  - Default value if optional
  Two tools have CONTRADICTIONS that must be fixed:
  - compliance_fetch_finra_broker: says "name or
    CRD" but schema only has crd_number. Remove
    "name or" — crd_number only.
  - domain_fetch_dns_records: says record_types
    is optional but schema marks it required.
    Change to "Required list of record types."

DIMENSION 3 — Geographical scope
  Any tool that only works for a specific country
  must state that explicitly.
  - compliance_* tools → US only (NPI, FINRA,
    SAM.gov)
  - nonprofit_fetch_nonprofit_by_ein → US only
  - nonprofit_fetch_charity_uk → UK only
  - legal_* tools → EP (European), US, or WO
  - govcon_* tools → US default, EU and UK
    available via jurisdiction parameter
  - regulatory_* tools → US federal (Regulations.gov
    + Federal Register)

DIMENSION 4 — When to use vs when NOT to use
  Every tool must have explicit guidance:
  "Use this when [condition].
  Use [sibling_tool] instead when [other condition]."

DIMENSION 5 — No marketing language (validate_tool_output)
  Remove: "AI-Ready output", "Token-efficient"
  from validate_tool_output description.
  These are flagged as marketing phrases.
  Replace with functional descriptions.

═══════════════════════════════════════════════════════
UNIVERSAL TEMPLATE — APPLY TO ALL 30 TOOLS
═══════════════════════════════════════════════════════

Every tool description must follow this structure:

"""
[One sentence: what it does, verb + resource]
Read-only. No side effects. Idempotent.
[Geographical scope if restricted.]
[Parameter 1]: [format + constraints + example]
[Parameter 2]: [format + optional/required + default]
[Parameter N]: [same]
Returns [specific fields list].
Use this when [specific condition].
Use [sibling] instead when [other condition].
[Hard stop if applicable — one line only]
Verified source: [source name]. [Cache TTL].
"""

Maximum length: 400 characters.
No bullet points — prose only.
No marketing phrases.

═══════════════════════════════════════════════════════
ALL 30 TOOL DESCRIPTIONS — EXACT REPLACEMENTS
═══════════════════════════════════════════════════════

Replace the description field in the @mcp.tool()
decorator for each tool. The file locations are:
  datanexus/tools/t04.py  — nonprofit_ tools
  datanexus/tools/t10.py  — security_ tools
  datanexus/tools/t22.py  — compliance_ tools
  datanexus/tools/t07.py  — domain_ tools
  datanexus/tools/t11.py  — legal_ tools
  datanexus/tools/t18.py  — govcon_ tools
  datanexus/tools/t19.py  — regulatory_ tools
  datanexus/tools/meta.py — search_datanexus_tools
  datanexus/tools/validation.py — validate_tool_output
  feedback/collector.py   — report_feedback
  payment/tools.py        — report_mcpize_link

── NONPROFIT (t04.py) ───────────────────────────────

nonprofit_fetch_nonprofit_by_ein:
"""
Fetch IRS 990 filing data for any US nonprofit
by EIN. Read-only. No side effects. Idempotent.
US only.
ein: 9-digit Employer ID with or without dash,
e.g. 13-1837418 or 131837418. Required.
Returns name, revenue, expenses, assets, NTEE
code, and mission from the most recent 990 filing.
Use this when you have the exact EIN.
Use nonprofit_search_nonprofits_by_name instead
when you only have a name.
Verified source: IRS EO BMF + IRS TEOS. 7-day cache.
"""

nonprofit_search_nonprofits_by_name:
"""
Search US nonprofits by name with optional state
filter. Read-only. No side effects. Idempotent.
US only. Returns up to 25 matches.
name: Full or partial organisation name. Required.
state: Two-letter US state code e.g. CA, NY.
Optional, defaults to all states.
Returns EIN, name, state, revenue, and NTEE code
for each match.
Use this when you have a name but not the EIN.
Use nonprofit_fetch_nonprofit_by_ein instead when
you have the exact EIN for a precise single lookup.
Verified source: IRS EO BMF. 7-day cache.
"""

nonprofit_fetch_charity_uk:
"""
Fetch UK registered charity details by charity
number or organisation name. Read-only. No side
effects. Idempotent. UK only.
charity_number_or_name: UK registered charity
number (7 digits, e.g. 1234567) or full/partial
organisation name. Required.
Returns registration status, income, expenditure,
activities, and trustee count.
Use this for UK charities. Use
nonprofit_fetch_nonprofit_by_ein or
nonprofit_search_nonprofits_by_name for US nonprofits.
Verified source: UK Charity Commission OGL v3.
24-hour cache.
"""

── SECURITY (t10.py) ────────────────────────────────

security_fetch_package_vulnerabilities:
"""
Fetch all known CVEs for an open source package
version. Read-only. No side effects. Idempotent.
package: Package name e.g. requests, lodash.
Required.
version: Exact version string e.g. 2.28.0.
Required.
ecosystem: One of PyPI, npm, Maven, Go, Cargo,
NuGet, RubyGems. Required.
Returns CVE ID, severity, CVSS score, affected
range, and fixed version for each vulnerability.
Use this to check a specific package version.
Use security_fetch_cve_detail instead when you
have a CVE ID and need full detail.
Use security_audit_sbom_vulnerabilities instead
when auditing an entire dependency manifest.
Verified source: Google OSV.dev + NIST NVD.
1-hour cache.
"""

security_fetch_cve_detail:
"""
Fetch full detail for a specific CVE by ID.
Read-only. No side effects. Idempotent.
cve_id: CVE identifier in format CVE-YYYY-NNNNN
e.g. CVE-2021-44228. Required.
Returns description, CVSS base score, affected
products, patch references, and publish date.
Use this when you have a CVE ID and need complete
detail beyond what a package scan returns.
Use security_fetch_package_vulnerabilities instead
when you want all CVEs for a package version.
Verified source: NIST NVD. 1-hour cache.
"""

security_fetch_dependency_graph:
"""
Fetch the full dependency tree for a package
version including transitive dependencies.
Read-only. No side effects. Idempotent.
Hard 8-second timeout — large dependency trees
may return partial results.
package: Package name. Required.
version: Exact version string e.g. 1.2.3.
Required.
ecosystem: One of PyPI, npm, Maven, Go, Cargo,
NuGet, RubyGems. Required.
Returns all direct and transitive dependencies
with version constraints.
Use this to understand full supply chain exposure.
Use security_fetch_package_vulnerabilities instead
when you only need CVEs for a single package.
Verified source: deps.dev (Google). 1-hour cache.
"""

security_audit_sbom_vulnerabilities:
"""
Audit a Software Bill of Materials for known
vulnerabilities across all listed packages.
Read-only. No side effects. Idempotent.
sbom_json: CycloneDX or SPDX SBOM as a JSON
string. Required. Large SBOMs (100+ packages)
may take up to 10 seconds.
Returns CVEs grouped by package with severity
and fixed versions.
Use this when you have a full SBOM to audit.
Use security_fetch_package_vulnerabilities instead
when checking a single package version.
Verified source: Google OSV.dev batch API.
1-hour cache.
"""

security_fetch_package_licence:
"""
Fetch the SPDX licence identifier for an open
source package version. Read-only. No side
effects. Idempotent.
package: Package name e.g. flask. Required.
version: Exact version string e.g. 2.3.0.
Required.
ecosystem: One of PyPI, npm, Maven, Go, Cargo,
NuGet, RubyGems. Required.
Returns the SPDX licence identifier e.g.
MIT, Apache-2.0, GPL-3.0.
Use this to verify licence compatibility before
including a dependency.
Use security_fetch_package_vulnerabilities instead
when checking for security issues not licences.
Verified source: deps.dev (Google). 1-hour cache.
"""

── COMPLIANCE (t22.py) ──────────────────────────────

compliance_fetch_npi_provider:
"""
Fetch NPI registration details for a US healthcare
provider by NPI number. Read-only. No side effects.
Idempotent. US only.
npi_number: 10-digit NPI number e.g. 1003000126.
Required. Do not include dashes or spaces.
Returns provider name, credential type, speciality
taxonomy, practice address, and active status.
Use this when you have the exact 10-digit NPI.
Use compliance_search_npi_by_name instead when
you only have the provider name.
Verified source: NPPES NPI Registry (CMS).
24-hour cache.
"""

compliance_search_npi_by_name:
"""
Search the NPPES NPI Registry by provider name
with optional state and speciality filters.
Read-only. No side effects. Idempotent. US only.
Returns up to 10 matches.
name: Full or partial provider name. Required.
state: Two-letter US state code e.g. CA. Optional.
speciality: Speciality keyword e.g. Cardiology.
Optional.
Returns NPI number, name, speciality, and address
for each match.
Use this when you do not have the NPI number.
Use compliance_fetch_npi_provider instead when
you have the exact 10-digit NPI.
Verified source: NPPES NPI Registry (CMS).
24-hour cache.
"""

compliance_fetch_finra_broker:
"""
Fetch FINRA BrokerCheck registration for a US
broker or investment adviser by CRD number.
Read-only. No side effects. Idempotent. US only.
crd_number: Central Registration Depository number
as a string of digits e.g. 1234567. Required.
CRD number only — name lookup is not supported.
Returns registration status, qualifications,
disclosure history, and employment history.
Use this when you have the CRD number.
Use compliance_search_npi_by_name instead for
healthcare providers, not financial advisers.
Verified source: FINRA BrokerCheck. 24-hour cache.
"""

compliance_check_sam_exclusion:
"""
Check whether an entity is on the US federal
exclusions list (debarred from government
contracts). Read-only. No side effects.
Idempotent. US only.
name_or_ein: Entity name or 9-digit EIN with or
without dash e.g. Acme Corp or 13-1234567.
Required. Name match is fuzzy — verify EIN for
exact results.
Returns excluded: true/false, exclusion type,
and exclusion dates if found.
Use this before awarding federal contracts or
grants. Use govcon_search_contract_awards instead
to find what contracts an entity has won.
Verified source: SAM.gov. 24-hour cache.
"""

── DOMAIN (t07.py) ──────────────────────────────────

domain_fetch_domain_rdap:
"""
Fetch domain registration details via IANA RDAP
(the modern structured replacement for WHOIS).
Read-only. No side effects. Idempotent.
domain: Domain name without protocol e.g.
example.com not https://example.com. Required.
Returns registrar, registration date, expiry
date, nameservers, and registrant info where
publicly available.
Use this when you need registration metadata.
Use domain_fetch_ssl_certificate_chain instead
when you need certificate history.
Use domain_fetch_dns_records instead when you
need live DNS resolution.
Verified source: IANA RDAP. 4-hour cache.
"""

domain_fetch_ssl_certificate_chain:
"""
Fetch SSL certificate history for a domain from
Certificate Transparency logs. Read-only. No side
effects. Idempotent.
domain: Domain name without protocol e.g.
github.com. Required. Does not support IP
addresses or wildcard domains.
Returns issuer, subject, validity period, and
Subject Alternative Names for each logged cert.
Use this to detect unexpected certificate issuance
or audit certificate history.
Use domain_fetch_domain_rdap instead when you
need registration data not certificate data.
Verified source: crt.sh Certificate Transparency.
4-hour cache.
"""

domain_fetch_dns_records:
"""
Fetch current DNS records for a domain via
Cloudflare DNS over HTTPS. Read-only. No side
effects. Idempotent.
domain: Domain name without protocol e.g.
cloudflare.com. Required.
record_types: List of DNS record types to fetch.
Required. Valid values: A, AAAA, MX, TXT, NS,
CNAME, SOA. Example: ["A", "MX", "TXT"].
Returns all matching records currently in effect.
Use this when you need live DNS resolution.
Use domain_fetch_domain_rdap instead when you
need registration metadata not DNS records.
Verified source: Cloudflare DoH. 4-hour cache.
"""

domain_fetch_domain_history:
"""
Fetch historical SSL certificate issuance for a
domain from Certificate Transparency logs.
Read-only. No side effects. Idempotent.
domain: Domain name without protocol e.g.
example.com. Required.
Returns all past certificates with issuer,
validity dates, and SANs in reverse chronological
order.
Use this to detect domain hijacking or audit
unexpected historical certificate issuance.
Use domain_fetch_ssl_certificate_chain instead
when you only need the current certificate chain.
Verified source: crt.sh Certificate Transparency.
4-hour cache.
"""

── LEGAL / PATENTS (t11.py) ─────────────────────────

legal_fetch_patent_by_number:
"""
Fetch full patent details by patent number and
jurisdiction. Read-only. No side effects.
Idempotent.
patent_number: Patent number in jurisdiction
format e.g. EP1000000 for European, US10000000
for USPTO, WO2020123456 for PCT. Required.
jurisdiction: One of EP (EPO), US (USPTO), or
WO (WIPO PCT). Required. Default EP.
Returns title, abstract, inventors, assignees,
filing date, claims summary, and citation count.
Use this when you have a specific patent number.
Use legal_search_patents_by_keyword instead when
you only have keywords and need to find patents.
Verified source: EPO OPS + USPTO. 24-hour cache.
"""

legal_search_patents_by_keyword:
"""
Search patents by keyword across EPO, USPTO, or
WIPO. Read-only. No side effects. Idempotent.
Returns up to 10 matches.
keywords: Search terms describing the invention
e.g. neural network image classification.
Required.
jurisdiction: One of EP, US, or WO. Optional.
Default EP.
date_from: Earliest filing date in ISO 8601
format e.g. 2020-01-31. Optional, defaults to
no lower bound.
Returns patent numbers, titles, and filing dates.
Use this when finding prior art or exploring
a technology landscape without a specific number.
Use legal_fetch_patent_by_number instead when
you have the patent number already.
Verified source: EPO OPS + USPTO. 24-hour cache.
"""

legal_fetch_patent_citations:
"""
Fetch forward and backward citation chains for
a specific patent. Read-only. No side effects.
Idempotent.
patent_number: Patent number in jurisdiction
format e.g. EP1000000, US10000000. Required.
jurisdiction: One of EP, US, or WO. Optional.
Default EP.
Returns citing patents (forward citations) and
cited patents (backward citations) with filing
dates and titles.
Use this when building a prior art citation chain
for a specific patent you already have.
Use legal_search_patents_by_keyword instead when
you need to find patents by topic not by citation.
Verified source: EPO OPS. 24-hour cache.
"""

legal_fetch_inventor_portfolio:
"""
Fetch the patent portfolio for a named inventor
with optional assignee filter. Read-only. No side
effects. Idempotent.
inventor_name: Inventor surname or full name
e.g. Smith or John Smith. Required. Fuzzy match
— common names may return many results.
assignee: Company or organisation name to narrow
results e.g. Apple Inc. Optional.
Returns patent numbers, titles, filing dates,
jurisdictions, and current status.
Use this when researching an inventor's work or
a company's patent portfolio.
Use legal_search_patents_by_keyword instead when
you need patents by topic not by inventor.
Verified source: EPO OPS + USPTO. 24-hour cache.
"""

── GOVCON (t18.py) ──────────────────────────────────

govcon_search_contract_awards:
"""
Search government contract awards by keyword,
agency, and date range. Read-only. No side
effects. Idempotent.
keyword: Search terms describing the contract
scope e.g. cybersecurity software. Required.
agency: Awarding agency name e.g. Department of
Defense. Optional, defaults to all agencies.
date_from: Earliest award date in ISO 8601 format
e.g. 2024-01-31. Optional, defaults to all dates.
jurisdiction: One of US, EU, or UK. Optional.
Default US.
Returns award amounts, recipient vendors, NAICS
codes, and award dates.
Use this when exploring the competitive landscape
for a topic area.
Use govcon_fetch_vendor_contract_history instead
when you need all contracts for a specific vendor.
Use govcon_fetch_open_solicitations instead when
you need active bids not past awards.
Verified source: USASpending.gov + SAM.gov.
4-hour cache.
"""

govcon_fetch_vendor_contract_history:
"""
Fetch the complete federal contract award history
for a specific vendor. Read-only. No side effects.
Idempotent.
vendor_name: Company or organisation name e.g.
Booz Allen Hamilton. Required. Fuzzy match used.
jurisdiction: One of US, EU, or UK. Optional.
Default US.
Returns total award value, top awarding agencies,
contract types, and recent awards with amounts
and dates.
Use this when researching a specific company's
government contracting history.
Use govcon_search_contract_awards instead when
exploring a topic area without a specific vendor.
Verified source: USASpending.gov. 4-hour cache.
"""

govcon_fetch_open_solicitations:
"""
Fetch currently open government contract
solicitations matching a keyword. Read-only.
No side effects. Idempotent.
keyword: Description of goods or services sought
e.g. cloud computing services. Required.
Encode special characters — + becomes %2B.
agency: Awarding agency name. Optional, defaults
to all agencies.
jurisdiction: One of US, EU, or UK. Optional.
Default US.
Returns solicitation title, agency, response
deadline, estimated value, and NAICS code.
Use this when looking for active bid opportunities.
Use govcon_search_contract_awards instead when
you need historical awards not open solicitations.
Verified source: SAM.gov + USASpending.gov.
4-hour cache.
"""

── REGULATORY (t19.py) ──────────────────────────────

regulatory_search_open_rulemakings:
"""
Search open rulemakings and public comment periods
on Regulations.gov and the Federal Register.
Read-only. No side effects. Idempotent. US federal
only.
keyword: Topic keywords e.g. artificial
intelligence, data privacy. Required.
agency: Agency abbreviation e.g. FTC, FDA, SEC,
EPA. Optional, defaults to all agencies.
status: One of open, closed, or all. Optional.
Default open.
Returns docket title, agency, comment deadline,
docket ID, and document count.
Use this when monitoring regulatory activity
on a topic. Use regulatory_fetch_docket_details
instead when you have a docket ID and need full
detail.
Verified source: Regulations.gov + Federal
Register. 4-hour cache.
"""

regulatory_fetch_docket_details:
"""
Fetch full details for a specific regulatory
docket by ID. Read-only. No side effects.
Idempotent. US federal only.
docket_id: Docket identifier in agency format
e.g. EPA-HQ-OAR-2021-0317 or FTC-2024-0041.
Required. Timeout is 30 seconds — large dockets
may be slow.
Returns docket title, agency, status, comment
period dates, total comment count, and list of
related documents.
Use this when you have a docket ID from a search.
Use regulatory_search_open_rulemakings instead
when you need to find dockets by topic first.
Verified source: Regulations.gov + Federal
Register fallback. 4-hour cache.
"""

regulatory_fetch_federal_register_notices:
"""
Fetch recent Federal Register notices and rules
for a specific agency. Read-only. No side effects.
Idempotent. US federal only.
agency: Agency name or abbreviation e.g. SEC,
Food and Drug Administration, EPA. Required.
keyword: Optional topic filter e.g. cryptocurrency.
Optional, defaults to all notices.
date_from: Earliest publication date in ISO 8601
format e.g. 2024-01-31. Optional, defaults to
last 90 days.
Returns document type, title, publication date,
effective date, and CFR citations.
Use this to monitor recent regulatory activity
for an agency. Use regulatory_search_open_rulemakings
instead when filtering by topic across all agencies.
Verified source: Federal Register API. 4-hour cache.
"""

── SHARED TOOLS ─────────────────────────────────────

search_datanexus_tools (meta.py or main.py):
"""
Find the right DataNexus tool by describing your
task in plain English. Read-only. No side effects.
Call this before any other DataNexus tool to
reduce context load from 40000 to 800 tokens.
query: Plain English description of your task
e.g. check if a Python package has CVEs or
look up a UK charity by name. Required.
domain: Restrict results to one sub-server:
nonprofit, security, compliance, domain, legal,
govcon, or regulatory. Optional.
Returns matching tool names and parameter hints
you can call directly.
Do not call this recursively or to validate
results — use validate_tool_output for that.
"""

validate_tool_output (validation.py):
"""
Validate a DataNexus tool response for data
quality issues using two-layer validation:
deterministic rules first, then AI review for
ambiguous cases. Read-only. Never blocks.
tool_id: DataNexus tool identifier e.g. T04, T10,
T22. Required. Find in the tool_id field of any
response.
query_hash: Hash from the response you are
validating. Required. Enables feedback correlation.
response_json: Full tool response serialised as
a JSON string. Required.
Returns pass or issues_found, with issues from
each layer and whether feedback was auto-filed.
Both layers must agree before feedback is filed.
Use validate_tool_output to check data quality.
Use report_feedback instead to manually report
an issue you have already identified.
"""

report_feedback (feedback/collector.py):
"""
Report a data quality issue with a specific
DataNexus tool response. Read-only call.
Records feedback for human and AI review.
tool_id: Tool identifier e.g. T04. Required.
query_hash: Hash from the response being reported.
Required. Found in the query_hash field of any
response.
signal: One of incorrect_data, missing_field,
stale_data, not_useful, wrong_entity, or
data_quality. Required.
comment: Description of the issue. Optional.
Max 500 characters.
missing_fields: List of field names that are
absent or wrong. Optional.
Call this after receiving a result that appears
wrong, outdated, or incomplete. Do not call this
to report network errors — those resolve on retry.
"""

report_mcpize_link (payment/tools.py):
"""
Check subscription status and access tier for
DataNexus tools. Read-only. No side effects.
No parameters required.
Returns free or paid status, access tier, and
upgrade URL during the free window.
Call this when a user asks about pricing,
subscription status, or access limits.
Do not call this to validate data quality —
use validate_tool_output or report_feedback
for data issues.
"""

═══════════════════════════════════════════════════════
IMPLEMENTATION INSTRUCTIONS
═══════════════════════════════════════════════════════

For each tool file:

1. Find the @mcp.tool() decorator
2. Find the existing docstring (triple-quoted string
   at start of function body)
3. Replace the ENTIRE docstring with the new
   description from above
4. Do not change any other code in the function
5. Do not add parameters that do not exist in
   the function signature
6. Preserve the existing function signature exactly

Verify each file imports are unchanged:
  python3 -c "import datanexus.tools.t04; print('ok')"
  python3 -c "import datanexus.tools.t10; print('ok')"
  python3 -c "import datanexus.tools.t22; print('ok')"
  python3 -c "import datanexus.tools.t07; print('ok')"
  python3 -c "import datanexus.tools.t11; print('ok')"
  python3 -c "import datanexus.tools.t18; print('ok')"
  python3 -c "import datanexus.tools.t19; print('ok')"
All must print 'ok' with no errors.

═══════════════════════════════════════════════════════
DEPLOY AND VERIFY
═══════════════════════════════════════════════════════

After all descriptions are updated:

Step 1: Run existing tests — must stay green
  pytest feedback/tests/ -v -q
  pytest payment/tests/ -v -q
  Must show 84/84 green. Zero regressions.

Step 2: Commit
  git add datanexus/tools/t04.py \
           datanexus/tools/t10.py \
           datanexus/tools/t22.py \
           datanexus/tools/t07.py \
           datanexus/tools/t11.py \
           datanexus/tools/t18.py \
           datanexus/tools/t19.py \
           datanexus/tools/meta.py \
           datanexus/tools/validation.py \
           feedback/collector.py \
           payment/tools.py
  git commit -m "Improve Glama tool descriptions:
    read-only declarations, parameter constraints,
    geo scope, when-to-use guidance, fix contradictions
    in finra_broker and dns_records"
  git push

Step 3: Deploy to Hetzner
  ssh datanexus && cd /app/datanexus
  git pull
  docker compose build --no-cache datanexus-mcp
  docker compose up -d
  sleep 10
  docker compose ps
  curl -s https://datanexusmcp.com/health

Step 4: Verify descriptions are live
  SESSION=$(curl -s -X POST \
    https://datanexusmcp.com/mcp \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,
    "method":"initialize","params":{
    "protocolVersion":"2024-11-05",
    "capabilities":{},"clientInfo":{
    "name":"test","version":"1.0"}}}' \
    -D /tmp/h.txt -o /dev/null 2>/dev/null && \
    grep -i mcp-session /tmp/h.txt | \
    awk '{print $2}' | tr -d '\r')

  curl -s -X POST https://datanexusmcp.com/mcp \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Session-Id: $SESSION" \
    -d '{"jsonrpc":"2.0","id":2,
    "method":"tools/list","params":{}}' | \
    python3 -c "
  import sys, re, json
  c = sys.stdin.read()
  m = re.search(r'data: (.+)', c)
  if m:
    d = json.loads(m.group(1))
    tools = d.get('result',{}).get('tools',[])
    for t in tools:
      desc = t.get('description','')
      has_readonly = 'Read-only' in desc
      has_geo = any(x in desc for x in
        ['US only','UK only','EP only',
         'US federal','US, EU'])
      print(f'{\"OK\" if has_readonly else \"MISSING read-only\":20} '
            f'{t[\"name\"]}')
  "
  PASS if: all 30 tools show "OK" (Read-only present)

Step 5: Bump npm version and publish
  npm version patch
  npm publish
  git push && git push --tags

Step 6: Trigger Glama Build & Release
  Go to Glama admin → Dockerfile → Build & Release
  New scores should appear within 24-48 hours.

═══════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════

  □ All 30 tool docstrings updated
  □ Contradiction in compliance_fetch_finra_broker
    fixed — "name or CRD" removed, CRD only
  □ Contradiction in domain_fetch_dns_records
    fixed — record_types marked as Required
  □ All tools contain "Read-only. No side effects."
  □ All geographically restricted tools state scope
  □ All tools have when-to-use + when-NOT-to-use
  □ All parameters explained with format and example
  □ validate_tool_output has no marketing phrases
  □ 84/84 existing tests green
  □ Deployed to Hetzner — 4 containers Up
  □ Live verify confirms Read-only in all 30
  □ npm patch version published
  □ Glama Build & Release triggered

Expected score improvement:
  Current average: 3.93 / 5.0
  Target average:  4.5+ / 5.0
  Lowest tool (compliance_fetch_finra_broker):
    Current 3.3 → Target 4.5+
