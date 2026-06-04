# DataNexus MCP — Sprint 3 Claude Code Prompts
# Version: Sprint 3 | May 2026
# Place alongside DataNexus_MCP_Spec_v7_5.docx and CLAUDE.md
#
# RULES:
# 1. Read CLAUDE.md before every prompt session
# 2. Run P01 → P10 sequentially — never skip
# 3. Definition of Done for each prompt must PASS before starting the next
# 4. Zero new tools — only the 29 live tools are in scope
#
# 29 TOOLS IN SCOPE:
# T04: fetch_nonprofit_by_ein, search_nonprofits_by_name, fetch_charity_uk
# T10: fetch_package_vulnerabilities, fetch_dependency_graph, fetch_cve_detail,
#      audit_sbom_vulnerabilities, fetch_package_licence
# T22: fetch_npi_provider, search_npi_by_name, fetch_finra_broker, check_sam_exclusion
# T07: fetch_domain_rdap, fetch_ssl_certificate_chain, fetch_dns_records, fetch_domain_history
# T11: fetch_patent_by_number, search_patents_by_keyword, fetch_patent_citations,
#      fetch_inventor_portfolio
# T18: search_contract_awards, fetch_vendor_contract_history, fetch_open_solicitations
# T19: search_open_rulemakings, fetch_docket_details, fetch_federal_register_notices
# Shared: report_feedback, report_mcpize_link, validate_tool_output

---

## P01 — Regroup 26 Data Tools into 7 FastMCP Sub-Servers
**Track 1 | Days 1-2 | Prerequisite: None**

Read CLAUDE.md first. Then execute exactly.

Create 7 FastMCP sub-server files. Move @mcp.tool() registrations only.
Do NOT change any tool logic, signatures, Redis keys, or return types.

```
datanexus/tools/nonprofit.py   → FastMCP("DataNexus Nonprofit")
  fetch_nonprofit_by_ein(ein: str) -> dict
  search_nonprofits_by_name(name: str, state: str = "") -> dict
  fetch_charity_uk(charity_number_or_name: str) -> dict

datanexus/tools/security.py    → FastMCP("DataNexus Security")
  fetch_package_vulnerabilities(package: str, version: str, ecosystem: str) -> dict
  fetch_dependency_graph(package: str, version: str, ecosystem: str) -> dict
  fetch_cve_detail(cve_id: str) -> dict
  audit_sbom_vulnerabilities(sbom_json: str) -> dict
  fetch_package_licence(package: str, version: str, ecosystem: str) -> dict

datanexus/tools/compliance.py  → FastMCP("DataNexus Compliance")
  fetch_npi_provider(npi_number: str) -> dict
  search_npi_by_name(name: str, state: str = "", specialty: str = "") -> dict
  fetch_finra_broker(name_or_crd: str) -> dict
  check_sam_exclusion(name_or_ein: str) -> dict

datanexus/tools/domain.py      → FastMCP("DataNexus Domain")
  fetch_domain_rdap(domain: str) -> dict
  fetch_ssl_certificate_chain(domain: str) -> dict
  fetch_dns_records(domain: str, record_type: str = "ALL") -> dict
  fetch_domain_history(domain: str) -> dict

datanexus/tools/legal.py       → FastMCP("DataNexus Legal")
  fetch_patent_by_number(patent_number: str, jurisdiction: str = "US") -> dict
  search_patents_by_keyword(keywords: str, jurisdiction: str = "US") -> dict
  fetch_patent_citations(patent_number: str, jurisdiction: str = "US") -> dict
  fetch_inventor_portfolio(inventor_name: str, assignee: str = "") -> dict

datanexus/tools/govcon.py      → FastMCP("DataNexus GovCon")
  search_contract_awards(keyword: str, agency: str = "", date_range: str = "") -> dict
  fetch_vendor_contract_history(vendor_name: str) -> dict
  fetch_open_solicitations(keyword: str) -> dict

datanexus/tools/regulatory.py  → FastMCP("DataNexus Regulatory")
  search_open_rulemakings(keyword: str, agency: str = "") -> dict
  fetch_docket_details(docket_id: str) -> dict
  fetch_federal_register_notices(agency: str, date_range: str = "") -> dict
```

Update datanexus/main.py:
```python
from fastmcp import FastMCP
from datanexus.tools.nonprofit  import nonprofit
from datanexus.tools.security   import security
from datanexus.tools.compliance import compliance
from datanexus.tools.domain     import domain
from datanexus.tools.legal      import legal
from datanexus.tools.govcon     import govcon
from datanexus.tools.regulatory import regulatory
from feedback.collector         import report_feedback
from payment.tools              import report_mcpize_link
from feedback.agents.master     import validate_tool_output

main = FastMCP("DataNexus MCP")
main.mount(nonprofit,   namespace="nonprofit")
main.mount(security,    namespace="security")
main.mount(compliance,  namespace="compliance")
main.mount(domain,      namespace="domain")
main.mount(legal,       namespace="legal")
main.mount(govcon,      namespace="govcon")
main.mount(regulatory,  namespace="regulatory")
main.tool()(report_feedback)
main.tool()(report_mcpize_link)
main.tool()(validate_tool_output)
main.run(transport="streamable-http")
```

### Definition of Done — P01
```bash
pytest -v --tb=short
# Expected: same pass count as before — zero new failures

ls datanexus/tools/{nonprofit,security,compliance,domain,legal,govcon,regulatory}.py
# Expected: all 7 files present

python3 -c "
import asyncio
from datanexus.main import main
tools = asyncio.run(main.get_tools())
names = [t.name for t in tools]
assert len(tools) == 29, f'Expected 29, got {len(tools)}'
for ns in ['nonprofit_','security_','compliance_','domain_','legal_','govcon_','regulatory_']:
    assert any(n.startswith(ns) for n in names), f'Missing namespace: {ns}'
for sh in ['report_feedback','report_mcpize_link','validate_tool_output']:
    assert sh in names, f'Missing shared tool: {sh}'
print(f'PASS — {len(tools)} tools, all namespaces present')
"
```

---

## P02 — Add search_datanexus_tools Meta-Tool
**Track 1 | Day 2 | Prerequisite: P01 DONE**

Read CLAUDE.md first. Then execute exactly.

Create datanexus/tools/meta.py. Implement search_datanexus_tools using
keyword overlap scoring against the task descriptions below. Log every
query as INCR to Redis key analytics:search:{YYYY-MM-DD} — never store
raw query text.

TOOL_REGISTRY entries (use exactly these task descriptions):
```python
TOOL_REGISTRY = [
  {"name":"nonprofit_fetch_nonprofit_by_ein",      "task":"research a US charity or nonprofit by EIN number"},
  {"name":"nonprofit_search_nonprofits_by_name",   "task":"search for nonprofits or charities by organisation name"},
  {"name":"nonprofit_fetch_charity_uk",            "task":"look up a UK registered charity by number or name"},
  {"name":"security_fetch_package_vulnerabilities","task":"check a software package for known CVEs and security vulnerabilities"},
  {"name":"security_fetch_dependency_graph",       "task":"get the full dependency tree for a software package"},
  {"name":"security_fetch_cve_detail",             "task":"get full detail on a specific CVE vulnerability by ID"},
  {"name":"security_audit_sbom_vulnerabilities",   "task":"audit a software bill of materials for known vulnerabilities"},
  {"name":"security_fetch_package_licence",        "task":"check the open source licence for a package version"},
  {"name":"compliance_fetch_npi_provider",         "task":"verify a US healthcare provider by NPI number"},
  {"name":"compliance_search_npi_by_name",         "task":"search for a healthcare provider by name and state"},
  {"name":"compliance_fetch_finra_broker",         "task":"verify a financial broker or advisor registration with FINRA"},
  {"name":"compliance_check_sam_exclusion",        "task":"check whether a person or company is excluded from federal contracting"},
  {"name":"domain_fetch_domain_rdap",              "task":"look up domain registration and ownership details"},
  {"name":"domain_fetch_ssl_certificate_chain",    "task":"inspect the SSL certificate chain for a domain"},
  {"name":"domain_fetch_dns_records",              "task":"get DNS records for a domain"},
  {"name":"domain_fetch_domain_history",           "task":"get historical SSL certificate records for a domain"},
  {"name":"legal_fetch_patent_by_number",          "task":"look up a specific patent by number across US EP or WO"},
  {"name":"legal_search_patents_by_keyword",       "task":"search for patents by keyword to find prior art"},
  {"name":"legal_fetch_patent_citations",          "task":"get forward and backward citation chains for a patent"},
  {"name":"legal_fetch_inventor_portfolio",        "task":"get all patents filed by a specific inventor or assignee"},
  {"name":"govcon_search_contract_awards",         "task":"search government contract awards by keyword or agency"},
  {"name":"govcon_fetch_vendor_contract_history",  "task":"get the full government contract history for a specific vendor"},
  {"name":"govcon_fetch_open_solicitations",       "task":"find currently open government procurement opportunities"},
  {"name":"regulatory_search_open_rulemakings",    "task":"find open regulatory rulemakings and comment periods"},
  {"name":"regulatory_fetch_docket_details",       "task":"get full details for a specific regulatory docket by ID"},
  {"name":"regulatory_fetch_federal_register_notices","task":"fetch recent Federal Register notices for an agency"},
]
```

Docstring must be exactly:
```
Use this to find the right DataNexus tool for your task.
Call this FIRST before any other DataNexus tool.
Provide a plain-language description of what you need.
Returns matching tool names you can call directly.

Examples:
  search_datanexus_tools("research a nonprofit organisation")
  search_datanexus_tools("check package for security vulnerabilities")
  search_datanexus_tools("verify a doctor NPI number")
  search_datanexus_tools("find government contracts awarded to a vendor")
  search_datanexus_tools("look up a patent", domain="legal")
```

Add to main.py (no namespace):
```python
from datanexus.tools.meta import search_datanexus_tools
main.tool()(search_datanexus_tools)
```

### Definition of Done — P02
```bash
python3 -c "
import asyncio
from datanexus.tools.meta import search_datanexus_tools

CASES = [
  ('research a nonprofit organisation',          'nonprofit'),
  ('check package for security vulnerabilities', 'security'),
  ('verify a doctor NPI number',                 'compliance'),
  ('find government contracts for a vendor',     'govcon'),
  ('search for patent prior art',                'legal'),
  ('check domain registration',                  'domain'),
  ('find open regulatory rulemakings',           'regulatory'),
]
async def test():
    for query, expected in CASES:
        r = await search_datanexus_tools(query)
        names = [t['name'] for t in r.get('tools',[])]
        ok = any(expected in n for n in names)
        print(f'  {"PASS" if ok else "FAIL"}: {query!r} -> {names[:2]}')
asyncio.run(test())
"
# Expected: PASS for all 7 cases

python3 -c "
import asyncio, redis
from datetime import date
from datanexus.tools.meta import search_datanexus_tools
asyncio.run(search_datanexus_tools('test query'))
r = redis.from_url('redis://localhost:6379', decode_responses=True)
v = r.get(f'analytics:search:{date.today().isoformat()}')
assert v and int(v) >= 1, 'Analytics counter not written'
print('Analytics counter: PASS')
"

python3 -c "
import asyncio
from datanexus.main import main
tools = asyncio.run(main.get_tools())
assert len(tools) == 30, f'Expected 30 (29+meta), got {len(tools)}'
print(f'Total tools: {len(tools)} — PASS')
"
```

---

## P03 — Rewrite All 26 Data Tool Descriptions
**Track 1 | Day 3 | Prerequisite: P02 DONE**

Read CLAUDE.md first. Then execute exactly.

Rewrite the docstring of every @mcp.tool() handler across all 7 sub-server files.
Rules: (1) Start with "Use this to" — user task not data source name.
(2) Input sentence. (3) Output sentence. (4) Under 300 characters total.
Do NOT change any function signatures or logic.

Apply these exact docstrings:

```
fetch_nonprofit_by_ein:
"Use this to research a US charity or nonprofit by EIN number.
Provide the EIN with or without dash. Returns financial history,
revenue, expenses, assets, and IRS registration status."

search_nonprofits_by_name:
"Use this to find US nonprofits by organisation name.
Provide a full or partial name and optional state code.
Returns up to 25 matches with EINs for precise lookup."

fetch_charity_uk:
"Use this to look up a UK registered charity by number or name.
Provide the charity number or organisation name.
Returns income, activities, and registration details."

fetch_package_vulnerabilities:
"Use this to check whether a software package has known security vulnerabilities.
Provide package name, version, and ecosystem (npm, PyPI, or Maven).
Returns CVE IDs, severity scores, and available patch versions."

fetch_dependency_graph:
"Use this to get the full dependency tree for a software package.
Provide package name, version, and ecosystem.
Returns all direct and transitive dependencies."

fetch_cve_detail:
"Use this to get full detail on a specific CVE by its identifier.
Provide the CVE ID such as CVE-2021-44228.
Returns severity, CVSS score, affected versions, and fix information."

audit_sbom_vulnerabilities:
"Use this to audit a software bill of materials for known vulnerabilities.
Provide a CycloneDX or SPDX SBOM as a JSON string.
Returns all CVEs found across every listed component."

fetch_package_licence:
"Use this to check the licence for an open source package version.
Provide package name, version, and ecosystem.
Returns the declared licence identifier such as MIT or Apache-2.0."

fetch_npi_provider:
"Use this to verify a US healthcare provider by their NPI number.
Provide the 10-digit NPI number.
Returns provider name, credential, speciality, and active status."

search_npi_by_name:
"Use this to find a healthcare provider by name when you do not have their NPI.
Provide name and optional state or speciality.
Returns matching providers with NPI numbers for precise lookup."

fetch_finra_broker:
"Use this to verify a financial broker or advisor is registered with FINRA.
Provide their name or CRD number.
Returns registration status, licences held, and disclosure history."

check_sam_exclusion:
"Use this to check whether a person or company is excluded from US federal contracting.
Provide their name or EIN.
Returns whether they appear on the SAM.gov exclusions list."

fetch_domain_rdap:
"Use this to look up domain registration details and ownership.
Provide the domain name such as example.com.
Returns registrar, registration date, expiry date, and current status."

fetch_ssl_certificate_chain:
"Use this to inspect the SSL certificate chain for a domain.
Provide the domain name.
Returns certificate issuer, validity dates, and full chain detail."

fetch_dns_records:
"Use this to get DNS records for a domain.
Provide the domain name and optional record type such as A, MX, or TXT.
Returns all matching DNS records currently in effect."

fetch_domain_history:
"Use this to get historical SSL certificate records for a domain.
Provide the domain name.
Returns past certificates from Certificate Transparency logs."

fetch_patent_by_number:
"Use this to look up a specific patent by its number.
Provide the patent number and jurisdiction: US, EP, or WO.
Returns filing details, claims summary, inventor, and current assignee."

search_patents_by_keyword:
"Use this to search for patents by keyword to find prior art before filing.
Provide keywords and optional jurisdiction.
Returns matching patents with numbers, titles, and filing dates."

fetch_patent_citations:
"Use this to get citation chains for a specific patent.
Provide the patent number and jurisdiction.
Returns patents that cite this one and patents this one cites."

fetch_inventor_portfolio:
"Use this to get all patents filed by a specific inventor.
Provide the inventor name and optional assignee to narrow results.
Returns the full portfolio with filing dates and current status."

search_contract_awards:
"Use this to search government contract awards by keyword or agency.
Provide a keyword, optional agency name, and optional date range.
Returns matching awards with values, recipients, and award dates."

fetch_vendor_contract_history:
"Use this to get the complete government contract history for a vendor.
Provide the vendor or company name.
Returns all contracts awarded with amounts, agencies, and dates."

fetch_open_solicitations:
"Use this to find currently open government procurement opportunities.
Provide keywords describing what goods or services you are seeking.
Returns active solicitations with deadlines and agency contact details."

search_open_rulemakings:
"Use this to find open regulatory rulemakings and active comment periods.
Provide keywords and optional agency abbreviation such as EPA or SEC.
Returns active rulemakings with comment deadlines and docket IDs."

fetch_docket_details:
"Use this to get full details for a specific regulatory docket.
Provide the docket ID such as EPA-HQ-OAR-2021-0317.
Returns docket summary, documents list, and total comment count."

fetch_federal_register_notices:
"Use this to fetch recent Federal Register notices for a US agency.
Provide the agency name or abbreviation.
Returns recent notices with publication dates and document types."
```

Do not rewrite: report_feedback, report_mcpize_link, validate_tool_output,
search_datanexus_tools — those docstrings are already correct.

### Definition of Done — P03
```bash
python3 -c "
import ast, pathlib, sys
SKIP = {'report_feedback','report_mcpize_link','validate_tool_output','search_datanexus_tools'}
violations = []
for f in pathlib.Path('datanexus/tools').glob('*.py'):
    tree = ast.parse(f.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name not in SKIP:
            ds = ast.get_docstring(node) or ''
            if ds and not ds.strip().startswith('Use this to'):
                violations.append(f'{f.name}: {node.name}')
if violations:
    print('FAIL:'); [print(f'  {v}') for v in violations]; sys.exit(1)
print(f'PASS — all {26 - len(violations)} data tool docstrings task-first')
"

python3 -c "
import ast, pathlib, sys
SKIP = {'report_feedback','report_mcpize_link','validate_tool_output','search_datanexus_tools'}
long_ones = []
for f in pathlib.Path('datanexus/tools').glob('*.py'):
    tree = ast.parse(f.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name not in SKIP:
            ds = ast.get_docstring(node) or ''
            if len(ds) > 300:
                long_ones.append(f'{f.name}: {node.name} ({len(ds)} chars)')
if long_ones:
    print('FAIL:'); [print(f'  {l}') for l in long_ones]; sys.exit(1)
print('PASS — all docstrings under 300 chars')
"
```

---

## P04 — Hard Timeout on All 26 Tool Handlers
**Track 2 | Day 4 | Prerequisite: P03 DONE**

Read CLAUDE.md first. Then execute exactly.

Create datanexus/core/timeout.py:
```python
import asyncio, functools

TOOL_TIMEOUT_SECONDS = 8.0

def with_timeout(fn):
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await asyncio.wait_for(fn(*args, **kwargs),
                                          timeout=TOOL_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            return {"status":"error","error_code":"upstream_timeout",
                    "message":"Data source did not respond in time. Try again shortly.",
                    "retry_after":30,"query_hash":None,
                    "ingest_healthy":False,"schema_version":"1.0","data_as_of":None}
    return wrapper
```

Apply to every @mcp.tool() handler in all 7 sub-server files.
Decorator order (top to bottom):
```python
@server.tool()
@with_timeout
async def fetch_nonprofit_by_ein(ein: str) -> dict:
```

Then measure fetch_dependency_graph warm-cache p99:
```bash
python3 -c "
import asyncio, time
from datanexus.tools.security import fetch_dependency_graph
times = [asyncio.run(fetch_dependency_graph('lodash','4.17.21','npm'))
         and (_ := time.monotonic()) for _ in range(5)]
"
```
If p99 > 2000ms: remove fetch_dependency_graph from security.py and add
to /app/specs/T10/TOOL_SPEC.md known_gaps:
  "fetch_dependency_graph: removed v1.0 — p99 exceeds 2s threshold. Target v1.1."

### Definition of Done — P04
```bash
python3 -c "
import asyncio
from datanexus.core.timeout import with_timeout, TOOL_TIMEOUT_SECONDS
async def slow(): await asyncio.sleep(TOOL_TIMEOUT_SECONDS + 1)
r = asyncio.run(with_timeout(slow)())
assert r['error_code'] == 'upstream_timeout'
assert r['retry_after'] == 30
assert r['ingest_healthy'] == False
print('Timeout decorator: PASS')
"

python3 -c "
import ast, pathlib, sys
SKIP = {'report_feedback','report_mcpize_link','validate_tool_output','search_datanexus_tools'}
missing = []
for f in pathlib.Path('datanexus/tools').glob('*.py'):
    if 'with_timeout' not in f.read_text(): continue
    for node in ast.walk(ast.parse(f.read_text())):
        if isinstance(node, ast.AsyncFunctionDef) and node.name not in SKIP:
            decs = [ast.unparse(d) for d in node.decorator_list]
            if any('tool' in d for d in decs) and not any('timeout' in d for d in decs):
                missing.append(f'{f.name}:{node.name}')
if missing:
    print('FAIL:'); [print(f'  {m}') for m in missing]; sys.exit(1)
print('PASS — with_timeout on all handlers')
"

python3 scripts/measure_p99.py --tools T04 T10 T22 T07 --calls 3 --threshold 3000
# Expected: PASS for all tools
```

---

## P05 — Circuit Breaker and Cache Pre-Warm
**Track 2 | Day 5 | Prerequisite: P04 DONE**

Read CLAUDE.md first. Then execute exactly.

Create datanexus/core/circuit_breaker.py:
```python
import time
import redis.asyncio as aioredis

FAILURE_THRESHOLD = 3
FAILURE_WINDOW_S  = 60
RESET_TIMEOUT_S   = 30

async def is_circuit_open(r, tool_id: str, upstream: str) -> bool:
    state = await r.hgetall(f"circuit:{tool_id}:{upstream}")
    if not state: return False
    if state.get("state") == "open":
        if time.time() - float(state.get("opened_at",0)) > RESET_TIMEOUT_S:
            await r.hset(f"circuit:{tool_id}:{upstream}", "state", "half-open")
            return False
        return True
    return False

async def record_failure(r, tool_id: str, upstream: str):
    fails_key = f"circuit:fails:{tool_id}:{upstream}"
    count = await r.incr(fails_key)
    await r.expire(fails_key, FAILURE_WINDOW_S)
    if count >= FAILURE_THRESHOLD:
        await r.hset(f"circuit:{tool_id}:{upstream}",
                     mapping={"state":"open","opened_at":str(time.time())})

async def record_success(r, tool_id: str, upstream: str):
    await r.hset(f"circuit:{tool_id}:{upstream}", "state", "closed")
    await r.delete(f"circuit:fails:{tool_id}:{upstream}")
```

Integrate into ingest base class: when circuit open, return stale cached
value with ingest_healthy=False instead of calling upstream.

Create datanexus/core/prewarm.py to pre-fetch these queries on startup:
```python
SEED = {
  "T04": [("fetch_nonprofit_by_ein","13-1788491"),
          ("fetch_nonprofit_by_ein","23-7363942"),
          ("fetch_nonprofit_by_ein","04-2103594")],
  "T10": [("fetch_package_vulnerabilities","lodash:4.17.21:npm"),
          ("fetch_cve_detail","CVE-2021-44228"),
          ("fetch_package_licence","express:4.18.2:npm")],
}
```

Register prewarm as FastMCP lifespan in main.py. Errors in prewarm
must be silently swallowed — never block server startup.

### Definition of Done — P05
```bash
python3 -c "
import asyncio, redis.asyncio as aioredis
from datanexus.core.circuit_breaker import record_failure, is_circuit_open, record_success
async def test():
    r = aioredis.from_url('redis://localhost:6379', decode_responses=True)
    await r.delete('circuit:T04:test','circuit:fails:T04:test')
    for _ in range(3): await record_failure(r,'T04','test')
    assert await is_circuit_open(r,'T04','test'), 'Circuit did not open'
    await record_success(r,'T04','test')
    assert not await is_circuit_open(r,'T04','test'), 'Circuit did not close'
    await r.aclose()
    print('Circuit breaker: PASS')
asyncio.run(test())
"

python3 -c "
import asyncio
from datanexus.core.prewarm import prewarm_cache
asyncio.run(prewarm_cache(['T04','T10']))
import redis
r = redis.from_url('redis://localhost:6379', decode_responses=True)
keys = r.keys('cache:T04:*')
assert len(keys) > 0, 'No T04 cache keys after prewarm'
print(f'Pre-warm: PASS — {len(keys)} T04 keys cached')
"
```

---

## P06 — Code Review Script and Gate
**Track 3 | Day 6 | Prerequisite: P05 DONE**

Read CLAUDE.md first. Then execute exactly.

Create scripts/code_review.sh, make it executable, run it, fix every
violation, and re-run until it outputs CODE REVIEW: PASS.

```bash
#!/bin/bash
# scripts/code_review.sh — run before handing to QA
DIR=${1:-datanexus}
FAIL=0
echo "=== DataNexus Code Review === $(date -u +%FT%TZ)"

echo "--- [1/6] Secrets scan"
detect-secrets scan $DIR --baseline .secrets.baseline --only-allowlisted || FAIL=1

echo "--- [2/6] Bandit security lint"
bandit -r $DIR -ll -q || FAIL=1

echo "--- [3/6] Forbidden patterns"
for p in "lru_cache" "import psycopg2" "from psycopg2"; do
  grep -rn "$p" $DIR && { echo "FAIL: $p found"; FAIL=1; } || true
done

echo "--- [4/6] Required patterns in handlers"
for f in $(grep -rl "@.*\.tool()" $DIR 2>/dev/null); do
  for req in "AuditContext" "standard_response_fields" "with_timeout"; do
    grep -q "$req" "$f" || { echo "FAIL: $f missing $req"; FAIL=1; }
  done
done

echo "--- [5/6] No hardcoded Redis keys"
grep -rn '"fb:' $DIR | grep -v "config.py\|#\|key_" && FAIL=1 || true

echo "--- [6/6] Ruff lint"
ruff check $DIR --quiet || FAIL=1

echo ""
[ $FAIL -eq 0 ] && echo "CODE REVIEW: PASS" || { echo "CODE REVIEW: FAIL"; exit 1; }
```

### Definition of Done — P06
```bash
test -x scripts/code_review.sh && echo "Executable: PASS"

bash scripts/code_review.sh datanexus/
# Final line must be exactly: CODE REVIEW: PASS
# Exit code must be 0: echo $? → 0
```

---

## P07 — Golden Dataset Accuracy Tests
**Track 4 | Day 7 | Prerequisite: P06 DONE**

Read CLAUDE.md. Read /app/specs/T04/TOOL_SPEC.md. Read /app/specs/T10/TOOL_SPEC.md.

Create scripts/accuracy_test.py. Calls live tool functions directly.
Uses asyncio.gather for parallelism. Must finish under 120 seconds.

T04 golden dataset — 10 EINs:
```python
T04_CASES = [
  ("13-1788491", lambda r: "Red Cross" in r.get("name","") and r.get("revenue",0) > 1_000_000_000),
  ("23-7363942", lambda r: "Doctors" in r.get("name","")),
  ("13-3433555", lambda r: "Human Rights" in r.get("name","")),
  ("52-1693387", lambda r: any(x in r.get("name","") for x in ["Public Radio","NPR"])),
  ("04-2103594", lambda r: "Harvard" in r.get("name","") and r.get("assets",0) > 1_000_000_000),
  ("94-1156365", lambda r: "Stanford" in r.get("name","") and r.get("state","") == "CA"),
  ("53-0196605", lambda r: "Geographic" in r.get("name","")),
  ("31-4379948", lambda r: "Salvation" in r.get("name","") and r.get("revenue",0) > 100_000_000),
  ("13-5613797", lambda r: "YMCA" in r.get("name","")),
  ("82-4059863", lambda r: "GiveDirectly" in r.get("name","")),
]
```

T10 golden dataset — 8 CVEs:
```python
T10_CASES = [
  # (cve_id, package, version, ecosystem, assertion)
  ("CVE-2021-44228","log4j-core","2.14.1","Maven",
   lambda r: r.get("severity")=="CRITICAL" and r.get("cvss_score",0)>=9.0),
  ("CVE-2022-22965","spring-webmvc","5.3.17","Maven",
   lambda r: r.get("severity")=="CRITICAL"),
  ("CVE-2014-0160","openssl","1.0.1","",
   lambda r: r.get("severity") in ("HIGH","CRITICAL") and r.get("patched_version") is not None),
  ("CVE-2024-3400","panos","10.0.0","",
   lambda r: r.get("severity")=="CRITICAL"),
  ("CVE-2017-5638","struts2-core","2.3.34","Maven",
   lambda r: r.get("severity")=="CRITICAL"),
  # Error handling — must return dict, never raise
  ("CVE-2019-0708","windows-rdp","","",   lambda r: isinstance(r, dict)),
  ("CVE-2020-1472","windows-netlogon","","", lambda r: isinstance(r, dict)),
  ("CVE-2023-44487","any","","",          lambda r: isinstance(r, dict)),
]
```

Script must also warn if data_as_of is stale:
T04: warn if data_as_of > 14 days old (TTL is 7 days)
T10: warn if data_as_of > 2 hours old (TTL is 1 hour)

### Definition of Done — P07
```bash
python3 scripts/accuracy_test.py
# Expected output format:
# T04 [1/10] EIN 13-1788491: PASS
# ...
# T04 [10/10] EIN 82-4059863: PASS
# T10 [1/8] CVE-2021-44228: PASS
# ...
# T10 [8/8] CVE-2023-44487: PASS
# ACCURACY TEST: PASS
# Exit code: 0

time python3 scripts/accuracy_test.py | tail -1
# Expected: ACCURACY TEST: PASS in under 2 minutes
```

---

## P08 — SESSION_STARTER.md and 8 TOOL_SPEC.md Files
**Track 5 | Days 8-9 | Prerequisite: P07 DONE**

Read CLAUDE.md first. Then execute exactly.

Create SESSION_STARTER.md in repo root (under 500 words):

```markdown
# DataNexus MCP — Session Starter
# Read this first. Then read TOOL_SPEC.md for the tool in scope.
# Never load the full spec. Never build unapproved tools.

## Sprint status: Sprint 3 in progress → Sprint 4 after P10 passes

## 29 live tools — do not build new ones this sprint
T04 nonprofit_:   fetch_nonprofit_by_ein, search_nonprofits_by_name, fetch_charity_uk
T10 security_:    fetch_package_vulnerabilities, fetch_dependency_graph*, fetch_cve_detail,
                  audit_sbom_vulnerabilities, fetch_package_licence
T22 compliance_:  fetch_npi_provider, search_npi_by_name, fetch_finra_broker, check_sam_exclusion
T07 domain_:      fetch_domain_rdap, fetch_ssl_certificate_chain, fetch_dns_records, fetch_domain_history
T11 legal_:       fetch_patent_by_number, search_patents_by_keyword, fetch_patent_citations,
                  fetch_inventor_portfolio
T18 govcon_:      search_contract_awards, fetch_vendor_contract_history, fetch_open_solicitations
T19 regulatory_:  search_open_rulemakings, fetch_docket_details, fetch_federal_register_notices
Shared:           report_feedback, report_mcpize_link, validate_tool_output
* fetch_dependency_graph removed from v1.0 if p99 > 2s — check T10/TOOL_SPEC.md

## 5 hard rules
1. Glama score >= 8.5. Fail closed — structured error dict, never partial result.
2. Never change @verify_entitlement or billing code — human PR required.
3. Never store query content — params_hash only in audit logs.
4. Streamable HTTP only — never SSE (deprecated), never stdio for remote.
5. Run scripts/code_review.sh → PASS required before handing to QA.

## Session types (one per session, never combine)
Spec session:     SESSION_STARTER.md + TOOL_SPEC.md only (20 min)
Scaffold session: SESSION_STARTER.md + TOOL_SPEC.md + template (30 min)
Build session:    SESSION_STARTER.md + TOOL_SPEC.md + scaffold (45 min)
Test session:     SESSION_STARTER.md + TOOL_SPEC.md + source file (30 min)
Review session:   SESSION_STARTER.md + code_review.sh output (20 min)

## Infrastructure signatures (on every server)
search_datanexus_tools(), report_feedback(), report_mcpize_link(), validate_tool_output()
```

Create TOOL_SPEC.md for all 7 tools + 1 shared = 8 files at /app/specs/:
- /app/specs/T04/TOOL_SPEC.md
- /app/specs/T10/TOOL_SPEC.md
- /app/specs/T22/TOOL_SPEC.md
- /app/specs/T07/TOOL_SPEC.md
- /app/specs/T11/TOOL_SPEC.md
- /app/specs/T18/TOOL_SPEC.md
- /app/specs/T19/TOOL_SPEC.md
- /app/specs/SHARED/TOOL_SPEC.md

Each file must contain these sections (use only what is actually implemented):
### Data sources | ### Signatures | ### Hard stops | ### Known gaps |
### upstream_fields | ### Cache TTL | ### Acceptance criteria
Each file under 1500 words.

### Definition of Done — P08
```bash
test -f SESSION_STARTER.md && echo "Exists: PASS"
WORDS=$(wc -w < SESSION_STARTER.md); [ $WORDS -lt 500 ]   && echo "Words $WORDS: PASS" || echo "FAIL: $WORDS words — trim"

find /app/specs -name "TOOL_SPEC.md" | wc -l
# Expected: 8

python3 -c "
import pathlib, sys
req = ['### Data sources','### Signatures','### Hard stops','### Acceptance criteria']
fail = False
for spec in pathlib.Path('/app/specs').rglob('TOOL_SPEC.md'):
    c = spec.read_text()
    for r in req:
        if r not in c:
            print(f'FAIL: {spec.parent.name} missing {r!r}')
            fail = True
print('PASS' if not fail else 'Fix above failures')
sys.exit(1 if fail else 0)
"
```

---

## P09 — OAuth 2.1 Rule and MCP Manifest
**Track 6 | Day 10 | Prerequisite: P08 DONE**

Read CLAUDE.md first. Then execute exactly.

Append to CLAUDE.md:
```markdown
## OAuth 2.1 Requirements (Sprint 3)

Hard requirements before MCPIZE_ACTIVE=true:
- Token validation before @verify_entitlement on every paid call
- Tokens in Redis only: oauth:token:{session_id} with 1-hour TTL
- PKCE: S256 required — plain method MUST be rejected
- Token audience MUST be datanexusmcp.com (RFC 8707)
- Unauthenticated requests allowed ONLY when MCPIZE_ACTIVE=false
- MCPize is the AS — DataNexus validates tokens only, never issues them
- Implementation: Sprint 4

Builder hard stops:
- NEVER implement token issuance
- NEVER store tokens in module-level memory
- NEVER accept plain PKCE
- NEVER enforce OAuth when MCPIZE_ACTIVE=false
```

Create static/.well-known/mcp-manifest.json with:
- name, version (match npm), transport: "streamable-http"
- endpoint: "https://datanexusmcp.com/mcp"
- discovery_tool: "search_datanexus_tools"
- 7 tool_groups with namespace, tool_count, description, and tool names list
- 4 shared_tools list
- links: homepage, npm, github

Add route to serve manifest at /.well-known/mcp-manifest.json in main.py.

### Definition of Done — P09
```bash
grep -c "OAuth 2.1" CLAUDE.md
# Expected: >= 3

python3 -c "
import json
d = json.load(open('static/.well-known/mcp-manifest.json'))
assert d['transport'] == 'streamable-http'
assert d['discovery_tool'] == 'search_datanexus_tools'
assert len(d['tool_groups']) == 7
assert len(d['shared_tools']) == 4
total = sum(g['tool_count'] for g in d['tool_groups'])
print(f'Manifest PASS — {total} data tools, 4 shared')
"
```

---

## P10 — Full Re-Deploy and Sprint 3 Gate
**Track All | Day 10 | Prerequisite: P09 DONE**

Read CLAUDE.md first. Run all gates. Fix any failure. Then deploy.

```bash
echo "=== SPRINT 3 FINAL GATE ==="

echo "[1] Code review"
bash scripts/code_review.sh datanexus/

echo "[2] Accuracy test"
python3 scripts/accuracy_test.py

echo "[3] Full test suite"
pytest -v --tb=short -q

echo "[4] Tool structure"
python3 -c "
import asyncio
from datanexus.main import main
tools = asyncio.run(main.get_tools())
names = [t.name for t in tools]
assert len(tools) in (29,30), f'Expected 29-30, got {len(tools)}'
for ns in ['nonprofit_','security_','compliance_','domain_','legal_','govcon_','regulatory_']:
    assert any(n.startswith(ns) for n in names), f'Missing: {ns}'
print(f'PASS — {len(tools)} tools, all 7 namespaces present')
"

echo "[5] Meta-tool routing"
python3 -c "
import asyncio
from datanexus.tools.meta import search_datanexus_tools
CASES = [('research a nonprofit','nonprofit'),('check package vulnerabilities','security'),
         ('verify NPI number','compliance'),('government contracts for vendor','govcon'),
         ('patent prior art','legal'),('domain registration','domain'),
         ('open regulatory rulemakings','regulatory')]
async def test():
    for q, ns in CASES:
        r = await search_datanexus_tools(q)
        names = [t['name'] for t in r.get('tools',[])]
        ok = any(ns in n for n in names)
        print(f'  {"PASS" if ok else "FAIL"}: {q!r}')
asyncio.run(test())
"
```

Deploy only when all 5 gates above print PASS:
```bash
docker compose build --no-cache && docker compose up -d && docker compose ps
curl -s https://datanexusmcp.com/health
# Expected: {"status":"ok"}

# Set 14-day freeze — Publisher required step
python3 -c "
import redis, time
r = redis.from_url('redis://localhost:6379', decode_responses=True)
exp = int(time.time()) + 14*86400
for t in ['T04','T10','T22','T07','T11','T18','T19']:
    r.set(f'fb:freeze:{t}:v1.0', str(exp))
    print(f'Freeze: {t} 14 days')
"

# Rebuild Hetzner snapshot and update AUTOSCALE_SNAPSHOT_ID in .env
# Resubmit all 7 tool groups to Glama with new descriptions
```

### Definition of Done — P10 (Sprint 3 COMPLETE)
```bash
# Gates 1-5 all output PASS — verified above

# Criterion 10: first organic call (monitor 7 days post-deploy)
# Run daily:
python3 -c "
import redis
from datetime import date
r = redis.from_url('redis://localhost:6379', decode_responses=True)
today = date.today().isoformat()
found = False
for tool in ['T04','T10','T22','T07','T11','T18','T19']:
    n = r.get(f'dau:{tool}:v1.0:{today}')
    if n and int(n) > 0:
        print(f'Activity: {tool} — {n} calls today')
        found = True
if not found:
    print('No organic activity yet — check again tomorrow')
"
# Sprint 3 is fully complete when this shows activity on a day you did not test.
```
