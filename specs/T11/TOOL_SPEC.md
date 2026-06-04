# Tool: T11 — Global Patent Intelligence
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **EPO OPS (Open Patent Services)** — ops.epo.org/3.2 — OAuth client_credentials; `EPO_OPS_KEY` + `EPO_OPS_SECRET` from env; 4 GB/month free tier
- **USPTO PatentsView** — api.patentsview.org — no key; US patent open API
- **WIPO PATENTSCOPE** — patentscope.wipo.int/search/api — no key; international patent search
- ToS commercial use confirmed: YES (EPO OPS commercial licence; PatentsView open data; WIPO public API)
- EPO free tier limit: 4 GB/month — circuit breaker trips at 3.8 GB

### Signatures
```python
async def fetch_patent_by_number(patent_number: str) -> dict
async def search_patents_by_keyword(keywords: str,
                                    jurisdiction: str = "US",
                                    date_from: str = "",
                                    date_to: str = "") -> dict
async def fetch_patent_citations(patent_number: str) -> dict
async def fetch_inventor_portfolio(inventor_name: str,
                                   jurisdiction: str = "US") -> dict
```

**Return fields:** `status`, `tool_id`, `source_url`, `fetch_timestamp`,
`cache_hit`, `sha256_hash`, `data`, `markdown_output`, `disclaimer`,
`data_as_of`, `ingest_healthy`, `query_hash`

**upstream_fields (EPO OPS):** `publication-reference`, `bibliographic-data`,
`abstract`, `claims`, `description`, `patent-citation`, `applicants`, `inventors`

**upstream_fields (PatentsView):** `patent_id`, `patent_number`, `patent_title`,
`patent_date`, `patent_abstract`, `inventors`, `assignees`, `cpcs`, `citations`

**upstream_fields (WIPO):** `patentFamily`, `title`, `filingDate`, `publicationDate`,
`applicant`, `inventor`, `ipc`

### Hard stops
- Do NOT produce patent monetary assessments or patent valuation estimates
- Do NOT produce claims about patent scope, breadth, or enforceability
- Do NOT state or imply ownership suitability or licensing recommendations
- Do NOT provide legal advice or opinions on patent validity against any third party
- NEVER characterise whether a patent is infringed or would be infringed
- EPO OPS: circuit breaker trips at 3.8 GB/month — never bypass the limit counter

### Known gaps
- EPO OPS token refresh required every 20 minutes — handled internally; cold-start adds ~300ms
- PatentsView updated quarterly; recent grants (< 3 months) may be absent
- WIPO PATENTSCOPE search covers PCT applications; national-phase-only filings may be missing
- `fetch_inventor_portfolio` returns up to 100 patents; prolific inventors may be truncated

### Cache TTL
- All T11 tools: 86400s (24 hours) — patent data is stable reference data

### Acceptance criteria
- `fetch_patent_by_number("US10000000")` returns `status=ok`, `data.title` non-empty
- `search_patents_by_keyword("machine learning", jurisdiction="US")` returns `data.results` list
- `fetch_patent_citations("US10000000")` returns `data.forward_citations` and `data.backward_citations` lists
- `fetch_inventor_portfolio("Nikola Tesla")` returns `data.patents` list (may be empty)
- All tools return structured error dict on upstream failure — no exceptions propagate
- Cache hit on second identical call verified via `cache_hit=true`
- No patent valuation, legal advice, or infringement analysis in any response field
- EPO byte counter increments on each live call; does not increment on cache hit
