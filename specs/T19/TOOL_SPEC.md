# Tool: T19 — Regulatory Docket & Comment Tracking
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **Regulations.gov API** — api.regulations.gov/v4 — `REGULATIONS_GOV_KEY` from env; 1,000 req/day free tier
- **Federal Register API** — federalregister.gov/api/v1 — no key required
- **EU Have Your Say** — ec.europa.eu/info/law/better-regulation/have-your-say/api — no key
- ToS commercial use confirmed: YES (all three are open government data APIs)
- Rate limits: Regulations.gov 1,000 req/day; Federal Register undocumented; EU HYS undocumented

### Signatures
```python
async def search_open_rulemakings(keyword: str = "",
                                   agency: str = "",
                                   jurisdiction: str = "US") -> dict
async def fetch_docket_details(docket_id: str) -> dict
async def fetch_federal_register_notices(agency: str = "",
                                          document_type: str = "",
                                          keyword: str = "",
                                          date_from: str = "") -> dict
```

**Return fields:** `status`, `tool_id`, `source_url`, `fetch_timestamp`,
`cache_hit`, `sha256_hash`, `data`, `markdown_output`, `disclaimer`,
`data_as_of`, `ingest_healthy`, `query_hash`

**upstream_fields (Regulations.gov):** `id`, `type`, `attributes.docketId`,
`attributes.title`, `attributes.agencyId`, `attributes.docketType`,
`attributes.modifyDate`, `attributes.commentCount`

**upstream_fields (Federal Register):** `document_number`, `title`,
`abstract`, `agencies`, `type`, `publication_date`, `comments_close_on`,
`full_text_xml_url`, `docket_ids`

**upstream_fields (EU HYS):** `id`, `shortTitle`, `reference`, `status`,
`legalBasis`, `openForFeedback`, `feedbackDeadline`, `responsibleUnit`

### Hard stops
- Do NOT add regulatory impact analysis on any party or entity
- Do NOT provide legal direction about what a rule requires or prohibits
- Do NOT characterise rule scope for any specific entity or industry
- Do NOT add compliance guidance — legal advisory territory
- Regulations.gov ingest worker runs at 21600s (6h) intervals — never reduce; stay within 1,000 req/day
- NEVER bypass the daily request counter or reset it mid-day

### Known gaps
- Regulations.gov API key required; without key, tool returns Federal Register data only with note
- Federal Register full-text XML not parsed — abstract and metadata only
- EU HYS initiatives in non-English languages returned without translation
- `fetch_docket_details` returns top 25 comments only; full comment export not supported

### Cache TTL
- All T19 tools: 14400s (4 hours)

### Acceptance criteria
- `search_open_rulemakings(agency="EPA", jurisdiction="US")` returns `status=ok`, `data.rulemakings` list
- `fetch_docket_details("EPA-HQ-OAR-2021-0317")` returns `data.title` non-empty and `data.comments` list
- `fetch_federal_register_notices(agency="FTC", document_type="Proposed Rule")` returns `data.notices` list
- All tools return structured error dict on upstream failure — no exceptions propagate
- Cache hit on second identical call verified via `cache_hit=true`
- No compliance guidance, legal direction, or regulatory impact analysis in any response field
- Regulations.gov calls degrade gracefully when key absent — Federal Register fallback with note
