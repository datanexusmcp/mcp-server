# Tool: T04 — IRS 990 / Nonprofit Data
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **IRS EO BMF** — irs.gov/pub/irs-soi/eo{1-4}.csv — public domain, no key
- **IRS TEOS** — bulk downloads, irs.gov — public domain, no key
- **UK Charity Commission** — ccewuksprdoneregsadata1.blob.core.windows.net — Open Government Licence v3.0, commercial use permitted with UK GDPR mitigation; no auth required
- Auth: none for all three sources
- ToS commercial use confirmed: YES (IRS public domain; UK OGL v3.0 with GDPR controller statement)
- Free tier: unlimited (public bulk data)

### Signatures
```python
async def fetch_nonprofit_by_ein(ein: str) -> dict
async def search_nonprofits_by_name(name: str, state: str = "") -> dict
async def fetch_charity_uk(charity_number_or_name: str) -> dict
```

**Return fields (all three tools):**
`status`, `tool_id`, `source_url`, `fetch_timestamp`, `cache_hit`, `staleness_notice`,
`sha256_hash`, `data`, `markdown_output`, `disclaimer`, `data_as_of`, `ingest_healthy`,
`query_hash`, `retry_after`

**upstream_fields (IRS BMF):** `EIN`, `NAME`, `STREET`, `CITY`, `STATE`, `ZIP`,
`NTEE_CD`, `RULING`, `SUBSECTION`, `STATUS`, `TAX_PERIOD`, `ASSET_AMT`,
`INCOME_AMT`, `REVENUE_AMT`

**upstream_fields (UK Charity):** `charity_number`, `name`, `status`,
`registration_date`, `income`, `expenditure`, `activities`, `web`

### Hard stops
- IRS direct sources only — no third-party aggregators (CC-NC restricted)
- NEVER return trustee names, officer details, or personal addresses
- NEVER add donor data, individual giving history, or donation amounts
- UK charity cache TTL is 86400s (24h) — UK GDPR maximum; never reduce
- UK GDPR controller statement MUST appear in all UK charity responses
- NEVER transition FeedbackRecord backwards to `pending` state

### Known gaps
- IRS BMF updated monthly; data can lag up to 30 days after filing
- TEOS full-text 990s not indexed — financial summary only from BMF
- UK bulk extract refreshed weekly; mid-week changes not reflected
- `search_nonprofits_by_name` streams all 4 BMF CSVs — slow on cold cache (~45s)

### Cache TTL
- IRS BMF: 604800s (7 days)
- UK Charity: 86400s (24h) — UK GDPR maximum, non-negotiable
- Archive copy: TTL × 4 (staleness fallback when circuit open)

### Acceptance criteria
- `fetch_nonprofit_by_ein("131788491")` returns `status=ok`, `data.ein` present, `ingest_healthy=true`
- `search_nonprofits_by_name("Red Cross", state="NY")` returns `data.count >= 1`
- `fetch_charity_uk("1043420")` returns `disclaimer` containing "Open Government Licence"
- All three tools return structured error dict (not exception) when upstream is down
- Cache hit on second identical call — upstream not contacted
- No stack traces, no internal paths in any error output
- Rate limit 429 returned with `Retry-After` header on breach
- UK response always includes `data_as_of` and GDPR controller statement
