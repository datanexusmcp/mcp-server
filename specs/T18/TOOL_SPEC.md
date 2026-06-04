# Tool: T18 — Government Contracting & Procurement
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **USASpending.gov** — api.usaspending.gov/api/v2 — no key required; built first as no-auth primary
- **SAM.gov Opportunities** — api.sam.gov/prod/opportunities/v2 — `SAM_GOV_API_KEY` from env
- **EU TED** — api.ted.europa.eu/v3 — no key; EU public procurement database
- **UK Find-a-Tender** — find-tender.service.gov.uk/api/1.0 — no key; UK procurement notices
- ToS commercial use confirmed: YES (all four are open government data APIs)
- USASpending: unlimited; SAM.gov: 450 req/hour; EU TED: undocumented; UK FAT: undocumented

### Signatures
```python
async def search_contract_awards(keyword: str = "", agency: str = "",
                                  recipient: str = "",
                                  date_from: str = "",
                                  date_to: str = "",
                                  jurisdiction: str = "US") -> dict
async def fetch_vendor_contract_history(vendor_name: str,
                                        jurisdiction: str = "US") -> dict
async def fetch_open_solicitations(keyword: str = "",
                                    agency: str = "",
                                    jurisdiction: str = "US") -> dict
```

**Return fields:** `status`, `tool_id`, `source_url`, `fetch_timestamp`,
`cache_hit`, `sha256_hash`, `data`, `markdown_output`, `disclaimer`,
`data_as_of`, `ingest_healthy`, `query_hash`

**upstream_fields (USASpending):** `award_id`, `recipient_name`, `awarding_agency_name`,
`total_obligation`, `period_of_performance_start_date`, `period_of_performance_current_end_date`,
`award_type`, `description`, `naics_code`

**upstream_fields (SAM.gov):** `noticeId`, `title`, `solicitationNumber`,
`agency`, `type`, `postedDate`, `responseDeadLine`, `description`, `placeOfPerformance`

**upstream_fields (EU TED / UK FAT):** `id`, `title`, `buyer.name`,
`tender.value.amount`, `tender.tenderPeriod.endDate`, `status`

### Hard stops
- Do NOT add procurement guidance, sourcing strategy, or bid coaching of any kind
- Do NOT produce win likelihood analysis or competitive positioning output
- Do NOT add classified contract data — public awards only
- USASpending award type codes restricted to `["A","B","C","D"]` (contracts) — no grants, loans
- NEVER produce advisory output about what an agency is likely to buy

### Known gaps
- USASpending data lags 24–48h after award publication in FPDS
- SAM.gov solicitations require key; without key, tool returns USASpending awards only with note
- EU TED English translations may be incomplete for non-English notices
- `fetch_vendor_contract_history` is US-only via USASpending; EU/UK vendor history not yet implemented

### Cache TTL
- All T18 tools: 14400s (4 hours)

### Acceptance criteria
- `search_contract_awards(keyword="cybersecurity", agency="DHS")` returns `status=ok`, `data.results` list
- `fetch_vendor_contract_history("Booz Allen Hamilton")` returns `data.awards` list with at least 1 entry
- `fetch_open_solicitations(keyword="AI", jurisdiction="US")` returns `data.solicitations` list
- All tools return structured error dict on upstream failure — no exceptions propagate
- Cache hit on second identical call verified via `cache_hit=true`
- No bid coaching, win likelihood, or procurement guidance in any response field
- SAM.gov calls absent gracefully when `SAM_GOV_API_KEY` not set — structured note, not exception
