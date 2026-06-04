# Tool: T22 — Professional Licence Verification
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **NPPES NPI Registry (CMS)** — npiregistry.cms.hhs.gov/api — no key required
- **FINRA BrokerCheck** — api.finra.org — `FINRA_API_KEY` from env; if absent tool runs NPPES-only with note in response
- **SAM.gov Exclusions** — api.sam.gov/exclusions/v1/api — `SAM_GOV_API_KEY` from env
- ToS commercial use confirmed: YES (NPPES public domain; FINRA public API; SAM.gov public)
- Rate limits: NPPES 20 req/s; FINRA not documented (key-gated); SAM.gov 450 req/hour

### Signatures
```python
async def fetch_npi_provider(npi: str) -> dict
async def search_npi_by_name(first_name: str, last_name: str,
                              state: str = "", limit: int = 10) -> dict
async def fetch_finra_broker(last_name: str, first_name: str = "") -> dict
async def check_sam_exclusion(entity_name: str = "",
                               uei: str = "", ein: str = "") -> dict
```

**Return fields:** `status`, `tool_id`, `source_url`, `fetch_timestamp`,
`cache_hit`, `sha256_hash`, `data`, `markdown_output`, `disclaimer`,
`data_as_of`, `ingest_healthy`, `query_hash`

**upstream_fields (NPPES):** `number`, `enumeration_type`, `basic.first_name`,
`basic.last_name`, `basic.credential`, `basic.status`, `basic.enumeration_date`,
`taxonomies`, `addresses`, `identifiers`

**upstream_fields (FINRA):** `hits.total`, `hits.hits._source.ind_bc_scope`,
`hits.hits._source.disclosures`, `hits.hits._source.exams`

**upstream_fields (SAM.gov):** `exclusionDetails`, `entitySummary.ueiSAM`,
`exclusionType`, `exclusionProgram`, `terminationDate`

### Hard stops
- Do NOT add licence status judgements, hiring suitability decisions, or employment endorsements
- Returns only: licence found / not found / status as registered in official registry
- NEVER surface home addresses of individual practitioners
- NEVER store or log NPI numbers, individual names, or personal details
- `check_sam_exclusion` must never be used to build exclusion watchlists — single-query only

### Known gaps
- FINRA BrokerCheck does not expose arbitration award details via public API
- NPPES bulk refresh is monthly; newly issued NPIs may lag 4–6 weeks
- SAM.gov exclusion API may not reflect same-day debarment actions
- `search_npi_by_name` returns at most 200 results per NPPES API limit; use state filter to narrow

### Cache TTL
- All T22 tools: 86400s (24 hours) — spec requirement, non-negotiable

### Acceptance criteria
- `fetch_npi_provider("1174558800")` returns `status=ok`, `data.basic.last_name` non-empty
- `search_npi_by_name("Smith", "John", state="CA")` returns `data.results` list, count >= 0
- `fetch_finra_broker("Smith")` returns `status=ok` or structured error when FINRA key absent
- `check_sam_exclusion(entity_name="Acme Corp")` returns `data.excluded` boolean field
- All tools return structured error dict on upstream failure — no exceptions propagate
- Cache hit on second identical call verified via `cache_hit=true`
- No suitability judgements or recommendations in any response field
- No personal addresses returned for individual providers
