# Tool: T10 — OSS Dependency & Vulnerability Intelligence
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **Google OSV.dev** — api.osv.dev/v1 — Apache 2.0, no key
- **NIST NVD CVE API** — services.nvd.nist.gov — public domain, no key
- **deps.dev** — api.deps.dev/v3alpha — Apache 2.0, no key
- Auth: none for all three sources
- ToS commercial use confirmed: YES (all three are open public APIs)
- Free tier: unlimited (public APIs)

### Signatures
```python
async def fetch_package_vulnerabilities(ecosystem: str, package: str,
                                        version: str = "") -> dict
async def fetch_dependency_graph(ecosystem: str, package: str,
                                 version: str) -> dict
async def fetch_cve_detail(cve_id: str) -> dict
async def audit_sbom_vulnerabilities(sbom: list[dict]) -> dict
async def fetch_package_licence(ecosystem: str, package: str,
                                version: str = "") -> dict
```

**Return fields:** `status`, `tool_id`, `source_url`, `fetch_timestamp`,
`cache_hit`, `sha256_hash`, `data`, `markdown_output`, `disclaimer`,
`data_as_of`, `ingest_healthy`, `query_hash`

**upstream_fields (OSV):** `id`, `aliases`, `summary`, `severity`,
`affected[].package`, `affected[].versions`, `references`

**upstream_fields (NVD):** `cve.id`, `cve.descriptions`, `cve.metrics`,
`cve.references`, `cve.published`, `cve.lastModified`

**upstream_fields (deps.dev):** `version`, `licenses`, `dependencies`,
`dependents`, `advisories`

### Hard stops
- NEVER return executable content of any kind
- NEVER return active scanning instructions or exploit code
- Remediation output: link to official patch release notes ONLY
- `fetch_dependency_graph`: HARD TIMEOUT 8000ms — never hangs silently
- `fetch_dependency_graph` removed from v1.0 if p99 latency > 2s under load test
- NEVER cache partial SBOM audit results — all-or-nothing only

### Known gaps
- OSV.dev ecosystem normalisation: `PyPI` → `pypi`, `npm` → `npm` (case-sensitive)
- NVD enrichment adds ~200ms per CVE; skipped when NVD circuit open
- `audit_sbom_vulnerabilities` limited to 50 packages per call
- WASM/Cargo/Swift ecosystems not yet indexed by OSV — returns empty, not error

### Cache TTL
- Vulnerability data: 14400s (4 hours)
- CVE detail: 14400s (4 hours)
- Licence data: 86400s (24 hours)
- Dependency graph: 3600s (1 hour) — trees change on minor releases

### Acceptance criteria
- `fetch_package_vulnerabilities("pypi", "requests", "2.28.0")` returns `status=ok`, `data.vulnerabilities` is a list
- `fetch_cve_detail("CVE-2021-44228")` returns `data.cvss_score` > 0 and `data.description` non-empty
- `audit_sbom_vulnerabilities` with 3-package list returns per-package verdict for each
- `fetch_package_licence("npm", "lodash", "4.17.21")` returns `data.spdx_id` non-empty
- `fetch_dependency_graph` completes within 8000ms or returns timeout error dict
- All tools return structured error dict on upstream failure — no exceptions propagate
- Cache hit on second identical call verified via `cache_hit=true` in response
- No CVE exploit code or scanning instructions in any output field
