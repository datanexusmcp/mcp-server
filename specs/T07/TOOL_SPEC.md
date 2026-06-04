# Tool: T07 — Domain & DNS Intelligence
# Version: 1.0.0
# Last reviewed: 2026-05-10

### Data sources
- **IANA RDAP** — rdap.iana.org — no key, no auth; modern structured WHOIS replacement
- **crt.sh Certificate Transparency** — crt.sh/json — no key; open CT log aggregator
- **Cloudflare DNS over HTTPS** — cloudflare-dns.com/dns-query — no key; passive DNS resolution
- ToS commercial use confirmed: YES (all three are public, unauthenticated APIs)
- Rate limits: RDAP — undocumented, respectful use; crt.sh — no published limit; Cloudflare DoH — unlimited public

### Signatures
```python
async def fetch_domain_rdap(domain: str) -> dict
async def fetch_ssl_certificate_chain(domain: str, port: int = 443) -> dict
async def fetch_dns_records(domain: str,
                            record_types: list[str] = None) -> dict
async def fetch_domain_history(domain: str) -> dict
```

**Return fields:** `status`, `tool_id`, `source_url`, `fetch_timestamp`,
`cache_hit`, `sha256_hash`, `data`, `markdown_output`, `disclaimer`,
`data_as_of`, `ingest_healthy`, `query_hash`

**upstream_fields (RDAP):** `ldhName`, `handle`, `status`, `events`,
`entities`, `nameservers`, `secureDNS`, `registrar`

**upstream_fields (crt.sh):** `id`, `logged_at`, `not_before`, `not_after`,
`common_name`, `name_value`, `issuer_name`

**upstream_fields (Cloudflare DoH):** `Status`, `Question`, `Answer[].name`,
`Answer[].type`, `Answer[].TTL`, `Answer[].data`

### Hard stops
- Do NOT add active probing, port scanning, address enumeration, or known-weakness checks
- Do NOT attempt zone transfers or force-based DNS lookups
- Passive registry and CT log queries ONLY — no active network interrogation
- `fetch_domain_history` uses crt.sh only — no WHOIS history scraping
- Never return raw registrant personal contact data (RDAP redacted fields must stay redacted)

### Known gaps
- RDAP bootstrap JSON cached 24h — new TLD delegations may lag one cycle
- crt.sh CT logs: pre-certificate SCTs not included; only final cert entries
- Cloudflare DoH returns NXDOMAIN for private/internal domains — not an error
- `fetch_domain_history` shows certificate issuance history only; registrar transfer history not available via CT logs

### Cache TTL
- All T07 tools: 14400s (4 hours)
- RDAP bootstrap: 86400s (24 hours — updated infrequently by IANA)

### Acceptance criteria
- `fetch_domain_rdap("datanexusmcp.com")` returns `status=ok`, `data.registrar` non-empty
- `fetch_ssl_certificate_chain("datanexusmcp.com")` returns `data.certificates` list with at least 1 entry
- `fetch_dns_records("datanexusmcp.com", ["A", "MX"])` returns `data.records` keyed by type
- `fetch_domain_history("datanexusmcp.com")` returns `data.history` list (may be empty for new domains)
- All tools return structured error dict on upstream failure — no exceptions propagate
- Cache hit on second identical call verified via `cache_hit=true`
- No active scanning instructions or port enumeration in any response field
- Redacted RDAP registrant fields remain redacted — not reconstructed
