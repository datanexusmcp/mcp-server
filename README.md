# DataNexus MCP

AI-Ready access to public data intelligence via the [Model Context Protocol](https://modelcontextprotocol.io).

**30 tools. No API key required for most tools. Token-efficient AI-Ready Markdown.**

---

## Connect (remote — no install)

Add to Claude Desktop or any MCP-compatible client:

```json
{
  "mcpServers": {
    "datanexus": {
      "type": "http",
      "url": "https://datanexusmcp.com/mcp"
    }
  }
}
```

Or via npx (bridges HTTP → stdio for clients that need it):

```bash
npx -y @datanexusmcp/mcp-server
```

---

## How agents use DataNexus MCP

Call `search_datanexus_tools` first with a natural language description of your task.
It returns the exact tools and usage instructions for that task.
Reduces context load from ~40,000 tokens to ~800 tokens.

```
search_datanexus_tools("research a nonprofit's financials")
→ returns: nonprofit_fetch_nonprofit_by_ein, nonprofit_search_nonprofits_by_name
```

---

## Available Tools (30 total)

Tools are grouped into 7 focused sub-servers with namespace prefixes.
Use `search_datanexus_tools` to discover the right tool — or browse by group below.

### Nonprofit (`nonprofit_` prefix) — T04
IRS 990 data, UK Charity Commission.

| Tool | Description | Source |
|------|-------------|--------|
| `nonprofit_fetch_nonprofit_by_ein` | IRS 990 data for any US nonprofit by EIN — name, address, NTEE code, revenue, assets | IRS EO BMF + IRS TEOS |
| `nonprofit_search_nonprofits_by_name` | Search US nonprofits by name with optional state filter — returns up to 25 results | IRS EO BMF |
| `nonprofit_fetch_charity_uk` | UK registered charity details — registration status, income, expenditure, activities | UK Charity Commission (OGL v3) |

### Security (`security_` prefix) — T10
OSV.dev, NIST NVD, deps.dev.

| Tool | Description | Source |
|------|-------------|--------|
| `security_fetch_package_vulnerabilities` | All known CVEs for a package version with CVSS scores and fixed versions | Google OSV.dev + NIST NVD |
| `security_fetch_dependency_graph` | Full transitive dependency tree — hard 8 s timeout, never hangs silently | deps.dev (Google) |
| `security_fetch_cve_detail` | Full CVE detail by ID — description, CVSS base score, affected products, patch URLs | NIST NVD |
| `security_audit_sbom_vulnerabilities` | Audit a CycloneDX or SPDX SBOM — per-component vulnerability count and severity | OSV.dev batch API |
| `security_fetch_package_licence` | SPDX licence identifier for any package version — use before adding a commercial dep | deps.dev (Google) |

### Compliance (`compliance_` prefix) — T22
NPPES NPI Registry, FINRA BrokerCheck, SAM.gov.

| Tool | Description | Source |
|------|-------------|--------|
| `compliance_fetch_npi_provider` | NPI registration for any US healthcare provider — name, taxonomy, speciality, status | NPPES NPI Registry (CMS) |
| `compliance_search_npi_by_name` | Search NPI registry by provider name with optional state and speciality filters | NPPES NPI Registry (CMS) |
| `compliance_fetch_finra_broker` | FINRA BrokerCheck registration by CRD number — licences, disclosures, employment history | FINRA BrokerCheck |
| `compliance_check_sam_exclusion` | Federal exclusions list check by name or EIN — debarred and suspended entities | SAM.gov |

### Domain (`domain_` prefix) — T07
IANA RDAP, crt.sh, Cloudflare DoH.

| Tool | Description | Source |
|------|-------------|--------|
| `domain_fetch_domain_rdap` | WHOIS-replacement RDAP lookup — registrar, expiry, nameservers, status flags | IANA RDAP |
| `domain_fetch_ssl_certificate_chain` | Certificate Transparency log certificates for a domain — issuer, SANs, validity | crt.sh |
| `domain_fetch_dns_records` | A / AAAA / MX / TXT / NS / CNAME records for any domain | Cloudflare DoH |
| `domain_fetch_domain_history` | Historical certificate issuance from CT logs — track domain ownership changes | crt.sh |

### Legal / Patents (`legal_` prefix) — T11
EPO OPS, USPTO, WIPO PATENTSCOPE.

| Tool | Description | Source |
|------|-------------|--------|
| `legal_fetch_patent_by_number` | Full bibliographic data for a patent — title, abstract, inventors, assignee, citations | EPO OPS + USPTO |
| `legal_search_patents_by_keyword` | Search EP / US / WO patents by keyword and date range | EPO OPS + USPTO |
| `legal_fetch_patent_citations` | Forward and backward citations for a patent — who cited it and what it cites | EPO OPS |
| `legal_fetch_inventor_portfolio` | Patent portfolio for an inventor, optionally filtered by assignee | EPO OPS |

### GovCon (`govcon_` prefix) — T18
USASpending.gov, SAM.gov, EU TED.

| Tool | Description | Source |
|------|-------------|--------|
| `govcon_search_contract_awards` | Search federal contract awards by keyword and agency — amounts, vendors, NAICS codes | USASpending.gov + SAM.gov |
| `govcon_fetch_vendor_contract_history` | Full contract history for a specific vendor — award totals, agencies, contract types | USASpending.gov |
| `govcon_fetch_open_solicitations` | Open bid opportunities matching a keyword — due dates, set-aside types, agencies | SAM.gov + EU TED + UK Find-a-Tender |

### Regulatory (`regulatory_` prefix) — T19
Regulations.gov, Federal Register.

| Tool | Description | Source |
|------|-------------|--------|
| `regulatory_search_open_rulemakings` | Open rulemakings and public comment periods — docket title, agency, comment deadline | Regulations.gov + Federal Register |
| `regulatory_fetch_docket_details` | Full docket details by ID — documents, comments, summary, agency contact | Regulations.gov |
| `regulatory_fetch_federal_register_notices` | Recent Federal Register notices by agency — type, publication date, abstract | Federal Register API |

### Shared — Available on all sub-servers

| Tool | Description |
|------|-------------|
| `search_datanexus_tools` | Find the right tool by describing your task in plain English. Use this first. Token-efficient entry point. |
| `report_feedback` | Report an incorrect, incomplete, or stale tool result — always returns `{status: 'recorded'}` |
| `report_mcpize_link` | Check subscription status and retrieve upgrade URL if required |
| `validate_tool_output` | Validate any DataNexus tool response for data quality anomalies — deterministic rules + Haiku AI review |

---

## Ecosystems supported (security_ tools)

`PyPI` · `npm` · `Maven` · `Go` · `Cargo` · `NuGet` · `RubyGems` · `Packagist`

---

## Response format

Every tool response includes:

| Field | Description |
|-------|-------------|
| `markdown_output` | AI-Ready Markdown — paste directly into a response |
| `query_hash` | 16-char hex — use as `query_hash` in `report_feedback` |
| `data_as_of` | ISO 8601 UTC timestamp of the data |
| `ingest_healthy` | `true` if upstream source was reachable |
| `cache_hit` | `true` if served from cache |
| `sha256_hash` | SHA-256 of the raw upstream payload |

---

## Environment variables

Only needed for self-hosted deployments. The hosted server at
`https://datanexusmcp.com/mcp` requires no configuration.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATANEXUS_REDIS_URL` | `redis://localhost:6379` | Redis for caching and telemetry |

No API keys are required for most tools — all primary upstream sources are public.

---

## License

MIT
