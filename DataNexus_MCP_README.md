# DataNexus MCP

**AI-Ready public data intelligence via the Model Context Protocol.**

30 tools across 7 verticals. Verified sources. Token-efficient AI-Ready Markdown. No API key required for most tools.

---

## What DataNexus does

DataNexus gives AI agents structured access to authoritative public data — IRS filings, CVE databases, patent offices, government contract records, regulatory dockets, domain registries, and professional licence registries. Every response is pre-formatted as AI-Ready Markdown optimised for LLM consumption.

---

## How to connect

**Claude Desktop / Cursor / Windsurf**

```json
{
  "mcpServers": {
    "datanexus": {
      "url": "https://datanexusmcp.com/mcp",
      "transport": "streamable-http"
    }
  }
}
```

**Via npx (bridges HTTP → stdio for clients that need it)**

```bash
npx -y @datanexusmcp/mcp-server
```

**Server URL**

```
https://datanexusmcp.com/mcp
```

---

## Start here — find the right tool

Before calling any specific tool, use `search_datanexus_tools` to find what you need:

```
search_datanexus_tools("research a US nonprofit by EIN")
search_datanexus_tools("check open source package for CVEs")
search_datanexus_tools("find government contract awards for a vendor")
```

This reduces the context load from ~40,000 tokens to ~800 tokens and routes you to the exact tool and parameters needed.

---

## Tool groups

### Nonprofit — `nonprofit_` prefix
*Sources: IRS EO BMF, IRS TEOS, UK Charity Commission (OGL v3)*

| Tool | What it does |
|---|---|
| `nonprofit_fetch_nonprofit_by_ein` | IRS 990 data for any US nonprofit by EIN — name, revenue, expenses, assets, NTEE code |
| `nonprofit_search_nonprofits_by_name` | Search US nonprofits by name with optional state filter — returns up to 25 results |
| `nonprofit_fetch_charity_uk` | UK registered charity details — registration status, income, activities |

**Example**
```
nonprofit_fetch_nonprofit_by_ein("13-1837418")
```

---

### Security — `security_` prefix
*Sources: Google OSV.dev, NIST NVD, deps.dev*

| Tool | What it does |
|---|---|
| `security_fetch_package_vulnerabilities` | All CVEs for a package version across PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems |
| `security_fetch_cve_detail` | Full CVE detail by ID — description, CVSS score, affected products, patch references |
| `security_fetch_dependency_graph` | Full dependency tree for a package version |
| `security_audit_sbom_vulnerabilities` | Audit a CycloneDX or SPDX SBOM against OSV.dev |
| `security_fetch_package_licence` | SPDX licence identifier for any package version |

**Example**
```
security_fetch_package_vulnerabilities("requests", "2.28.0", "PyPI")
security_fetch_cve_detail("CVE-2023-32681")
```

> Vulnerability data is for informational and research purposes. Verify with your security team before making decisions.

---

### Compliance — `compliance_` prefix
*Sources: NPPES NPI Registry (CMS), FINRA BrokerCheck, SAM.gov*

| Tool | What it does |
|---|---|
| `compliance_fetch_npi_provider` | NPI registration details for any US healthcare provider |
| `compliance_search_npi_by_name` | Search NPI registry by name with state and speciality filters |
| `compliance_fetch_finra_broker` | FINRA BrokerCheck registration by CRD number — qualifications, disclosures |
| `compliance_check_sam_exclusion` | Check if an entity is on the federal exclusions list |

**Example**
```
compliance_fetch_npi_provider("1003000126")
compliance_check_sam_exclusion("Acme Corp")
```

> Returns registration status only. DataNexus does not provide fitness-for-hire opinions or compliance determinations.

---

### Domain & DNS — `domain_` prefix
*Sources: IANA RDAP, crt.sh Certificate Transparency, Cloudflare DoH*

| Tool | What it does |
|---|---|
| `domain_fetch_domain_rdap` | Domain registration via IANA RDAP — registrar, expiry, nameservers |
| `domain_fetch_ssl_certificate_chain` | SSL certificate history from Certificate Transparency logs |
| `domain_fetch_dns_records` | A, AAAA, MX, TXT, NS, CNAME records via Cloudflare DoH |
| `domain_fetch_domain_history` | Historical certificate issuance — detect unexpected cert issuance |

**Example**
```
domain_fetch_domain_rdap("stripe.com")
domain_fetch_dns_records("cloudflare.com", ["A", "MX", "TXT"])
```

---

### Legal / Patents — `legal_` prefix
*Sources: EPO OPS (OAuth), USPTO, WIPO PATENTSCOPE*

| Tool | What it does |
|---|---|
| `legal_fetch_patent_by_number` | Full patent details by number — title, abstract, inventors, citations |
| `legal_search_patents_by_keyword` | Search EP, US, or WO patents by keyword and date |
| `legal_fetch_patent_citations` | Forward and backward citations for prior art research |
| `legal_fetch_inventor_portfolio` | Patent portfolio for an inventor with optional assignee filter |

**Supported jurisdictions:** EP (EPO), US (USPTO), WO (WIPO PCT)

**Example**
```
legal_fetch_patent_by_number("EP1000000", "EP")
legal_search_patents_by_keyword("neural network image classification", "US", "2020-01-01")
```

> DataNexus does not provide patent valuation, infringement analysis, or legal opinions.

---

### Government Contracting — `govcon_` prefix
*Sources: USASpending.gov, SAM.gov, EU TED, UK Find-a-Tender*

| Tool | What it does |
|---|---|
| `govcon_search_contract_awards` | Search federal contract awards by keyword, agency, date — US, EU, UK |
| `govcon_fetch_vendor_contract_history` | Total award history for a specific vendor |
| `govcon_fetch_open_solicitations` | Open bid opportunities matching a keyword |

**Example**
```
govcon_search_contract_awards("cybersecurity", "Department of Defense", "", "US")
govcon_fetch_vendor_contract_history("Booz Allen Hamilton", "US")
```

> DataNexus returns raw public contract data. It does not provide procurement strategy advice or bid consulting.

---

### Regulatory — `regulatory_` prefix
*Sources: Regulations.gov, Federal Register API, EU Have Your Say*

| Tool | What it does |
|---|---|
| `regulatory_search_open_rulemakings` | Open rulemakings and comment periods by keyword and agency |
| `regulatory_fetch_docket_details` | Full docket details by ID — status, comment count, related documents |
| `regulatory_fetch_federal_register_notices` | Recent Federal Register notices for an agency |

**Example**
```
regulatory_search_open_rulemakings("artificial intelligence", "FTC", "open")
regulatory_fetch_docket_details("FDA-2023-N-0001")
```

> DataNexus returns regulatory data only. It does not provide compliance advice or interpret rules for specific businesses.

---

## Shared tools

| Tool | What it does |
|---|---|
| `search_datanexus_tools` | Find the right tool by describing your task in plain English |
| `validate_tool_output` | Two-layer validation of any tool response — deterministic rules + AI review |
| `report_feedback` | Report a data quality issue with a specific tool response |
| `report_mcpize_link` | Check subscription status |

---

## Cache and freshness

| Vertical | Cache TTL | Update frequency |
|---|---|---|
| Nonprofit (IRS) | 7 days | IRS bulk data updates monthly |
| Nonprofit (UK) | 24 hours | UK GDPR requirement |
| Security / CVE | 1 hour | CVEs published continuously |
| Compliance (NPI, FINRA) | 24 hours | Registry updates daily |
| Domain & DNS | 4 hours | DNS TTL-aware |
| Patents | 24 hours | Patent offices update weekly |
| GovCon | 4 hours | USASpending updates daily |
| Regulatory | 4 hours | Regulations.gov rate-limit aware |

Every response includes `data_as_of`, `cache_hit`, and `ingest_healthy` fields so agents can assess data freshness.

---

## Response format

Every tool response includes:

```json
{
  "tool_id": "T04",
  "markdown_output": "## Wikimedia Foundation...",
  "data": { ... },
  "query_hash": "3d1697d3...",
  "cache_hit": true,
  "data_as_of": "2026-05-09T00:00:00Z",
  "ingest_healthy": true,
  "sha256_hash": "a3f8c2...",
  "disclaimer": "Data sourced from IRS EO BMF..."
}
```

`markdown_output` is pre-formatted for direct LLM consumption. `data` contains structured fields for agent parsing. `query_hash` links responses to feedback reports.

---

## Report a data quality issue

If a tool returns incorrect, stale, or incomplete data:

```
report_feedback(
  tool_id="T10",
  query_hash="3d1697d3abcf404c...",
  signal="incorrect_data",
  comment="GHSA-xxxx has UNKNOWN severity despite CVSS vector present"
)
```

Valid signals: `incorrect_data`, `missing_field`, `stale_data`, `not_useful`, `wrong_entity`, `data_quality`

Feedback is reviewed by an automated Haiku validation pipeline and escalated to human review when confirmed at high confidence.

---

## Data sources and licences

| Vertical | Source | Licence |
|---|---|---|
| US Nonprofits | IRS EO BMF + IRS TEOS | Public domain |
| UK Charities | Charity Commission for England and Wales | Open Government Licence v3.0 |
| CVE / Vulnerabilities | Google OSV.dev + NIST NVD | CC0 / public domain |
| NPI Registry | NPPES (CMS) | Public domain |
| FINRA BrokerCheck | FINRA | Public access |
| SAM.gov Exclusions | SAM.gov | Public domain |
| Domain / DNS | IANA RDAP + crt.sh + Cloudflare DoH | Public access |
| Patents | EPO OPS + USPTO + WIPO | Public access |
| Government Contracts | USASpending.gov + SAM.gov | Public domain |
| Regulatory | Regulations.gov + Federal Register | Public domain |

DataNexus acts as data controller for UK charity data processed under OGL v3.0. Individuals whose data appears in charity records may contact dataprotection@datanexusmcp.com to exercise rights under UK GDPR Article 17.

---

## Links

- **Server:** https://datanexusmcp.com/mcp
- **Homepage:** https://datanexusmcp.com
- **npm:** https://www.npmjs.com/package/@datanexusmcp/mcp-server
- **GitHub:** https://github.com/datanexusmcp/mcp-server
