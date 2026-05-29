# DataNexus MCP

[![Glama](https://glama.ai/mcp/servers/datanexusmcp/mcp-server/badge)](https://glama.ai/mcp/servers/datanexusmcp/mcp-server)
[![npm](https://img.shields.io/npm/dm/@datanexusmcp/mcp-server)](https://www.npmjs.com/package/@datanexusmcp/mcp-server)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Smithery](https://smithery.ai/badge/@datanexusmcp/mcp-server)](https://smithery.ai/servers/datanexusmcp/mcp-server)

**35 tools. One URL. No API key.**

Verified public data — CVE/SBOM security audits, nonprofit 990 filings, federal contracts, NPI lookups, patents, and domain intelligence — delivered as AI-Ready Markdown inside any MCP client.

Connect in 30 seconds:

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

Or via npx (for stdio clients like Claude Desktop):

```bash
npx -y @datanexusmcp/mcp-server
```

---
## Who Uses DataNexus

**Compliance analysts** running background checks across IRS, SAM.gov, and NPPES — manually 45 minutes, with DataNexus 4 minutes.

**Security engineers** auditing SBOMs against CISA KEV before federal software submissions — manually 2 hours, with DataNexus one tool call.

**Researchers and journalists** following money across nonprofits, government contracts, and patent filings — without switching between 6 different government websites.

**M&A and legal teams** doing due diligence on organizations — SAM exclusion checks, contract history, NPI verification, and patent portfolio in a single Claude conversation.

---
## 5-Minute Quickstart

Copy any of these into Claude after connecting DataNexus:

**Nonprofit due diligence:**
> "Look up EIN 46-5734087, check if they're excluded from federal contracts, and find any government contracts they've won."

**Security audit:**
> "Check lodash 4.17.15 for CVEs, get the EPSS exploit probability for any critical findings, and check if they're on the CISA KEV list."

**Healthcare provider verification:**
> "Find NPI records for Dr. Jane Smith in California and verify their FINRA registration."

**Patent research:**
> "Search patents by keyword 'federated learning privacy' and pull the full record for the most recent filing."

**Government contractor check:**
> "Get the federal contract history for Lockheed Martin and check for any open solicitations in AI."

---
## Why Not Just Use the Government Websites?

| Data | Manual source | Manual time | DataNexus |
|------|--------------|-------------|-----------|
| Nonprofit financials | IRS Tax Exempt Search + CSV | 12 min | 2 sec |
| SAM exclusions | SAM.gov exclusions portal | 8 min | 1 sec |
| CVE details + CVSS | NVD search + JSON parsing | 10 min | 1 sec |
| SBOM audit vs KEV | Grype + manual KEV cross-ref | 60 min | 3 sec |
| Federal contracts | USASpending.gov export | 25 min | 2 sec |
| NPI verification | NPPES NPI Registry | 8 min | 1 sec |
| Patent search | Google Patents + USPTO | 20 min | 2 sec |

All sources are public. DataNexus normalises, caches, and delivers them as AI-Ready Markdown so your agent gets structured data, not HTML to parse.

---
## Tools (35 total)

### T04 — Nonprofit Intelligence
| Tool | Description |
|------|-------------|
| `nonprofit_fetch_nonprofit_by_ein` | Full 990 filing data for any US nonprofit by EIN |
| `nonprofit_search_nonprofits_by_name` | Search US nonprofits by name and state |
| `nonprofit_fetch_charity_uk` | UK registered charities via Charity Commission |

### T07 — Domain Intelligence
| Tool | Description |
|------|-------------|
| `domain_fetch_dns_records` | DNS records for any domain |
| `domain_check_email_security` | SPF, DMARC, DKIM validation |
| `domain_fetch_domain_rdap` | Domain registration details |
| `domain_fetch_reverse_ip` | Domains co-hosted on same IP |
| `domain_fetch_subdomains` | Enumerate subdomains via CT logs |
| `domain_fetch_ssl_certificate_chain` | SSL certificate history |
| `domain_fetch_domain_history` | Historical SSL issuance |

### T10 — Security & Vulnerability Intelligence
| Tool | Description |
|------|-------------|
| `security_fetch_cve_detail` | Full CVE detail with CVSS scores |
| `security_fetch_cve_epss` | EPSS exploit probability score |
| `security_fetch_cisa_kev` | CISA Known Exploited Vulnerabilities check |
| `security_fetch_package_vulnerabilities` | CVEs for any npm/PyPI/Go package |
| `security_fetch_package_licence` | SPDX licence for any package version |
| `security_fetch_dependency_graph` | Full dependency tree with transitive deps |
| `security_audit_sbom_vulnerabilities` | Audit CycloneDX SBOM against KEV |
| `search_datanexus_tools` | Find the right DataNexus tool for your task |
| `report_feedback` | Report data quality issues |
| `validate_tool_output` | Validate tool response for anomalies |

### T11 — Patent & Legal Intelligence
| Tool | Description |
|------|-------------|
| `legal_fetch_patent_by_number` | Full patent record by number |
| `legal_search_patents_by_keyword` | Patent search across EPO/USPTO/WIPO |
| `legal_fetch_inventor_portfolio` | All patents by inventor name |
| `legal_fetch_patent_citations` | Forward and backward citation chains |

### T18 — Government Contracts
| Tool | Description |
|------|-------------|
| `govcon_fetch_vendor_contract_history` | Federal contract history for any vendor |
| `govcon_search_contract_awards` | Search contract awards by keyword/agency |
| `govcon_fetch_open_solicitations` | Open contract opportunities |

### T19 — Regulatory Intelligence
| Tool | Description |
|------|-------------|
| `regulatory_search_open_rulemakings` | Open rulemakings on Regulations.gov |
| `regulatory_fetch_docket_details` | Full docket details by ID |
| `regulatory_fetch_federal_register_notices` | Recent Federal Register notices |

### T22 — Compliance & Identity Verification
| Tool | Description |
|------|-------------|
| `compliance_check_sam_exclusion` | SAM.gov federal exclusion check |
| `compliance_fetch_npi_provider` | NPI provider details by number |
| `compliance_search_npi_by_name` | Search NPI registry by name |
| `compliance_fetch_finra_broker` | FINRA BrokerCheck registration |
| `report_mcpize_link` | Subscription and payment tier status |

---
## Data Sources

| Source | Data | Tools |
|--------|------|-------|
| IRS EO BMF + TEOS | US nonprofit 990 filings | T04 |
| UK Charity Commission | UK charity registrations | T04 |
| NIST NVD | CVE database with CVSS scores | T10 |
| OSV.dev | Open source vulnerability database | T10 |
| CISA KEV | Known exploited vulnerabilities | T10 |
| FIRST EPSS | Exploit prediction scores | T10 |
| deps.dev | Dependency graphs and licences | T10 |
| Cloudflare DNS | DNS over HTTPS | T07 |
| crt.sh | Certificate transparency logs | T07 |
| EPO / USPTO / WIPO | Patent databases | T11 |
| USASpending.gov | Federal contract awards | T18 |
| SAM.gov | Contract opportunities + exclusions | T18, T22 |
| Regulations.gov | Open rulemakings and dockets | T19 |
| Federal Register | Agency notices and rules | T19 |
| NPPES NPI Registry | Healthcare provider verification | T22 |
| FINRA BrokerCheck | Broker/adviser registrations | T22 |

---
## Installation

### Hosted (recommended — no setup required)
No Docker, no API keys, no configuration.
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

### Via npx (stdio clients — Claude Desktop, Cursor)
```bash
npx -y @datanexusmcp/mcp-server
```

### Via npm (programmatic use)
```bash
npm install @datanexusmcp/mcp-server
```

### Self-hosted
Only needed if you want to run your own instance. See [docker-compose.yml](docker-compose.yml) for the full stack.

---
## License
MIT — see [LICENSE](LICENSE)

---
[![mcp-server MCP server](https://glama.ai/mcp/servers/datanexusmcp/mcp-server/badge)](https://glama.ai/mcp/servers/datanexusmcp/mcp-server)
