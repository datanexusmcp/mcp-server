[![Glama](https://glama.ai/mcp/servers/badge/datanexusmcp)](https://glama.ai/mcp/servers/datanexusmcp) [![Smithery Badge](https://smithery.ai/badge/@datanexusmcp/mcp-server)](https://smithery.ai/server/@datanexusmcp/mcp-server) [![npm](https://img.shields.io/npm/v/@datanexusmcp/mcp-server)](https://www.npmjs.com/package/@datanexusmcp/mcp-server) [![MIT License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

# DataNexus MCP

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

## Tools (35 total)

Start with `search_datanexus_tools("your task in plain English")` to get the exact tool and parameters — reduces context from 40,000 tokens to under 800.

### T04 — Security

| Tool | What it returns | Source |
|------|----------------|--------|
| `security_fetch_cisa_kev` | KEV status, date added, ransomware flag for any CVE | CISA |
| `security_fetch_cve_epss` | Exploit probability score + percentile, recalculated daily | FIRST.org |
| `security_fetch_cve_detail` | Full CVE with CVSS, description, and exact versions to upgrade | OSV + NVD |
| `security_fetch_package_vulnerabilities` | All CVEs for a package — PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems; up to 50 packages per call | OSV + NVD |
| `security_audit_sbom_vulnerabilities` | Full CVE audit for a CycloneDX or SPDX SBOM | OSV + NVD |
| `security_fetch_dependency_graph` | Complete transitive dependency tree for any package version | deps.dev |
| `security_fetch_package_licence` | SPDX licence identifier — catches GPL contamination before production | deps.dev |

### T07 — Domain Intelligence

| Tool | What it returns | Source |
|------|----------------|--------|
| `domain_fetch_subdomains` | All subdomains from Certificate Transparency logs, deduplicated | crt.sh |
| `domain_check_email_security` | SPF, DMARC, DKIM assessment with A–F grade | DNS / Cloudflare DoH |
| `domain_fetch_reverse_ip` | All domains co-hosted on the same IP | SecurityTrails |
| `domain_fetch_domain_rdap` | Registrar, registration date, expiry, nameservers | IANA RDAP |
| `domain_fetch_ssl_certificate_chain` | Certificate issuance history from CT logs | crt.sh |
| `domain_fetch_dns_records` | Live A, AAAA, MX, TXT, NS, CNAME records | Cloudflare DoH |
| `domain_fetch_domain_history` | Past certificates with validity dates and SANs | crt.sh |

### T10 — Patents

| Tool | What it returns | Source |
|------|----------------|--------|
| `legal_fetch_patent_by_number` | Title, abstract, inventors, assignees, filing date, claims summary | EPO OPS / USPTO |
| `legal_search_patents_by_keyword` | Up to 10 matching patents by keyword and date across EP, US, WO | EPO OPS / USPTO |
| `legal_fetch_patent_citations` | Forward and backward citation chains for any patent | EPO OPS / USPTO |
| `legal_fetch_inventor_portfolio` | All patents for a named inventor with optional assignee filter | EPO OPS / USPTO |

### T11 — Nonprofits

| Tool | What it returns | Source |
|------|----------------|--------|
| `nonprofit_fetch_nonprofit_by_ein` | IRS 990 data: revenue, expenses, assets, NTEE code, mission | IRS EO BMF + TEOS |
| `nonprofit_search_nonprofits_by_name` | Up to 25 US nonprofits by name with optional state filter | IRS EO BMF |
| `nonprofit_fetch_charity_uk` | UK charity income, expenditure, activities by number or name | UK Charity Commission |

### T18 — Government Contracting

| Tool | What it returns | Source |
|------|----------------|--------|
| `govcon_search_contract_awards` | Federal awards by keyword, agency, date — amounts, recipients, NAICS codes | USASpending + SAM.gov |
| `govcon_fetch_vendor_contract_history` | Complete award history for any vendor — total, top agencies, recent contracts | USASpending |
| `govcon_fetch_open_solicitations` | Open opportunities by keyword — title, agency, deadline, estimated value | SAM.gov |

### T19 — Regulatory

| Tool | What it returns | Source |
|------|----------------|--------|
| `regulatory_search_open_rulemakings` | Open rulemakings by keyword and agency — docket ID, comment deadline | Regulations.gov |
| `regulatory_fetch_docket_details` | Full docket: status, comment period dates, document count | Regulations.gov |
| `regulatory_fetch_federal_register_notices` | Recent Federal Register notices filtered by agency and keyword, with CFR citations | Federal Register API |

### T22 — Compliance

| Tool | What it returns | Source |
|------|----------------|--------|
| `compliance_fetch_npi_provider` | NPI registration: name, credential, specialty, practice address, active status | NPPES (CMS) |
| `compliance_search_npi_by_name` | NPI Registry search by name, state, and specialty — up to 25 results | NPPES (CMS) |
| `compliance_fetch_finra_broker` | BrokerCheck: qualifications, disclosures, employment history by CRD number | FINRA |
| `compliance_check_sam_exclusion` | Federal exclusion status by name or EIN — exclusion type and dates | SAM.gov |

---

## Why Not Just Use the Government Websites?

| Data | Manual source | Manual time | DataNexus |
|------|--------------|-------------|-----------|
| Nonprofit financials | IRS Tax Exempt Search + CSV download | 12 min | 2 sec |
| SAM exclusions | SAM.gov exclusions portal | 8 min | 1 sec |
| CVE details + CVSS | NVD search + JSON parsing | 10 min | 1 sec |
| SBOM audit vs KEV | Grype + manual KEV cross-ref | 60 min | 3 sec |
| Federal contracts | USASpending.gov export | 25 min | 2 sec |
| NPI verification | NPPES NPI Registry | 8 min | 1 sec |
| Patent search | Google Patents + USPTO | 20 min | 2 sec |

All sources are public. DataNexus normalises, caches, and delivers them as AI-Ready Markdown so your agent gets structured data, not HTML to parse.

---

## Installation

### Hosted (recommended — no setup)

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

### Via npx (for stdio clients like Claude Desktop)

```bash
npx -y @datanexusmcp/mcp-server
```

### Via npm (for programmatic use)

```bash
npm install @datanexusmcp/mcp-server
```

No API keys required for any tool on the free tier.

---

## Data Sources

| Vertical | Source | Cache TTL |
|----------|--------|-----------|
| CISA KEV | cisa.gov | 24-hour refresh |
| CVE EPSS | FIRST.org | 6-hour cache |
| CVE / vulnerabilities | Google OSV.dev + NIST NVD | 1-hour cache |
| Dependency graphs | deps.dev (Google) | 1-hour cache |
| Subdomains | crt.sh CT logs | 24-hour cache |
| Email security | DNS TXT records (Cloudflare DoH) | Live |
| Reverse IP | SecurityTrails | 24-hour cache |
| Domain RDAP | IANA RDAP | 4-hour cache |
| SSL certificates | crt.sh CT logs | 4-hour cache |
| DNS records | Cloudflare DoH | 4-hour cache |
| Patents | EPO OPS + USPTO | 24-hour cache |
| US nonprofits | IRS EO BMF + IRS TEOS | 7-day cache |
| UK charities | UK Charity Commission | 24-hour cache |
| US contracts | USASpending.gov + SAM.gov | 4-hour cache |
| EU/UK contracts | EU TED + Find-a-Tender | 4-hour cache |
| Regulatory dockets | Regulations.gov | 4-hour cache |
| Federal Register | Federal Register API | 4-hour cache |
| NPI registry | NPPES (CMS) | 24-hour cache |
| FINRA BrokerCheck | FINRA | 24-hour cache |
| SAM.gov exclusions | SAM.gov | 24-hour cache |

All sources are authoritative government or institutional databases. No scraping. No third-party aggregators for most tools.

---

[![mcp-server MCP server](https://glama.ai/mcp/servers/badge/datanexusmcp)](https://glama.ai/mcp/servers/datanexusmcp)
