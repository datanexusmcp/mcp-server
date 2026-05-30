# DataNexus MCP

[![Glama](https://glama.ai/mcp/servers/datanexusmcp/mcp-server/badge)](https://glama.ai/mcp/servers/datanexusmcp/mcp-server)
[![npm](https://img.shields.io/npm/dm/@datanexusmcp/mcp-server)](https://www.npmjs.com/package/@datanexusmcp/mcp-server)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Smithery](https://smithery.ai/badge/@datanexusmcp/mcp-server)](https://smithery.ai/servers/datanexusmcp/mcp-server)

**46 tools. One URL. No API key.**

Verified public data — CVE/SBOM security audits, licence compliance, nonprofit 990 filings, federal contracts, NPI lookups, patents, and domain intelligence — delivered as AI-Ready Markdown inside any MCP client.

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

**Security engineers** auditing SBOMs against CISA KEV, triaging CVEs with instant CRITICAL/HIGH/MODERATE/LOW verdicts, and checking licence compatibility across their entire dependency list — without leaving their AI client.

**Compliance analysts** running background checks across IRS, SAM.gov, and NPPES — manually 45 minutes, with DataNexus 4 minutes.

**Nonprofit researchers and grant-makers** discovering organizations by category, tracking 5-year revenue trends, and running full 990-based due diligence — in one conversation.

**M&A and legal teams** doing due diligence on organizations — SAM exclusion checks, contract history, NPI verification, and patent portfolio in a single Claude conversation.

**Researchers and journalists** following money across nonprofits, government contracts, and patent filings — without switching between 6 different government websites.

---

## 5-Minute Quickstart

Copy any of these into Claude after connecting DataNexus:

**Licence compliance audit:**
> "Check the licences of requests, flask, and numpy. Are they compatible for use in a commercial SaaS product?"

**CVE risk triage:**
> "Get the full risk summary for CVE-2021-44228 — CVSS, CISA KEV status, EPSS probability, and patch availability in one call."

**Nonprofit due diligence:**
> "Find education nonprofits in California, pick one, and show me their 5-year revenue trend."

**Security audit:**
> "Check lodash 4.17.15 for CVEs, get the EPSS exploit probability for any critical findings, and check if they're on the CISA KEV list."

**Healthcare provider verification:**
> "Find NPI records for Dr. Jane Smith in California and verify their FINRA registration."

**Government contractor check:**
> "Get the federal contract history for Lockheed Martin and check for any open solicitations in AI."

---

## Why Not Just Use the Government Websites?

| Data | Manual source | Manual time | DataNexus |
|------|--------------|-------------|-----------|
| Nonprofit financials | IRS Tax Exempt Search + CSV | 12 min | 2 sec |
| Nonprofit 5-yr trends | ProPublica + manual spreadsheet | 30 min | 2 sec |
| SAM exclusions | SAM.gov exclusions portal | 8 min | 1 sec |
| CVE details + CVSS | NVD search + JSON parsing | 10 min | 1 sec |
| CVE risk verdict | NVD + CISA KEV + EPSS — 3 tabs | 15 min | 1 sec |
| Licence compatibility | SPDX docs + legal research | 20 min | 1 sec |
| SBOM audit vs KEV | Grype + manual KEV cross-ref | 60 min | 3 sec |
| Federal contracts | USASpending.gov export | 25 min | 2 sec |
| NPI verification | NPPES NPI Registry | 8 min | 1 sec |
| Patent search | Google Patents + USPTO | 20 min | 2 sec |

All sources are public. DataNexus normalises, caches, and delivers them as AI-Ready Markdown so your agent gets structured data, not HTML to parse.

---

## Tools (46 total)

### T04 — Nonprofit Intelligence

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `nonprofit_fetch_nonprofit_by_ein` | Full IRS 990 filing data for any US nonprofit — revenue, expenses, executive compensation, risk flags | ProPublica + IRS e-File | None |
| `nonprofit_search_nonprofits_by_name` | Search US nonprofits by name and optional state filter | ProPublica Nonprofit Explorer | None |
| `nonprofit_fetch_charity_uk` | UK registered charity details — income, trustees, activities | UK Charity Commission API | None |
| `nonprofit_fetch_nonprofit_full_profile` | Complete due diligence in one call — financials, exec pay, risk flags, health score (0–100), programme ratio, fundraising sustainability | ProPublica + IRS e-File | None |
| `nonprofit_search_nonprofits_by_category` | Search nonprofits by mission category (education, healthcare, arts, environment, human_services, civil_rights, international, religion, science, sports) or raw NTEE code A–Z. Optional state filter. Returns up to 25 results | ProPublica Nonprofit Explorer | None |
| `nonprofit_fetch_nonprofit_financial_trends` | 5-year (or up to 10-year) revenue, expense, and asset trends for any US nonprofit. Returns CAGR, trend direction (GROWING/STABLE/DECLINING/VOLATILE/INSUFFICIENT_DATA), year-by-year health scores | ProPublica + IRS Form 990 | None |

**Health score (0–100):** Weighted composite of programme ratio (40 pts), expense efficiency (30 pts), revenue growth (20 pts), and reserve months (10 pts). Null when revenue is zero.

**Trend direction rules (evaluated in order):**
- `VOLATILE` — any two consecutive years with opposite-sign change and both >20% magnitude
- `GROWING` — CAGR > 5%
- `STABLE` — CAGR between −5% and +5%
- `DECLINING` — CAGR < −5%
- `INSUFFICIENT_DATA` — fewer than 2 filings available

---

### T10 — Security & Vulnerability Intelligence

#### Sprint 4 — Core CVE & Package Tools

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_fetch_package_vulnerabilities` | CVE list for any npm/PyPI/Go/Maven/Cargo package at a specific version. Returns critical/high counts and CVE IDs | OSV.dev | None |
| `security_fetch_package_licence` | SPDX licence identifier for any package version | deps.dev | None |
| `security_fetch_dependency_graph` | Full transitive dependency tree. Hard timeout 8s — large graphs may truncate | deps.dev | None |
| `security_audit_sbom_vulnerabilities` | Audit a CycloneDX or SPDX SBOM JSON against OSV.dev. Returns CVEs grouped by package with severity and fixed versions | OSV.dev batch API | None |
| `security_fetch_cve_detail` | Full CVE record — CVSS score, description, affected products, patch references, publish date | NIST NVD | None |
| `security_fetch_cisa_kev` | Check whether a CVE is in the CISA Known Exploited Vulnerabilities catalog. Returns `in_kev`, date added, ransomware use flag | CISA KEV (daily refresh) | None |
| `security_fetch_cve_epss` | EPSS exploit probability score (0.0–1.0) for a CVE — predicts likelihood of exploitation in next 30 days. >0.7 = patch immediately | FIRST.org EPSS API | None |

#### Sprint 6 — Package Risk & Supply Chain

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_fetch_package_risk_brief` | Single-call SHIP/CAUTION/BLOCK verdict combining CVEs, licence risk, maintainer health, and transitive dependency count. The fastest triage tool for any package | OSV.dev + deps.dev + PyPI/npm | None |
| `security_fetch_package_maintainer_history` | Maintainer ownership timeline, account age, and anomaly score for npm and PyPI packages. Flags sudden ownership transfers | PyPI + npm registries | None |
| `security_detect_typosquatting` | Detect supply-chain typosquatting attacks — Damerau-Levenshtein distance ≤ 2 against top-10,000 packages. Returns similar packages with anomaly scores and SUSPICIOUS/CLEAN verdict | PyPI + npm download stats | None |
| `security_fetch_cve_watch` | Persistent CVE watchlist — create once, check anytime for patch releases, KEV listings, PoC publications, exploitation detected. Stateful across sessions | NVD + CISA KEV + OSV | None |
| `security_audit_sbom_continuous` | Register a CycloneDX/SPDX SBOM once, check anytime for new CVEs affecting your dependency snapshot. Stateful across sessions | OSV.dev | None |

#### Sprint 7 — Licence Intelligence & CVE Aggregator

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_fetch_licence_analysis` | Understand any SPDX licence in plain English. Returns risk level (PERMISSIVE/COPYLEFT/STRONG_COPYLEFT/INCOMPATIBLE/UNKNOWN), obligations, permissions, limitations, OSI/FSF status, and a one-line verdict. Static bundle covers top-50 licences — no network call needed for MIT, Apache-2.0, GPL-*, LGPL-*, AGPL-*, MPL-2.0, BSD-*, ISC. **All risk levels assume proprietary/commercial use context.** | SPDX licence list (static + API fallback) | None |
| `security_audit_licence_compatibility` | Audit licence compatibility across your entire dependency list. Input package names (with ecosystem) or SPDX IDs directly. Returns COMPATIBLE/CONFLICT/UNKNOWN verdict, specific conflicting pairs with reasons, combined obligations, and recommended action. Max 50 items. Package path resolves licences from deps.dev with max 10 concurrent calls (prevents 429). SPDX-ID path is fully static — no HTTP | SPDX static table + deps.dev | None |
| `security_fetch_cve_risk_summary` | Instant CVE risk verdict. Aggregates CVSS severity, CISA KEV exploitation status, and EPSS probability in one parallel call. Returns CRITICAL_EXPLOIT/HIGH_RISK/MODERATE/LOW/UNKNOWN verdict with patch availability from vendor advisory allowlist. **UNKNOWN means all upstream sources unreachable — not that risk is low.** Designed as the follow-through tool when `security_fetch_cve_watch` fires | NIST NVD + CISA KEV + FIRST EPSS | None |

**Verdict table for `security_fetch_cve_risk_summary` (first match wins):**

| Priority | Verdict | Condition |
|----------|---------|-----------|
| 1 | `UNKNOWN` | All three inputs null (all upstreams down) |
| 2 | `CRITICAL_EXPLOIT` | `kev_listed == true` OR `epss_score ≥ 0.7` |
| 3 | `HIGH_RISK` | `cvss_score ≥ 9.0` OR (`epss ≥ 0.3` AND `cvss ≥ 7.0`) |
| 4 | `MODERATE` | `cvss_score ≥ 4.0` |
| 5 | `LOW` | At least one input non-null, no higher threshold met |

**Degraded null semantics:**
- `kev_listed: null` = could not check CISA (not `false` = checked, not listed)
- `epss_score: null` = EPSS unreachable (not `0.0` = checked, zero probability)
- `patch_available: null` = no recognized vendor advisory URL found (not `false` = confirmed no patch)

**Licence risk levels (proprietary/commercial context):**

| Risk Level | Licences | Implication |
|-----------|---------|-------------|
| `PERMISSIVE` | MIT, Apache-2.0, BSD-*, ISC, 0BSD | Attribution only — safe for commercial use |
| `COPYLEFT` | LGPL-*, MPL-2.0 | Modifications to licensed files must be shared |
| `STRONG_COPYLEFT` | GPL-2.0, GPL-3.0, EUPL-1.1 | All derivative works must be open-sourced |
| `INCOMPATIBLE` | AGPL-3.0 (in proprietary SaaS) | Cannot use in closed-source services |
| `UNKNOWN` | Unrecognized SPDX ID | Verify at spdx.org/licenses |

---

### T11 — Patent & Legal Intelligence

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `legal_fetch_patent_by_number` | Full patent record — claims, abstract, filing date, assignees, IPC classifications | EPO / USPTO / WIPO | None |
| `legal_search_patents_by_keyword` | Patent search across EPO, USPTO, and WIPO by keyword or phrase | EPO / USPTO / WIPO | None |
| `legal_fetch_inventor_portfolio` | All patents by a named inventor — portfolio size, filing dates, assignees | EPO / USPTO / WIPO | None |
| `legal_fetch_patent_citations` | Forward and backward citation chains for a patent | EPO / USPTO / WIPO | None |

---

### T18 — Government Contracts

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `govcon_fetch_vendor_contract_history` | Federal contract award history for any vendor by name or DUNS — amounts, agencies, PSC codes | USASpending.gov | None |
| `govcon_search_contract_awards` | Search contract awards by keyword, agency, or PSC code | USASpending.gov | None |
| `govcon_fetch_open_solicitations` | Open contract opportunities currently accepting bids | SAM.gov | None |

---

### T19 — Regulatory Intelligence

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `regulatory_search_open_rulemakings` | Open rulemaking proceedings on Regulations.gov by keyword or agency | Regulations.gov API | None |
| `regulatory_fetch_docket_details` | Full docket record — comments, documents, status — by docket ID | Regulations.gov API | None |
| `regulatory_fetch_federal_register_notices` | Recent Federal Register notices and rules by agency or keyword | Federal Register API | None |

---

### T22 — Compliance & Identity Verification

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `compliance_check_sam_exclusion` | Check if an entity is excluded from US federal contracts (debarred) on SAM.gov | SAM.gov Exclusions | None |
| `compliance_fetch_npi_provider` | NPI provider details — name, specialty, address, taxonomy codes | NPPES NPI Registry | None |
| `compliance_search_npi_by_name` | Search NPI registry by provider name and state | NPPES NPI Registry | None |
| `compliance_fetch_finra_broker` | FINRA BrokerCheck registration, disclosures, and exam history | FINRA BrokerCheck | None |

---

### T07 — Domain Intelligence

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `domain_fetch_dns_records` | A, AAAA, MX, TXT, NS, CNAME records for any domain | Cloudflare DNS over HTTPS | None |
| `domain_check_email_security` | SPF, DMARC, and DKIM validation — misconfiguration flags | Cloudflare DNS | None |
| `domain_fetch_domain_rdap` | Domain registration details — registrar, registrant, creation date | RDAP | None |
| `domain_fetch_reverse_ip` | All domains co-hosted on the same IP address | HackerTarget / Cloudflare | None |
| `domain_fetch_subdomains` | Enumerate subdomains via certificate transparency logs | crt.sh | None |
| `domain_fetch_ssl_certificate_chain` | Full SSL certificate chain — issuer, expiry, SANs | crt.sh | None |
| `domain_fetch_domain_history` | Historical SSL certificate issuance timeline | crt.sh | None |

---

### Shared Tools

| Tool | What it does |
|------|-------------|
| `search_datanexus_tools` | Find the right DataNexus tool for your task by keyword — returns matching tools with descriptions |
| `report_feedback` | Report data quality issues or gaps — routes feedback to the DataNexus team |
| `report_mcpize_link` | Returns subscription and payment tier status for the current session |
| `validate_tool_output` | Validate a tool response for anomalies or schema issues |

---

## Data Sources

| Source | Data | Tools |
|--------|------|-------|
| ProPublica Nonprofit Explorer | US nonprofit 990 filings, multi-year financials | T04 |
| IRS EO BMF + e-File | US nonprofit registrations and raw 990 data | T04 |
| UK Charity Commission | UK charity registrations | T04 |
| NIST NVD | CVE database with CVSS scores and references | T10 |
| OSV.dev | Open source vulnerability database | T10 |
| CISA KEV | Known exploited vulnerabilities catalog (daily refresh) | T10 |
| FIRST.org EPSS | Exploit prediction scores | T10 |
| deps.dev | Dependency graphs, licences, transitive counts | T10 |
| SPDX licence list | Licence metadata (static bundle + API fallback) | T10 |
| PyPI + npm registries | Maintainer history and download stats | T10 |
| Cloudflare DNS over HTTPS | DNS records and email security | T07 |
| crt.sh | Certificate transparency logs and SSL history | T07 |
| EPO / USPTO / WIPO | Patent databases | T11 |
| USASpending.gov | Federal contract awards | T18 |
| SAM.gov | Contract opportunities and exclusions | T18, T22 |
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

## Changelog

### v2.3.0 — Sprint 7 (2026-05-29)
**5 new tools — licence intelligence, CVE aggregator, nonprofit depth**
- `security_fetch_licence_analysis` — plain-English licence explainer with risk level for any SPDX ID
- `security_audit_licence_compatibility` — COMPATIBLE/CONFLICT audit for up to 50 packages or SPDX IDs
- `security_fetch_cve_risk_summary` — one-call CVE verdict aggregating CVSS + CISA KEV + EPSS
- `nonprofit_search_nonprofits_by_category` — search nonprofits by NTEE category with health scores
- `nonprofit_fetch_nonprofit_financial_trends` — multi-year revenue/expense/asset trends with CAGR
- Centralized circuit breakers (`_circuit_breakers.py`) — shared failure state across all tools
- Health score formula extracted to `_nonprofit_utils.py` — single source of truth

### v2.2.0 — Sprint 6
**6 new tools — package risk, maintainer health, stateful CVE/SBOM monitoring**
- `security_fetch_package_risk_brief` — SHIP/CAUTION/BLOCK verdict
- `security_fetch_package_maintainer_history` — maintainer ownership anomaly detection
- `security_detect_typosquatting` — supply-chain attack detection
- `security_fetch_cve_watch` — persistent CVE watchlist
- `security_audit_sbom_continuous` — continuous SBOM vulnerability monitoring
- `nonprofit_fetch_nonprofit_full_profile` — full 990 due diligence with health score

### v2.1.0 — Sprint 4
Added CISA KEV, EPSS, and SBOM audit tools (35 tools total).

---

## License
MIT — see [LICENSE](LICENSE)

---

[![mcp-server MCP server](https://glama.ai/mcp/servers/datanexusmcp/mcp-server/badge)](https://glama.ai/mcp/servers/datanexusmcp/mcp-server)
