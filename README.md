# DataNexus MCP
[![mcp-server MCP server](https://glama.ai/mcp/servers/datanexusmcp/mcp-server/badges/score.svg)](https://glama.ai/mcp/servers/datanexusmcp/mcp-server)
[![npm](https://img.shields.io/npm/dm/@datanexusmcp/mcp-server)](https://www.npmjs.com/package/@datanexusmcp/mcp-server)
[![License: BSL 1.1](https://img.shields.io/badge/license-BSL%201.1-orange.svg)](LICENSE)
[![smithery badge](https://smithery.ai/badge/dev-7bd0/mcp-server)](https://smithery.ai/servers/dev-7bd0/mcp-server)
[![ToolRank](https://toolrank.dev/badge/dominant.svg)](https://toolrank.dev/ranking/dev-7bd0/mcp-server)
[![MCP Index rank](https://mcp.kymatalabs.com/badge/com-datanexusmcp-mcp-server.svg)](https://mcp.kymatalabs.com/s/com-datanexusmcp-mcp-server/)
[![Socket Badge](https://badge.socket.dev/npm/package/@datanexusmcp/mcp-server/2.4.10)](https://badge.socket.dev/npm/package/@datanexusmcp/mcp-server/2.4.10)

**55 tools. One URL. Free tier — no credit card.**

Verified public data — CVE/SBOM security audits, licence compliance, frontend security scanning, nonprofit 990 filings, federal contracts, NPI lookups, patents, and domain intelligence — delivered as AI-Ready Markdown inside any MCP client.

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

## Free Tier & API Keys

DataNexus is free to use. Usage is tracked per session.

| Tier | Calls/month | How to activate |
|------|------------|-----------------|
| Anonymous | 100 | Just connect — no setup |
| Registered (free) | 500 | Generate a free key (see below) |

Every response includes a `usage` field showing your current month's count against your limit. When you approach your limit, responses include an `upgrade_hint` pointing to [datanexusmcp.com](https://datanexusmcp.com).

### Getting a free API key (5× more calls)

From any MCP client connected to DataNexus:

```
apikeys_generate_api_key(email="you@example.com")
```

Returns a `dnx_...` key. Store it — it is shown only once.

### Using your API key

**Claude Desktop / HTTP clients:**
```json
{
  "mcpServers": {
    "datanexus": {
      "type": "http",
      "url": "https://datanexusmcp.com/mcp",
      "headers": {
        "X-DataNexus-Key": "dnx_your_key_here"
      }
    }
  }
}
```

**npx / stdio clients:** pass the key as an environment variable or use the HTTP config above.

### Managing your key

| Tool | What it does |
|------|-------------|
| `apikeys_generate_api_key(email)` | Issue a new key — rate-limited to 3/IP/day |
| `apikeys_rotate_api_key(current_key)` | Revoke old key, issue replacement |
| `apikeys_revoke_api_key(key)` | Permanently revoke a key |

---

## Who Uses DataNexus

**Security engineers** auditing SBOMs against CISA KEV, triaging CVEs with instant CRITICAL/HIGH/MODERATE/LOW verdicts, scanning CI pipelines for exposed secrets, and checking licence compatibility across their entire dependency list — without leaving their AI client.

**Frontend developers** catching typosquats against the top-500 frontend corpus, auditing `package.json` for supply-chain risk before shipping, and getting one-verdict package risk briefs scoped to npm.

**Compliance analysts** running background checks across IRS, SAM.gov, and NPPES — manually 45 minutes, with DataNexus 4 minutes.

**Nonprofit researchers and grant-makers** discovering organizations by category, tracking 5-year revenue trends, and running full 990-based due diligence — in one conversation.

**M&A and legal teams** doing due diligence on organizations — SAM exclusion checks, contract history, NPI verification, and patent portfolio in a single Claude conversation.

---

## 5-Minute Quickstart

Copy any of these into Claude after connecting DataNexus:

**Register a free API key:**
> "Generate a DataNexus API key for me using my email address."

**Licence compliance audit:**
> "Check the licences of requests, flask, and numpy. Are they compatible for use in a commercial SaaS product?"

**CVE risk triage:**
> "Get the full risk summary for CVE-2021-44228 — CVSS, CISA KEV status, EPSS probability, and patch availability in one call."

**Audit a package.json:**
> "Audit my package.json for supply-chain risk — check for critical CVEs, licence issues, and abandoned packages."

**Scan a GitHub Actions workflow:**
> "Scan this GitHub Actions workflow for exposed secrets, unpinned actions, and missing lockfile enforcement."

**Nonprofit due diligence:**
> "Find education nonprofits in California, pick one, and show me their 5-year revenue trend."

**CVE watch inbox:**
> "Check all my active CVE watches for new events since my last poll."

---

## Tools (55 total)

### API Key Management

| Tool | What it does | Auth |
|------|-------------|------|
| `apikeys_generate_api_key` | Generate a free `dnx_...` API key tied to your email. Rate-limited 3/IP/day. Returns key once — store it immediately | None |
| `apikeys_rotate_api_key` | Revoke current key and issue a replacement in one atomic operation | Current key |
| `apikeys_revoke_api_key` | Permanently revoke an API key and invalidate its Redis cache entry | Key to revoke |

---

### Security & Vulnerability Intelligence (T10)

#### Core CVE & Package Tools

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_fetch_package_vulnerabilities` | CVE list for any npm/PyPI/Go/Maven/Cargo package at a specific version. Batch up to 50 packages | OSV.dev | None |
| `security_fetch_package_licence` | SPDX licence identifier for any package version | deps.dev | None |
| `security_fetch_dependency_graph` | Full transitive dependency tree with **CVE-flagged transitive deps highlighted** via OSV cross-check. Hard timeout 8s | deps.dev + OSV.dev | None |
| `security_audit_sbom_vulnerabilities` | Audit a CycloneDX or SPDX SBOM JSON against OSV.dev. CVEs grouped by package with severity | OSV.dev batch | None |
| `security_fetch_cve_detail` | Full CVE record — CVSS score, description, affected products, patch references | NIST NVD | None |
| `security_fetch_cisa_kev` | Check whether a CVE is in the CISA Known Exploited Vulnerabilities catalog | CISA KEV | None |
| `security_fetch_cve_epss` | EPSS exploit probability (0.0–1.0) for a CVE. >0.7 = patch immediately | FIRST.org EPSS | None |

#### Package Risk & Supply Chain

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_fetch_package_risk_brief` | Single-call SHIP/CAUTION/BLOCK verdict combining CVEs, licence risk, maintainer health, and transitive count | OSV.dev + deps.dev + PyPI/npm | None |
| `security_fetch_package_maintainer_history` | Maintainer ownership timeline and anomaly score. Flags sudden ownership transfers | PyPI + npm | None |
| `security_detect_typosquatting` | DL-distance ≤ 2 against top-10,000 packages. Returns SUSPICIOUS/CLEAN verdict | PyPI + npm stats | None |
| `security_fetch_cve_watch` | Persistent CVE watchlist — create once, check anytime for patch releases, KEV listings, PoC publications | NVD + CISA KEV + OSV | None |
| `security_audit_sbom_continuous` | Register a CycloneDX/SPDX SBOM once, check anytime for new CVEs | OSV.dev | None |

#### Licence Intelligence & CVE Aggregator

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_fetch_licence_analysis` | Plain-English licence explainer. Risk level, obligations, permissions for any SPDX ID. Static bundle covers top-50 | SPDX list | None |
| `security_audit_licence_compatibility` | COMPATIBLE/CONFLICT audit for up to 50 packages or SPDX IDs. Specific conflicting pairs with remediation | SPDX + deps.dev | None |
| `security_fetch_cve_risk_summary` | One-call CVE verdict: CRITICAL_EXPLOIT/HIGH_RISK/MODERATE/LOW/UNKNOWN. Aggregates CVSS + KEV + EPSS in parallel | NVD + CISA + EPSS | None |

#### Sprint 8B — Backend Security Depth

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `security_audit_sbom_license_policy` | Audit a CycloneDX/SPDX SBOM against a custom SPDX licence policy. Returns PASS/WARN/BLOCK per package. Default policy blocks GPL-3.0/AGPL-3.0. Unlisted licences → WARN | deps.dev | None |
| `security_fetch_cve_watch_status` | Polling inbox for all active CVE watches. Returns only watches with new events since last poll using per-user cursor. First call returns last 30 days | Redis | API key recommended |

---

### Frontend Security (T20)

New in Sprint 8B. Frontend-specific security tools scoped to the npm ecosystem with a curated top-500 frontend package corpus.

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `frontend_security_detect_typosquatting` | Typosquatting detection against the top-500 frontend packages (React, Vite, Axios, Lodash, etc.). DL-distance ≤ 2. Fewer false positives than the full-npm scan | Static corpus | None |
| `frontend_security_audit_manifest` | Audit a `package.json` for supply-chain risk. Returns SHIP/CAUTION/BLOCK verdict with CVE counts, licence risks, and abandoned packages. Accepts optional `package-lock.json` for pinned-version accuracy | OSV.dev + deps.dev + npm | None |
| `frontend_security_audit_ci_pipeline` | Scan GitHub Actions, Vercel, or Netlify configs for exposed secrets, unpinned actions, missing lockfile enforcement, and overly broad permissions. `${{ secrets.FOO }}` references are **never flagged** — only literal credential values | Static analysis | None |
| `frontend_security_fetch_package_risk_brief` | npm-scoped SHIP/CAUTION/BLOCK risk brief with frontend-specific signals: `weekly_downloads` and `is_ui_component` (detects react-*, @mui/*, @radix-ui/*, etc.) | OSV.dev + deps.dev + npm | None |

> **Differentiator vs mcp-security-audit:** DataNexus frontend tools return one actionable verdict (SHIP/CAUTION/BLOCK) with licence risk and abandonment signals, not a raw CVE dump.

---

### Nonprofit Intelligence (T04)

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `nonprofit_fetch_nonprofit_by_ein` | Full IRS 990 filing data for any US nonprofit — revenue, expenses, executive compensation, risk flags | ProPublica + IRS e-File | None |
| `nonprofit_search_nonprofits_by_name` | Search US nonprofits by name and optional state filter | ProPublica | None |
| `nonprofit_fetch_charity_uk` | UK registered charity details — income, trustees, activities | UK Charity Commission | None |
| `nonprofit_fetch_nonprofit_full_profile` | Complete due diligence in one call — financials, exec pay, risk flags, health score (0–100), programme ratio, fundraising sustainability | ProPublica + IRS | None |
| `nonprofit_search_nonprofits_by_category` | Search by mission category (education, healthcare, arts, environment, human_services, civil_rights, international, religion, science, sports) or raw NTEE code | ProPublica | None |
| `nonprofit_fetch_nonprofit_financial_trends` | 5-year (up to 10-year) revenue, expense, and asset trends with CAGR and health score history | ProPublica + IRS 990 | None |

---

### Compliance & Identity Verification (T22)

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `compliance_check_sam_exclusion` | Check if an entity is excluded from US federal contracts (debarred) on SAM.gov | SAM.gov | None |
| `compliance_fetch_npi_provider` | NPI provider details — name, specialty, address, taxonomy codes | NPPES NPI Registry | None |
| `compliance_search_npi_by_name` | Search NPI registry by provider name and state | NPPES NPI Registry | None |
| `compliance_fetch_finra_broker` | FINRA BrokerCheck registration, disclosures, and exam history | FINRA BrokerCheck | None |

---

### Domain Intelligence (T07)

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `domain_fetch_dns_records` | A, AAAA, MX, TXT, NS, CNAME records for any domain | Cloudflare DoH | None |
| `domain_check_email_security` | SPF, DMARC, and DKIM validation — misconfiguration flags, A–F grade | Cloudflare DNS | None |
| `domain_fetch_domain_rdap` | Domain registration details — registrar, registrant, creation date | RDAP | None |
| `domain_fetch_reverse_ip` | All domains co-hosted on the same IP address | HackerTarget | None |
| `domain_fetch_subdomains` | Enumerate subdomains via certificate transparency logs | crt.sh | None |
| `domain_fetch_ssl_certificate_chain` | Full SSL certificate chain — issuer, expiry, SANs | crt.sh | None |
| `domain_fetch_domain_history` | Historical SSL certificate issuance timeline | crt.sh | None |

---

### Patent & Legal Intelligence (T11)

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `legal_fetch_patent_by_number` | Full patent record — claims, abstract, filing date, assignees, IPC classifications | EPO / USPTO / WIPO | None |
| `legal_search_patents_by_keyword` | Patent search across EPO, USPTO, and WIPO by keyword or phrase | EPO / USPTO / WIPO | None |
| `legal_fetch_inventor_portfolio` | All patents by a named inventor — portfolio size, filing dates, assignees | EPO / USPTO / WIPO | None |
| `legal_fetch_patent_citations` | Forward and backward citation chains for a patent | EPO / USPTO / WIPO | None |

---

### Government Contracts (T18)

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `govcon_fetch_vendor_contract_history` | Federal contract award history for any vendor | USASpending.gov | None |
| `govcon_search_contract_awards` | Search contract awards by keyword, agency, or PSC code | USASpending.gov | None |
| `govcon_fetch_open_solicitations` | Open contract opportunities currently accepting bids | SAM.gov | None |

---

### Regulatory Intelligence (T19)

| Tool | What it does | Source | Auth |
|------|-------------|--------|------|
| `regulatory_search_open_rulemakings` | Open rulemaking proceedings on Regulations.gov by keyword or agency | Regulations.gov | None |
| `regulatory_fetch_docket_details` | Full docket record — comments, documents, status | Regulations.gov | None |
| `regulatory_fetch_federal_register_notices` | Recent Federal Register notices and rules by agency or keyword | Federal Register | None |

---

### Shared Tools

| Tool | What it does |
|------|-------------|
| `search_datanexus_tools` | Find the right DataNexus tool for your task by keyword |
| `report_feedback` | Report data quality issues or gaps |
| `report_mcpize_link` | Returns subscription and payment tier status |
| `validate_tool_output` | Validate a tool response for anomalies or schema issues |

---

## Data Sources

| Source | Data | Tools |
|--------|------|-------|
| ProPublica Nonprofit Explorer | US nonprofit 990 filings, multi-year financials | T04 |
| IRS EO BMF + e-File | US nonprofit registrations and raw 990 data | T04 |
| UK Charity Commission | UK charity registrations | T04 |
| NIST NVD | CVE database with CVSS scores and references | T10 |
| OSV.dev | Open source vulnerability database | T10, T20 |
| CISA KEV | Known exploited vulnerabilities catalog (daily refresh) | T10 |
| FIRST.org EPSS | Exploit prediction scores | T10 |
| deps.dev | Dependency graphs, licences, transitive counts | T10, T20 |
| SPDX licence list | Licence metadata (static bundle + API fallback) | T10 |
| PyPI + npm registries | Maintainer history and download stats | T10, T20 |
| npm downloads API | Weekly download counts for packages | T20 |
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

### With a registered API key (500 calls/month)
```json
{
  "mcpServers": {
    "datanexus": {
      "type": "http",
      "url": "https://datanexusmcp.com/mcp",
      "headers": {
        "X-DataNexus-Key": "dnx_your_key_here"
      }
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

---

## Changelog

### v2.4.0 — Sprint 8 (2026-05-30)
**10 new tools — API key infrastructure, backend security depth, frontend security wedge**

**Sprint 8A — API Key Infrastructure:**
- `apikeys_generate_api_key` — issue a free `dnx_...` key tied to your email (500 calls/month)
- `apikeys_rotate_api_key` — atomic key rotation
- `apikeys_revoke_api_key` — immediate revocation + Redis cache invalidation
- `_UsageMiddleware` — usage counting injected into every tool response at middleware level. Zero changes to existing tool files
- Anonymous tier: 100 calls/month (IP-keyed). Registered tier: 500 calls/month (key-keyed)
- `PAYMENT_ENABLED` flag: soft gate today → hard 429 when payment is enabled (env var flip, no code change)

**Sprint 8B — Sub-category Taxonomy + Backend Security Depth + Frontend Security Wedge:**
- `security_audit_sbom_license_policy` — SBOM → PASS/WARN/BLOCK per org licence policy (CycloneDX/SPDX). Default policy blocks GPL-3.0/AGPL-3.0. Unlisted licences default to WARN
- `security_fetch_cve_watch_status` — CVE watch polling inbox with per-user cursor. Returns only new events since last poll
- `security_fetch_dependency_graph` enhanced — `cvs_filtered_transitive_deps` field added: transitive deps with ≥1 open CVE highlighted via OSV.dev cross-check
- `frontend_security_detect_typosquatting` — DL-distance ≤ 2 against curated top-500 frontend corpus
- `frontend_security_audit_manifest` — `package.json` → SHIP/CAUTION/BLOCK with licence risks and abandonment signals
- `frontend_security_audit_ci_pipeline` — GitHub Actions/Vercel/Netlify secret scanner. `${{ secrets.X }}` safe refs never flagged
- `frontend_security_fetch_package_risk_brief` — npm-scoped risk brief with `weekly_downloads` and `is_ui_component` signals
- `CATEGORIES.md` — 8-category tool taxonomy added to repo

### v2.3.0 — Sprint 7 (2026-05-29)
**5 new tools — licence intelligence, CVE aggregator, nonprofit depth**
- `security_fetch_licence_analysis`, `security_audit_licence_compatibility`, `security_fetch_cve_risk_summary`
- `nonprofit_search_nonprofits_by_category`, `nonprofit_fetch_nonprofit_financial_trends`

### v2.2.0 — Sprint 6
**6 new tools — package risk, maintainer health, stateful CVE/SBOM monitoring**
- `security_fetch_package_risk_brief`, `security_fetch_package_maintainer_history`, `security_detect_typosquatting`
- `security_fetch_cve_watch`, `security_audit_sbom_continuous`, `nonprofit_fetch_nonprofit_full_profile`

### v2.1.0 — Sprint 4
Added CISA KEV, EPSS, and SBOM audit tools (35 tools total).

---

## License

DataNexus MCP is licensed under the [Business Source License 1.1](LICENSE).

**What this means in plain English:**

- ✅ Free to use for personal projects, research, and self-hosting your own instance
- ✅ Free to read, modify, and learn from the source code
- ✅ Converts automatically to Apache 2.0 on 2030-06-11 — no strings attached after that
- ❌ Cannot be used to offer a competing hosted data intelligence service without a commercial license

**Why BSL and not MIT?**

We're building a sustainable hosted service on top of this codebase. BSL lets us keep the source open and auditable — important for a tool handling compliance and security data — while protecting the ability to fund continued development.

If you want to run a commercial service using DataNexus internals, [get in touch](mailto:info@datanexusmcp.com). If you're self-hosting for your own agents, you're fully covered at no charge.


---

[![mcp-server MCP server](https://glama.ai/mcp/servers/datanexusmcp/mcp-server/badge)](https://glama.ai/mcp/servers/datanexusmcp/mcp-server)
