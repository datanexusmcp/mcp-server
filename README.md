# DataNexus MCP

**CISA KEV, CVE EPSS, SBOM audits, patent search, nonprofit 990 data, government contracts, and domain intelligence for AI agents. Zero install. One URL.**

```
https://datanexusmcp.com/mcp
```

---

## Security intelligence — without the setup

CISA KEV, CVE exploit probability (EPSS), SBOM audits, subdomain enumeration,
email security scoring, and CVE detail with remediation. Your AI assistant can
now answer "is this package being actively exploited in the wild?" without Snyk,
without Tenable, without SecurityTrails, and without any API key.

### `security_fetch_cisa_kev` — Is this CVE actively exploited?
Check any CVE against the CISA Known Exploited Vulnerabilities catalog.
Returns `in_kev`, date added, remediation due date, and ransomware use flag.
CISA KEV is the authoritative US government list of CVEs with confirmed
active exploitation. Not available in NVD or OSV.
*"Is CVE-2021-44228 being exploited right now?" → yes, since 2021-12-10,
ransomware campaigns confirmed.*

### `security_fetch_cve_epss` — How likely is this to be exploited?
CVSS tells you severity. EPSS tells you urgency.
Returns exploit probability score (0.0–1.0) and percentile for any CVE.
CVSS 9.8 + EPSS 0.02 = theoretical risk. CVSS 7.5 + EPSS 0.94 = fix now.
Source: FIRST.org EPSS model, recalculated daily.

### `security_fetch_package_vulnerabilities` — All CVEs for a package
CVEs, CVSS scores, severity, and fixed versions across PyPI, npm, Maven,
Go, Cargo, NuGet, and RubyGems. Now supports batch input — check up to
50 packages in one call. Real package.json files have hundreds of
dependencies. This tool handles them.
Source: Google OSV.dev + NIST NVD.

### `security_fetch_cve_detail` — Full CVE with remediation
Full CVE detail plus remediation: exactly which package versions to upgrade
to, pulled from OSV advisory data. "You have CVE-2023-1234" is useless
without "upgrade lodash to 4.17.21 to fix it."

### `security_fetch_cve_epss` — Exploit prediction score
Probability a CVE will be exploited in the next 30 days.
EPSS percentile tells you where this CVE sits relative to all others.

### `security_audit_sbom_vulnerabilities` — Full SBOM audit in one call
Submit a CycloneDX or SPDX SBOM as JSON. Get back every CVE across
every package in your dependency manifest. Replaces a Snyk or Dependabot
scan for research and triage workflows.

### `security_fetch_dependency_graph` — Full supply chain exposure
Complete dependency tree including transitive dependencies for any
package version. Source: deps.dev (Google).

### `security_fetch_package_licence` — Licence compliance check
SPDX licence identifier for any package version. Catches GPL contamination
before it reaches production. Source: deps.dev (Google).

---

## Domain and DNS intelligence — deeper than WHOIS

Subdomain enumeration, email security scoring, co-hosted domain discovery,
SSL certificate history, live DNS, and RDAP registration. Everything
SecurityTrails charges $200/month for — most of it free via crt.sh,
Cloudflare DoH, and IANA RDAP.

### `domain_fetch_subdomains` — Subdomain enumeration via CT logs
All subdomains for any domain from Certificate Transparency logs.
Deduplicated, sorted, wildcard entries stripped. The #1 recon feature
security engineers check. Source: crt.sh (free, no auth).
*"What subdomains does anthropic.com have?" → api., cdn., research., ...*

### `domain_check_email_security` — SPF, DMARC, DKIM assessment
Full email security posture: SPF policy and score, DMARC policy and
reporting, DKIM selector discovery across 10 common selectors.
Returns an overall grade (A–F) using a defined scoring rubric.
Vendor security assessments always check this.
*"Does google.com have proper email security?" → Grade A, p=reject DMARC,
-all SPF, multiple DKIM selectors found.*

### `domain_fetch_reverse_ip` — Co-hosted domains on same IP
All domains sharing the same IP address. Identifies shared hosting risk,
maps corporate infrastructure, detects CDN configurations.
Source: SecurityTrails (1,000 free queries/month — requires API key).

### `domain_fetch_domain_rdap` — Registration via IANA RDAP
Registrar, registration date, expiry date, nameservers, registrant info.
Modern structured replacement for WHOIS. Source: IANA RDAP.

### `domain_fetch_ssl_certificate_chain` — Certificate history
SSL certificate issuance history from Certificate Transparency logs.
Detect unexpected certificate issuance. Source: crt.sh.

### `domain_fetch_dns_records` — Live DNS resolution
A, AAAA, MX, TXT, NS, CNAME records via Cloudflare DoH.
Specify which record types you need.

### `domain_fetch_domain_history` — Historical cert issuance
All past certificates for a domain with validity dates and SANs.
Useful for detecting domain hijacking. Source: crt.sh.

---

## Patent intelligence — EPO, USPTO, WIPO

Search patents by keyword across European, US, and PCT patent offices.
Fetch full bibliographic data, citation chains, and inventor portfolios.
No subscription. No patent database login.

### `legal_fetch_patent_by_number`
Full patent details by number — title, abstract, inventors, assignees,
filing date, claims summary, citation count. Jurisdictions: EP, US, WO.

### `legal_search_patents_by_keyword`
Search by keyword and date across EPO, USPTO, or WIPO.
Returns up to 10 matching patents with titles and filing dates.
*Good for: prior art research, technology landscape analysis.*

### `legal_fetch_patent_citations`
Forward and backward citation chains for any patent.
Build a complete prior art citation graph.

### `legal_fetch_inventor_portfolio`
All patents for a named inventor with optional assignee filter.
Filing dates, jurisdictions, and current status.

---

## Nonprofit data — IRS 990 and UK Charity Commission

### `nonprofit_fetch_nonprofit_by_ein`
IRS 990 filing data for any US nonprofit by EIN.
Revenue, expenses, assets, NTEE code, mission. Source: IRS EO BMF + TEOS.

### `nonprofit_search_nonprofits_by_name`
Search US nonprofits by name with optional state filter. Up to 25 results.

### `nonprofit_fetch_charity_uk`
UK registered charity details by charity number or name.
Income, expenditure, activities. Source: UK Charity Commission (OGL v3).

---

## Government contracting — US, EU, UK

### `govcon_search_contract_awards`
Search federal contract awards by keyword, agency, and date.
Award amounts, recipients, NAICS codes.
Sources: USASpending.gov + SAM.gov (US), EU TED (EU), Find-a-Tender (UK).

### `govcon_fetch_vendor_contract_history`
Complete contract award history for any vendor.
Total awards, top agencies, recent contracts.

### `govcon_fetch_open_solicitations`
Currently open contract opportunities matching a keyword.
Title, agency, deadline, estimated value, NAICS code.

---

## Regulatory tracking — Regulations.gov and Federal Register

### `regulatory_search_open_rulemakings`
Open rulemakings and comment periods by keyword and agency.
Returns docket ID, comment deadline, document count.

### `regulatory_fetch_docket_details`
Full details for a specific docket by ID.
Status, comment period dates, total comments, related documents.

### `regulatory_fetch_federal_register_notices`
Recent Federal Register notices for any agency.
Filter by keyword and date. CFR citations included.

---

## Compliance verification — NPI, FINRA, SAM.gov

### `compliance_fetch_npi_provider`
NPI registration for any US healthcare provider by 10-digit NPI.
Name, credential, speciality, practice address, active status.

### `compliance_search_npi_by_name`
Search NPPES NPI Registry by name with state and speciality filters.

### `compliance_fetch_finra_broker`
FINRA BrokerCheck registration by CRD number.
Qualifications, disclosures, employment history.

### `compliance_check_sam_exclusion`
Check the federal exclusions list by name or EIN.
Returns excluded status, exclusion type, and dates.

---

## Start here

Call `search_datanexus_tools` first with a plain English description
of your task. It returns the exact tool and parameters to use.
Cuts context load from 40,000 tokens to under 800.

```
search_datanexus_tools("is this CVE being actively exploited")
search_datanexus_tools("check email security for a domain")
search_datanexus_tools("find all subdomains of a company")
search_datanexus_tools("audit a Python package for CVEs")
search_datanexus_tools("look up government contracts for a vendor")
```

---

## Connect

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

**Via npx**
```bash
npx -y @datanexusmcp/mcp-server
```

---

## Data sources and freshness

| Vertical | Source | Cache TTL |
|---|---|---|
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

All sources are authoritative government or institutional databases.
No scraping. No third-party aggregators for most tools.
