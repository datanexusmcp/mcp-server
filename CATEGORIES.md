# DataNexus MCP — Tool Categories

Sprint 8B taxonomy. Tool names are flat (no nesting); categories live in README section headers,
Glama listing `tags`/`category` fields, and `description` field prefixes.

| Category | Prefix | Tools | Use case |
|---|---|---|---|
| **security** | `security_*` | CVE lookup, SBOM audit, package vulnerabilities, maintainer health, typosquatting, CVE watch, SBOM continuous, licence compat, CVE risk summary | Backend security engineers auditing OSS supply chain |
| **frontend_security** | `frontend_security_*` | Frontend typosquatting (top-500 corpus), manifest audit, CI pipeline scan, frontend risk brief | Frontend devs and DevSecOps auditing JS/TS stacks |
| **compliance** | `compliance_*` | NPI provider lookup, NPI name search, FINRA broker check, SAM exclusion | Legal, healthcare, financial compliance teams |
| **nonprofit** | `nonprofit_*` | EIN lookup, name search, UK charity, full profile, financial trends, search by category | Donors, grant makers, due diligence researchers |
| **domain** | `domain_*` | RDAP lookup, SSL certificate chain, DNS records, domain history, subdomains, email security, reverse IP | Security teams, domain researchers, infosec |
| **legal** | `legal_*` | Patent by number, patent keyword search, patent citations, inventor portfolio | IP attorneys, R&D teams, patent researchers |
| **govcon** | `govcon_*` | Contract awards search, vendor contract history, open solicitations | Government contractors, BD teams |
| **regulatory** | `regulatory_*` | Open rulemakings, docket details, Federal Register notices | Policy teams, legal researchers, compliance |

## Notes

- Tool names on MCP are flat — no nesting. The category prefix is part of the tool name.
- `frontend_security_*` tools target npm ecosystem by default and use a curated top-500 frontend corpus.
- `security_*` tools cover all ecosystems (npm, PyPI, Go, Cargo, Maven, NuGet, RubyGems).
- Glama `tags`: each tool should carry its category name as a tag plus relevant keywords.
- Glama `category`: use the category column value above for the primary listing category.

## Tool Count by Category (Sprint 8B)

| Category | Count |
|---|---|
| security | 18 |
| frontend_security | 4 |
| compliance | 4 |
| nonprofit | 6 |
| domain | 7 |
| legal | 4 |
| govcon | 3 |
| regulatory | 3 |
| apikeys | 3 |
| shared/meta | 4 |
| **Total** | **56** |
