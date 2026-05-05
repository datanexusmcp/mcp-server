# DataNexus MCP

AI-Ready access to US/UK nonprofit data and OSS vulnerability intelligence
via the [Model Context Protocol](https://modelcontextprotocol.io).

**10 tools. No API key required. Token-efficient AI-Ready Markdown.**

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

## Tools (10 total)

### T04 — US/UK Nonprofit Data

| Tool | Description | Source |
|------|-------------|--------|
| `fetch_nonprofit_by_ein` | IRS 990 data for any US nonprofit by EIN — name, address, NTEE code, revenue, assets | IRS EO BMF + IRS TEOS |
| `search_nonprofits_by_name` | Search US nonprofits by name with optional state filter — returns up to 25 results | IRS EO BMF |
| `fetch_charity_uk` | UK registered charity details — registration status, income, expenditure, activities | UK Charity Commission (OGL v3) |

### T10 — OSS Vulnerability Intelligence

| Tool | Description | Source |
|------|-------------|--------|
| `fetch_package_vulnerabilities` | All known CVEs for a package version with CVSS scores and fixed versions | Google OSV.dev + NIST NVD |
| `fetch_dependency_graph` | Full transitive dependency tree — hard 8 s timeout, never hangs silently | deps.dev (Google) |
| `fetch_cve_detail` | Full CVE detail by ID — description, CVSS base score, affected products, patch URLs | NIST NVD |
| `audit_sbom_vulnerabilities` | Audit a CycloneDX or SPDX SBOM — per-component vulnerability count and severity | OSV.dev batch API |
| `fetch_package_licence` | SPDX licence identifier for any package version — use before adding a commercial dep | deps.dev (Google) |

### Shared Infrastructure

| Tool | Description |
|------|-------------|
| `report_feedback` | Report an incorrect, incomplete, or stale tool result — always returns `{status: 'recorded'}` |
| `report_mcpize_link` | Check subscription status and retrieve upgrade URL if required |

---

## Ecosystems supported (T10)

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
| `DATANEXUS_REDIS_URL` | `redis://localhost:6379` | Redis for caching and feedback |

No API keys are required for T04 or T10 — all upstream sources are public.

---

## License

MIT
