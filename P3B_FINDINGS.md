# P3b Findings — pipeline_mcp / Smithery IP Misattribution

**Discovered during P3b exempt-IP verification (Sprint 9, 2026-06-06).**

The "pipeline_mcp" fingerprint `bf43d728e28002bc` (342 calls/week, described in
SPRINT9_DESIGN.md as a "Biotech/life sciences AI agent") resolves to client IP
`162.158.146.239`.

This IP is *the same IP* the design doc independently identifies (line 79) as a
**Smithery health-checker probe**: "amazon.com and github.com DNS queries are
Smithery health checker probes (162.158.146.238/239) — not Amazon or GitHub
enterprise usage."

It also falls inside the Smithery exempt CIDR `162.158.0.0/15` that P3b is
required to exempt from rate limiting.

**Conclusion:** "pipeline_mcp" is not a separate biotech AI agent — it is
Smithery's own scanning/health-check infrastructure. The 342 calls/week are
Smithery probe traffic, not a distinct organic commercial user.

**Resolution (decided 2026-06-06):** Keep the Smithery CIDR exemption as
specified — exempting infrastructure traffic is correct and prevents
recreating the P1-class problem (rate-limiting a scanner breaks discovery).
The acceptance criterion "pipeline_mcp fingerprint bf43d728e28002bc gets
limit_reached at call 11" is INVALIDATED by this finding and should be
removed/corrected in any future revision of the design doc — it can never
be satisfied without breaking Smithery's health checks.

**Action for future sprints:** Re-profile actual organic/commercial MCP
clients using IPs outside known scanner/proxy CIDRs (Glama, Smithery,
Anthropic) before attributing usage patterns to named "users."
