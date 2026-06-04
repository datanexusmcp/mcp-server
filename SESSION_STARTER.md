# DataNexus MCP — Session Starter
# Read this first. Then read TOOL_SPEC.md for the tool in scope.
# Never load the full spec. Never build unapproved tools.

## Sprint status: Sprint 3 in progress → Sprint 4 after P10 passes

## 29 live tools — do not build new ones this sprint
T04 nonprofit_:   fetch_nonprofit_by_ein, search_nonprofits_by_name, fetch_charity_uk
T10 security_:    fetch_package_vulnerabilities, fetch_dependency_graph*, fetch_cve_detail,
                  audit_sbom_vulnerabilities, fetch_package_licence
T22 compliance_:  fetch_npi_provider, search_npi_by_name, fetch_finra_broker, check_sam_exclusion
T07 domain_:      fetch_domain_rdap, fetch_ssl_certificate_chain, fetch_dns_records, fetch_domain_history
T11 legal_:       fetch_patent_by_number, search_patents_by_keyword, fetch_patent_citations,
                  fetch_inventor_portfolio
T18 govcon_:      search_contract_awards, fetch_vendor_contract_history, fetch_open_solicitations
T19 regulatory_:  search_open_rulemakings, fetch_docket_details, fetch_federal_register_notices
Shared:           report_feedback, report_mcpize_link, validate_tool_output
* fetch_dependency_graph removed from v1.0 if p99 > 2s — check T10/TOOL_SPEC.md

## 5 hard rules
1. Glama score >= 8.5. Fail closed — structured error dict, never partial result.
2. Never change @verify_entitlement or billing code — human PR required.
3. Never store query content — params_hash only in audit logs.
4. Streamable HTTP only — never SSE (deprecated), never stdio for remote.
5. Run scripts/code_review.sh → PASS required before handing to QA.

## Session types (one per session, never combine)
Spec session:     SESSION_STARTER.md + TOOL_SPEC.md only (20 min)
Scaffold session: SESSION_STARTER.md + TOOL_SPEC.md + template (30 min)
Build session:    SESSION_STARTER.md + TOOL_SPEC.md + scaffold (45 min)
Test session:     SESSION_STARTER.md + TOOL_SPEC.md + source file (30 min)
Review session:   SESSION_STARTER.md + code_review.sh output (20 min)

## Infrastructure signatures (on every server)
search_datanexus_tools(), report_feedback(), report_mcpize_link(), validate_tool_output()
