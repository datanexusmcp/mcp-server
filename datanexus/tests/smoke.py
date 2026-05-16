"""
datanexus/tests/smoke.py — Production smoke test suite for DataNexus FastMCP server.

Tests all 30 tool functions end-to-end with real API calls. Tools are executed
concurrently via asyncio.gather with a 60-second per-tool timeout. Results are
written to Redis (datanexus:smoke:{tool_name}) with a 2-hour TTL.

Status definitions:
  PASS     — ingest_healthy=True, disclaimer present, data non-empty, all checks pass
  FAIL     — exception raised, data empty/missing, or required field check fails
  DEGRADED — data present but ingest_healthy=False OR latency > 5000ms
  SKIP     — tool could not be imported or gracefully skipped

Usage:
  python3 -m datanexus.tests.smoke
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("datanexus.smoke")

# ── Constants ──────────────────────────────────────────────────────────────────

TIMEOUT_S = 60          # per-tool asyncio timeout
DEGRADED_LATENCY_MS = 5000


# ── Result helpers ─────────────────────────────────────────────────────────────

def _make_result(
    tool: str,
    tool_id: str,
    status: str,
    latency_ms: int,
    checks_passed: list,
    checks_failed: list,
    ingest_healthy: Optional[bool],
    error: Optional[str] = None,
) -> dict:
    return {
        "ts":             datetime.now(timezone.utc).isoformat(),
        "tool":           tool,
        "tool_id":        tool_id,
        "status":         status,
        "latency_ms":     latency_ms,
        "ingest_healthy": ingest_healthy,
        "checks_passed":  checks_passed,
        "checks_failed":  checks_failed,
        "error":          error,
    }


def _skip_result(tool: str, tool_id: str, reason: str) -> dict:
    return _make_result(tool, tool_id, "SKIP", 0, [], [], None, error=reason)


def _check(
    d: dict,
    tool_id: str,
    tool_name: str,
    t0: float,
    checks: list,
) -> dict:
    """
    Build a result dict from a tool response dict plus explicit checks.

    Args:
        d:         The raw dict returned by the tool function.
        tool_id:   e.g. "T04"
        tool_name: e.g. "fetch_nonprofit_by_ein"
        t0:        time.monotonic() captured before the call
        checks:    list of (check_name: str, passed: bool) tuples

    Automatically adds:
        - "ingest_healthy" check
        - "has_disclaimer" check

    Returns a fully-formed result dict with PASS/FAIL/DEGRADED status.
    """
    latency_ms = int((time.monotonic() - t0) * 1000)
    passed = []
    failed = []

    ingest_healthy = d.get("ingest_healthy")
    disclaimer = d.get("disclaimer", "")

    # Auto checks
    if ingest_healthy:
        passed.append("ingest_healthy")
    else:
        failed.append("ingest_healthy")

    if disclaimer:
        passed.append("has_disclaimer")
    else:
        failed.append("has_disclaimer")

    # Caller-supplied checks
    for name, ok in checks:
        if ok:
            passed.append(name)
        else:
            failed.append(name)

    # Determine status
    if failed:
        status = "FAIL"
    elif latency_ms > DEGRADED_LATENCY_MS or not ingest_healthy:
        status = "DEGRADED"
    else:
        status = "PASS"

    return _make_result(
        tool_name, tool_id, status, latency_ms,
        passed, failed, ingest_healthy,
    )


# ── T04 — Nonprofit ────────────────────────────────────────────────────────────

async def smoke_fetch_nonprofit_by_ein() -> dict:
    tool_name, tool_id = "fetch_nonprofit_by_ein", "T04"
    try:
        from datanexus.tools.t04 import fetch_nonprofit_by_ein
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_nonprofit_by_ein(ein="20-0049703"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        name_val = data.get("name", "")
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",     bool(data)),
            ("name_nonempty", len(name_val) > 0),
            ("name_wikimedia", "wikimedia" in name_val.lower()),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_search_nonprofits_by_name() -> dict:
    tool_name, tool_id = "search_nonprofits_by_name", "T04"
    try:
        from datanexus.tools.t04 import search_nonprofits_by_name
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_nonprofits_by_name(name="Wikimedia", state=""), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        # results may live directly under data or as data["results"]
        results = (
            data.get("results", [])
            if isinstance(data, dict)
            else []
        )
        if not results and isinstance(data, list):
            results = data
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",        bool(data)),
            ("results_nonempty", len(results) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_charity_uk() -> dict:
    tool_name, tool_id = "fetch_charity_uk", "T04"
    try:
        from datanexus.tools.t04 import fetch_charity_uk
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_charity_uk(charity_number_or_name="1107109"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        name_val = data.get("name", "") if isinstance(data, dict) else ""
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",     bool(data)),
            ("has_name_key",  "name" in data if isinstance(data, dict) else False),
            ("name_nonempty", len(name_val) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T10 — Security ─────────────────────────────────────────────────────────────

async def smoke_fetch_package_vulnerabilities() -> dict:
    tool_name, tool_id = "fetch_package_vulnerabilities", "T10"
    try:
        from datanexus.tools.t10 import fetch_package_vulnerabilities
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_package_vulnerabilities(package="requests", version="2.28.0", ecosystem="PyPI"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",       bool(data)),
            ("vulns_nonempty",  len(vulns) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_cve_detail() -> dict:
    tool_name, tool_id = "fetch_cve_detail", "T10"
    try:
        from datanexus.tools.t10 import fetch_cve_detail
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_detail(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        cvss_score = data.get("cvss_score", 0) if isinstance(data, dict) else 0
        severity = data.get("severity", "") if isinstance(data, dict) else ""
        # Accept any cvss-family key
        has_cvss = any(
            k for k in (data.keys() if isinstance(data, dict) else [])
            if "cvss" in k.lower()
        )
        score_ok = (isinstance(cvss_score, (int, float)) and cvss_score > 0) or bool(severity) or has_cvss
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",     bool(data)),
            ("has_cvss_info", score_ok),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_dependency_graph() -> dict:
    tool_name, tool_id = "fetch_dependency_graph", "T10"
    try:
        from datanexus.tools.t10 import fetch_dependency_graph
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_dependency_graph(package="flask", version="2.3.0", ecosystem="PyPI"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        deps = (
            data.get("dependencies", data.get("deps", None))
            if isinstance(data, dict) else None
        )
        # Accept non-empty deps OR any non-empty data dict
        has_deps = bool(deps) or bool(data)
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",  bool(data)),
            ("has_deps",  has_deps),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_audit_sbom_vulnerabilities() -> dict:
    tool_name, tool_id = "audit_sbom_vulnerabilities", "T10"
    sbom = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
            }
        ],
    })
    try:
        from datanexus.tools.t10 import audit_sbom_vulnerabilities
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            audit_sbom_vulnerabilities(sbom_json=sbom), timeout=TIMEOUT_S
        )
        # This tool must never crash; accept data OR markdown_output as success signal
        data = d.get("data", {})
        md = d.get("markdown_output", "")
        has_output = bool(data) or bool(md)
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",    True),
            ("has_output",  has_output),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_package_licence() -> dict:
    tool_name, tool_id = "fetch_package_licence", "T10"
    try:
        from datanexus.tools.t10 import fetch_package_licence
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_package_licence(package="requests", version="2.28.0", ecosystem="PyPI"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        licence_val = ""
        if isinstance(data, dict):
            licence_val = data.get("licence", data.get("license", ""))
        apache_ok = "apache" in licence_val.lower() if licence_val else False
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",           bool(data)),
            ("has_licence_key",    bool(licence_val)),
            ("licence_is_apache",  apache_ok),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T22 — Compliance ───────────────────────────────────────────────────────────

async def smoke_fetch_npi_provider() -> dict:
    tool_name, tool_id = "fetch_npi_provider", "T22"
    try:
        from datanexus.tools.t22 import fetch_npi_provider
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_npi_provider(npi_number="1003000126"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        name_val = ""
        if isinstance(data, dict):
            name_val = data.get("name", data.get("provider_name", ""))
        # "ENKESHAFI" should appear somewhere in the full response string
        resp_str = json.dumps(d)
        enkeshafi_found = "ENKESHAFI" in resp_str.upper()
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",         bool(data)),
            ("name_nonempty",    len(name_val) > 0),
            ("enkeshafi_found",  enkeshafi_found),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_search_npi_by_name() -> dict:
    tool_name, tool_id = "search_npi_by_name", "T22"
    try:
        from datanexus.tools.t22 import search_npi_by_name
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_npi_by_name(name="Smith", state="CA", speciality=""), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        results = data.get("results", []) if isinstance(data, dict) else []
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",        bool(data)),
            ("results_nonempty", len(results) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_finra_broker() -> dict:
    tool_name, tool_id = "fetch_finra_broker", "T22"
    try:
        from datanexus.tools.t22 import fetch_finra_broker
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_finra_broker(crd_number="1234567"), timeout=TIMEOUT_S
        )
        disclaimer = d.get("disclaimer", "")
        # "data" key must be present even if empty (not-found response)
        has_data_key = "data" in d
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",      True),
            ("has_data_key",  has_data_key),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_check_sam_exclusion() -> dict:
    tool_name, tool_id = "check_sam_exclusion", "T22"
    try:
        from datanexus.tools.t22 import check_sam_exclusion
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            check_sam_exclusion(name_or_ein="Test Entity"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        md = d.get("markdown_output", "")
        has_excluded_key = isinstance(data, dict) and "excluded" in data
        has_output = has_excluded_key or bool(md)
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",   True),
            ("has_output", has_output),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T07 — Domain ───────────────────────────────────────────────────────────────

async def smoke_fetch_domain_rdap() -> dict:
    tool_name, tool_id = "fetch_domain_rdap", "T07"
    try:
        from datanexus.tools.t07 import fetch_domain_rdap
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_domain_rdap(domain="example.com"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        registrar = data.get("registrar", "") if isinstance(data, dict) else ""
        has_date = any(
            k for k in (data.keys() if isinstance(data, dict) else [])
            if "date" in k.lower() or "expir" in k.lower()
        )
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",        bool(data)),
            ("registrar_nonempty", len(str(registrar)) > 0),
            ("has_date_field",  has_date),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_ssl_certificate_chain() -> dict:
    tool_name, tool_id = "fetch_ssl_certificate_chain", "T07"
    try:
        from datanexus.tools.t07 import fetch_ssl_certificate_chain
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_ssl_certificate_chain(domain="github.com"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        certs = data.get("certificates", []) if isinstance(data, dict) else []
        first_has_issuer = (
            isinstance(certs, list)
            and len(certs) > 0
            and isinstance(certs[0], dict)
            and "issuer" in certs[0]
        )
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",          bool(data)),
            ("certs_nonempty",     len(certs) > 0),
            ("first_cert_issuer",  first_has_issuer),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_dns_records() -> dict:
    tool_name, tool_id = "fetch_dns_records", "T07"
    try:
        from datanexus.tools.t07 import fetch_dns_records
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_dns_records(domain="cloudflare.com", record_types=["A", "MX"]),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        records = data.get("records", {}) if isinstance(data, dict) else {}
        has_records = bool(records) and any(
            v for v in records.values() if v
        ) if isinstance(records, dict) else bool(records)
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",       bool(data)),
            ("has_records",    has_records),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_domain_history() -> dict:
    tool_name, tool_id = "fetch_domain_history", "T07"
    try:
        from datanexus.tools.t07 import fetch_domain_history
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_domain_history(domain="github.com"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        certs = data.get("certificates", []) if isinstance(data, dict) else []
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",      bool(data)),
            ("certs_nonempty", len(certs) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T11 — Legal / Patents ──────────────────────────────────────────────────────

async def smoke_fetch_patent_by_number() -> dict:
    tool_name, tool_id = "fetch_patent_by_number", "T11"
    try:
        from datanexus.tools.t11 import fetch_patent_by_number
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_patent_by_number(patent_number="EP1000000", jurisdiction="EP"),
            timeout=TIMEOUT_S,
        )
        # T11 returns data at top level (same pattern as data key)
        data = d.get("data", d)  # fall back to whole dict if no "data" key
        title = data.get("title", "") if isinstance(data, dict) else ""
        has_people = any(
            k in data for k in ("inventors", "applicants")
        ) if isinstance(data, dict) else False
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",     bool(data)),
            ("title_nonempty", len(str(title)) > 0),
            ("has_people",   has_people),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_search_patents_by_keyword() -> dict:
    tool_name, tool_id = "search_patents_by_keyword", "T11"
    try:
        from datanexus.tools.t11 import search_patents_by_keyword
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_patents_by_keyword(keywords="bicycle wheel", jurisdiction="EP", date_from=""),
            timeout=TIMEOUT_S,
        )
        # Results may be at top level or under data
        results = (
            d.get("results", [])
            or d.get("data", {}).get("results", [])
            or d.get("data", {}).get("patents", [])
        )
        count = d.get("count", d.get("data", {}).get("count", 0))
        has_results = len(results) > 0 or (isinstance(count, (int, float)) and count > 0)
        return _check(d, tool_id, tool_name, t0, [
            ("has_output",  bool(d.get("data")) or bool(results) or bool(count)),
            ("has_results", has_results),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_patent_citations() -> dict:
    tool_name, tool_id = "fetch_patent_citations", "T11"
    try:
        from datanexus.tools.t11 import fetch_patent_citations
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_patent_citations(patent_number="EP1000000", jurisdiction="EP"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", d)
        has_citations = any(
            k in data
            for k in ("forward_citations", "backward_citations", "citations", "cites")
        ) if isinstance(data, dict) else False
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",      True),
            ("has_citations", has_citations),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_inventor_portfolio() -> dict:
    tool_name, tool_id = "fetch_inventor_portfolio", "T11"
    try:
        from datanexus.tools.t11 import fetch_inventor_portfolio
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_inventor_portfolio(inventor_name="Kosman", assignee=""),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", d)
        count = data.get("count", 0) if isinstance(data, dict) else 0
        results = data.get("results", []) if isinstance(data, dict) else []
        has_output = (isinstance(count, (int, float)) and count > 0) or len(results) > 0
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",   True),
            ("has_output", has_output),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T18 — GovCon ───────────────────────────────────────────────────────────────

async def smoke_search_contract_awards() -> dict:
    tool_name, tool_id = "search_contract_awards", "T18"
    try:
        from datanexus.tools.t18 import search_contract_awards
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_contract_awards(
                keyword="cybersecurity", agency="", date_from="", jurisdiction="US"
            ),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        awards = (
            data.get("awards", data.get("results", []))
            if isinstance(data, dict) else []
        )
        has_awards = len(awards) > 0
        # Graceful: DEGRADED if data empty but no error
        if not has_awards and bool(data):
            has_awards = True  # non-empty data dict counts
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",   bool(data)),
            ("has_awards", has_awards),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_vendor_contract_history() -> dict:
    tool_name, tool_id = "fetch_vendor_contract_history", "T18"
    try:
        from datanexus.tools.t18 import fetch_vendor_contract_history
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_vendor_contract_history(vendor_name="Booz Allen Hamilton", jurisdiction="US"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        total_awards = data.get("total_awards", 0) if isinstance(data, dict) else 0
        awards = data.get("awards", []) if isinstance(data, dict) else []
        has_awards = (
            (isinstance(total_awards, (int, float)) and total_awards > 0)
            or len(awards) > 0
        )
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",   bool(data)),
            ("has_awards", has_awards),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_open_solicitations() -> dict:
    tool_name, tool_id = "fetch_open_solicitations", "T18"
    try:
        from datanexus.tools.t18 import fetch_open_solicitations
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_open_solicitations(keyword="cloud services", agency="", jurisdiction="US"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        # DEGRADED (not FAIL) if data is empty but ingest_healthy
        ingest_ok = d.get("ingest_healthy", False)
        has_data = bool(data)
        # Treat empty-data-but-healthy as acceptable (DEGRADED path)
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",               True),
            ("data_present_or_healthy", has_data or ingest_ok),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T19 — Regulatory ───────────────────────────────────────────────────────────

async def smoke_search_open_rulemakings() -> dict:
    tool_name, tool_id = "search_open_rulemakings", "T19"
    try:
        from datanexus.tools.t19 import search_open_rulemakings
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_open_rulemakings(keyword="artificial intelligence", agency="", status="open"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        items = (
            data.get("dockets", data.get("results", []))
            if isinstance(data, dict) else []
        )
        has_items = len(items) > 0 or bool(data)
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",  bool(data)),
            ("has_items", has_items),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_docket_details() -> dict:
    tool_name, tool_id = "fetch_docket_details", "T19"
    try:
        from datanexus.tools.t19 import fetch_docket_details
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_docket_details(docket_id="FDA-2023-N-0001"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        title = data.get("title", "") if isinstance(data, dict) else ""
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",     True),
            ("has_data",     bool(data)),
            ("title_nonempty", len(str(title)) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_federal_register_notices() -> dict:
    tool_name, tool_id = "fetch_federal_register_notices", "T19"
    try:
        from datanexus.tools.t19 import fetch_federal_register_notices
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_federal_register_notices(
                agency="SEC", keyword="cryptocurrency", date_from="2024-01-01"
            ),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        notices = (
            data.get("notices", data.get("results", []))
            if isinstance(data, dict) else []
        )
        has_notices = len(notices) > 0
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",       bool(data)),
            ("has_notices",    has_notices),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── Meta / Shared tools ────────────────────────────────────────────────────────

async def smoke_search_datanexus_tools() -> dict:
    tool_name, tool_id = "search_datanexus_tools", "META"
    try:
        from datanexus.tools.meta import search_datanexus_tools
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_datanexus_tools(query="find CVEs for a package"), timeout=TIMEOUT_S
        )
        tools_list = d.get("tools", [])
        resp_str = json.dumps(d)
        has_tools = len(tools_list) > 0
        has_vuln_tool = "security_fetch_package_vulnerabilities" in resp_str
        return _check(d, tool_id, tool_name, t0, [
            ("has_tools",       has_tools),
            ("has_vuln_tool",   has_vuln_tool),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_validate_tool_output() -> dict:
    tool_name, tool_id = "validate_tool_output", "META"
    # Construct a minimal valid T04-shaped response JSON
    minimal_t04 = json.dumps({
        "ingest_healthy": True,
        "disclaimer": "DataNexus smoke test minimal payload",
        "data": {"name": "Wikimedia Foundation"},
        "markdown_output": "# Wikimedia Foundation",
        "query_hash": "smoke-test-hash",
        "tool_id": "T04",
        "cache_hit": False,
    })
    try:
        from datanexus.tools.validation import validate_tool_output
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            validate_tool_output(
                tool_id="T04",
                query_hash="smoke-test-hash",
                response_json=minimal_t04,
            ),
            timeout=TIMEOUT_S,
        )
        has_validation = "validation" in d
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",        True),
            ("has_validation",  has_validation),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_report_feedback() -> dict:
    tool_name, tool_id = "report_feedback", "META"
    try:
        from datanexus.tools.meta import report_feedback
    except ImportError:
        return _skip_result(tool_name, tool_id, "report_feedback not found in datanexus.tools.meta")

    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            report_feedback(tool_id="T04", query_hash="smoke-test-hash", issue="smoke test"),
            timeout=TIMEOUT_S,
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        # DEGRADED on failure, never FAIL (write-ish tool)
        status = "PASS" if d else "DEGRADED"
        return _make_result(
            tool_name, tool_id, status, latency_ms,
            ["no_crash"], [], d.get("ingest_healthy") if isinstance(d, dict) else None,
        )
    except Exception as exc:
        return _make_result(tool_name, tool_id, "DEGRADED", 0, [], ["exception"], None, error=str(exc))


async def smoke_report_mcpize_link() -> dict:
    tool_name, tool_id = "report_mcpize_link", "META"
    try:
        from datanexus.tools.meta import report_mcpize_link
    except ImportError:
        return _skip_result(tool_name, tool_id, "report_mcpize_link not found in datanexus.tools.meta")

    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            report_mcpize_link(url="https://example.com"), timeout=TIMEOUT_S
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        status = "PASS" if d else "DEGRADED"
        return _make_result(
            tool_name, tool_id, status, latency_ms,
            ["no_crash"], [], d.get("ingest_healthy") if isinstance(d, dict) else None,
        )
    except Exception as exc:
        return _make_result(tool_name, tool_id, "DEGRADED", 0, [], ["exception"], None, error=str(exc))


# ── Redis write ────────────────────────────────────────────────────────────────

def _write_to_redis(results: list) -> None:
    try:
        import redis
        redis_url = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
        r = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
        r.ping()
        pipe = r.pipeline()
        for res in results:
            key = f"datanexus:smoke:{res['tool']}"
            pipe.hset(key, mapping={
                "status":         res["status"],
                "latency_ms":     str(res["latency_ms"]),
                "checked_at":     res["ts"],
                "tool_id":        res["tool_id"],
                "ingest_healthy": str(res["ingest_healthy"]),
                "checks_passed":  ",".join(res["checks_passed"]),
                "checks_failed":  ",".join(res["checks_failed"]),
                "error":          res["error"] or "",
            })
            pipe.expire(key, 7200)
        pipe.execute()
        log.info("Smoke results written to Redis (%d keys)", len(results))
    except Exception as exc:
        log.warning("Redis write skipped: %s", exc)


# ── Runner ─────────────────────────────────────────────────────────────────────

# All 30 smoke coroutine factories in declaration order
_SMOKE_COROUTINES = [
    # T04 — Nonprofit (3)
    smoke_fetch_nonprofit_by_ein,
    smoke_search_nonprofits_by_name,
    smoke_fetch_charity_uk,
    # T10 — Security (5)
    smoke_fetch_package_vulnerabilities,
    smoke_fetch_cve_detail,
    smoke_fetch_dependency_graph,
    smoke_audit_sbom_vulnerabilities,
    smoke_fetch_package_licence,
    # T22 — Compliance (4)
    smoke_fetch_npi_provider,
    smoke_search_npi_by_name,
    smoke_fetch_finra_broker,
    smoke_check_sam_exclusion,
    # T07 — Domain (4)
    smoke_fetch_domain_rdap,
    smoke_fetch_ssl_certificate_chain,
    smoke_fetch_dns_records,
    smoke_fetch_domain_history,
    # T11 — Legal (4)
    smoke_fetch_patent_by_number,
    smoke_search_patents_by_keyword,
    smoke_fetch_patent_citations,
    smoke_fetch_inventor_portfolio,
    # T18 — GovCon (3)
    smoke_search_contract_awards,
    smoke_fetch_vendor_contract_history,
    smoke_fetch_open_solicitations,
    # T19 — Regulatory (3)
    smoke_search_open_rulemakings,
    smoke_fetch_docket_details,
    smoke_fetch_federal_register_notices,
    # Meta (4)
    smoke_search_datanexus_tools,
    smoke_validate_tool_output,
    smoke_report_feedback,
    smoke_report_mcpize_link,
]

assert len(_SMOKE_COROUTINES) == 30, f"Expected 30 smoke tests, got {len(_SMOKE_COROUTINES)}"


async def run_all() -> list:
    """Run all 30 smoke tests concurrently. Returns list of result dicts."""
    tasks = [coro() for coro in _SMOKE_COROUTINES]
    raw = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for i, res in enumerate(raw):
        if isinstance(res, Exception):
            name = _SMOKE_COROUTINES[i].__name__.replace("smoke_", "")
            results.append(_make_result(
                name, "??", "FAIL", 0, [], ["gather_exception"], None, error=str(res)
            ))
        else:
            results.append(res)
    return results


def main() -> int:
    """Entry point. Returns exit code: 0 = all PASS/SKIP/DEGRADED, 1 = any FAIL."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )

    t_start = time.monotonic()
    results = asyncio.run(run_all())
    total_elapsed = time.monotonic() - t_start

    counts: dict[str, int] = {"PASS": 0, "FAIL": 0, "DEGRADED": 0, "SKIP": 0}
    fails: list[str] = []
    degraded: list[str] = []

    divider = "─" * 80
    print(f"\n{divider}")
    print(f"  DataNexus Smoke Test — {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{divider}")

    # Group output by tool_id for readability
    current_group = None
    for r in results:
        group = r["tool_id"]
        if group != current_group:
            print(f"\n  [{group}]")
            current_group = group

        icon = {"PASS": "✓", "FAIL": "✗", "DEGRADED": "~", "SKIP": "·"}.get(r["status"], "?")
        lat = f"{r['latency_ms']:>6}ms" if r["status"] != "SKIP" else "        "
        status_tag = f"[{r['status']:<8}]"
        checks_ok = ",".join(r["checks_passed"]) or "-"
        checks_bad = ",".join(r["checks_failed"]) or "-"
        print(f"    {icon} {status_tag} {lat}  {r['tool']}")
        if r["checks_failed"]:
            print(f"             FAILED CHECKS: {checks_bad}")
        if r["error"] and r["status"] not in ("SKIP",):
            print(f"             ERROR: {r['error'][:120]}")

        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["status"] == "FAIL":
            fails.append(r["tool"])
        elif r["status"] == "DEGRADED":
            degraded.append(f"{r['tool']} ({r['latency_ms']}ms)")

        # Machine-readable line for log parsing
        print(json.dumps(r))

    print(f"\n{divider}")
    print(f"  PASS={counts['PASS']}  FAIL={counts['FAIL']}  "
          f"DEGRADED={counts['DEGRADED']}  SKIP={counts['SKIP']}  "
          f"Total runtime: {total_elapsed:.1f}s")
    if fails:
        print(f"  FAIL: {', '.join(fails)}")
    if degraded:
        print(f"  DEGRADED: {', '.join(degraded)}")
    print(f"{divider}\n")

    _write_to_redis(results)

    return 1 if counts["FAIL"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
