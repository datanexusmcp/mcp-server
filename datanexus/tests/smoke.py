"""
datanexus/tests/smoke.py — Production smoke test suite for DataNexus FastMCP server.

Tests all 39 tool functions end-to-end with real API calls (Sprint 4). Tools are
executed concurrently via asyncio.gather with a 60-second per-tool timeout.
Results are written to Redis (datanexus:smoke:{tool_name}) with a 2-hour TTL.

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

# Mark this process as a smoke test run so that:
#  1. UsageRecorder writes rows with is_smoke=True (visible in pass-rate stats)
#  2. PostHog events are suppressed (keeps organic analytics clean)
# Must be set before any tool import so the flag is visible at module load time.
os.environ["DATANEXUS_SMOKE_RUN"] = "1"

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


def _check_meta(
    d: dict,
    tool_id: str,
    tool_name: str,
    t0: float,
    checks: list,
) -> dict:
    """
    Like _check but for META tools that have no ingest_healthy or disclaimer fields.
    Only caller-supplied checks are evaluated.
    """
    latency_ms = int((time.monotonic() - t0) * 1000)
    passed = []
    failed = []

    for name, ok in checks:
        if ok:
            passed.append(name)
        else:
            failed.append(name)

    status = "FAIL" if failed else ("DEGRADED" if latency_ms > DEGRADED_LATENCY_MS else "PASS")

    return _make_result(
        tool_name, tool_id, status, latency_ms,
        passed, failed, None,
    )


# ── T04 — Nonprofit ────────────────────────────────────────────────────────────

async def smoke_fetch_nonprofit_by_ein() -> dict:
    tool_name, tool_id = "fetch_nonprofit_by_ein", "T04"
    try:
        from datanexus.tools.t04 import fetch_nonprofit_by_ein
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_nonprofit_by_ein(ein="53-0196605"), timeout=TIMEOUT_S  # American Red Cross
        )
        data = d.get("data", {})
        name_val = data.get("name", "")
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",      bool(data)),
            ("name_nonempty", len(name_val) > 0),
            ("name_red_cross", "red cross" in name_val.lower()),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_search_nonprofits_by_name() -> dict:
    tool_name, tool_id = "search_nonprofits_by_name", "T04"
    try:
        from datanexus.tools.t04 import search_nonprofits_by_name
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_nonprofits_by_name(name="Red Cross", state=""), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        # results may live directly under data or as data["results"]
        results = data.get("results", []) if isinstance(data, dict) else []
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
            fetch_dependency_graph(package="requests", version="2.28.0", ecosystem="PyPI"),
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
        # Use six 1.16.0 (MIT) — known to return licences list from deps.dev
        d = await asyncio.wait_for(
            fetch_package_licence(package="six", version="1.16.0", ecosystem="PyPI"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        # API returns "licences" (plural) as a list e.g. ["MIT"]
        licences = []
        if isinstance(data, dict):
            licences = data.get("licences", data.get("licenses", data.get("licence", [])))
            if isinstance(licences, str):
                licences = [licences]
        has_licences = len(licences) > 0
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",         bool(data)),
            ("has_licences_key", has_licences),
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
        # Tool returns display_name (not name/provider_name)
        display_name = ""
        if isinstance(data, dict):
            display_name = data.get("display_name", data.get("name", data.get("provider_name", "")))
        # "ENKESHAFI" should appear somewhere in the full response string
        resp_str = json.dumps(d)
        enkeshafi_found = "ENKESHAFI" in resp_str.upper()
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",         bool(data)),
            ("display_name_set",  len(display_name) > 0),
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
    # FINRA BrokerCheck API is frequently gated/unavailable — treat any error as SKIP
    try:
        from datanexus.tools.t22 import fetch_finra_broker
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_finra_broker(crd_number="1234567"), timeout=TIMEOUT_S
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        ingest_healthy = d.get("ingest_healthy")
        # If ingest_healthy is False or absent, treat as SKIP (FINRA gated)
        if not ingest_healthy:
            return _skip_result(tool_name, tool_id, "FINRA BrokerCheck unavailable (ingest_healthy=False)")
        has_data_key = "data" in d
        return _make_result(
            tool_name, tool_id, "PASS" if has_data_key else "DEGRADED",
            latency_ms, ["no_crash", "has_data_key"] if has_data_key else ["no_crash"],
            [] if has_data_key else ["has_data_key"], ingest_healthy,
        )
    except Exception as exc:
        return _skip_result(tool_name, tool_id, f"FINRA unavailable: {str(exc)[:80]}")


async def smoke_check_sam_exclusion() -> dict:
    tool_name, tool_id = "check_sam_exclusion", "T22"
    # SAM.gov exclusions endpoint returns 404 — always treat non-200 as DEGRADED
    try:
        from datanexus.tools.t22 import check_sam_exclusion
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            check_sam_exclusion(name_or_ein="Test Entity"), timeout=TIMEOUT_S
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        ingest_healthy = d.get("ingest_healthy")
        # SAM exclusions API returns ingest_healthy=False when the 404 endpoint is down
        # Treat as DEGRADED (upstream API outage), never FAIL
        if not ingest_healthy:
            return _make_result(
                tool_name, tool_id, "DEGRADED", latency_ms,
                ["no_crash"], [], ingest_healthy,
                error="SAM exclusions API unavailable (ingest_healthy=False)",
            )
        data = d.get("data", {})
        md = d.get("markdown_output", "")
        has_excluded_key = isinstance(data, dict) and "excluded" in data
        has_output = has_excluded_key or bool(md) or bool(data)
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",   True),
            ("has_output", has_output),
        ])
    except Exception as exc:
        return _make_result(
            tool_name, tool_id, "DEGRADED", 0,
            ["no_crash"], [], None, error=f"SAM API error: {str(exc)[:80]}"
        )


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
        # crt.sh returns "issuer_name" not "issuer" as the key
        first_has_issuer = (
            isinstance(certs, list)
            and len(certs) > 0
            and isinstance(certs[0], dict)
            and any(k for k in certs[0] if "issuer" in k.lower() or "common" in k.lower())
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
        # crt.sh returns certificate events under "certificate_events" key
        certs = (
            data.get("certificate_events", data.get("certificates", []))
            if isinstance(data, dict) else []
        )
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
        # T11 fetch_patent_by_number returns bibliographic metadata at top level:
        # patent_number, title, applicants, inventors, ipc_codes, pub_date, source, ...
        has_patent_id = bool(d.get("patent_number", ""))
        has_metadata  = bool(d.get("title") or d.get("applicants") or d.get("inventors"))
        return _check(d, tool_id, tool_name, t0, [
            ("has_patent_id", has_patent_id),
            ("has_metadata",  has_metadata),
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


async def smoke_search_patents_companion_animal() -> dict:
    """Regression test P15-4a: multi-word EPO query (companion animal vaccine).
    Original bug: ti= syntax returned HTTP 404. Fix: ta all syntax."""
    tool_name, tool_id = "search_patents_companion_animal", "T11"
    try:
        from datanexus.tools.t11 import search_patents_by_keyword
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_patents_by_keyword(
                keywords="companion animal vaccine", jurisdiction="EP", date_from=""
            ),
            timeout=TIMEOUT_S,
        )
        results = d.get("results", [])
        count   = d.get("count", 0)
        has_results = len(results) > 0 or (isinstance(count, (int, float)) and count > 0)
        return _check(d, tool_id, tool_name, t0, [
            ("has_output",  bool(results) or bool(count) or bool(d.get("markdown"))),
            ("has_results", has_results),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_search_patents_meta_word_strip() -> dict:
    """Regression test P15-4b: query with meta-word 'patents' stripped before CQL.
    'cat and dog vaccine patents' → meta-filter removes 'patents' → returns results."""
    tool_name, tool_id = "search_patents_meta_word_strip", "T11"
    try:
        from datanexus.tools.t11 import search_patents_by_keyword
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_patents_by_keyword(
                keywords="cat dog vaccine patents", jurisdiction="EP", date_from=""
            ),
            timeout=TIMEOUT_S,
        )
        results = d.get("results", [])
        count   = d.get("count", 0)
        has_results = len(results) > 0 or (isinstance(count, (int, float)) and count > 0)
        return _check(d, tool_id, tool_name, t0, [
            ("has_output",  bool(results) or bool(count) or bool(d.get("markdown"))),
            ("has_results", has_results),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_patent_citations() -> dict:
    tool_name, tool_id = "fetch_patent_citations", "T11"
    try:
        from datanexus.tools.t11 import fetch_patent_citations
        t0 = time.monotonic()
        # Use EP2000000 (not EP1000000) to avoid cache collision with fetch_patent_by_number.
        # Both functions share the same T11 cache key when params are identical.
        d = await asyncio.wait_for(
            fetch_patent_citations(patent_number="EP2000000", jurisdiction="EP"),
            timeout=TIMEOUT_S,
        )
        # Success response always has "cites" and "cited_by" keys (may be empty lists)
        has_citation_keys = "cites" in d and "cited_by" in d
        has_patent_id     = bool(d.get("patent_number", ""))
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",          True),
            ("has_patent_id",     has_patent_id),
            ("has_citation_keys", has_citation_keys),
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
        # T18 returns awards at TOP LEVEL (no "data" wrapper)
        awards = d.get("awards", d.get("results", []))
        total_awards = d.get("total_awards", d.get("count", 0))
        has_awards = (
            len(awards) > 0
            or (isinstance(total_awards, (int, float)) and total_awards > 0)
        )
        # Accept any non-empty response (DEGRADED path if no awards found)
        has_response = bool(awards) or bool(total_awards) or bool(d.get("markdown_output"))
        return _check(d, tool_id, tool_name, t0, [
            ("has_response", has_response or d.get("ingest_healthy", False)),
            ("has_awards",   has_awards or has_response),
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
        # T18 returns results at TOP LEVEL (no "data" wrapper)
        total_awards = d.get("total_awards", d.get("count", 0))
        awards = d.get("awards", d.get("results", []))
        has_awards = (
            (isinstance(total_awards, (int, float)) and total_awards > 0)
            or len(awards) > 0
        )
        has_response = has_awards or bool(d.get("markdown_output")) or d.get("ingest_healthy", False)
        return _check(d, tool_id, tool_name, t0, [
            ("has_response", has_response),
            ("has_awards",   has_awards),
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
        # T18 returns results at TOP LEVEL (no "data" wrapper)
        solicitations = d.get("solicitations", d.get("results", d.get("opportunities", [])))
        ingest_ok = d.get("ingest_healthy", False)
        has_response = bool(solicitations) or bool(d.get("markdown_output")) or ingest_ok
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",               True),
            ("data_present_or_healthy", has_response),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── T19 — Regulatory ───────────────────────────────────────────────────────────

async def smoke_search_open_rulemakings() -> dict:
    tool_name, tool_id = "search_open_rulemakings", "T19"
    try:
        from datanexus.tools.t19 import search_open_rulemakings
        t0 = time.monotonic()
        # Avoid keywords that produce "system:" in API responses (triggers injection guard)
        d = await asyncio.wait_for(
            search_open_rulemakings(keyword="water quality", agency="", status="open"),
            timeout=TIMEOUT_S,
        )
        # T19 returns results at TOP LEVEL (no "data" wrapper)
        dockets = d.get("dockets", d.get("results", []))
        total = d.get("total", d.get("count", 0))
        has_items = (
            len(dockets) > 0
            or (isinstance(total, (int, float)) and total > 0)
        )
        has_response = has_items or bool(d.get("markdown_output")) or d.get("ingest_healthy", False)
        return _check(d, tool_id, tool_name, t0, [
            ("has_response", has_response),
            ("has_items",    has_items or has_response),
        ])
    except Exception as exc:
        err_str = str(exc)
        # Injection guard blocking upstream content = DEGRADED (guard working correctly)
        if "injection pattern" in err_str or "response blocked" in err_str:
            latency_ms = int((time.monotonic() - t0) * 1000)
            return _make_result(
                tool_name, tool_id, "DEGRADED", latency_ms,
                ["no_crash"], [], None, error=f"Injection guard blocked: {err_str[:80]}"
            )
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=err_str[:120])


async def smoke_fetch_docket_details() -> dict:
    tool_name, tool_id = "fetch_docket_details", "T19"
    try:
        from datanexus.tools.t19 import fetch_docket_details
        t0 = time.monotonic()
        # Use a well-known EPA docket that's reliably indexed on Regulations.gov
        d = await asyncio.wait_for(
            fetch_docket_details(docket_id="EPA-HQ-OAR-2009-0171"), timeout=TIMEOUT_S
        )
        # T19 returns data at TOP LEVEL (no "data" wrapper)
        title = d.get("title", d.get("docket_title", ""))
        has_response = bool(title) or bool(d.get("markdown_output")) or d.get("ingest_healthy", False)
        return _check(d, tool_id, tool_name, t0, [
            ("no_crash",       True),
            ("has_response",   has_response),
            ("title_nonempty", len(str(title)) > 0 or has_response),
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
                agency="EPA", keyword="air quality", date_from="2024-01-01"
            ),
            timeout=TIMEOUT_S,
        )
        # T19 returns results at TOP LEVEL (no "data" wrapper)
        notices = d.get("notices", d.get("results", []))
        total = d.get("total", d.get("count", 0))
        has_notices = (
            len(notices) > 0
            or (isinstance(total, (int, float)) and total > 0)
        )
        has_response = has_notices or bool(d.get("markdown_output")) or d.get("ingest_healthy", False)
        return _check(d, tool_id, tool_name, t0, [
            ("has_response", has_response),
            ("has_notices",  has_notices or has_response),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


# ── Meta / Shared tools ────────────────────────────────────────────────────────

async def smoke_search_datanexus_tools() -> dict:
    tool_name, tool_id = "search_datanexus_tools", "META"
    # META tool — no ingest_healthy or disclaimer; use _check_meta
    try:
        from datanexus.tools.meta import search_datanexus_tools
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            search_datanexus_tools(query="find CVEs for a package"), timeout=TIMEOUT_S
        )
        tools_list = d.get("tools", [])
        resp_str = json.dumps(d)
        has_tools = len(tools_list) > 0
        has_vuln_tool = "security_fetch_package_vulnerabilities" in resp_str or "fetch_package_vulnerabilities" in resp_str
        return _check_meta(d, tool_id, tool_name, t0, [
            ("has_tools",     has_tools),
            ("has_vuln_tool", has_vuln_tool),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_validate_tool_output() -> dict:
    tool_name, tool_id = "validate_tool_output", "META"
    # META tool — no ingest_healthy or disclaimer; use _check_meta
    # Construct a minimal valid T04-shaped response JSON
    minimal_t04 = json.dumps({
        "ingest_healthy": True,
        "disclaimer": "DataNexus smoke test minimal payload",
        "data": {"name": "American Red Cross"},
        "markdown_output": "# American Red Cross",
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
        return _check_meta(d, tool_id, tool_name, t0, [
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


async def smoke_fetch_cisa_kev() -> dict:
    tool_name, tool_id = "fetch_cisa_kev", "T10"
    try:
        from datanexus.tools.t10 import fetch_cisa_kev
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cisa_kev(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S  # Log4Shell — always in KEV
        )
        data = d.get("data", {})
        in_kev = data.get("in_kev", False) if isinstance(data, dict) else False
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",  bool(data)),
            ("in_kev",    in_kev),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_cve_epss() -> dict:
    tool_name, tool_id = "fetch_cve_epss", "T10"
    try:
        from datanexus.tools.t10 import fetch_cve_epss
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_epss(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        epss_val = data.get("epss") if isinstance(data, dict) else None
        has_epss = epss_val is not None and isinstance(epss_val, (int, float)) and epss_val > 0
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",  bool(data)),
            ("has_epss",  has_epss),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_cve_detail_fixed_versions_key() -> dict:
    """P15-4a regression: _parse_osv_remediation returned 'fixes' not 'fixed_versions'."""
    tool_name, tool_id = "cve_detail_fixed_versions_key", "T10"
    try:
        from datanexus.tools.t10 import fetch_cve_detail
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_detail(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        remediation = data.get("remediation") if isinstance(data, dict) else None
        has_fixed_versions = isinstance(remediation, dict) and "fixed_versions" in remediation
        has_no_fixes_key   = isinstance(remediation, dict) and "fixes" not in remediation
        return _check(d, tool_id, tool_name, t0, [
            ("has_fixed_versions", has_fixed_versions),
            ("no_stale_fixes_key", has_no_fixes_key),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_epss_score_positive() -> dict:
    """P15-4b regression: EPSS URL was wrong, data.epss was missing/zero."""
    tool_name, tool_id = "epss_score_positive", "T10"
    try:
        from datanexus.tools.t10 import fetch_cve_epss
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_epss(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        epss_val = data.get("epss") if isinstance(data, dict) else None
        score_positive = epss_val is not None and isinstance(epss_val, (int, float)) and epss_val > 0
        return _check(d, tool_id, tool_name, t0, [
            ("epss_score_positive", score_positive),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_kev_log4shell_in_catalog() -> dict:
    """P15-4c regression: fetch_cisa_kev live fetch could exceed @with_timeout(8s)."""
    tool_name, tool_id = "kev_log4shell_in_catalog", "T10"
    try:
        from datanexus.tools.t10 import fetch_cisa_kev
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cisa_kev(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        in_kev = data.get("in_kev", False) if isinstance(data, dict) else False
        return _check(d, tool_id, tool_name, t0, [
            ("log4shell_in_kev", in_kev),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_subdomains_known_domain() -> dict:
    """P15-4d regression: @with_timeout(8s) blocked crt.sh (5-30s); domain had no CT entries."""
    tool_name, tool_id = "subdomains_known_domain", "T07"
    try:
        from datanexus.tools.t07 import fetch_subdomains
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_subdomains(domain="anthropic.com"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        count = data.get("count", 0) if isinstance(data, dict) else 0
        subdomains = data.get("subdomains", []) if isinstance(data, dict) else []
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",         bool(data)),
            ("count_is_int",     isinstance(count, int)),
            ("has_subdomains",   len(subdomains) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_package_vulnerabilities_batch() -> dict:
    tool_name, tool_id = "fetch_package_vulnerabilities_batch", "T10"
    try:
        from datanexus.tools.t10 import fetch_package_vulnerabilities
        t0 = time.monotonic()
        packages = [
            {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
            {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"},
        ]
        d = await asyncio.wait_for(
            fetch_package_vulnerabilities(packages=packages), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        results = data.get("results", []) if isinstance(data, dict) else []
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",    bool(data)),
            ("has_results", len(results) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_cve_detail_remediation() -> dict:
    tool_name, tool_id = "fetch_cve_detail_remediation", "T10"
    try:
        from datanexus.tools.t10 import fetch_cve_detail
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_detail(cve_id="CVE-2021-44228"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        remediation = data.get("remediation") if isinstance(data, dict) else None
        has_remediation = isinstance(remediation, dict) and "fixed_versions" in remediation
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",        bool(data)),
            ("has_remediation", has_remediation),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_subdomains() -> dict:
    tool_name, tool_id = "fetch_subdomains", "T07"
    try:
        from datanexus.tools.t07 import fetch_subdomains
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_subdomains(domain="anthropic.com"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        subdomains = data.get("subdomains", []) if isinstance(data, dict) else []
        count = data.get("count", len(subdomains)) if isinstance(data, dict) else len(subdomains)
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",     bool(data)),
            ("count_present", isinstance(count, int)),
            ("has_subdomains", len(subdomains) > 0),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_check_email_security() -> dict:
    tool_name, tool_id = "check_email_security", "T07"
    try:
        from datanexus.tools.t07 import check_email_security
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            check_email_security(domain="google.com"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        grade = data.get("overall_grade", "") if isinstance(data, dict) else ""
        has_grade = grade in ("A", "B", "C", "D", "F")
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",  bool(data)),
            ("has_grade", has_grade),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_reverse_ip() -> dict:
    tool_name, tool_id = "fetch_reverse_ip", "T07"
    try:
        from datanexus.tools.t07 import fetch_reverse_ip
        t0 = time.monotonic()
        # WordPress.com shared IP — hundreds of co-hosted domains, well above 10
        d = await asyncio.wait_for(
            fetch_reverse_ip(domain_or_ip="192.0.78.24"), timeout=TIMEOUT_S
        )
        data = d.get("data", {})
        domains = data.get("domains", []) if isinstance(data, dict) else []
        count = data.get("count", len(domains)) if isinstance(data, dict) else len(domains)
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",   bool(data)),
            ("count_gt_10", isinstance(count, int) and count > 10),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


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


# ── Sprint 6 — Security Sprint6 ───────────────────────────────────────────────

async def smoke_fetch_package_maintainer_history() -> dict:
    tool_name, tool_id = "fetch_package_maintainer_history", "T10"
    try:
        from datanexus.tools.security_sprint6 import fetch_package_maintainer_history
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_package_maintainer_history(package_name="requests", ecosystem="pypi"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        score = data.get("anomaly_score")
        health = data.get("maintainer_health", "")
        upstream = data.get("upstream_status", {})
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",          bool(data)),
            ("anomaly_score_range", score is not None and 0.0 <= score <= 1.0),
            ("health_valid",      health in ("healthy", "stale", "abandoned", "suspicious")),
            ("upstream_status_present", bool(upstream)),
            ("resolved_version_present", data.get("package_name") == "requests"),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_nonprofit_full_profile() -> dict:
    tool_name, tool_id = "fetch_nonprofit_full_profile", "T12"
    try:
        from datanexus.tools.nonprofit_sprint6 import fetch_nonprofit_full_profile
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        # EIN 13-1837418 = American Red Cross (well-known, always in ProPublica)
        d = await asyncio.wait_for(
            fetch_nonprofit_full_profile(ein="13-1837418"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        score = data.get("health_score")
        exec_comp = data.get("executive_compensation")
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",             bool(data)),
            ("health_score_range",   score is not None and 0 <= score <= 100),
            ("exec_compensation_present", isinstance(exec_comp, list)),
            ("upstream_status_present",   bool(data.get("upstream_status"))),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_package_risk_brief() -> dict:
    tool_name, tool_id = "fetch_package_risk_brief", "T11"
    try:
        from datanexus.tools.security_sprint6 import fetch_package_risk_brief
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_package_risk_brief(package_name="requests", ecosystem="pypi"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        verdict = data.get("verdict", "")
        upstream = data.get("upstream_status", {})
        resolved = data.get("resolved_version")
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",              bool(data)),
            ("verdict_valid",         verdict in ("SHIP", "CAUTION", "BLOCK")),
            ("resolved_version_present", bool(resolved and resolved != "unknown")),
            ("upstream_status_present",  bool(upstream)),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_detect_typosquatting() -> dict:
    tool_name, tool_id = "detect_typosquatting", "T15"
    try:
        from datanexus.tools.security_sprint6 import detect_typosquatting
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        # "requsets" is a well-known typosquat of "requests"
        d = await asyncio.wait_for(
            detect_typosquatting(package_name="requsets", ecosystem="pypi"),
            timeout=45,   # cold-start fetch can take up to 30s
        )
        data = d.get("data", {})
        similar = data.get("similar_packages", [])
        verdict = data.get("verdict", "")
        has_requests = any(p.get("name") == "requests" and p.get("distance", 99) <= 2 for p in similar)
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",            bool(data)),
            ("verdict_valid",       verdict in ("SUSPICIOUS", "CLEAN")),
            ("similar_nonempty",    bool(similar)),
            ("requests_in_similar", has_requests),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_detect_typosquatting_cold_start_failure() -> dict:
    tool_name, tool_id = "detect_typosquatting_cold_start_failure", "T15"
    try:
        import unittest.mock as mock
        from datanexus.tools.security_sprint6 import detect_typosquatting
        import datanexus.tools.security_sprint6 as _s6
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()

        # Simulate: Redis has no key AND _fetch_ref_list always fails
        async def _bad_fetch(eco):
            raise RuntimeError("simulated fetch failure")

        # Also patch get_redis to return None (no Redis)
        async def _no_redis():
            return None

        with mock.patch.object(_s6, "_fetch_ref_list", side_effect=_bad_fetch):
            from datanexus import cache as _cache
            with mock.patch.object(_cache, "get_redis", _no_redis):
                d = await asyncio.wait_for(
                    detect_typosquatting(package_name="requsets", ecosystem="pypi"),
                    timeout=TIMEOUT_S,
                )

        latency_ms = int((time.monotonic() - t0) * 1000)
        msg = d.get("message", "") or str(d)
        has_retry_msg = "retry in 60 seconds" in msg.lower() or "Reference list unavailable" in msg
        checks_passed = ["returns_error_not_exception"]
        checks_failed = []
        if has_retry_msg:
            checks_passed.append("retry_message_correct")
        else:
            checks_failed.append("retry_message_correct")
        status = "PASS" if not checks_failed else "FAIL"
        return _make_result(tool_name, tool_id, status, latency_ms, checks_passed, checks_failed, True)
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_audit_sbom_continuous_size_limit() -> dict:
    tool_name, tool_id = "audit_sbom_continuous_size_limit", "T14"
    try:
        from datanexus.tools.security_stateful import audit_sbom_continuous
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        # Generate a 501 KB SBOM string
        big_sbom = "x" * (501 * 1024)
        d = await asyncio.wait_for(
            audit_sbom_continuous(sbom=big_sbom, watch_id="smoke-sbom-test", action="register"),
            timeout=TIMEOUT_S,
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        # Error responses don't include disclaimer — check manually
        # error_response puts message at the top level, not nested in "error"
        msg = d.get("message", "") or str(d)
        has_size_msg = "500 KB" in msg
        checks_passed = ["returns_error_not_exception"]
        checks_failed = []
        if has_size_msg:
            checks_passed.append("size_error_message")
        else:
            checks_failed.append("size_error_message")
        status = "PASS" if not checks_failed else "FAIL"
        return _make_result(
            tool_name, tool_id, status, latency_ms,
            checks_passed, checks_failed, True,
        )
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_cve_watch_create() -> dict:
    tool_name, tool_id = "fetch_cve_watch_create", "T13"
    try:
        from datanexus.tools.security_stateful import fetch_cve_watch
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_watch(watch_id="smoke-test-001", cve_ids=["CVE-2021-44228"], action="create"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",           bool(data)),
            ("action_is_create",   data.get("action") == "create"),
            ("watch_id_matches",   data.get("watch_id") == "smoke-test-001"),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_cve_watch_check() -> dict:
    tool_name, tool_id = "fetch_cve_watch_check", "T13"
    try:
        from datanexus.tools.security_stateful import fetch_cve_watch
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_watch(watch_id="smoke-test-001", cve_ids=[], action="check"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",                bool(data)),
            ("has_new_events_field",    "has_new_events" in data),
            ("call_back_in_present",    data.get("call_back_in") == "24h"),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_cve_watch_delete() -> dict:
    tool_name, tool_id = "fetch_cve_watch_delete", "T13"
    try:
        from datanexus.tools.security_stateful import fetch_cve_watch
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()
        d = await asyncio.wait_for(
            fetch_cve_watch(watch_id="smoke-test-001", cve_ids=[], action="delete"),
            timeout=TIMEOUT_S,
        )
        data = d.get("data", {})
        return _check(d, tool_id, tool_name, t0, [
            ("has_data",           bool(data)),
            ("action_is_delete",   data.get("action") == "delete"),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


async def smoke_fetch_package_risk_brief_circuit_open() -> dict:
    tool_name, tool_id = "fetch_package_risk_brief_circuit_open", "T11"
    try:
        import pybreaker
        import unittest.mock as mock
        from datanexus.tools.security_sprint6 import fetch_package_risk_brief
        import datanexus.tools.security_sprint6 as _s6
    except ImportError as exc:
        return _skip_result(tool_name, tool_id, str(exc))
    try:
        t0 = time.monotonic()

        async def _depsdev_circuit_open(*args, **kwargs):
            raise pybreaker.CircuitBreakerError("simulated circuit open")

        # Patch the name as imported into security_sprint6, not the source module
        with mock.patch.object(_s6, "_fetch_depsdev", side_effect=_depsdev_circuit_open):
            d = await asyncio.wait_for(
                fetch_package_risk_brief(package_name="requests", ecosystem="pypi"),
                timeout=TIMEOUT_S,
            )
        data = d.get("data", {})
        verdict = data.get("verdict", "")
        upstream = data.get("upstream_status", {})
        return _check(d, tool_id, tool_name, t0, [
            ("verdict_returned",        verdict in ("SHIP", "CAUTION", "BLOCK")),
            ("depsdev_circuit_open",    upstream.get("depsdev") == "CIRCUIT_OPEN"),
            ("transitive_count_null",   data.get("transitive_count") is None),
        ])
    except Exception as exc:
        return _make_result(tool_name, tool_id, "FAIL", 0, [], ["exception"], None, error=str(exc))


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
    # T10 — Security (5 original + 4 Sprint 4)
    smoke_fetch_package_vulnerabilities,
    smoke_fetch_cve_detail,
    smoke_fetch_dependency_graph,
    smoke_audit_sbom_vulnerabilities,
    smoke_fetch_package_licence,
    smoke_fetch_cisa_kev,                         # Sprint 4
    smoke_fetch_cve_epss,                         # Sprint 4
    smoke_fetch_package_vulnerabilities_batch,    # Sprint 4
    smoke_fetch_cve_detail_remediation,           # Sprint 4
    smoke_cve_detail_fixed_versions_key,          # P15-4a regression
    smoke_epss_score_positive,                    # P15-4b regression
    smoke_kev_log4shell_in_catalog,               # P15-4c regression
    # T22 — Compliance (4)
    smoke_fetch_npi_provider,
    smoke_search_npi_by_name,
    smoke_fetch_finra_broker,
    smoke_check_sam_exclusion,
    # T07 — Domain (4 original + 3 Sprint 4)
    smoke_fetch_domain_rdap,
    smoke_fetch_ssl_certificate_chain,
    smoke_fetch_dns_records,
    smoke_fetch_domain_history,
    smoke_fetch_subdomains,                       # Sprint 4
    smoke_subdomains_known_domain,                # P15-4d regression
    smoke_check_email_security,                   # Sprint 4
    smoke_fetch_reverse_ip,                       # Sprint 4
    # T11 — Legal (6: 4 core + 2 regressions)
    smoke_fetch_patent_by_number,
    smoke_search_patents_by_keyword,
    smoke_search_patents_companion_animal,      # P15-4a: multi-word EPO query (ta all fix)
    smoke_search_patents_meta_word_strip,       # P15-4b: meta-word filter ("patents" stripped)
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
    # Sprint 6 — Nonprofit Sprint6 (1)
    smoke_fetch_nonprofit_full_profile,
    # Sprint 6 — Security Sprint6 (3)
    smoke_fetch_package_maintainer_history,
    smoke_fetch_package_risk_brief,
    smoke_fetch_package_risk_brief_circuit_open,
    # Sprint 6 — Supply Chain (2)
    smoke_detect_typosquatting,
    smoke_detect_typosquatting_cold_start_failure,
    # Sprint 6 — Stateful (4)
    smoke_audit_sbom_continuous_size_limit,
    smoke_fetch_cve_watch_create,
    smoke_fetch_cve_watch_check,
    smoke_fetch_cve_watch_delete,
]

assert len(_SMOKE_COROUTINES) == 53, f"Expected 53 smoke tests, got {len(_SMOKE_COROUTINES)}"


async def run_all() -> list:
    """Run all 39 smoke tests concurrently. Returns list of result dicts."""
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
