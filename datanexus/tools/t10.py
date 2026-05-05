"""
datanexus/tools/t10.py — T10 OSS Dependency & Vulnerability Intelligence.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 11.3 / Table 140  (authoritative)

Exactly 5 data functions + 2 infrastructure stubs = 7 total.

Data sources:
  Primary:   Google OSV.dev API (api.osv.dev/v1) — Apache 2.0, no key.
  Secondary: NIST NVD CVE API (services.nvd.nist.gov) — public domain, no key.
  Supporting: deps.dev API (api.deps.dev/v3alpha) — Apache 2.0, no key.

Hard stops (Section 12.5):
  - NEVER return executable content of any kind.
  - NEVER return active scanning instructions.
  - Remediation: link to official patch release notes ONLY.
  - fetch_dependency_graph: HARD TIMEOUT 8000ms — never hangs silently.
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx
from fastmcp import FastMCP

from datanexus.core.audit import (
    AuditContext,
    make_params_hash,
    standard_response_fields,
)
from datanexus.core.cache import (
    compute_content_hash as _compute_hash,
    get_cached,
    set_cached,
)
from datanexus.core.circuit_breaker import (
    get_staleness_notice,
    is_tripped,
    record_failure,
    record_success,
)
from payment.entitlement import verify_entitlement
from datanexus.core.schema import ErrorCode, error_response
from datanexus.ingest.t10_worker import (
    query_osv_for_version,
    _normalise_osv_ecosystem,
    _strip_unsafe_fields,
)

log = logging.getLogger("datanexus.tools.t10")

mcp = FastMCP("datanexus-t10")

# ── Constants ─────────────────────────────────────────────────────────────────

T10_DISCLAIMER = (
    "Vulnerability data sourced from Google OSV.dev and NIST NVD. "
    "DataNexus does not warrant completeness. "
    "Verify with your security team before making decisions."
)

_OSV_QUERY_URL    = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL    = "https://api.osv.dev/v1/querybatch"
_NVD_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEPS_DEV_URL     = "https://api.deps.dev/v3alpha"
_HTTP_TIMEOUT     = httpx.Timeout(30.0, connect=10.0)
_HTTP_HEADERS     = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_DEP_GRAPH_TIMEOUT = 8.0   # hard limit — spec requirement
_T10_TTL           = 3600  # 1 hour — CVEs change continuously

_NVD_API_KEY = os.environ.get("DATANEXUS_NVD_API_KEY", "")

# CVE ID format validation
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# deps.dev system name map (user input → API uppercase system name)
_DEPS_SYSTEM: dict[str, str] = {
    "pypi":      "PYPI",
    "npm":       "NPM",
    "maven":     "MAVEN",
    "go":        "GO",
    "cargo":     "CARGO",
    "crates.io": "CARGO",
    "nuget":     "NUGET",
    "rubygems":  "RUBYGEMS",
    "packagist": "PACKAGIST",
}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 1 — fetch_package_vulnerabilities
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T10")
async def fetch_package_vulnerabilities(
    package: str,
    version: str,
    ecosystem: str,
) -> dict:
    """
    Fetch all known CVEs and security advisories for an open-source package
    version across PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems, Packagist.

    Returns severity, CVSS score, fixed versions, and affected ranges in
    AI-Ready Markdown. Verified sources: Google OSV.dev + NIST NVD.
    Token-efficient.

    ecosystem values: PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems, Packagist
    Example: fetch_package_vulnerabilities('requests', '2.28.0', 'PyPI')

    On source unavailable: returns archived scan with staleness notice.
    Cache TTL: 3600 seconds (CVEs published continuously).
    Rate limit: 60/minute per IP.
    """
    pkg_clean = package.strip()
    ver_clean = version.strip()
    eco_clean = ecosystem.strip()
    params    = {"package": pkg_clean, "version": ver_clean, "ecosystem": eco_clean}

    async with AuditContext("T10", params, "1.0") as ctx:
        phash = make_params_hash(params)

        # ── 1. Cache check ────────────────────────────────────────────────────
        cached = get_cached("T10", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    cached.get("ingest_healthy", True),
                ),
                "cache_hit": True,
            }

        # ── 2. Circuit breaker ────────────────────────────────────────────────
        if is_tripped("osv_dev"):
            archive = get_cached("T10", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return {
                "status":           "error",
                "tool_id":          "T10",
                "data":             archive or {},
                "markdown_output":  _archive_markdown(archive, pkg_clean, ver_clean, eco_clean),
                "staleness_notice": get_staleness_notice(
                    "osv_dev", (archive or {}).get("data_as_of", "unknown"),
                ),
                "disclaimer":  T10_DISCLAIMER,
                "cache_hit":   False,
                "sha256_hash": "",
                **standard_response_fields(ctx.query_hash, "", False),
            }

        # ── 3. Live fetch — OSV.dev ───────────────────────────────────────────
        osv_ecosystem = _normalise_osv_ecosystem(eco_clean)
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
            ) as client:
                osv_data = await query_osv_for_version(
                    client, pkg_clean, ver_clean, osv_ecosystem,
                )
        except httpx.TimeoutException:
            record_failure("osv_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_TIMEOUT,
                message="OSV.dev timed out. Try again shortly.",
                query_hash=ctx.query_hash,
                retry_after=30,
                ingest_healthy=False,
            )
        except httpx.HTTPStatusError:
            record_failure("osv_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                message="OSV.dev temporarily unavailable.",
                query_hash=ctx.query_hash,
                retry_after=60,
                ingest_healthy=False,
            )
        except Exception:
            record_failure("osv_dev")
            log.exception("t10.fetch_package_vulnerabilities error pkg=%s", pkg_clean)
            return error_response(
                error_code=ErrorCode.INTERNAL_ERROR,
                message="An internal error occurred. Please try again.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=False,
            )

        record_success("osv_dev")

        vulns      = osv_data.get("vulns", [])
        # Phase 0 response-formatter fixes (query-time layer — belt-and-suspenders)
        vulns      = _fmt_dedup_pysec_ghsa(vulns)
        vulns      = _fmt_fix_severity_levels(vulns)
        osv_data["vulns"] = vulns   # keep osv_data consistent for result_data
        raw_bytes  = json.dumps(osv_data).encode()
        phash_val  = _compute_hash(raw_bytes)
        data_as_of = datetime.now(timezone.utc).isoformat()
        markdown   = _build_vuln_markdown(vulns, pkg_clean, ver_clean, eco_clean)

        result_data = {
            "status":           "ok",
            "tool_id":          "T10",
            "source_url":       "https://api.osv.dev/v1/query",
            "fetch_timestamp":  data_as_of,
            "cache_hit":        False,
            "staleness_notice": None,
            "sha256_hash":      phash_val,
            "data":             osv_data,
            "markdown_output":  markdown,
            "disclaimer":       T10_DISCLAIMER,
            "data_as_of":       data_as_of,
            "ingest_healthy":   True,
        }

        set_cached("T10", phash, result_data, _T10_TTL)
        set_cached("T10", phash + "_archive", result_data, _T10_TTL * 24)
        ctx.set_cache_hit(False)

        log.info("t10.fetch_package_vulnerabilities ok pkg=%s ver=%s eco=%s vulns=%d",
                 pkg_clean, ver_clean, eco_clean, len(vulns))

        return {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — fetch_dependency_graph
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T10")
async def fetch_dependency_graph(
    package: str,
    version: str,
    ecosystem: str,
) -> dict:
    """
    Fetch the dependency graph for a package from deps.dev. Returns direct
    and transitive dependencies in AI-Ready Markdown.

    IMPORTANT: p99 latency may exceed 4 seconds for large dependency trees.
    Hard limit: if response time exceeds 8000ms a structured timeout error is
    returned — this tool NEVER hangs silently.
    error_code: 'upstream_timeout' on hard limit breach.
    Verified source: deps.dev (Google Open Source Insights). Data freshness: 1-hour cache.

    ecosystem values: PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems
    Example: fetch_dependency_graph('fastapi', '0.100.0', 'PyPI')

    Cache TTL: 3600 seconds.
    Rate limit: 60/minute per IP.
    """
    pkg_clean = package.strip()
    ver_clean = version.strip()
    eco_clean = ecosystem.strip()
    params    = {"package": pkg_clean, "version": ver_clean, "ecosystem": eco_clean}

    async with AuditContext("T10", params, "1.0") as ctx:
        phash = make_params_hash(params)

        # ── Cache check ───────────────────────────────────────────────────────
        cached = get_cached("T10", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    cached.get("ingest_healthy", True),
                ),
                "cache_hit": True,
            }

        # ── Circuit breaker ───────────────────────────────────────────────────
        if is_tripped("deps_dev"):
            archive = get_cached("T10", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return {
                "status":           "error",
                "tool_id":          "T10",
                "data":             archive or {},
                "markdown_output":  "Dependency graph temporarily unavailable.",
                "staleness_notice": get_staleness_notice(
                    "deps_dev", (archive or {}).get("data_as_of", "unknown"),
                ),
                "disclaimer":  T10_DISCLAIMER,
                "cache_hit":   False,
                "sha256_hash": "",
                **standard_response_fields(ctx.query_hash, "", False),
            }

        # ── Live fetch — HARD TIMEOUT 8000ms ──────────────────────────────────
        eco_lower   = eco_clean.lower()
        deps_system = _DEPS_SYSTEM.get(eco_lower, eco_lower.upper())

        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
            ) as client:
                dep_data = await asyncio.wait_for(
                    _fetch_dep_graph_live(client, deps_system, pkg_clean, ver_clean),
                    timeout=_DEP_GRAPH_TIMEOUT,
                )

        except asyncio.TimeoutError:
            record_failure("deps_dev")
            log.warning("t10.fetch_dependency_graph timeout pkg=%s ver=%s eco=%s",
                        pkg_clean, ver_clean, eco_clean)
            return error_response(
                error_code=ErrorCode.UPSTREAM_TIMEOUT,
                message=(
                    "Dependency graph fetch timed out. "
                    "Try again or reduce package complexity."
                ),
                query_hash=ctx.query_hash,
                retry_after=30,
                ingest_healthy=False,
            )
        except httpx.TimeoutException:
            record_failure("deps_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_TIMEOUT,
                message="Dependency graph fetch timed out.",
                query_hash=ctx.query_hash,
                retry_after=30,
                ingest_healthy=False,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return error_response(
                    error_code=ErrorCode.NOT_FOUND,
                    message=f"Package '{pkg_clean}@{ver_clean}' not found in {eco_clean}.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )
            record_failure("deps_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                message="deps.dev temporarily unavailable.",
                query_hash=ctx.query_hash,
                retry_after=60,
                ingest_healthy=False,
            )
        except Exception:
            record_failure("deps_dev")
            log.exception("t10.fetch_dependency_graph error pkg=%s", pkg_clean)
            return error_response(
                error_code=ErrorCode.INTERNAL_ERROR,
                message="An internal error occurred. Please try again.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=False,
            )

        record_success("deps_dev")

        raw_bytes  = json.dumps(dep_data).encode()
        phash_val  = _compute_hash(raw_bytes)
        data_as_of = datetime.now(timezone.utc).isoformat()
        markdown   = _build_dep_graph_markdown(dep_data, pkg_clean, ver_clean, eco_clean)

        result_data = {
            "status":           "ok",
            "tool_id":          "T10",
            "source_url":       (
                f"{_DEPS_DEV_URL}/systems/{deps_system}/packages/"
                f"{quote(pkg_clean, safe='')}/versions/"
                f"{quote(ver_clean, safe='')}/dependencies"
            ),
            "fetch_timestamp":  data_as_of,
            "cache_hit":        False,
            "staleness_notice": None,
            "sha256_hash":      phash_val,
            "data":             dep_data,
            "markdown_output":  markdown,
            "disclaimer":       T10_DISCLAIMER,
            "data_as_of":       data_as_of,
            "ingest_healthy":   True,
        }

        set_cached("T10", phash, result_data, _T10_TTL)
        set_cached("T10", phash + "_archive", result_data, _T10_TTL * 24)
        ctx.set_cache_hit(False)

        log.info("t10.fetch_dependency_graph ok pkg=%s ver=%s eco=%s deps=%d",
                 pkg_clean, ver_clean, eco_clean, dep_data.get("total_deps", 0))

        return {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_cve_detail
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T10")
async def fetch_cve_detail(cve_id: str) -> dict:
    """
    Fetch full CVE detail by CVE ID from NIST NVD.

    Returns description, CVSS base score, severity level, affected products,
    and patch reference URLs in AI-Ready Markdown.
    Verified source: NIST NVD (public domain, US government data).

    cve_id format: 'CVE-YYYY-NNNNN' (e.g. 'CVE-2023-32681')
    Example: fetch_cve_detail('CVE-2023-32681')

    Cache TTL: 3600 seconds.
    Rate limit: 60/minute per IP.
    """
    cve_clean = cve_id.strip().upper()
    params    = {"cve_id": cve_clean}

    async with AuditContext("T10", params, "1.0") as ctx:
        if not _CVE_RE.match(cve_clean):
            return error_response(
                error_code=ErrorCode.VALIDATION_ERROR,
                message="Invalid CVE ID format. Expected CVE-YYYY-NNNNN.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=True,
            )

        phash = make_params_hash(params)

        # ── Cache check ───────────────────────────────────────────────────────
        cached = get_cached("T10", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    cached.get("ingest_healthy", True),
                ),
                "cache_hit": True,
            }

        # ── Circuit breaker ───────────────────────────────────────────────────
        if is_tripped("nist_nvd"):
            archive = get_cached("T10", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return {
                "status":           "error",
                "tool_id":          "T10",
                "data":             archive or {},
                "markdown_output":  f"NVD data for {cve_clean} temporarily unavailable.",
                "staleness_notice": get_staleness_notice(
                    "nist_nvd", (archive or {}).get("data_as_of", "unknown"),
                ),
                "disclaimer":  T10_DISCLAIMER,
                "cache_hit":   False,
                "sha256_hash": "",
                **standard_response_fields(ctx.query_hash, "", False),
            }

        # ── Live fetch — NIST NVD ─────────────────────────────────────────────
        nvd_headers = {**_HTTP_HEADERS}
        if _NVD_API_KEY:
            nvd_headers["apiKey"] = _NVD_API_KEY

        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, headers=nvd_headers, follow_redirects=True,
            ) as client:
                resp = await client.get(_NVD_URL, params={"cveId": cve_clean})
                if resp.status_code == 404:
                    return error_response(
                        error_code=ErrorCode.NOT_FOUND,
                        message=f"{cve_clean} not found in NIST NVD.",
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                    )
                resp.raise_for_status()
                nvd_raw = resp.json()

        except httpx.TimeoutException:
            record_failure("nist_nvd")
            return error_response(
                error_code=ErrorCode.UPSTREAM_TIMEOUT,
                message="NIST NVD timed out. Try again shortly.",
                query_hash=ctx.query_hash,
                retry_after=30,
                ingest_healthy=False,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_RATE_LIMITED,
                    message="NIST NVD rate limit reached. Try again in 30 seconds.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=True,
                )
            record_failure("nist_nvd")
            return error_response(
                error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                message="NIST NVD temporarily unavailable.",
                query_hash=ctx.query_hash,
                retry_after=60,
                ingest_healthy=False,
            )
        except Exception:
            record_failure("nist_nvd")
            log.exception("t10.fetch_cve_detail error cve=%s", cve_clean)
            return error_response(
                error_code=ErrorCode.INTERNAL_ERROR,
                message="An internal error occurred. Please try again.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=False,
            )

        record_success("nist_nvd")

        cve_data   = _parse_nvd_cve(nvd_raw, cve_clean)
        raw_bytes  = json.dumps(cve_data).encode()
        phash_val  = _compute_hash(raw_bytes)
        data_as_of = datetime.now(timezone.utc).isoformat()
        markdown   = _build_cve_markdown(cve_data)

        result_data = {
            "status":           "ok",
            "tool_id":          "T10",
            "source_url":       f"https://nvd.nist.gov/vuln/detail/{cve_clean}",
            "fetch_timestamp":  data_as_of,
            "cache_hit":        False,
            "staleness_notice": None,
            "sha256_hash":      phash_val,
            "data":             cve_data,
            "markdown_output":  markdown,
            "disclaimer":       T10_DISCLAIMER,
            "data_as_of":       data_as_of,
            "ingest_healthy":   True,
        }

        set_cached("T10", phash, result_data, _T10_TTL)
        set_cached("T10", phash + "_archive", result_data, _T10_TTL * 24)
        ctx.set_cache_hit(False)

        log.info("t10.fetch_cve_detail ok cve=%s score=%s",
                 cve_clean, cve_data.get("cvss_base_score", ""))

        return {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — audit_sbom_vulnerabilities
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T10")
async def audit_sbom_vulnerabilities(sbom_json: str) -> dict:
    """
    Audit a Software Bill of Materials in CycloneDX or SPDX JSON format.
    Call this when a user supplies an SBOM file and wants to know which
    components have known security vulnerabilities.

    Returns all packages with known vulnerabilities, severity summary, and
    fix version pointers in AI-Ready Markdown.
    Verified source: OSV.dev batch query API (Google).

    Input: sbom_json — stringified CycloneDX 1.4+ or SPDX 2.2+ JSON.
    Returns per-component vulnerability count, highest severity, and advisory
    reference links. No executable content returned.

    Cache TTL: 3600 seconds. Token-efficient.
    Rate limit: 60/minute per IP.
    """
    import hashlib
    params = {"sbom_hash": hashlib.sha256(sbom_json.encode()).hexdigest()[:32]}

    async with AuditContext("T10", params, "1.0") as ctx:
        phash = make_params_hash(params)

        cached = get_cached("T10", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    cached.get("ingest_healthy", True),
                ),
                "cache_hit": True,
            }

        try:
            sbom_data = json.loads(sbom_json)
        except json.JSONDecodeError:
            return error_response(
                error_code=ErrorCode.VALIDATION_ERROR,
                message="Invalid JSON in sbom_json. Provide valid CycloneDX or SPDX JSON.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=True,
            )

        components = _extract_sbom_components(sbom_data)
        if not components:
            return error_response(
                error_code=ErrorCode.VALIDATION_ERROR,
                message=(
                    "No parseable components found in SBOM. "
                    "Ensure CycloneDX components[] or SPDX packages[] with PURLs are present."
                ),
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=True,
            )

        if is_tripped("osv_dev"):
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return error_response(
                error_code=ErrorCode.CIRCUIT_OPEN,
                message="OSV.dev currently unavailable. Try again later.",
                query_hash=ctx.query_hash,
                retry_after=300,
                ingest_healthy=False,
            )

        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
            ) as client:
                batch_results = await _batch_osv_query(client, components)
        except httpx.TimeoutException:
            record_failure("osv_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_TIMEOUT,
                message="OSV.dev batch query timed out.",
                query_hash=ctx.query_hash,
                retry_after=30,
                ingest_healthy=False,
            )
        except Exception:
            record_failure("osv_dev")
            log.exception("t10.audit_sbom_vulnerabilities error")
            return error_response(
                error_code=ErrorCode.INTERNAL_ERROR,
                message="An internal error occurred. Please try again.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=False,
            )

        record_success("osv_dev")

        audit_data = _build_audit_data(components, batch_results)
        raw_bytes  = json.dumps(audit_data).encode()
        phash_val  = _compute_hash(raw_bytes)
        data_as_of = datetime.now(timezone.utc).isoformat()
        markdown   = _build_sbom_audit_markdown(audit_data)

        result_data = {
            "status":           "ok",
            "tool_id":          "T10",
            "source_url":       "https://api.osv.dev/v1/querybatch",
            "fetch_timestamp":  data_as_of,
            "cache_hit":        False,
            "staleness_notice": None,
            "sha256_hash":      phash_val,
            "data":             audit_data,
            "markdown_output":  markdown,
            "disclaimer":       T10_DISCLAIMER,
            "data_as_of":       data_as_of,
            "ingest_healthy":   True,
        }

        set_cached("T10", phash, result_data, _T10_TTL)
        ctx.set_cache_hit(False)

        log.info("t10.audit_sbom_vulnerabilities ok components=%d vuln_count=%d",
                 len(components), audit_data.get("total_vulns", 0))

        return {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 5 — fetch_package_licence
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T10")
async def fetch_package_licence(
    package: str,
    version: str,
    ecosystem: str,
) -> dict:
    """
    Fetch the declared software licence for any open source package version.
    Returns the SPDX licence identifier (e.g. MIT, Apache-2.0, GPL-3.0) and
    compatibility notes in AI-Ready Markdown.

    Verified source: deps.dev (Google Open Source Insights).
    Data freshness: 1-hour cache.

    Use this before including a dependency in a commercial project to verify
    licence compatibility.

    ecosystem values: PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems
    Example: fetch_package_licence('fastapi', '0.100.0', 'PyPI')

    Token-efficient. Rate limit: 60/minute per IP.
    """
    pkg_clean = package.strip()
    ver_clean = version.strip()
    eco_clean = ecosystem.strip()
    params    = {"package": pkg_clean, "version": ver_clean, "ecosystem": eco_clean}

    async with AuditContext("T10", params, "1.0") as ctx:
        phash = make_params_hash(params)

        cached = get_cached("T10", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    cached.get("ingest_healthy", True),
                ),
                "cache_hit": True,
            }

        if is_tripped("deps_dev"):
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return error_response(
                error_code=ErrorCode.CIRCUIT_OPEN,
                message="deps.dev currently unavailable. Try again later.",
                query_hash=ctx.query_hash,
                retry_after=300,
                ingest_healthy=False,
            )

        eco_lower   = eco_clean.lower()
        deps_system = _DEPS_SYSTEM.get(eco_lower, eco_lower.upper())

        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
            ) as client:
                lic_data = await _fetch_licence_live(client, deps_system, pkg_clean, ver_clean)
        except httpx.TimeoutException:
            record_failure("deps_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_TIMEOUT,
                message="deps.dev timed out. Try again shortly.",
                query_hash=ctx.query_hash,
                retry_after=30,
                ingest_healthy=False,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return error_response(
                    error_code=ErrorCode.NOT_FOUND,
                    message=f"Package '{pkg_clean}@{ver_clean}' not found in {eco_clean}.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )
            record_failure("deps_dev")
            return error_response(
                error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                message="deps.dev temporarily unavailable.",
                query_hash=ctx.query_hash,
                retry_after=60,
                ingest_healthy=False,
            )
        except Exception:
            record_failure("deps_dev")
            log.exception("t10.fetch_package_licence error pkg=%s", pkg_clean)
            return error_response(
                error_code=ErrorCode.INTERNAL_ERROR,
                message="An internal error occurred. Please try again.",
                query_hash=ctx.query_hash,
                retry_after=0,
                ingest_healthy=False,
            )

        record_success("deps_dev")

        raw_bytes  = json.dumps(lic_data).encode()
        phash_val  = _compute_hash(raw_bytes)
        data_as_of = datetime.now(timezone.utc).isoformat()
        markdown   = _build_licence_markdown(lic_data)

        result_data = {
            "status":           "ok",
            "tool_id":          "T10",
            "source_url":       (
                f"{_DEPS_DEV_URL}/systems/{deps_system}/packages/"
                f"{quote(pkg_clean, safe='')}/versions/{quote(ver_clean, safe='')}"
            ),
            "fetch_timestamp":  data_as_of,
            "cache_hit":        False,
            "staleness_notice": None,
            "sha256_hash":      phash_val,
            "data":             lic_data,
            "markdown_output":  markdown,
            "disclaimer":       T10_DISCLAIMER,
            "data_as_of":       data_as_of,
            "ingest_healthy":   True,
        }

        set_cached("T10", phash, result_data, _T10_TTL)
        ctx.set_cache_hit(False)

        log.info("t10.fetch_package_licence ok pkg=%s ver=%s eco=%s licences=%s",
                 pkg_clean, ver_clean, eco_clean, lic_data.get("licences", []))

        return {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE STUBS
# ══════════════════════════════════════════════════════════════════════════════

async def report_feedback(
    tool_id: str,
    query_hash: str,
    signal: str,
    comment: str = "",
) -> dict:
    """
    Submit feedback about a tool response.
    Stub — replaced by feedback.collector.report_feedback in Phase 4.
    Always returns {'status': 'recorded'}.
    """
    return {"status": "recorded"}


async def report_mcpize_link(tool_id: str = "T10") -> dict:
    """
    Get the MCPize subscription link for T10.
    Delegates to payment.tools.report_mcpize_link (Phase 5).
    Returns status='free' during the free window, or upgrade_url when active.
    """
    from payment.tools import report_mcpize_link as _real
    return _real(tool_id)


mcp.tool()(report_feedback)
mcp.tool()(report_mcpize_link)


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS — live fetchers
# ══════════════════════════════════════════════════════════════════════════════

async def _fetch_dep_graph_live(
    client: httpx.AsyncClient,
    system: str,
    package: str,
    version: str,
) -> dict:
    """Fetch dependency graph from deps.dev. Called under asyncio.wait_for."""
    pkg_enc = quote(package, safe="")
    ver_enc = quote(version, safe="")
    url = (
        f"{_DEPS_DEV_URL}/systems/{system}/packages/"
        f"{pkg_enc}/versions/{ver_enc}/dependencies"
    )
    resp = await client.get(url)
    resp.raise_for_status()
    raw = resp.json()

    nodes = []
    for node in raw.get("nodes", []):
        vk = node.get("versionKey", {})
        nodes.append({
            "system":   vk.get("system", ""),
            "name":     vk.get("name", ""),
            "version":  vk.get("version", ""),
            "relation": node.get("relation", "INDIRECT"),
        })

    return {
        "package":    package,
        "version":    version,
        "ecosystem":  system,
        "nodes":      nodes[:200],
        "total_deps": len(nodes),
        "source":     "deps.dev",
    }


async def _fetch_licence_live(
    client: httpx.AsyncClient,
    system: str,
    package: str,
    version: str,
) -> dict:
    """Fetch package version info (including licences) from deps.dev."""
    pkg_enc = quote(package, safe="")
    ver_enc = quote(version, safe="")
    url = (
        f"{_DEPS_DEV_URL}/systems/{system}/packages/"
        f"{pkg_enc}/versions/{ver_enc}"
    )
    resp = await client.get(url)
    resp.raise_for_status()
    raw = resp.json()

    return {
        "package":    package,
        "version":    version,
        "ecosystem":  system,
        "licences":   raw.get("licenses", []),
        "is_default": raw.get("isDefault", False),
        "published":  raw.get("publishedAt", ""),
        "source":     "deps.dev",
    }


async def _batch_osv_query(
    client: httpx.AsyncClient,
    components: list[dict],
) -> list[dict]:
    """Batch query OSV.dev for up to 1000 components."""
    queries = []
    for comp in components[:1000]:
        q: dict = {
            "package": {
                "name":      comp["name"],
                "ecosystem": _normalise_osv_ecosystem(comp.get("ecosystem", "")),
            }
        }
        if comp.get("version"):
            q["version"] = comp["version"]
        queries.append(q)

    resp = await client.post(_OSV_BATCH_URL, json={"queries": queries})
    resp.raise_for_status()
    return resp.json().get("results", [])


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS — parsers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_nvd_cve(nvd_raw: dict, cve_id: str) -> dict:
    """Extract safe fields from NVD CVE response. No executable content."""
    vulns = nvd_raw.get("vulnerabilities", [])
    if not vulns:
        return {"cve_id": cve_id, "found": False}

    cve = vulns[0].get("cve", {})

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")[:1000]
            break

    cvss_score, cvss_severity, cvss_vector = "", "", ""
    metrics = cve.get("metrics", {})
    for m in metrics.get("cvssMetricV31", []):
        cd = m.get("cvssData", {})
        cvss_score    = str(cd.get("baseScore", ""))
        cvss_severity = cd.get("baseSeverity", "")
        cvss_vector   = cd.get("vectorString", "")
        break
    if not cvss_score:
        for m in metrics.get("cvssMetricV2", []):
            cd = m.get("cvssData", {})
            cvss_score    = str(cd.get("baseScore", ""))
            cvss_severity = m.get("baseSeverity", "")
            cvss_vector   = cd.get("vectorString", "")
            break

    refs = [
        {"url": r.get("url", ""), "tags": r.get("tags", [])}
        for r in cve.get("references", [])[:8]
    ]

    return {
        "cve_id":          cve_id,
        "found":           True,
        "description":     desc,
        "cvss_base_score": cvss_score,
        "cvss_severity":   cvss_severity,
        "cvss_vector":     cvss_vector,
        "published":       cve.get("published", ""),
        "last_modified":   cve.get("lastModified", ""),
        "references":      refs,
        "source":          "NIST NVD",
    }


def _extract_sbom_components(sbom: dict) -> list[dict]:
    """Parse CycloneDX or SPDX JSON and extract (name, version, ecosystem)."""
    components = []
    if sbom.get("bomFormat") == "CycloneDX" or "components" in sbom:
        for comp in sbom.get("components", []):
            p = _parse_purl(comp.get("purl", ""))
            if p:
                components.append(p)
            elif comp.get("name"):
                components.append({
                    "name": comp["name"],
                    "version": comp.get("version", ""),
                    "ecosystem": "",
                })
        return components
    if "spdxVersion" in sbom or "packages" in sbom:
        for pkg in sbom.get("packages", []):
            for ext in pkg.get("externalRefs", []):
                if ext.get("referenceType") == "purl":
                    p = _parse_purl(ext.get("referenceLocator", ""))
                    if p:
                        components.append(p)
                        break
            else:
                if pkg.get("name"):
                    components.append({
                        "name": pkg["name"],
                        "version": pkg.get("versionInfo", ""),
                        "ecosystem": "",
                    })
    return components


def _parse_purl(purl: str) -> Optional[dict]:
    """Parse a Package URL (PURL) string into (name, version, ecosystem)."""
    try:
        if not purl.startswith("pkg:"):
            return None
        rest     = purl[4:]
        slash    = rest.find("/")
        if slash < 0:
            return None
        pkg_type = rest[:slash].lower()
        rest     = rest[slash + 1:]
        at       = rest.rfind("@")
        version  = ""
        if at >= 0:
            version = rest[at + 1:].split("?")[0].split("#")[0]
            rest    = rest[:at]
        name = rest.split("/")[-1]
        eco_map = {
            "pypi":    "PyPI", "npm": "npm", "maven": "Maven",
            "golang":  "Go",   "cargo": "crates.io", "nuget": "NuGet",
            "gem":     "RubyGems", "composer": "Packagist",
        }
        return {"name": name, "version": version, "ecosystem": eco_map.get(pkg_type, pkg_type)}
    except Exception:
        return None


def _build_audit_data(components: list[dict], osv_results: list[dict]) -> dict:
    """Merge components with OSV batch results into audit summary."""
    audited     = []
    total_vulns = 0
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    for comp, result in zip(components, osv_results):
        safe  = _strip_unsafe_fields(result)
        vulns = safe.get("vulns", [])
        count = len(vulns)
        total_vulns += count

        highest = "NONE"
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"]
        for v in vulns:
            level = v.get("severity", {}).get("level", "UNKNOWN")
            if sev_order.index(level) < sev_order.index(highest):
                highest = level
            sev_counts[level] = sev_counts.get(level, 0) + 1

        audited.append({
            "name":             comp.get("name", ""),
            "version":          comp.get("version", ""),
            "ecosystem":        comp.get("ecosystem", ""),
            "vuln_count":       count,
            "highest_severity": highest,
            "cve_ids": [
                a for v in vulns for a in v.get("aliases", [])
                if a.startswith("CVE-")
            ][:5],
        })

    return {
        "total_components": len(components),
        "total_vulns":      total_vulns,
        "severity_summary": sev_counts,
        "components":       audited,
        "source":           "OSV.dev",
    }


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 RESPONSE-FORMATTER FIXES
# Applied at query time so stale cached data is also corrected on serve.
# The ingest worker (t10_worker.py) applies the same logic at cache-write time.
# Both layers are required — they operate independently.
# ══════════════════════════════════════════════════════════════════════════════

def _fmt_fix_severity_levels(vulns: list) -> list:
    """
    Phase 0 Bug 1 fix — response formatter (query-time).

    If any vulnerability record has severity.level == 'UNKNOWN' or missing
    AND a cvss_vector field is present, derive the correct level from the
    CVSS base score using the standard severity bands:
        0.0 = NONE, 0.1-3.9 = LOW, 4.0-6.9 = MEDIUM,
        7.0-8.9 = HIGH, 9.0-10.0 = CRITICAL
    Mutates record in place. Logs each correction as structured JSON.
    """
    import math

    def _score_to_level(score: float) -> str:
        if score == 0.0:  return "NONE"
        if score < 4.0:   return "LOW"
        if score < 7.0:   return "MEDIUM"
        if score < 9.0:   return "HIGH"
        return "CRITICAL"

    def _derive_level(vector: str) -> str:
        if not vector:
            return "UNKNOWN"
        try:
            return _score_to_level(float(vector))
        except (ValueError, TypeError):
            pass
        raw = vector.upper()
        for prefix in ("CVSS:3.1/", "CVSS:3.0/", "CVSS:2.0/"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break
        metrics: dict = {}
        for part in raw.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k] = v
        if not metrics:
            return "UNKNOWN"
        if "AV" in metrics and "AC" in metrics and "S" in metrics:
            _cia = {"N": 0.00, "L": 0.22, "H": 0.56}
            c_v = _cia.get(metrics.get("C", "N"), 0.0)
            i_v = _cia.get(metrics.get("I", "N"), 0.0)
            a_v = _cia.get(metrics.get("A", "N"), 0.0)
            iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)
            if iss == 0.0:
                return "NONE"
            scope_changed = metrics.get("S", "U") == "C"
            impact = (7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15.0)
                      if scope_changed else 6.42 * iss)
            _av  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
            _ac  = {"L": 0.77, "H": 0.44}
            _pru = {"N": 0.85, "L": 0.62, "H": 0.27}
            _prc = {"N": 0.85, "L": 0.68, "H": 0.50}
            _ui  = {"N": 0.85, "R": 0.62}
            av_v  = _av.get(metrics.get("AV", "L"), 0.55)
            ac_v  = _ac.get(metrics.get("AC", "L"), 0.77)
            pr_v  = (_prc if scope_changed else _pru).get(metrics.get("PR", "N"), 0.85)
            ui_v  = _ui.get(metrics.get("UI", "N"), 0.85)
            exploit = 8.22 * av_v * ac_v * pr_v * ui_v
            raw_score = (min(1.08 * (impact + exploit), 10.0)
                         if scope_changed else min(impact + exploit, 10.0))
            base = math.ceil(raw_score * 10.0) / 10.0
            return _score_to_level(base)
        # CVSS v2 simplified CIA heuristic
        _cia2 = {"N": 0.0, "P": 0.275, "C": 0.660}
        c2 = _cia2.get(metrics.get("C", "N"), 0.0)
        i2 = _cia2.get(metrics.get("I", "N"), 0.0)
        a2 = _cia2.get(metrics.get("A", "N"), 0.0)
        return _score_to_level(max(0.0, 10.0 * (c2 + i2 + a2) / 3.0))

    fixed = 0
    for vuln in vulns:
        sev    = vuln.get("severity") or {}
        level  = sev.get("level", "UNKNOWN")
        vector = sev.get("vector", "")
        if level in ("UNKNOWN", "", None) and vector:
            derived = _derive_level(vector)
            if derived != "UNKNOWN":
                sev["level"] = derived
                vuln["severity"] = sev
                fixed += 1
                log.info(json.dumps({
                    "fix":       "severity_level_from_vector",
                    "layer":     "response_formatter",
                    "vuln_id":   vuln.get("id", ""),
                    "old_level": level,
                    "new_level": derived,
                    "vector":    vector,
                }))
    if fixed:
        log.info(json.dumps({
            "fix":         "severity_level_from_vector",
            "layer":       "response_formatter",
            "total_fixed": fixed,
        }))
    return vulns


def _fmt_dedup_pysec_ghsa(vulns: list) -> list:
    """
    Phase 0 Bug 2 fix — response formatter (query-time).

    Suppresses PYSEC records that share a CVE alias with a GHSA record.
    GHSA records carry more complete advisory data — keep GHSA, drop PYSEC.
    Logs each suppression as structured JSON.
    """
    ghsa_cve_aliases: set[str] = set()
    ghsa_by_cve: dict[str, str] = {}
    for v in vulns:
        if v.get("id", "").startswith("GHSA-"):
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    ghsa_cve_aliases.add(alias)
                    ghsa_by_cve[alias] = v["id"]

    deduped: list = []
    for v in vulns:
        if v.get("id", "").startswith("PYSEC-"):
            shared = {a for a in v.get("aliases", []) if a.startswith("CVE-")} & ghsa_cve_aliases
            if shared:
                shared_alias = next(iter(shared))
                log.info(json.dumps({
                    "fix":          "deduplicate_by_cve_alias",
                    "layer":        "response_formatter",
                    "suppressed":   v["id"],
                    "kept":         ghsa_by_cve.get(shared_alias, ""),
                    "shared_alias": shared_alias,
                }))
                continue
        deduped.append(v)
    return deduped


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS — markdown builders
# ══════════════════════════════════════════════════════════════════════════════

def _build_vuln_markdown(
    vulns: list, package: str, version: str, ecosystem: str,
) -> str:
    lines = [
        f"## Vulnerability Report: `{package}@{version}` ({ecosystem})",
        "",
    ]
    if not vulns:
        lines += [
            "**No known vulnerabilities** found for this package version.",
            "",
            f"*{T10_DISCLAIMER}*",
        ]
        return "\n".join(lines)

    lines.append(
        f"Found **{len(vulns)}** known "
        f"vulnerabilit{'y' if len(vulns) == 1 else 'ies'}."
    )
    lines += ["", "| ID | Aliases | Summary | Severity |",
              "|----|---------|---------|----------|"]

    for v in vulns[:20]:
        aliases = ", ".join(v.get("aliases", [])[:2])
        summary = v.get("summary", "")[:80]
        level   = v.get("severity", {}).get("level", "UNKNOWN")
        lines.append(f"| {v.get('id','')} | {aliases} | {summary} | {level} |")

    fix_versions: set[str] = set()
    for v in vulns:
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fix_versions.add(ev["fixed"])
    if fix_versions:
        lines += [
            "",
            "**Fixed in:** " + ", ".join(f"`{fv}`" for fv in sorted(fix_versions)[:5]),
        ]

    lines += ["", f"*{T10_DISCLAIMER}*"]
    return "\n".join(lines)


def _build_dep_graph_markdown(
    data: dict, package: str, version: str, ecosystem: str,
) -> str:
    nodes    = data.get("nodes", [])
    direct   = [n for n in nodes if n.get("relation") == "DIRECT"]
    indirect = [n for n in nodes if n.get("relation") != "DIRECT"]
    lines = [
        f"## Dependency Graph: `{package}@{version}` ({ecosystem})",
        "",
        f"**Direct:** {len(direct)}  |  "
        f"**Transitive:** {len(indirect)}  |  "
        f"**Total:** {data.get('total_deps', len(nodes))}",
        "",
    ]
    if direct:
        lines += ["### Direct Dependencies", "| Package | Version |", "|---------|---------|"]
        for n in direct[:25]:
            lines.append(f"| {n.get('name','')} | {n.get('version','')} |")
    lines += ["", f"*{T10_DISCLAIMER}*"]
    return "\n".join(lines)


def _build_cve_markdown(data: dict) -> str:
    if not data.get("found"):
        return f"## {data.get('cve_id','CVE')}\n\nNot found in NIST NVD.\n"

    lines = [
        f"## {data['cve_id']}",
        "",
        f"**CVSS Base Score:** {data.get('cvss_base_score','N/A')}  "
        f"|  **Severity:** {data.get('cvss_severity','')}",
        f"**Published:** {str(data.get('published',''))[:10]}",
        "",
        "### Description",
        data.get("description", ""),
        "",
    ]
    refs = data.get("references", [])
    if refs:
        lines += ["### References"]
        for ref in refs[:5]:
            lines.append(f"- {ref.get('url','')}")
        lines.append("")
    lines.append(f"*{T10_DISCLAIMER}*")
    return "\n".join(lines)


def _build_sbom_audit_markdown(data: dict) -> str:
    sev = data.get("severity_summary", {})
    lines = [
        "## SBOM Vulnerability Audit",
        "",
        f"**Components scanned:** {data.get('total_components',0)}  "
        f"|  **Total vulnerabilities:** {data.get('total_vulns',0)}",
        "",
        "### Severity Summary",
        "| CRITICAL | HIGH | MEDIUM | LOW |",
        "|----------|------|--------|-----|",
        f"| {sev.get('CRITICAL',0)} | {sev.get('HIGH',0)} | "
        f"{sev.get('MEDIUM',0)} | {sev.get('LOW',0)} |",
        "",
    ]
    vulnerable = [c for c in data.get("components", []) if c.get("vuln_count", 0) > 0]
    if vulnerable:
        lines += [
            "### Vulnerable Components",
            "| Package | Version | Vulns | Highest Severity |",
            "|---------|---------|-------|-----------------|",
        ]
        for c in vulnerable[:25]:
            lines.append(
                f"| {c.get('name','')} | {c.get('version','')} "
                f"| {c.get('vuln_count',0)} | {c.get('highest_severity','')} |"
            )
    else:
        lines.append("**No vulnerabilities found** in any scanned component.")
    lines += ["", f"*{T10_DISCLAIMER}*"]
    return "\n".join(lines)


def _build_licence_markdown(data: dict) -> str:
    lics    = data.get("licences", [])
    lic_str = ", ".join(f"`{l}`" for l in lics) if lics else "Not declared"
    lines = [
        f"## Licence: `{data.get('package','')}@{data.get('version','')}` ({data.get('ecosystem','')})",
        "",
        f"**SPDX Licence:** {lic_str}",
    ]
    pub = data.get("published", "")
    if pub:
        lines.append(f"**Published:** {str(pub)[:10]}")
    lines += ["", f"*{T10_DISCLAIMER}*"]
    return "\n".join(lines)


def _archive_markdown(
    archive: Optional[dict], package: str, version: str, ecosystem: str,
) -> str:
    if archive and archive.get("markdown_output"):
        return archive["markdown_output"]
    return (
        f"## {package}@{version} ({ecosystem}) — Archived Data\n"
        "Vulnerability source temporarily unavailable. "
        "Serving last known scan.\n\n"
        f"*{T10_DISCLAIMER}*"
    )
