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
import time
from datetime import datetime, timezone
from typing import Annotated, Optional

from pydantic import Field
from urllib.parse import quote

# Sprint 4 additions
from datanexus.core.cache import get_cached as _get_cached, set_cached as _set_cached

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
    record_failure_sync,
    record_success_sync,
)
from payment.entitlement import verify_entitlement
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.ingest.t10_worker import (
    query_osv_for_version,
    _normalise_osv_ecosystem,
    _strip_unsafe_fields,
)
from datanexus.analytics import fire_and_forget, track_tool_call, track_tool_error

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
_DEPS_DEV_URL     = "https://api.deps.dev/v3"
_HTTP_TIMEOUT     = httpx.Timeout(30.0, connect=10.0)
_HTTP_HEADERS     = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_DEP_GRAPH_TIMEOUT = 8.0   # hard limit — spec requirement
_T10_TTL           = 3600  # 1 hour — CVEs change continuously

_NVD_API_KEY = os.environ.get("DATANEXUS_NVD_API_KEY", "")

# CVE ID format validation
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Sprint 4 — new upstream constants
_CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL      = "https://api.first.org/data/v1/epss"
_OSV_VULNS_URL = "https://api.osv.dev/v1/vulns"
_KEV_STALE_H   = 48       # warn if KEV catalog older than 48h
_EPSS_TTL      = 6 * 3600  # 6h — EPSS recalculates daily, changes slowly intraday
_BATCH_MAX     = 50        # max packages per OSV querybatch call

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

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_package_vulnerabilities(
    package: Annotated[Optional[str], Field(description="Package name e.g. requests. Required in single-package mode.")] = None,
    version: Annotated[Optional[str], Field(description="Package version e.g. 2.28.0. Required in single-package mode.")] = None,
    ecosystem: Annotated[Optional[str], Field(description="Package ecosystem: npm, pypi, cargo, go, maven, nuget. Required.")] = None,
    packages: Annotated[Optional[list], Field(description="Batch list of {name, version, ecosystem} objects. Max 50.")] = None,
) -> dict:
    """Fetch all known CVEs for an open source package version or a batch of packages. Read-only. No side effects. Idempotent. Single-package mode: package (e.g. requests), version (e.g. 2.28.0), ecosystem (PyPI/npm/Maven/Go/Cargo/NuGet/RubyGems). Batch mode: packages array of {name, version, ecosystem} objects — max 50 per call. If packages array is provided and non-empty, batch mode is used and package/version/ecosystem are ignored. Batch returns {results: [...], partial: bool, failed_count: int}. Each result has vuln_count and vulnerabilities list. Returns CVE ID, severity, CVSS score, affected range, and fixed version. Use security_fetch_cve_detail for full detail by CVE ID. Use security_audit_sbom_vulnerabilities for SBOM files. Verified source: Google OSV.dev. 1-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_package_vulnerabilities", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        # ── Disambiguation (Sprint 4 spec) ────────────────────────────────────
        _batch_mode = packages is not None and len(packages) > 0
        _single_mode = package is not None and version is not None and ecosystem is not None

        if _batch_mode and _single_mode:
            log.warning("t10.fetch_package_vulnerabilities: both packages[] and "
                        "package/version/ecosystem provided — packages[] wins")

        if not _batch_mode and not _single_mode:
            from datanexus.core.audit import AuditContext as _AC, make_params_hash as _mph
            async with _AC("T10", {}, "1.0") as ctx:
                return error_response(
                    error_code=ErrorCode.MISSING_PARAMS,
                    message=(
                        "Provide either packages[] array (batch) or "
                        "package + version + ecosystem (single)."
                    ),
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                    upstream="",
                    retryable=False,
                )

        # ── BATCH PATH ────────────────────────────────────────────────────────
        if _batch_mode:
            pkg_list = packages[:_BATCH_MAX]
            if len(packages) > _BATCH_MAX:
                log.warning("t10.fetch_package_vulnerabilities: batch capped at %d (got %d)",
                            _BATCH_MAX, len(packages))
            params = {"batch_hash": __import__("hashlib").sha256(
                json.dumps(pkg_list, sort_keys=True).encode()
            ).hexdigest()[:32]}

            async with AuditContext("T10", params, "1.0") as ctx:
                if is_tripped("osv_dev"):
                    ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                    return error_response(
                        error_code=ErrorCode.CIRCUIT_OPEN,
                        message="OSV.dev currently unavailable. Try again later.",
                        query_hash=ctx.query_hash,
                        retry_after=300,
                        ingest_healthy=False,
                        upstream="osv.dev",
                        retryable=True,
                    )

                try:
                    async with httpx.AsyncClient(
                        timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
                    ) as client:
                        raw_results = await _batch_osv_query(client, pkg_list)
                except httpx.TimeoutException:
                    record_failure_sync("osv_dev")
                    return error_response(
                        error_code=ErrorCode.UPSTREAM_TIMEOUT,
                        message="OSV.dev batch query timed out.",
                        query_hash=ctx.query_hash,
                        retry_after=30,
                        ingest_healthy=False,
                        upstream="osv.dev",
                        retryable=True,
                    )
                except Exception:
                    record_failure_sync("osv_dev")
                    log.exception("t10.fetch_package_vulnerabilities batch error")
                    return error_response(
                        error_code=ErrorCode.INTERNAL_ERROR,
                        message="An internal error occurred. Please try again.",
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=False,
                        upstream="osv.dev",
                        retryable=True,
                    )

                record_success_sync("osv_dev")

                results = []
                failed_count = 0
                for comp, osv_result in zip(pkg_list, raw_results):
                    try:
                        safe  = _strip_unsafe_fields(osv_result) if osv_result else {}
                        vulns = safe.get("vulns", [])
                        vulns = _fmt_dedup_pysec_ghsa(vulns)
                        vulns = _fmt_fix_severity_levels(vulns)
                        results.append({
                            "name":            comp.get("name", ""),
                            "version":         comp.get("version", ""),
                            "ecosystem":       comp.get("ecosystem", ""),
                            "vulnerabilities": vulns,
                            "vuln_count":      len(vulns),
                            "error":           None,
                        })
                    except Exception as exc:
                        failed_count += 1
                        results.append({
                            "name":            comp.get("name", ""),
                            "version":         comp.get("version", ""),
                            "ecosystem":       comp.get("ecosystem", ""),
                            "vulnerabilities": [],
                            "vuln_count":      0,
                            "error":           "OSV lookup failed",
                        })

                data_as_of = datetime.now(timezone.utc).isoformat()
                batch_data = {
                    "results":      results,
                    "partial":      failed_count > 0,
                    "failed_count": failed_count,
                    "total":        len(results),
                }
                markdown = _build_batch_vuln_markdown(batch_data)

                out = {
                    "status":           "ok",
                    "tool_id":          "T10",
                    "source_url":       "https://api.osv.dev/v1/querybatch",
                    "fetch_timestamp":  data_as_of,
                    "cache_hit":        False,
                    "staleness_notice": None,
                    "sha256_hash":      "",
                    "data":             batch_data,
                    "markdown_output":  markdown,
                    "disclaimer":       T10_DISCLAIMER,
                    "data_as_of":       data_as_of,
                    "ingest_healthy":   True,
                    **standard_response_fields(ctx.query_hash, data_as_of, True),
                }
                _success = True
                return out

        # ── SINGLE-PACKAGE PATH (backward-compatible) ─────────────────────────
        pkg_clean = package.strip()
        ver_clean = version.strip()
        eco_clean = ecosystem.strip()
        params    = {"package": pkg_clean, "version": ver_clean, "ecosystem": eco_clean}

        async with AuditContext("T10", params, "1.0") as ctx:
            phash = make_params_hash(params)

            cached = get_cached("T10", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            if is_tripped("osv_dev"):
                archive = get_cached("T10", phash + "_archive")
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
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

            osv_ecosystem = _normalise_osv_ecosystem(eco_clean)
            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
                ) as client:
                    osv_data = await query_osv_for_version(
                        client, pkg_clean, ver_clean, osv_ecosystem,
                    )
            except httpx.TimeoutException:
                record_failure_sync("osv_dev")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="OSV.dev timed out. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                    upstream="osv.dev",
                    retryable=True,
                )
            except httpx.HTTPStatusError:
                record_failure_sync("osv_dev")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="OSV.dev temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                    upstream="osv.dev",
                    retryable=True,
                )
            except Exception:
                record_failure_sync("osv_dev")
                log.exception("t10.fetch_package_vulnerabilities error pkg=%s", pkg_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                    upstream="osv.dev",
                    retryable=True,
                )

            record_success_sync("osv_dev")

            vulns      = osv_data.get("vulns", [])
            vulns      = _fmt_dedup_pysec_ghsa(vulns)
            vulns      = _fmt_fix_severity_levels(vulns)
            osv_data["vulns"] = vulns
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

            _out = {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_package_vulnerabilities",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
            ecosystem=ecosystem,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — fetch_dependency_graph
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_dependency_graph(
    package: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    version: Annotated[str, Field(description="Package version e.g. 2.28.0. Required.")],
    ecosystem: Annotated[str, Field(description="Package ecosystem: npm, pypi, cargo, go, maven, nuget. Required.")],
) -> dict:
    """Fetch the full dependency tree for a package version including transitive dependencies. Read-only. No side effects. Idempotent. Hard 8-second timeout — large dependency trees may return partial results. package: Package name. Required. version: Exact version string e.g. 1.2.3. Required. ecosystem: One of PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems. Required. Returns all direct and transitive dependencies with version constraints. Use this to understand full supply chain exposure. Use security_fetch_package_vulnerabilities instead when you only need CVEs for a single package. Verified source: deps.dev (Google). 1-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_dependency_graph", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
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
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            # ── Circuit breaker ───────────────────────────────────────────────────
            if is_tripped("deps_dev"):
                archive = get_cached("T10", phash + "_archive")
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
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
                record_failure_sync("deps_dev")
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
                record_failure_sync("deps_dev")
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
                record_failure_sync("deps_dev")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="deps.dev temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )
            except Exception:
                record_failure_sync("deps_dev")
                log.exception("t10.fetch_dependency_graph error pkg=%s", pkg_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                )

            record_success_sync("deps_dev")

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
                    f"{quote(ver_clean, safe='')}:dependencies"
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

            _out = {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_dependency_graph",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_cve_detail
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_cve_detail(cve_id: Annotated[str, Field(description="CVE identifier e.g. CVE-2021-44228. Required.")]) -> dict:
    """Fetch full detail for a specific CVE by ID. Read-only. No side effects. Idempotent. cve_id: CVE identifier in format CVE-YYYY-NNNNN e.g. CVE-2021-44228. Required. Returns description, CVSS base score, affected products, patch references, and publish date. Use this when you have a CVE ID and need complete detail beyond what a package scan returns. Use security_fetch_package_vulnerabilities instead when you want all CVEs for a package version. Verified source: NIST NVD. 1-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_cve_detail", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
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
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            # ── Circuit breaker ───────────────────────────────────────────────────
            if is_tripped("nist_nvd"):
                archive = get_cached("T10", phash + "_archive")
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
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

            # ── Live fetch — NIST NVD + OSV (concurrent for remediation) ─────────
            nvd_headers = {**_HTTP_HEADERS}
            if _NVD_API_KEY:
                nvd_headers["apiKey"] = _NVD_API_KEY

            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
                ) as client:
                    nvd_task = client.get(
                        _NVD_URL, params={"cveId": cve_clean},
                        headers=nvd_headers,
                    )
                    osv_task = client.get(f"{_OSV_VULNS_URL}/{cve_clean}")
                    nvd_resp, osv_resp = await asyncio.gather(
                        nvd_task, osv_task, return_exceptions=True,
                    )

                # Handle NVD response
                if isinstance(nvd_resp, Exception):
                    raise nvd_resp
                if nvd_resp.status_code == 404:
                    return error_response(
                        error_code=ErrorCode.NOT_FOUND,
                        message=f"{cve_clean} not found in NIST NVD.",
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                        upstream="nvd.nist.gov",
                        retryable=False,
                    )
                nvd_resp.raise_for_status()
                nvd_raw = nvd_resp.json()

                # Parse OSV remediation (best-effort; NVD-only is fine)
                if isinstance(osv_resp, Exception) or osv_resp.status_code == 404:
                    osv_advisory = None
                else:
                    try:
                        osv_advisory = osv_resp.json() if osv_resp.status_code == 200 else None
                    except Exception:
                        osv_advisory = None

            except httpx.TimeoutException:
                record_failure_sync("nist_nvd")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="NIST NVD timed out. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                    upstream="nvd.nist.gov",
                    retryable=True,
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    return error_response(
                        error_code=ErrorCode.UPSTREAM_RATE_LIMITED,
                        message="NIST NVD rate limit reached. Try again in 30 seconds.",
                        query_hash=ctx.query_hash,
                        retry_after=30,
                        ingest_healthy=True,
                        upstream="nvd.nist.gov",
                        retryable=True,
                    )
                record_failure_sync("nist_nvd")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="NIST NVD temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                    upstream="nvd.nist.gov",
                    retryable=True,
                )
            except Exception:
                record_failure_sync("nist_nvd")
                log.exception("t10.fetch_cve_detail error cve=%s", cve_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                    upstream="nvd.nist.gov",
                    retryable=True,
                )

            record_success_sync("nist_nvd")

            cve_data   = _parse_nvd_cve(nvd_raw, cve_clean)
            # Append remediation from OSV (Sprint 4)
            cve_data["remediation"] = _parse_osv_remediation(osv_advisory)
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

            _out = {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_cve_detail",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — audit_sbom_vulnerabilities
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def audit_sbom_vulnerabilities(sbom_json: Annotated[str, Field(description="CycloneDX or SPDX SBOM as JSON string. Required.")]) -> dict:
    """Audit a Software Bill of Materials for known vulnerabilities across all listed packages. Read-only. No side effects. Idempotent. sbom_json: CycloneDX or SPDX SBOM as a JSON string. Required. Large SBOMs (100+ packages) may take up to 10 seconds. Returns CVEs grouped by package with severity and fixed versions. Use this when you have a full SBOM to audit. Use security_fetch_package_vulnerabilities instead when checking a single package version. Verified source: Google OSV.dev batch API. 1-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_audit_sbom_vulnerabilities", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        import hashlib
        params = {"sbom_hash": hashlib.sha256(sbom_json.encode()).hexdigest()[:32]}

        async with AuditContext("T10", params, "1.0") as ctx:
            phash = make_params_hash(params)

            cached = get_cached("T10", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

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
                _error_code = "CIRCUIT_OPEN"
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
                record_failure_sync("osv_dev")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="OSV.dev batch query timed out.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                )
            except Exception:
                record_failure_sync("osv_dev")
                log.exception("t10.audit_sbom_vulnerabilities error")
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                )

            record_success_sync("osv_dev")

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

            _out = {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="audit_sbom_vulnerabilities",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 5 — fetch_package_licence
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_package_licence(
    package: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    version: Annotated[str, Field(description="Package version e.g. 2.28.0. Required.")],
    ecosystem: Annotated[str, Field(description="Package ecosystem: npm, pypi, cargo, go, maven, nuget. Required.")],
) -> dict:
    """Fetch the SPDX licence identifier for an open source package version. Read-only. No side effects. Idempotent. package: Package name e.g. flask. Required. version: Exact version string e.g. 2.3.0. Required. ecosystem: One of PyPI, npm, Maven, Go, Cargo, NuGet, RubyGems. Required. Returns the SPDX licence identifier e.g. MIT, Apache-2.0, GPL-3.0. Use this to verify licence compatibility before including a dependency. Use security_fetch_package_vulnerabilities instead when checking for security issues not licences. Verified source: deps.dev (Google). 1-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_package_licence", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        pkg_clean = package.strip()
        ver_clean = version.strip()
        eco_clean = ecosystem.strip()
        params    = {"package": pkg_clean, "version": ver_clean, "ecosystem": eco_clean}

        async with AuditContext("T10", params, "1.0") as ctx:
            phash = make_params_hash(params)

            cached = get_cached("T10", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            if is_tripped("deps_dev"):
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
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
                record_failure_sync("deps_dev")
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
                record_failure_sync("deps_dev")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="deps.dev temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )
            except Exception:
                record_failure_sync("deps_dev")
                log.exception("t10.fetch_package_licence error pkg=%s", pkg_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                )

            record_success_sync("deps_dev")

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

            _out = {**result_data, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_package_licence",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 6 — fetch_cisa_kev  (Sprint 4)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_cisa_kev(cve_id: Annotated[str, Field(description="CVE identifier e.g. CVE-2021-44228. Required.")]) -> dict:
    """Check whether a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog. Read-only. No side effects. Idempotent. cve_id: CVE identifier in format CVE-YYYY-NNNNN e.g. CVE-2021-44228. Required. Returns in_kev (bool), date_added, due_date, ransomware_use, and notes from the CISA KEV catalog. KEV status answers 'Is this being actively exploited?' — a critical triage question not available in NIST NVD. Verified source: CISA KEV catalog (updated daily, cached). Use security_fetch_cve_detail for full CVE severity. Use security_fetch_cve_epss for exploit probability. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_cisa_kev", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
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
                    upstream="",
                    retryable=False,
                )

            # ── 1. Load KEV catalog from Redis (datanexus:kev:catalog) ──────────
            # get_cached("kev", "catalog") → key datanexus:kev:catalog
            catalog_raw = _get_cached("kev", "catalog")
            fetched_at_raw = _get_cached("kev", "fetched_at")
            stale_warning = None

            if catalog_raw:
                _cache_hit = True
                # Staleness check: warn if catalog > 48h old
                if fetched_at_raw and isinstance(fetched_at_raw, dict):
                    pass  # stored as dict — shouldn't happen, ignore
                elif fetched_at_raw and isinstance(fetched_at_raw, str):
                    try:
                        from datetime import timedelta
                        fetched_dt = datetime.fromisoformat(fetched_at_raw)
                        age_h = (datetime.now(timezone.utc) - fetched_dt).total_seconds() / 3600
                        if age_h > _KEV_STALE_H:
                            stale_warning = "KEV catalog may be stale"
                    except Exception:
                        pass

                # catalog_raw is a dict (from get_cached which json.loads)
                if isinstance(catalog_raw, dict) and "vulnerabilities" in catalog_raw:
                    kev_data = catalog_raw
                else:
                    kev_data = None
            else:
                # Redis miss or outage — fall through to direct fetch
                kev_data = None

            if kev_data is None:
                # Direct upstream fetch with circuit breaker
                if is_tripped("cisa_gov"):
                    return error_response(
                        error_code=ErrorCode.CIRCUIT_OPEN,
                        message="CISA KEV temporarily unavailable. Try again later.",
                        query_hash=ctx.query_hash,
                        retry_after=900,
                        ingest_healthy=False,
                        upstream="cisa.gov",
                        retryable=True,
                    )
                try:
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(7.0, connect=3.0),
                        headers=_HTTP_HEADERS,
                        follow_redirects=True,
                    ) as client:
                        resp = await client.get(_CISA_KEV_URL)
                        resp.raise_for_status()
                        kev_data = resp.json()
                    record_success_sync("cisa_gov")
                    # Store in Redis for next call
                    now_iso = datetime.now(timezone.utc).isoformat()
                    _set_cached("kev", "catalog", kev_data, 25 * 3600)
                    _set_cached("kev", "fetched_at", now_iso, 25 * 3600)
                except httpx.TimeoutException:
                    record_failure_sync("cisa_gov")
                    return error_response(
                        error_code=ErrorCode.UPSTREAM_TIMEOUT,
                        message="CISA KEV timed out. Try again shortly.",
                        query_hash=ctx.query_hash,
                        retry_after=30,
                        ingest_healthy=False,
                        upstream="cisa.gov",
                        retryable=True,
                    )
                except Exception:
                    record_failure_sync("cisa_gov")
                    log.exception("t10.fetch_cisa_kev live fetch failed cve=%s", cve_clean)
                    return error_response(
                        error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                        message="CISA KEV temporarily unavailable.",
                        query_hash=ctx.query_hash,
                        retry_after=60,
                        ingest_healthy=False,
                        upstream="cisa.gov",
                        retryable=True,
                    )

            # ── 2. Look up CVE in catalog ──────────────────────────────────────
            vulns = kev_data.get("vulnerabilities", [])
            entry = next(
                (v for v in vulns if v.get("cveID", "").upper() == cve_clean),
                None,
            )

            if entry:
                result = {
                    "in_kev":          True,
                    "cve_id":          cve_clean,
                    "date_added":      entry.get("dateAdded", ""),
                    "due_date":        entry.get("dueDate", ""),
                    "ransomware_use":  entry.get("knownRansomwareCampaignUse", ""),
                    "notes":           entry.get("notes", ""),
                    "vulnerability_name": entry.get("vulnerabilityName", ""),
                    "vendor_project":  entry.get("vendorProject", ""),
                    "product":         entry.get("product", ""),
                    "source":          "cisa.gov",
                }
            else:
                result = {
                    "in_kev":   False,
                    "cve_id":   cve_clean,
                    "source":   "cisa.gov",
                }
            if stale_warning:
                result["warning"] = stale_warning

            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown   = _build_kev_markdown(result, cve_clean)

            out = {
                "status":           "ok",
                "tool_id":          "T10",
                "source_url":       "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        _cache_hit,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             result,
                "markdown_output":  markdown,
                "disclaimer":       T10_DISCLAIMER,
                "data_as_of":       data_as_of,
                "ingest_healthy":   True,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
            _success = True
            return out

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_cisa_kev",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 7 — fetch_cve_epss  (Sprint 4)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_cve_epss(cve_id: Annotated[str, Field(description="CVE identifier e.g. CVE-2021-44228. Required.")]) -> dict:
    """EPSS exploit probability score for a CVE — predicts likelihood of exploitation in the next 30 days.

    cve_id: CVE identifier e.g. "CVE-2021-44228".

    Returns: epss (float 0.0–1.0) and percentile (float 0.0–100.0).
    Thresholds: >0.7 patch immediately, 0.3–0.7 patch soon, <0.3 monitor.
    Use with security_fetch_cve_detail to prioritize patching — EPSS measures urgency, CVSS measures severity.
    Source: FIRST.org. 6-hour cache.

    Example: fetch_cve_epss(cve_id="CVE-2021-44228")
    """
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
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
                    upstream="",
                    retryable=False,
                )

            # ── 1. Cache check (datanexus:epss:{cve_id}, TTL 6h) ──────────────
            # Use get_cached("epss", cve_clean) → key datanexus:epss:{cve_clean}
            cached = _get_cached("epss", cve_clean)
            if cached and isinstance(cached, dict) and "epss" in cached:
                _cache_hit = True
                _success = True
                data_as_of = cached.get("date", datetime.now(timezone.utc).isoformat())
                out = {
                    "status":          "ok",
                    "tool_id":         "T10",
                    "source_url":      "https://api.first.org/epss",
                    "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
                    "cache_hit":       True,
                    "staleness_notice": None,
                    "sha256_hash":     "",
                    "data":            cached,
                    "markdown_output": _build_epss_markdown(cached),
                    "disclaimer":      T10_DISCLAIMER,
                    "data_as_of":      data_as_of,
                    "ingest_healthy":  True,
                    **standard_response_fields(ctx.query_hash, data_as_of, True),
                }
                return out

            # ── 2. Live fetch from first.org (no stale serving — accuracy matters) ──
            if is_tripped("first_org"):
                return error_response(
                    error_code=ErrorCode.CIRCUIT_OPEN,
                    message="FIRST.org EPSS temporarily unavailable. Try again later.",
                    query_hash=ctx.query_hash,
                    retry_after=900,
                    ingest_healthy=False,
                    upstream="first.org",
                    retryable=True,
                )

            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT,
                    headers=_HTTP_HEADERS,
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(_EPSS_URL, params={"cve": cve_clean})
                    resp.raise_for_status()
                    raw = resp.json()
            except httpx.TimeoutException:
                record_failure_sync("first_org")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="FIRST.org EPSS timed out. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                    upstream="first.org",
                    retryable=True,
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    return error_response(
                        error_code=ErrorCode.NOT_FOUND,
                        message=f"{cve_clean} not found in EPSS database.",
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                        upstream="first.org",
                        retryable=False,
                    )
                record_failure_sync("first_org")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="FIRST.org EPSS temporarily unavailable.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                    upstream="first.org",
                    retryable=True,
                )
            except Exception:
                record_failure_sync("first_org")
                log.exception("t10.fetch_cve_epss error cve=%s", cve_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                    upstream="first.org",
                    retryable=True,
                )

            record_success_sync("first_org")

            data_items = raw.get("data", [])
            if not data_items:
                return error_response(
                    error_code=ErrorCode.NOT_FOUND,
                    message=f"{cve_clean} not found in EPSS database.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                    upstream="first.org",
                    retryable=False,
                )

            item = data_items[0]
            epss_data = {
                "cve":           item.get("cve", cve_clean),
                "epss":          float(item.get("epss", 0)),
                "percentile":    float(item.get("percentile", 0)),
                "model_version": raw.get("version", ""),
                "date":          item.get("date", ""),
                "source":        "first.org",
            }

            # Store in Redis (do NOT serve stale — accuracy matters)
            _set_cached("epss", cve_clean, epss_data, _EPSS_TTL)

            data_as_of = epss_data["date"] or datetime.now(timezone.utc).isoformat()
            out = {
                "status":          "ok",
                "tool_id":         "T10",
                "source_url":      "https://api.first.org/epss",
                "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     "",
                "data":            epss_data,
                "markdown_output": _build_epss_markdown(epss_data),
                "disclaimer":      T10_DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
            _success = True
            return out

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_cve_epss",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


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
    pkg_enc = quote(package, safe="")
    ver_enc = quote(version, safe="")
    url = (
        f"{_DEPS_DEV_URL}/systems/{system}/packages/"
        f"{pkg_enc}/versions/{ver_enc}:dependencies"
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

    # Sprint 8B: cross-check transitive deps against OSV.dev — only include those
    # with ≥1 open CVE. Clean deps are omitted from list but counted in total_deps.
    transitive_nodes = [n for n in nodes if n.get("relation") != "DIRECT"][:50]
    cvs_filtered: list[dict] = []
    if transitive_nodes:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=2.0),
                headers=_HTTP_HEADERS,
                follow_redirects=True,
            ) as osv_client:
                queries = [
                    {
                        "package": {"name": n["name"], "ecosystem": n["system"] or system},
                        "version": n["version"],
                    }
                    for n in transitive_nodes
                    if n.get("name")
                ]
                if queries:
                    osv_resp = await osv_client.post(
                        _OSV_BATCH_URL, json={"queries": queries}, timeout=5.0
                    )
                    if osv_resp.status_code == 200:
                        for node, result in zip(transitive_nodes, osv_resp.json().get("results", [])):
                            if result and result.get("vulns"):
                                cvs_filtered.append({
                                    "name":      node["name"],
                                    "version":   node["version"],
                                    "system":    node["system"],
                                    "cve_count": len(result["vulns"]),
                                })
        except Exception as _osv_exc:
            log.debug("fetch_dependency_graph: OSV cross-check failed (non-fatal): %s", _osv_exc)

    return {
        "package":    package,
        "version":    version,
        "ecosystem":  system,
        "nodes":      nodes[:200],
        "total_deps": len(nodes),
        "cvs_filtered_transitive_deps": cvs_filtered,
        "source":     "deps.dev",
    }


async def _fetch_licence_live(
    client: httpx.AsyncClient,
    system: str,
    package: str,
    version: str,
) -> dict:
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
        if score == 0.0:
            return "NONE"
        if score < 4.0:
            return "LOW"
        if score < 7.0:
            return "MEDIUM"
        if score < 9.0:
            return "HIGH"
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

    # Sprint 4: remediation block
    rem = data.get("remediation")
    if rem is not None:
        if rem.get("patch_available") is None:
            lines += ["### Remediation", "No OSV advisory found — patch status unknown.", ""]
        elif rem.get("patch_available"):
            lines += ["### Remediation", "**Patch available.** Upgrade to:"]
            for fix in rem.get("fixed_versions", [])[:10]:
                lines.append(f"- **{fix.get('package','')}** ({fix.get('ecosystem','')}) → `{fix.get('upgrade_to','')}`")
            lines.append("")
        else:
            lines += ["### Remediation", "No fix version recorded in OSV at this time.", ""]

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
    lic_str = ", ".join(f"`{lic}`" for lic in lics) if lics else "Not declared"
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


# ── Sprint 4 helpers ──────────────────────────────────────────────────────────

def _parse_osv_remediation(osv_advisory: Optional[dict]) -> dict:
    """Extract remediation/fix data from an OSV advisory response.

    Returns:
      {patch_available: true,  fixed_versions: [{package, ecosystem, upgrade_to}]} — fix found
      {patch_available: false, fixed_versions: []}                                  — advisory exists, no fix
      {patch_available: null,  fixed_versions: null}                                — not in OSV (NVD-only)
    """
    if osv_advisory is None:
        return {"patch_available": None, "fixed_versions": None}

    fixes = []
    for affected in osv_advisory.get("affected", []):
        pkg_info = affected.get("package", {})
        pkg_name = pkg_info.get("name", "")
        pkg_eco  = pkg_info.get("ecosystem", "")
        for rng in affected.get("ranges", []):
            if rng.get("type", "") == "GIT":
                continue   # git commit ranges — not useful as upgrade_to
            for event in rng.get("events", []):
                fixed_ver = event.get("fixed")
                if fixed_ver:
                    fixes.append({
                        "package":    pkg_name,
                        "ecosystem":  pkg_eco,
                        "upgrade_to": fixed_ver,
                    })

    # Deduplicate (same package may appear in multiple ranges)
    seen = set()
    deduped = []
    for f in fixes:
        key = (f["package"], f["ecosystem"], f["upgrade_to"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return {"patch_available": len(deduped) > 0, "fixed_versions": deduped}


def _build_kev_markdown(result: dict, cve_id: str) -> str:
    lines = [f"## CISA KEV — {cve_id}", ""]
    if result.get("in_kev"):
        lines += [
            "**Status: IN KEV** — This CVE is actively exploited.",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Date Added | {result.get('date_added', '')} |",
            f"| Due Date | {result.get('due_date', '')} |",
            f"| Ransomware Use | {result.get('ransomware_use', '')} |",
        ]
        vname = result.get("vulnerability_name", "")
        if vname:
            lines.append(f"| Vulnerability | {vname} |")
        notes = result.get("notes", "")
        if notes:
            lines += ["", f"**Notes:** {notes[:300]}"]
    else:
        lines.append("**Status: NOT in KEV** — No active exploitation recorded by CISA.")
    if result.get("warning"):
        lines += ["", f"> ⚠ {result['warning']}"]
    lines += ["", f"*{T10_DISCLAIMER}*"]
    return "\n".join(lines)


def _build_epss_markdown(data: dict) -> str:
    epss = data.get("epss", 0.0)
    pct  = data.get("percentile", 0.0)
    urgency = "CRITICAL" if epss >= 0.9 else ("HIGH" if epss >= 0.5 else ("MEDIUM" if epss >= 0.1 else "LOW"))
    lines = [
        f"## EPSS — {data.get('cve', '')}",
        "",
        f"**EPSS Score:** {epss:.4f}  |  **Percentile:** {pct:.1%}  |  **Urgency:** {urgency}",
        f"**Date:** {data.get('date', '')}",
        "",
        "EPSS = probability of exploitation in the next 30 days.",
        "CVSS measures severity; EPSS measures urgency.",
        "",
        f"*{T10_DISCLAIMER}*",
    ]
    return "\n".join(lines)


def _build_batch_vuln_markdown(data: dict) -> str:
    results = data.get("results", [])
    failed  = data.get("failed_count", 0)
    lines = [
        "## Batch Vulnerability Scan",
        "",
        f"**Packages scanned:** {len(results)}  |  **Failed:** {failed}",
        "",
        "| Package | Version | Ecosystem | Vulns | Status |",
        "|---------|---------|-----------|-------|--------|",
    ]
    for r in results:
        status = "FAILED" if r.get("error") else (
            f"{r.get('vuln_count', 0)} vuln(s)"
        )
        lines.append(
            f"| {r.get('name','')} | {r.get('version','')} "
            f"| {r.get('ecosystem','')} | {r.get('vuln_count',0)} | {status} |"
        )
    if data.get("partial"):
        lines += ["", f"> {failed} package(s) could not be checked (OSV lookup failed)."]
    lines += ["", f"*{T10_DISCLAIMER}*"]
    return "\n".join(lines)
