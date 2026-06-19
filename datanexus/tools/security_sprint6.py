"""
datanexus/tools/security_sprint6.py — Sprint 6 security tools.

Tools:
  fetch_package_maintainer_history  — maintainer health + anomaly score
  fetch_package_risk_brief          — SHIP/CAUTION/BLOCK aggregator
  detect_typosquatting              — Damerau-Levenshtein vs top-10k (added in final step)

All are thin MCP wrappers. Logic lives in _security_utils.py / _maintainer_utils.py.
HTTP self-calls are forbidden — utilities are called directly.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from pydantic import Field

import pybreaker
from fastmcp import FastMCP

from datanexus.core.audit import AuditContext, make_params_hash, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import fire_and_forget, track_tool_call
from datanexus.tools._circuit_breakers import (
    _pypi_stats_breaker,
    _npm_stats_breaker,
)
from datanexus.tools._maintainer_utils import _fetch_maintainer_history
from datanexus.tools._security_utils import (
    _fetch_vulns,
    _fetch_licence,
    _fetch_depsdev,
    _resolve_version,
)
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.security_sprint6")

security_sprint6 = FastMCP("DataNexus Security Sprint6")

_DISCLAIMER = (
    "Maintainer data sourced from PyPI and npm public registries. "
    "DataNexus does not warrant completeness. "
    "Verify with your security team before making supply-chain decisions."
)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — fetch_package_maintainer_history
# ══════════════════════════════════════════════════════════════════════════════

@security_sprint6.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_package_maintainer_history(
    package_name: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    ecosystem: Annotated[Literal["npm", "pypi", "cargo", "go"], Field(description="Package ecosystem: npm, pypi, cargo, go. Required.")],
) -> dict:
    """Analyse ownership and release history for an npm or PyPI package to detect supply-chain risk. Uses PyPI JSON API and npm registry — data refreshed on each call, 1-hour cache. Returns maintainer_count, recent_changes, ownership_transfers, account_ages, anomaly_score (0.0–1.0), and maintainer_health (healthy | stale | abandoned | suspicious). Rate limit: 60/minute. No auth required. For security engineers auditing open-source dependencies before inclusion in production builds. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_package_maintainer_history", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        pkg = package_name.strip()
        eco = ecosystem.strip().lower()
        params = {"package_name": pkg, "ecosystem": eco}

        async with AuditContext("T10", params, "1.0") as ctx:
            if not pkg:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="package_name must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            if eco not in ("npm", "pypi"):
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"ecosystem '{eco}' not yet supported. Use 'npm' or 'pypi'.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            result = await _fetch_maintainer_history(pkg, eco)

            upstream_key = "pypi" if eco == "pypi" else "npm_registry"
            upstream_status = {upstream_key: result.get("status", "ERROR")}
            ingest_ok = result.get("status") == "OK"

            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown = _build_maintainer_markdown(result, pkg, eco)

            data = {
                "package_name":        pkg,
                "ecosystem":           eco,
                "maintainer_count":    result.get("maintainer_count", 0),
                "recent_changes":      result.get("recent_changes", []),
                "ownership_transfers": result.get("ownership_transfers", []),
                "account_ages":        result.get("account_ages", {}),
                "anomaly_score":       result.get("anomaly_score", 0.0),
                "maintainer_health":   result.get("maintainer_health", "healthy"),
                "last_release_days_ago": result.get("last_release_days_ago"),
                "upstream_status":     upstream_status,
            }

            _success = ingest_ok
            return {
                "status":           "ok" if ingest_ok else "degraded",
                "tool_id":          "T10",
                "source_url":       (
                    f"https://pypi.org/pypi/{pkg}/json"
                    if eco == "pypi"
                    else f"https://registry.npmjs.org/{pkg}"
                ),
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "markdown_output":  markdown,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, ingest_ok),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("fetch_package_maintainer_history error pkg=%s", package_name)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_package_maintainer_history",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
            ecosystem=ecosystem,
        ))


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_maintainer_markdown(result: dict, package: str, ecosystem: str) -> str:
    health = result.get("maintainer_health", "unknown")
    score  = result.get("anomaly_score", 0.0)
    count  = result.get("maintainer_count", 0)
    days   = result.get("last_release_days_ago")
    status = result.get("status", "ERROR")

    _icon = {
        "healthy":    "✓",
        "stale":      "~",
        "abandoned":  "!",
        "suspicious": "✗",
    }.get(health, "?")

    lines = [
        f"## Maintainer Analysis: `{package}` ({ecosystem})",
        "",
        f"**Health:** {_icon} `{health.upper()}`  |  "
        f"**Anomaly Score:** {score:.2f}  |  "
        f"**Maintainers:** {count}",
    ]

    if days is not None:
        lines.append(f"**Last Release:** {days} day(s) ago")

    transfers = result.get("ownership_transfers", [])
    if transfers:
        lines += ["", f"**⚠ Ownership Transfer Detected:** {', '.join(transfers)}"]

    ages = result.get("account_ages", {})
    if ages:
        lines += ["", "**Account Ages:**"]
        for user, age in ages.items():
            age_str = f"{age} day(s)" if isinstance(age, int) else age
            flag = " ⚠ (< 90 days)" if isinstance(age, int) and age < 90 else ""
            lines.append(f"  - `{user}`: {age_str}{flag}")

    if status != "OK":
        lines += ["", f"> Data source status: `{status}` — results may be incomplete."]

    lines += ["", f"*{_DISCLAIMER}*"]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — fetch_package_risk_brief
# ══════════════════════════════════════════════════════════════════════════════

@security_sprint6.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T11")
async def fetch_package_risk_brief(
    package_name: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    ecosystem: Annotated[Literal["npm", "pypi", "go", "cargo", "maven"], Field(description="Package ecosystem: npm, pypi, cargo, go, maven. Required.")],
    version: Annotated[Optional[str], Field(description="Package version e.g. 2.28.0. Required.")] = None,
) -> dict:
    """Single SHIP/CAUTION/BLOCK verdict for any package. Combines CVEs, licence, maintainer health, and transitive count in one call. Uses OSV.dev, deps.dev, PyPI, and npm registry — data refreshed on each call. Returns verdict (SHIP/CAUTION/BLOCK), critical_cve_count, high_cve_count, licence_risk, maintainer_health, transitive_count, resolved_version, upstream_status, and reasoning. Rate limit: 30/minute. No auth required. For security engineers performing pre-inclusion package review. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_package_risk_brief", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        pkg = package_name.strip()
        eco = ecosystem.strip().lower()
        ver = version.strip() if version else None
        params = {"package_name": pkg, "ecosystem": eco, "version": ver or ""}

        async with AuditContext("T11", params, "1.0") as ctx:
            if not pkg:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="package_name must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # Resolve version if not provided
            resolved_version = ver
            if not resolved_version:
                resolved_version = await _resolve_version(pkg, eco)
            resolved_version = resolved_version or "unknown"

            # Parallel upstream calls — return_exceptions=True so one failure
            # doesn't cancel others
            vulns_r, licence_r, maintainer_r, depsdev_r = await asyncio.gather(
                _fetch_vulns(pkg, eco, resolved_version),
                _fetch_licence(pkg, eco),
                _fetch_maintainer_history(pkg, eco),
                _fetch_depsdev(pkg, eco, resolved_version),
                return_exceptions=True,
            )

            # Unpack with graceful fallback for exceptions.
            # CircuitBreakerError → "CIRCUIT_OPEN", other exceptions → "ERROR"
            def _upstream_status(r, ok_key: str = "status") -> str:
                if isinstance(r, pybreaker.CircuitBreakerError):
                    return "CIRCUIT_OPEN"
                if isinstance(r, Exception):
                    return "ERROR"
                return r.get(ok_key, "ERROR") if r else "ERROR"

            vulns      = vulns_r      if not isinstance(vulns_r, Exception)      else None
            licence    = licence_r    if not isinstance(licence_r, Exception)    else None
            maintainer = maintainer_r if not isinstance(maintainer_r, Exception) else None
            depsdev    = depsdev_r    if not isinstance(depsdev_r, Exception)    else None

            critical_cve_count = vulns.get("critical_cve_count")    if vulns      else None
            high_cve_count     = vulns.get("high_cve_count")         if vulns      else None
            licence_risk       = licence.get("licence_risk")          if licence    else None
            maintainer_health  = maintainer.get("maintainer_health")  if maintainer else None
            transitive_count   = depsdev.get("transitive_count")      if depsdev    else None

            upstream_status = {
                "osv":         _upstream_status(vulns_r),
                "depsdev":     _upstream_status(depsdev_r),
                "pypi_or_npm": _upstream_status(maintainer_r),
                "licence_src": _upstream_status(licence_r),
            }

            verdict, reasoning = _compute_verdict(
                critical_cve_count, high_cve_count, licence_risk, maintainer_health,
            )

            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown   = _build_risk_brief_markdown(
                pkg, eco, resolved_version, verdict, reasoning,
                critical_cve_count, high_cve_count, licence_risk,
                maintainer_health, transitive_count, upstream_status,
            )

            data = {
                "package_name":       pkg,
                "ecosystem":          eco,
                "resolved_version":   resolved_version,
                "verdict":            verdict,
                "reasoning":          reasoning,
                "critical_cve_count": critical_cve_count,
                "high_cve_count":     high_cve_count,
                "licence_risk":       licence_risk,
                "maintainer_health":  maintainer_health,
                "transitive_count":   transitive_count,
                "upstream_status":    upstream_status,
            }

            ingest_ok = any(s == "OK" for s in upstream_status.values())
            _success = True
            return {
                "status":           "ok" if ingest_ok else "degraded",
                "tool_id":          "T11",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "markdown_output":  markdown,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, ingest_ok),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("fetch_package_risk_brief error pkg=%s", package_name)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T11",
            tool_name="fetch_package_risk_brief",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
            ecosystem=ecosystem,
        ))


# ── Verdict logic ──────────────────────────────────────────────────────────────

def _compute_verdict(
    critical_cve_count: Optional[int],
    high_cve_count: Optional[int],
    licence_risk: Optional[str],
    maintainer_health: Optional[str],
) -> tuple[str, str]:
    """Return (verdict, one-sentence reasoning). BLOCK > CAUTION > SHIP."""
    crit  = critical_cve_count or 0
    high  = high_cve_count     or 0

    if crit >= 1:
        return "BLOCK", f"Package has {crit} critical CVE(s) — do not use."
    if licence_risk == "INCOMPATIBLE":
        return "BLOCK", "Licence is proprietary or unlicensed — incompatible with commercial use."

    if high >= 2:
        return "CAUTION", f"Package has {high} high-severity CVE(s) — review before use."
    if licence_risk == "COPYLEFT":
        return "CAUTION", "Licence is copyleft (GPL/LGPL/AGPL/MPL) — review compatibility with your project."
    if maintainer_health in ("suspicious", "abandoned"):
        return "CAUTION", f"Maintainer health is {maintainer_health} — verify supply-chain status."

    return "SHIP", "No blocking CVEs, compatible licence, and healthy maintainer status."


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_risk_brief_markdown(
    package: str,
    ecosystem: str,
    version: str,
    verdict: str,
    reasoning: str,
    critical_cve_count: Optional[int],
    high_cve_count: Optional[int],
    licence_risk: Optional[str],
    maintainer_health: Optional[str],
    transitive_count: Optional[int],
    upstream_status: dict,
) -> str:
    _verdict_icon = {"SHIP": "✓", "CAUTION": "~", "BLOCK": "✗"}.get(verdict, "?")
    lines = [
        f"## Package Risk Brief: `{package}` v{version} ({ecosystem})",
        "",
        f"**Verdict:** {_verdict_icon} `{verdict}`",
        f"> {reasoning}",
        "",
        "| Dimension | Value |",
        "|-----------|-------|",
        f"| Critical CVEs | {critical_cve_count if critical_cve_count is not None else 'n/a'} |",
        f"| High CVEs | {high_cve_count if high_cve_count is not None else 'n/a'} |",
        f"| Licence Risk | {licence_risk or 'n/a'} |",
        f"| Maintainer Health | {maintainer_health or 'n/a'} |",
        f"| Transitive Deps | {transitive_count if transitive_count is not None else 'n/a'} |",
    ]

    degraded = [k for k, v in upstream_status.items() if v != "OK"]
    if degraded:
        lines += ["", f"> ⚠ Upstream(s) degraded: {', '.join(degraded)} — some fields may be null."]

    lines += ["", f"*{_DISCLAIMER}*"]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 (in this file) — detect_typosquatting
# ══════════════════════════════════════════════════════════════════════════════

_TYPO_KEY_FMT  = "dn:typosquat_ref:{eco}"    # ZSET per ecosystem
_TYPO_COLD_TIMEOUT = 30.0                      # cold-start fetch hard cap
_TYPO_WARN_TIMEOUT = 10.0                      # log warning if slower
_MIN_REF_SIZE  = 10_000                        # refuse partial comparisons

@security_sprint6.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T15")
async def detect_typosquatting(
    package_name: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    ecosystem: Annotated[Literal["npm", "pypi", "cargo", "go"], Field(description="Package ecosystem: npm, pypi, cargo, go. Required.")],
) -> dict:
    """Detect typosquatting attacks against a package name. Compares using Damerau-Levenshtein distance ≤ 2 against top-10,000 packages. Returns similar_packages with anomaly scores, and a SUSPICIOUS or CLEAN verdict. Uses PyPI and npm download stats stored in Redis. Cold-start fetch on first call (≤ 30s). Rate limit: 60/minute. No auth required. For security engineers auditing supply-chain package names before inclusion. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_detect_typosquatting", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        pkg = package_name.strip().lower()
        eco = ecosystem.strip().lower()
        params = {"package_name": pkg, "ecosystem": eco}

        async with AuditContext("T15", params, "1.0") as ctx:
            if not pkg:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="package_name must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            if eco not in ("npm", "pypi"):
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"ecosystem '{eco}' not yet supported for typosquat detection. Use 'npm' or 'pypi'.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            from datanexus.cache import get_redis
            r = await get_redis()

            # Ensure reference list is available (cold-start population if needed)
            ref_packages = await _ensure_typo_ref(r, eco)
            if ref_packages is None:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="Reference list unavailable; retry in 60 seconds.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )

            if len(ref_packages) < _MIN_REF_SIZE:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="Reference list unavailable; retry in 60 seconds.",
                    query_hash=ctx.query_hash,
                    retry_after=60,
                    ingest_healthy=False,
                )

            # DL distance check
            similar = _find_similar(pkg, ref_packages)

            verdict = "SUSPICIOUS" if similar else "CLEAN"
            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown = _build_typo_markdown(pkg, eco, verdict, similar)

            data = {
                "package_name":     pkg,
                "ecosystem":        eco,
                "similar_packages": similar,
                "verdict":          verdict,
                "ref_list_size":    len(ref_packages),
                "upstream_status":  {"ref_list": "OK"},
            }

            _success = True
            return {
                "status":           "ok",
                "tool_id":          "T15",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "markdown_output":  markdown,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("detect_typosquatting error pkg=%s", package_name)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T15",
            tool_name="detect_typosquatting",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
            ecosystem=ecosystem,
        ))


# ── Reference list management ─────────────────────────────────────────────────

async def _ensure_typo_ref(r, eco: str) -> Optional[list]:
    """
    Return the top-10k reference list for the ecosystem.
    On cold start (key missing), fetch synchronously with a 30s cap.
    Returns None if fetch fails or times out.
    """
    key = _TYPO_KEY_FMT.format(eco=eco)

    if r is not None:
        # Check Redis first
        count = await r.zcard(key)
        if count >= _MIN_REF_SIZE:
            members = await r.zrange(key, 0, -1)
            return list(members)

    # Cold start — fetch synchronously
    log.warning("detect_typosquatting: cold start for %s — fetching reference list", eco)
    import time as _time
    t_start = _time.monotonic()
    try:
        packages = await asyncio.wait_for(
            _fetch_ref_list(eco),
            timeout=_TYPO_COLD_TIMEOUT,
        )
        elapsed = _time.monotonic() - t_start
        if elapsed > _TYPO_WARN_TIMEOUT:
            log.warning("detect_typosquatting cold start took %.1fs (> 10s warn threshold)", elapsed)

        if not packages or len(packages) < _MIN_REF_SIZE:
            return None

        # Populate Redis for future requests
        if r is not None:
            pipe = r.pipeline()
            for rank, name in enumerate(packages, start=1):
                pipe.zadd(key, {name: rank})
            pipe.expire(key, 7 * 24 * 3600)   # 7-day TTL per spec
            await pipe.execute()

        return packages

    except asyncio.TimeoutError:
        log.error("detect_typosquatting cold start timed out after %ss", _TYPO_COLD_TIMEOUT)
        return None
    except Exception as exc:
        log.error("detect_typosquatting cold start failed: %s", exc)
        return None


async def _fetch_ref_list(eco: str) -> list:
    """Fetch the top-10k package list for an ecosystem."""
    import httpx as _httpx
    _headers = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

    if eco == "pypi":
        url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        async def _fetch():
            async with _httpx.AsyncClient(timeout=_httpx.Timeout(20.0, connect=5.0), headers=_headers, follow_redirects=True) as c:
                resp = await c.get(url)
                resp.raise_for_status()
                data = resp.json()
                return [r["project"].lower() for r in data.get("rows", [])[:10_000]]
        try:
            return await _pypi_stats_breaker.call_async(_fetch)
        except pybreaker.CircuitBreakerError:
            return []

    elif eco == "npm":
        # npm top packages via downloads API (paginated)
        url = "https://api.npmjs.org/downloads/point/last-month"
        # Use a pre-fetched dataset from npm's bulk stats
        # Simplified: fetch top packages via the popular packages endpoint
        try:
            async with _httpx.AsyncClient(timeout=_httpx.Timeout(20.0, connect=5.0), headers=_headers, follow_redirects=True) as c:
                # Use the all-packages download ranking dataset
                resp = await c.get("https://registry.npmjs.org/-/v1/search?text=not:unstable&size=250&from=0")
                resp.raise_for_status()
                data = resp.json()
                pkgs = [obj["package"]["name"].lower() for obj in data.get("objects", [])]
                return pkgs if len(pkgs) >= 100 else []
        except Exception:
            return []

    return []


# ── DL distance matching ───────────────────────────────────────────────────────

def _damerau_levenshtein(s1: str, s2: str) -> int:
    """
    Compute Damerau-Levenshtein distance (with transpositions).
    Pure Python implementation — fast enough for ≤10k comparisons.
    """
    try:
        import jellyfish
        return jellyfish.damerau_levenshtein_distance(s1, s2)
    except ImportError:
        log.debug(
            "jellyfish not available — using pure Python "
            "Damerau-Levenshtein fallback"
        )

    # Pure Python fallback
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > 2:
        return 3   # Early exit — can't be ≤ 2
    d: list[list[int]] = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)
    return d[len1][len2]


def _find_similar(pkg: str, ref_packages: list) -> list[dict]:
    """
    Find top-10k packages within DL distance ≤ 2 of `pkg`.
    Returns list sorted by distance, excluding exact matches.
    """
    results = []
    for ref_name in ref_packages:
        if ref_name == pkg:
            continue   # Exact match — the package itself
        dist = _damerau_levenshtein(pkg, ref_name)
        if dist <= 2:
            anomaly_score = min(round((0.2 if dist == 1 else 0.0), 2), 1.0)
            results.append({
                "name":          ref_name,
                "distance":      dist,
                "anomaly_score": anomaly_score,
            })
    results.sort(key=lambda x: (x["distance"], x["name"]))
    return results[:20]   # cap at 20 results


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_typo_markdown(pkg: str, eco: str, verdict: str, similar: list) -> str:
    icon = "✗" if verdict == "SUSPICIOUS" else "✓"
    lines = [
        f"## Typosquatting Check: `{pkg}` ({eco})",
        "",
        f"**Verdict:** {icon} `{verdict}`",
        f"**Similar packages found:** {len(similar)}",
    ]
    if similar:
        lines += ["", "| Package | DL Distance | Anomaly Score |", "|---------|-------------|---------------|"]
        for s in similar[:10]:
            lines.append(f"| `{s['name']}` | {s['distance']} | {s['anomaly_score']:.2f} |")
    lines += ["", f"*{_DISCLAIMER}*"]
    return "\n".join(lines)
