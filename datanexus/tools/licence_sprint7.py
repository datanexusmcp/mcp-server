"""
datanexus/tools/licence_sprint7.py — Sprint 7 licence intelligence tools.

Tools:
  fetch_licence_analysis       — plain-English licence explainer, risk_level, obligations
  audit_licence_compatibility  — COMPATIBLE/CONFLICT verdict for a set of packages or SPDX IDs

Static-first pattern: _licence_compat.STATIC_LICENCES checked before any HTTP call.
Circuit breaker: _spdx_breaker from _circuit_breakers.py.
Concurrency: asyncio.Semaphore(10) on package-name path (prevents 429 at 50 items).

All risk_level values assume proprietary/commercial use context (eng review D3).
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import pybreaker
from fastmcp import FastMCP

from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import track_tool_call
from datanexus.tools._circuit_breakers import _spdx_breaker
from datanexus.tools._licence_compat import get_compatibility, STATIC_LICENCES
from datanexus.tools._security_utils import _fetch_licence
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.licence_sprint7")

licence_sprint7 = FastMCP("DataNexus Licence Sprint7")

_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT      = httpx.Timeout(8.0, connect=5.0)
_SPDX_API     = "https://spdx.org/licenses/{id}.json"

_VALID_ECOSYSTEMS = {"pypi", "npm", "maven", "go", "cargo", "nuget", "rubygems"}

_DISCLAIMER = (
    "Licence information sourced from SPDX licence list and deps.dev. "
    "DataNexus does not provide legal advice. "
    "Consult qualified legal counsel before making licence compliance decisions."
)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — fetch_licence_analysis
# ══════════════════════════════════════════════════════════════════════════════

@licence_sprint7.tool()
@with_timeout
@verify_entitlement("T10")
async def fetch_licence_analysis(spdx_id: str) -> dict:
    """Understand any software licence in plain English. Returns obligations, permissions, limitations, risk level, and OSI/FSF status for any SPDX licence identifier. Static bundle covers top-50 common licences (no network call). Falls back to spdx.org API for rare identifiers. All risk levels assume proprietary/commercial use. Rate limit: 60/minute. No auth required. For security engineers and developers understanding what a licence allows before including a dependency. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_licence_analysis", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        spdx_clean = spdx_id.strip()
        params = {"spdx_id": spdx_clean}

        async with AuditContext("T10", params, "1.0") as ctx:
            if not spdx_clean:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="spdx_id must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            data_as_of = datetime.now(timezone.utc).isoformat()

            # ── 1. Static bundle (STATIC-FIRST — no network call) ─────────────
            if spdx_clean in STATIC_LICENCES:
                entry = STATIC_LICENCES[spdx_clean]
                result = {
                    "spdx_id":        spdx_clean,
                    "plain_english":  entry["plain_english"],
                    "risk_level":     entry["risk_level"],
                    "obligations":    entry["obligations"],
                    "permissions":    entry["permissions"],
                    "limitations":    entry["limitations"],
                    "osi_approved":   entry["osi_approved"],
                    "fsf_libre":      entry["fsf_libre"],
                    "tldr":           entry["tldr"],
                    "upstream_status": {"spdx_api": "N/A"},
                }
                _success = True
                return {
                    "status":           "ok",
                    "tool_id":          "T10",
                    "fetch_timestamp":  data_as_of,
                    "cache_hit":        True,
                    "staleness_notice": None,
                    "sha256_hash":      "",
                    "data":             result,
                    "disclaimer":       _DISCLAIMER,
                    **standard_response_fields(ctx.query_hash, data_as_of, True),
                }

            # ── 2. SPDX API fallback ──────────────────────────────────────────
            spdx_status = "ERROR"
            live_data: Optional[dict] = None

            async def _call_spdx() -> dict:
                async with httpx.AsyncClient(
                    timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
                ) as client:
                    resp = await client.get(_SPDX_API.format(id=spdx_clean))
                    if resp.status_code == 404:
                        return {}
                    resp.raise_for_status()
                    return resp.json()

            try:
                raw = await _spdx_breaker.call_async(_call_spdx)
                if raw:
                    spdx_status = "OK"
                    live_data = raw
                else:
                    spdx_status = "ERROR"
            except pybreaker.CircuitBreakerError:
                spdx_status = "CIRCUIT_OPEN"
            except Exception as exc:
                log.warning("fetch_licence_analysis spdx api error id=%s: %s", spdx_clean, exc)
                spdx_status = "ERROR"

            # ── 3. Build response from SPDX API data or DEGRADED ─────────────
            if live_data:
                is_osi  = live_data.get("isOsiApproved", None)
                is_fsf  = live_data.get("isFsfLibre", None)
                risk    = _classify_spdx_risk(spdx_clean, live_data)
                obligations, permissions, limitations = _extract_spdx_obligations(live_data)
                plain, tldr = _build_plain_english(spdx_clean, risk, live_data)

                result = {
                    "spdx_id":        spdx_clean,
                    "plain_english":  plain,
                    "risk_level":     risk,
                    "obligations":    obligations,
                    "permissions":    permissions,
                    "limitations":    limitations,
                    "osi_approved":   is_osi,
                    "fsf_libre":      is_fsf,
                    "tldr":           tldr,
                    "upstream_status": {"spdx_api": spdx_status},
                }
                _success = True
                return {
                    "status":           "ok",
                    "tool_id":          "T10",
                    "fetch_timestamp":  data_as_of,
                    "cache_hit":        False,
                    "staleness_notice": None,
                    "sha256_hash":      "",
                    "data":             result,
                    "disclaimer":       _DISCLAIMER,
                    **standard_response_fields(ctx.query_hash, data_as_of, True),
                }

            # ── 4. DEGRADED — not in bundle AND API unavailable/404 ───────────
            result = {
                "spdx_id":        spdx_clean,
                "plain_english":  None,
                "risk_level":     "UNKNOWN",
                "obligations":    [],
                "permissions":    [],
                "limitations":    [],
                "osi_approved":   None,
                "fsf_libre":      None,
                "tldr":           "Licence identifier not recognized. Verify at spdx.org/licenses.",
                "upstream_status": {"spdx_api": spdx_status},
            }
            _success = True
            return {
                "status":           "ok",
                "tool_id":          "T10",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": "Licence identifier not recognized — results may be incomplete.",
                "sha256_hash":      "",
                "data":             result,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("fetch_licence_analysis error spdx_id=%s", spdx_id)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T10",
            tool_name="fetch_licence_analysis",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


def _classify_spdx_risk(spdx_id: str, raw: dict) -> str:
    """Map an SPDX licence to risk_level for proprietary/commercial use."""
    sid = spdx_id.upper()
    if "AGPL" in sid:
        return "INCOMPATIBLE"
    if "GPL" in sid and "LGPL" not in sid:
        return "STRONG_COPYLEFT"
    if any(x in sid for x in ("LGPL", "MPL", "EUPL", "CDDL", "CPL", "EPL")):
        return "COPYLEFT"
    is_osi = raw.get("isOsiApproved", False)
    if is_osi:
        return "PERMISSIVE"
    return "UNKNOWN"


def _extract_spdx_obligations(raw: dict) -> tuple[list, list, list]:
    """Extract obligations, permissions, limitations from SPDX JSON (best-effort)."""
    return (
        ["Comply with licence terms as stated at spdx.org/licenses"],
        ["Commercial use" if raw.get("isOsiApproved") else "Non-commercial use"],
        ["No liability", "No warranty"],
    )


def _build_plain_english(spdx_id: str, risk_level: str, raw: dict) -> tuple[str, str]:
    """Build plain_english and tldr for an SPDX-API-fetched licence."""
    name = raw.get("name", spdx_id)
    if risk_level == "INCOMPATIBLE":
        plain = (
            f"{name} is incompatible with proprietary/commercial software distribution. "
            "INCOMPATIBLE for proprietary SaaS. "
            "Compatible with open source projects — see SPDX for details."
        )
        tldr = f"INCOMPATIBLE for proprietary/commercial use. Open source: see plain_english."
    elif risk_level == "STRONG_COPYLEFT":
        plain = (
            f"{name} requires all derivative works to be distributed under the same licence "
            "with full source code. Cannot be combined with proprietary software."
        )
        tldr = f"Strong copyleft. All derivative works must share source under {spdx_id}."
    elif risk_level == "COPYLEFT":
        plain = (
            f"{name} is a weak/file-level copyleft licence. "
            "Modifications to the licensed files must be shared, but combination with "
            "proprietary code may be permitted."
        )
        tldr = f"Weak copyleft. Modifications to licensed files must be shared."
    else:
        plain = (
            f"{name} is a permissive open source licence. "
            "Commercial use is generally permitted with attribution."
        )
        tldr = f"Permissive. Commercial use allowed with attribution."
    return plain, tldr


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — audit_licence_compatibility
# ══════════════════════════════════════════════════════════════════════════════

@licence_sprint7.tool()
@with_timeout
@verify_entitlement("T10")
async def audit_licence_compatibility(
    packages: Optional[list] = None,
    spdx_ids: Optional[list] = None,
) -> dict:
    """Audit the licence compatibility of your entire dependency list. Input package names (with ecosystem) or SPDX IDs; get a COMPATIBLE/CONFLICT verdict with specific conflicting pairs and recommended action. Uses static SPDX compatibility table — no network call for spdx_ids path. Package path resolves licences from deps.dev (max 10 concurrent). Max 50 items. Rate limit: 60/minute. No auth required. For developers and compliance teams auditing open source licence risk before shipping. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_audit_licence_compatibility", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        params = {"packages": bool(packages), "spdx_ids": bool(spdx_ids)}

        async with AuditContext("T10", params, "1.0") as ctx:
            data_as_of = datetime.now(timezone.utc).isoformat()

            # ── Input validation ──────────────────────────────────────────────
            has_packages = packages is not None and len(packages) > 0
            has_spdx     = spdx_ids  is not None and len(spdx_ids)  > 0

            if has_packages and has_spdx:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="Provide either 'packages' or 'spdx_ids', not both.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            if not has_packages and not has_spdx:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="Provide either 'packages' (list of {package_name, ecosystem}) or 'spdx_ids' (list of SPDX ID strings). Both are empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            items = packages if has_packages else spdx_ids
            if len(items) > 50:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="Maximum 50 items per call.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # ── Path A: package names → resolve SPDX IDs via deps.dev ────────
            spdx_api_status = "N/A"
            failed_packages: list[str] = []
            resolved_ids: list[str] = []

            if has_packages:
                # Validate ecosystems first
                for p in packages:
                    eco = (p.get("ecosystem") or "").lower()
                    if eco not in _VALID_ECOSYSTEMS:
                        return error_response(
                            error_code=ErrorCode.VALIDATION_ERROR,
                            message=f"Unrecognized ecosystem '{eco}'. Valid: {sorted(_VALID_ECOSYSTEMS)}",
                            query_hash=ctx.query_hash,
                            retry_after=0,
                            ingest_healthy=True,
                        )

                sem = asyncio.Semaphore(10)

                async def _resolve_one(p: dict):
                    async with sem:
                        return await _fetch_licence(p["package_name"], p["ecosystem"])

                results = await asyncio.gather(
                    *[_resolve_one(p) for p in packages],
                    return_exceptions=True,
                )

                for pkg, res in zip(packages, results):
                    pkg_label = f"{pkg['package_name']}@{pkg['ecosystem']}"
                    if isinstance(res, Exception):
                        failed_packages.append(pkg_label)
                    else:
                        lics = res.get("licences", [])
                        if lics:
                            resolved_ids.extend(lics)
                        else:
                            failed_packages.append(pkg_label)
                        status = res.get("status", "ERROR")
                        if status != "N/A":
                            spdx_api_status = status if spdx_api_status == "N/A" else spdx_api_status

                if not resolved_ids and failed_packages:
                    return error_response(
                        error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                        message=f"Could not resolve licences for any package. Failed: {failed_packages}",
                        query_hash=ctx.query_hash,
                        retry_after=30,
                        ingest_healthy=False,
                    )

            # ── Path B: spdx_ids directly (static bundle only, no HTTP) ──────
            else:
                resolved_ids = [s.strip() for s in spdx_ids]

            # ── Compatibility check ───────────────────────────────────────────
            conflicts = []
            all_compatible = True
            any_unknown = False
            combined_obligations: list[str] = []
            copyleft_found: Optional[tuple[str, str]] = None  # (pkg, licence)

            for i in range(len(resolved_ids)):
                for j in range(i + 1, len(resolved_ids)):
                    a, b = resolved_ids[i], resolved_ids[j]
                    result = get_compatibility(a, b)
                    if result == "CONFLICT":
                        all_compatible = False
                        pkg_label = (packages[i]["package_name"] if has_packages and i < len(packages) else a)
                        conflicts.append({
                            "licence_a": a,
                            "licence_b": b,
                            "reason": _conflict_reason(a, b),
                            "package": pkg_label,
                        })
                    elif result == "UNKNOWN":
                        any_unknown = True

            # Gather obligations from static bundle
            for spdx_id in resolved_ids:
                if spdx_id in STATIC_LICENCES:
                    for ob in STATIC_LICENCES[spdx_id].get("obligations", []):
                        if ob not in combined_obligations:
                            combined_obligations.append(ob)
                    risk = STATIC_LICENCES[spdx_id].get("risk_level", "")
                    if risk in ("COPYLEFT", "STRONG_COPYLEFT") and copyleft_found is None:
                        pkg_name = resolved_ids[resolved_ids.index(spdx_id)] if not has_packages else (
                            packages[resolved_ids.index(spdx_id)]["package_name"]
                            if resolved_ids.index(spdx_id) < len(packages) else spdx_id
                        )
                        copyleft_found = (pkg_name, spdx_id)

            # ── Verdict ───────────────────────────────────────────────────────
            if conflicts:
                compatibility = "CONFLICT"
            elif any_unknown:
                compatibility = "UNKNOWN"
            else:
                compatibility = "COMPATIBLE"

            # ── Recommended action ────────────────────────────────────────────
            if compatibility == "CONFLICT":
                c = conflicts[0]
                recommended_action = (
                    f"Remove or replace {c['package']} ({c['licence_b']}), "
                    f"or obtain a commercial licence for it."
                )
            elif compatibility == "COMPATIBLE" and copyleft_found:
                pkg_n, lic_n = copyleft_found
                recommended_action = (
                    f"Compatible. Note: {pkg_n} uses {lic_n} — "
                    f"ensure you comply with share-alike obligations."
                )
            elif compatibility == "COMPATIBLE":
                recommended_action = "All licences are compatible. Attribution only."
            else:
                a = resolved_ids[0] if resolved_ids else "?"
                b = resolved_ids[1] if len(resolved_ids) > 1 else "?"
                recommended_action = (
                    f"Compatibility undetermined for {a} + {b}. Consult legal."
                )

            data = {
                "compatibility":        compatibility,
                "conflicts":            conflicts,
                "combined_obligations": combined_obligations,
                "recommended_action":   recommended_action,
                "resolved_spdx_ids":    resolved_ids,
                "upstream_status": {
                    "spdx_api":       spdx_api_status,
                    "failed_packages": failed_packages,
                },
            }

            _success = True
            return {
                "status":           "ok",
                "tool_id":          "T10",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      "",
                "data":             data,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("audit_licence_compatibility error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T10",
            tool_name="audit_licence_compatibility",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


def _conflict_reason(a: str, b: str) -> str:
    """Return a human-readable reason for a known conflict pair."""
    pair = frozenset({a, b})
    if "GPL-2.0-only" in pair and "Apache-2.0" in pair:
        return "GPL-2.0-only is incompatible with Apache-2.0 (ASF position 2007)."
    if "GPL-3.0-only" in pair and "Apache-2.0" in pair:
        return "GPL-3.0-only is incompatible with Apache-2.0 (ASF position 2007)."
    if any("AGPL" in x for x in pair):
        return "AGPL requires all network-accessible code to be open-sourced — incompatible with proprietary SaaS."
    if "GPL-2.0-only" in pair and "GPL-3.0-only" in pair:
        return "GPL-2.0-only and GPL-3.0-only are not mutually compatible (version incompatibility)."
    if "EUPL-1.1" in pair and any("GPL-3.0" in x for x in pair):
        return "EUPL-1.1 is incompatible with GPL-3.0 (different copyleft terms)."
    return f"{a} and {b} have incompatible licence terms."
