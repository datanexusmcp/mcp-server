"""
datanexus/tools/t10_sprint8.py — Sprint 8B backend security depth.

New tools:
  audit_sbom_license_policy  — SBOM → PASS/WARN/BLOCK per org licence policy
  fetch_cve_watch_status     — polling inbox for all active CVE watches
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from pydantic import Field
from urllib.parse import quote

import httpx
from fastmcp import FastMCP

from datanexus.cache import get_redis
from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.request_context import api_key_var
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import fire_and_forget, track_tool_call
from datanexus.tools._sbom_utils import extract_components
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.t10_sprint8")

t10_sprint8 = FastMCP("datanexus-t10-sprint8")

_DISCLAIMER = (
    "Licence data sourced from deps.dev (Google). "
    "DataNexus does not warrant completeness. "
    "Verify with your legal team before making licence decisions."
)

_DEPS_DEV_URL  = "https://api.deps.dev/v3"
_HTTP_TIMEOUT  = httpx.Timeout(15.0, connect=5.0)
_HTTP_HEADERS  = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_LICENCE_TTL   = 3600  # 1 hour

_DEFAULT_POLICY = {
    "block": ["GPL-3.0", "AGPL-3.0"],
    "warn":  ["LGPL-2.1", "MPL-2.0", "BSD-4-Clause"],
    "allow": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
}

_DEPS_SYSTEM = {
    "pypi":    "PYPI",
    "npm":     "NPM",
    "maven":   "MAVEN",
    "go":      "GO",
    "cargo":   "CARGO",
    "nuget":   "NUGET",
}

_CVE_WATCH_PREFIX = "dn:cve_watch:"


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — audit_sbom_license_policy
# ══════════════════════════════════════════════════════════════════════════════

@t10_sprint8.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def audit_sbom_license_policy(
    sbom: Annotated[str, Field(description="CycloneDX or SPDX SBOM as JSON string. Required. 500 KB max.")],
    policy: Annotated[Optional[dict], Field(description="Policy dict with block/warn/allow arrays of SPDX licence IDs. Optional.")] = None,
) -> dict:
    """Audit a CycloneDX or SPDX SBOM against an SPDX licence policy and return a PASS/WARN/BLOCK verdict. sbom: Full SBOM as a JSON string — CycloneDX or SPDX format. Required. 500 KB max. policy: Optional dict with block/warn/allow arrays of exact SPDX licence identifiers (e.g. GPL-3.0, MIT). Defaults to block GPL-3.0 and AGPL-3.0, warn LGPL-2.1/MPL-2.0/BSD-4-Clause, allow MIT/Apache-2.0/BSD-2-Clause/BSD-3-Clause. No glob patterns — exact SPDX IDs only. Unlisted licences default to WARN. Returns verdict (PASS/WARN/BLOCK), blocked_packages, warned_packages, and the policy applied. Use security_audit_sbom_vulnerabilities for CVE auditing instead. Sources: deps.dev (Google). 1-hour cache per package. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_audit_sbom_license_policy", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        if len(sbom.encode()) > 512_000:
            return {
                "verdict": "ERROR",
                "error": "SBOM exceeds 500 KB size limit.",
                "blocked_packages": [],
                "warned_packages": [],
            }

        effective_policy = _merge_policy(policy)
        sbom_hash = hashlib.sha256(sbom.encode()).hexdigest()[:32]
        policy_hash = hashlib.sha256(json.dumps(effective_policy, sort_keys=True).encode()).hexdigest()[:16]
        params = {"sbom_hash": sbom_hash, "policy_hash": policy_hash}

        async with AuditContext("T10", params, "1.0") as ctx:
            try:
                components, fmt = extract_components(sbom)
            except ValueError as exc:
                return {
                    "verdict": "ERROR",
                    "error": f"Invalid SBOM format — expected CycloneDX or SPDX JSON. Detail: {exc}",
                    "blocked_packages": [],
                    "warned_packages": [],
                }

            if not components:
                return {
                    "verdict": "ERROR",
                    "error": "No parseable components found in SBOM.",
                    "blocked_packages": [],
                    "warned_packages": [],
                }

            sem = asyncio.Semaphore(10)
            licence_results = await asyncio.gather(
                *[_fetch_licence_for_component(comp, sem) for comp in components],
                return_exceptions=True,
            )

            blocked = []
            warned  = []
            for comp, lic_result in zip(components, licence_results):
                if isinstance(lic_result, Exception):
                    licences = []
                else:
                    licences = lic_result if lic_result else []

                if not licences:
                    warned.append({
                        "name":    comp["name"],
                        "version": comp["version"],
                        "licence": "UNKNOWN",
                        "reason":  "Licence could not be determined — manual review required",
                    })
                    continue

                for lic in licences:
                    verdict_for_lic = _apply_policy(lic, effective_policy)
                    if verdict_for_lic == "BLOCK":
                        blocked.append({
                            "name":    comp["name"],
                            "version": comp["version"],
                            "licence": lic,
                            "reason":  f"Licence {lic} is in the block list",
                        })
                    elif verdict_for_lic == "WARN":
                        warned.append({
                            "name":    comp["name"],
                            "version": comp["version"],
                            "licence": lic,
                            "reason":  (
                                f"Licence {lic} is in the warn list"
                                if lic in effective_policy.get("warn", [])
                                else f"Licence {lic} not in policy — manual review required"
                            ),
                        })

            if blocked:
                overall = "BLOCK"
            elif warned:
                overall = "WARN"
            else:
                overall = "PASS"

            data_as_of = datetime.now(timezone.utc).isoformat()
            _success = True
            return {
                "status":          "ok",
                "tool_id":         "T10",
                "verdict":         overall,
                "sbom_format":     fmt,
                "total_components": len(components),
                "blocked_packages": blocked,
                "warned_packages":  warned,
                "policy_applied":   effective_policy,
                "disclaimer":       _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as exc:
        _error_code = type(exc).__name__
        log.exception("audit_sbom_license_policy error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="audit_sbom_license_policy",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — fetch_cve_watch_status
# ══════════════════════════════════════════════════════════════════════════════

@t10_sprint8.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T10")
async def fetch_cve_watch_status(
    watch_ids: Annotated[list, Field(description="List of watch IDs to check e.g. ['watch-1','watch-2']. Required.")],
) -> dict:
    """Check all specified CVE watches for new events since your last poll. Returns only watches with new events, making it efficient to run on a schedule. watch_ids: List of watch IDs to check — same IDs used when creating watches with security_fetch_cve_watch. Required. Uses a per-user cursor (last_polled timestamp) stored in Redis. First call returns events from the last 30 days. Subsequent calls return only events newer than the last poll. Sources: Redis (existing watch data written by security_fetch_cve_watch). No external API calls — instant response. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_cve_watch_status", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        if not watch_ids:
            return {
                "status": "error",
                "error_code": "MISSING_PARAMS",
                "message": "watch_ids is required and must not be empty.",
            }

        clean_ids = [w.strip() for w in watch_ids if w and w.strip()]
        if not clean_ids:
            return {
                "status": "error",
                "error_code": "MISSING_PARAMS",
                "message": "watch_ids must contain at least one valid watch ID.",
            }

        params = {"watch_ids_hash": hashlib.sha256(json.dumps(sorted(clean_ids)).encode()).hexdigest()[:16]}

        async with AuditContext("T10", params, "1.0") as ctx:
            r = await get_redis()
            if not r:
                return {
                    "status": "error",
                    "error_code": "REDIS_UNAVAILABLE",
                    "message": "Watch status unavailable — Redis is not reachable.",
                }

            api_key_hash = api_key_var.get()
            cursor_key = f"dn:cve_watch:{api_key_hash or 'anon'}:_last_polled"
            now = datetime.now(timezone.utc)

            try:
                last_polled_str = await r.get(cursor_key)
                if last_polled_str:
                    last_polled = datetime.fromisoformat(last_polled_str)
                else:
                    last_polled = now - timedelta(days=30)
            except Exception as exc:
                log.warning("fetch_cve_watch_status: cursor read failed: %s", exc)
                last_polled = now - timedelta(days=30)

            watches_with_new = []
            total_watches = 0
            errors = []

            for wid in clean_ids:
                key = f"{_CVE_WATCH_PREFIX}{wid}"
                try:
                    watch_data = await r.hgetall(key)
                    if not watch_data:
                        continue
                    total_watches += 1
                    events_raw = watch_data.get("events", "[]")
                    try:
                        events = json.loads(events_raw) if events_raw else []
                    except json.JSONDecodeError:
                        events = []

                    new_events = []
                    for ev in events:
                        ev_date_str = ev.get("event_date", "")
                        try:
                            ev_dt = datetime.fromisoformat(ev_date_str)
                            if ev_dt > last_polled:
                                new_events.append({
                                    "cve_id":     ev.get("cve_id", ""),
                                    "event_type": ev.get("event_type", ""),
                                    "event_date": ev_date_str,
                                    "summary":    ev.get("summary", ""),
                                })
                        except (ValueError, TypeError):
                            continue

                    if new_events:
                        watches_with_new.append({
                            "watch_id":   wid,
                            "cve_ids":    json.loads(watch_data.get("cve_ids", "[]")),
                            "new_events": new_events,
                        })
                except Exception as exc:
                    log.warning("fetch_cve_watch_status: watch %s read failed: %s", wid, exc)
                    errors.append(wid)

            now_iso = now.isoformat()
            try:
                await r.set(cursor_key, now_iso, ex=90 * 24 * 3600)
            except Exception as exc:
                log.warning("fetch_cve_watch_status: cursor update failed: %s", exc)

            data_as_of = now_iso
            _success = True
            return {
                "status":               "ok",
                "tool_id":              "T10",
                "watches_with_new_events": watches_with_new,
                "total_watches_checked": total_watches,
                "last_polled":          last_polled.isoformat(),
                "polled_at":            now_iso,
                "errors":               errors,
                "disclaimer":           _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as exc:
        _error_code = type(exc).__name__
        log.exception("fetch_cve_watch_status error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T10",
            tool_name="fetch_cve_watch_status",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ── Internal helpers ──────────────────────────────────────────────────────────

def _merge_policy(user_policy: Optional[dict]) -> dict:
    """Merge user policy with defaults. User values override defaults."""
    if not user_policy:
        return _DEFAULT_POLICY.copy()
    return {
        "block": user_policy.get("block", _DEFAULT_POLICY["block"]),
        "warn":  user_policy.get("warn",  _DEFAULT_POLICY["warn"]),
        "allow": user_policy.get("allow", _DEFAULT_POLICY["allow"]),
    }


def _apply_policy(licence: str, policy: dict) -> str:
    """Return BLOCK/WARN/ALLOW for a single SPDX licence string."""
    if licence in policy.get("block", []):
        return "BLOCK"
    if licence in policy.get("warn", []):
        return "WARN"
    if licence in policy.get("allow", []):
        return "ALLOW"
    return "WARN"  # unlisted → WARN, not silent pass


async def _fetch_licence_for_component(comp: dict, sem: asyncio.Semaphore) -> list[str]:
    """Fetch SPDX licence(s) for one component. Returns [] on failure."""
    name    = comp.get("name", "")
    version = comp.get("version", "")
    eco     = comp.get("ecosystem", "")
    if not name or not eco:
        return []
    deps_system = _DEPS_SYSTEM.get(eco.lower(), eco.upper())
    url = (
        f"{_DEPS_DEV_URL}/systems/{deps_system}/packages/"
        f"{quote(name, safe='')}/versions/{quote(version or 'latest', safe='')}"
    )
    async with sem:
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                data = resp.json()
                return data.get("licenses", [])
        except Exception as exc:
            log.debug("_fetch_licence_for_component failed %s@%s: %s", name, version, exc)
            return []
