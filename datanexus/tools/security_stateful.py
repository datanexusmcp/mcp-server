"""
datanexus/tools/security_stateful.py — Sprint 6 stateful security tools.

Tools:
  fetch_cve_watch     — persistent CVE watchlist (create/check/delete)
  audit_sbom_continuous — continuous SBOM monitoring (register/check/deregister)

Redis key schema (dn: prefix):
  dn:cve_watch:{watch_id}    — Hash (watch data)
  dn:cve_watch_ids           — SET  (watch index)
  dn:sbom_watch:{watch_id}   — Hash (SBOM watch data)
  dn:sbom_watch_ids          — SET  (SBOM watch index)

Scheduler: see datanexus/schedulers.py
  _cve_refresh_loop()   — 24h cycle, reads dn:cve_watch_ids via SMEMBERS
  _sbom_refresh_loop()  — 24h cycle, reads dn:sbom_watch_ids via SMEMBERS

Hard rules:
  - NO asyncio.create_task inside tool handlers for scheduler work
  - NO Redis SCAN — use SMEMBERS on the SET index
  - NO push notifications — user pulls by calling check
  - SBOM input limit: 500 KB (checked BEFORE parsing)
  - SBOM hash: SHA-256 only
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Literal, List, Optional

from pydantic import Field

from fastmcp import FastMCP

from datanexus.cache import get_redis
from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import track_tool_call
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.security_stateful")

security_stateful = FastMCP("DataNexus Security Stateful")

_DISCLAIMER = (
    "CVE data sourced from NVD, CISA KEV, and FIRST EPSS public APIs. "
    "DataNexus does not warrant completeness. "
    "Verify with your security team before making remediation decisions."
)

_TTL_90D = 90 * 24 * 3600   # 90 days in seconds
_CVE_WATCH_PREFIX = "dn:cve_watch:"
_CVE_WATCH_INDEX  = "dn:cve_watch_ids"
_SBOM_WATCH_PREFIX = "dn:sbom_watch:"
_SBOM_WATCH_INDEX  = "dn:sbom_watch_ids"
_SBOM_SIZE_LIMIT   = 512_000   # 500 KB


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — fetch_cve_watch
# ══════════════════════════════════════════════════════════════════════════════

@security_stateful.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@with_timeout
@verify_entitlement("T13")
async def fetch_cve_watch(
    watch_id: Annotated[str, Field(description="Unique watch identifier to create, check, or delete. Required.")],
    cve_ids: Annotated[List[str], Field(description="List of CVE IDs to watch e.g. ['CVE-2021-44228']. Required for create.")],
    action: Annotated[Literal["create", "check", "delete"], Field(description="Action: create, check, or delete the watchlist. Required.")],
) -> dict:
    """Persistent CVE watchlist. Create once, check anytime for new events since your last visit — patch releases, KEV listings, PoC publications, exploitation detected. Uses Redis for persistence, NVD + CISA KEV + EPSS for daily background refresh. Returns has_new_events, events (list), call_back_in="24h" on check. Rate limit: 60/minute. No auth required. For security engineers tracking CVE exposure over time. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_cve_watch", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        wid     = watch_id.strip()
        cve_ids = [c.strip().upper() for c in (cve_ids or []) if c.strip()]
        params  = {"watch_id": wid, "action": action, "cve_ids": cve_ids}

        async with AuditContext("T13", params, "1.0") as ctx:
            if not wid:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="watch_id must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            r = await get_redis()
            if r is None:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="Redis unavailable — stateful watch requires Redis.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                )

            data_as_of = datetime.now(timezone.utc).isoformat()

            if action == "create":
                data = await _handle_cve_create(r, wid, cve_ids, data_as_of)
            elif action == "check":
                data = await _handle_cve_check(r, wid, data_as_of)
            elif action == "delete":
                data = await _handle_cve_delete(r, wid)
            else:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"Unknown action '{action}'. Use create, check, or delete.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            _success = True
            return {
                "status":          "ok",
                "tool_id":         "T13",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     "",
                "data":            data,
                "markdown_output": _build_cve_watch_markdown(data, wid, action),
                "disclaimer":      _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("fetch_cve_watch error watch_id=%s action=%s", watch_id, action)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T13",
            tool_name="fetch_cve_watch",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ── CVE watch action handlers ──────────────────────────────────────────────────

async def _create_cve_watch(r, watch_id: str, cve_ids: List[str]) -> None:
    """
    Create a CVE watch entry in Redis.
    Exported for use by the PRE-4 integration test.
    """
    key       = f"{_CVE_WATCH_PREFIX}{watch_id}"
    now_iso   = datetime.now(timezone.utc).isoformat()
    pipe      = r.pipeline()
    pipe.hset(key, mapping={
        "created_at":   now_iso,
        "last_checked": now_iso,
        "cve_ids":      json.dumps(cve_ids),
        "events":       json.dumps([]),
    })
    pipe.sadd(_CVE_WATCH_INDEX, watch_id)
    pipe.expire(key, _TTL_90D)
    await pipe.execute()


async def _delete_cve_watch(r, watch_id: str) -> None:
    """
    Delete a CVE watch entry from Redis.
    Exported for use by the PRE-4 integration test.
    """
    key  = f"{_CVE_WATCH_PREFIX}{watch_id}"
    pipe = r.pipeline()
    pipe.delete(key)
    pipe.srem(_CVE_WATCH_INDEX, watch_id)
    await pipe.execute()


async def _handle_cve_create(r, watch_id: str, cve_ids: List[str], now_iso: str) -> dict:
    key = f"{_CVE_WATCH_PREFIX}{watch_id}"
    exists = await r.exists(key)
    if exists:
        return {
            "action":    "create",
            "watch_id":  watch_id,
            "created":   False,
            "message":   f"Watch '{watch_id}' already exists. Use action=check to poll.",
            "cve_ids":   cve_ids,
        }

    await _create_cve_watch(r, watch_id, cve_ids)
    return {
        "action":   "create",
        "watch_id": watch_id,
        "created":  True,
        "message":  f"Watching {len(cve_ids)} CVE(s). Call action=check after 24h for updates.",
        "cve_ids":  cve_ids,
        "call_back_in": "24h",
    }


async def _handle_cve_check(r, watch_id: str, now_iso: str) -> dict:
    key = f"{_CVE_WATCH_PREFIX}{watch_id}"
    watch = await r.hgetall(key)
    if not watch:
        return {
            "action":   "check",
            "watch_id": watch_id,
            "found":    False,
            "message":  f"No watch found for '{watch_id}'. Create it first with action=create.",
        }

    events_raw = watch.get("events", "[]")
    try:
        all_events = json.loads(events_raw)
    except json.JSONDecodeError:
        all_events = []

    last_checked = watch.get("last_checked", "")
    new_events = [
        e for e in all_events
        if e.get("detected_at", "") > last_checked
    ]

    # Update last_checked + refresh TTL
    pipe = r.pipeline()
    pipe.hset(key, "last_checked", now_iso)
    pipe.expire(key, _TTL_90D)
    await pipe.execute()

    return {
        "action":          "check",
        "watch_id":        watch_id,
        "found":           True,
        "has_new_events":  bool(new_events),
        "events":          new_events,
        "all_events_count": len(all_events),
        "call_back_in":    "24h",
        "cve_ids":         json.loads(watch.get("cve_ids", "[]")),
    }


async def _handle_cve_delete(r, watch_id: str) -> dict:
    key    = f"{_CVE_WATCH_PREFIX}{watch_id}"
    exists = await r.exists(key)
    await _delete_cve_watch(r, watch_id)
    return {
        "action":   "delete",
        "watch_id": watch_id,
        "deleted":  bool(exists),
        "message":  f"Watch '{watch_id}' {'deleted' if exists else 'not found (already deleted)'}.",
    }


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_cve_watch_markdown(data: dict, watch_id: str, action: str) -> str:
    lines = [f"## CVE Watch: `{watch_id}` — {action.upper()}", ""]

    if action == "create":
        status = "✓ Created" if data.get("created") else "⚠ Already exists"
        lines += [f"**Status:** {status}", f"**CVEs:** {', '.join(data.get('cve_ids', []))}"]
        if data.get("call_back_in"):
            lines.append(f"**Call back in:** {data['call_back_in']}")

    elif action == "check":
        if not data.get("found"):
            lines.append(f"⚠ Watch not found — create first with `action=create`.")
        else:
            has_new = data.get("has_new_events", False)
            new_events = data.get("events", [])
            lines += [
                f"**New events:** {'Yes' if has_new else 'None since last check'}",
                f"**Call back in:** {data.get('call_back_in', '24h')}",
            ]
            if new_events:
                lines += ["", "**Events:**"]
                for e in new_events[:10]:
                    lines.append(f"  - `{e.get('cve_id', '?')}` — {e.get('event_type', '?')} ({e.get('detected_at', '?')[:10]})")

    elif action == "delete":
        icon = "✓" if data.get("deleted") else "~"
        lines.append(f"**Status:** {icon} {data.get('message', '')}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — audit_sbom_continuous
# ══════════════════════════════════════════════════════════════════════════════

_SBOM_DISCLAIMER = (
    "SBOM vulnerability data sourced from OSV.dev. "
    "DataNexus does not warrant completeness. "
    "Verify critical findings with your security team before remediation."
)


@security_stateful.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@with_timeout
@verify_entitlement("T14")
async def audit_sbom_continuous(
    sbom: Annotated[str, Field(description="CycloneDX or SPDX SBOM as JSON string. Required for register action.")],
    watch_id: Annotated[str, Field(description="Unique watch identifier for this SBOM watch. Required.")],
    action: Annotated[Literal["register", "check", "deregister"], Field(description="Action: register, check, or deregister the SBOM watch. Required.")],
) -> dict:
    """Persistent SBOM watch. Register once, check anytime for new CVEs affecting your dependency snapshot. Silent permanent watch — CycloneDX and SPDX supported. Uses OSV.dev for vulnerability lookup, Redis for persistence with 90-day TTL. Supports CycloneDX 1.4/1.5 and SPDX 2.3 JSON. Input size limit: 500 KB. Returns go_no_go signal on register; new_findings on check. Rate limit: 10/minute. No auth required. For DevSecOps teams monitoring production dependency exposure. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_audit_sbom_continuous", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        wid    = watch_id.strip()
        params = {"watch_id": wid, "action": action}

        async with AuditContext("T14", params, "1.0") as ctx:
            if not wid:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="watch_id must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # ── Size limit — check BEFORE any parsing ──────────────────────
            if action in ("register",) and sbom:
                raw_bytes = sbom.encode("utf-8", errors="replace")
                if len(raw_bytes) > _SBOM_SIZE_LIMIT:
                    return error_response(
                        error_code=ErrorCode.VALIDATION_ERROR,
                        message=(
                            "SBOM exceeds 500 KB. For large SBOMs, compress or split by "
                            "component group. SBOM URL input is a Sprint 8 candidate."
                        ),
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                    )

            r = await get_redis()
            if r is None:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                    message="Redis unavailable — stateful SBOM watch requires Redis.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                )

            data_as_of = datetime.now(timezone.utc).isoformat()

            if action == "register":
                data = await _handle_sbom_register(r, wid, sbom, data_as_of)
            elif action == "check":
                data = await _handle_sbom_check(r, wid, data_as_of)
            elif action == "deregister":
                data = await _handle_sbom_deregister(r, wid)
            else:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message=f"Unknown action '{action}'. Use register, check, or deregister.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            _success = True
            return {
                "status":           "ok",
                "tool_id":          "T14",
                "fetch_timestamp":  data_as_of,
                "cache_hit":        False,
                "staleness_notice": None,
                "sha256_hash":      data.get("sbom_hash", ""),
                "data":             data,
                "markdown_output":  _build_sbom_markdown(data, wid, action),
                "disclaimer":       _SBOM_DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        log.exception("audit_sbom_continuous error watch_id=%s action=%s", watch_id, action)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T14",
            tool_name="audit_sbom_continuous",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ── SBOM action handlers ───────────────────────────────────────────────────────

async def _handle_sbom_register(r, watch_id: str, sbom: str, now_iso: str) -> dict:
    """Parse SBOM, extract PURLs, run initial audit, store in Redis."""
    sbom_hash = hashlib.sha256(sbom.encode()).hexdigest()

    # Parse SBOM → extract PURLs
    try:
        purls, fmt = _extract_purls(sbom)
    except Exception as exc:
        return {
            "action":    "register",
            "watch_id":  watch_id,
            "registered": False,
            "error":     f"SBOM parse failed: {exc}",
            "sbom_hash": sbom_hash,
        }

    # Initial vulnerability audit against OSV.dev
    audit_results = await _audit_purls(purls)

    critical_count = sum(1 for r2 in audit_results if r2.get("critical_cve_count", 0) > 0)
    go_no_go = "NO_GO" if critical_count > 0 else "GO"

    key  = f"{_SBOM_WATCH_PREFIX}{watch_id}"
    pipe = r.pipeline()
    pipe.hset(key, mapping={
        "registered_at":    now_iso,
        "last_audit":       now_iso,
        "sbom_hash":        sbom_hash,
        "sbom_format":      fmt,
        "component_list":   json.dumps(purls),
        "last_audit_results": json.dumps(audit_results),
        "new_findings":     json.dumps([]),
    })
    pipe.sadd(_SBOM_WATCH_INDEX, watch_id)
    pipe.expire(key, _TTL_90D)
    await pipe.execute()

    return {
        "action":           "register",
        "watch_id":         watch_id,
        "registered":       True,
        "sbom_hash":        sbom_hash,
        "sbom_format":      fmt,
        "component_count":  len(purls),
        "go_no_go":         go_no_go,
        "critical_issues":  critical_count,
        "audit_results":    audit_results[:10],   # top 10 in response
        "message":          f"Watching {len(purls)} components. Call action=check after 7 days for new CVEs.",
        "call_back_in":     "7d",
    }


async def _handle_sbom_check(r, watch_id: str, now_iso: str) -> dict:
    key = f"{_SBOM_WATCH_PREFIX}{watch_id}"
    data = await r.hgetall(key)
    if not data:
        return {
            "action":   "check",
            "watch_id": watch_id,
            "found":    False,
            "message":  f"No SBOM watch found for '{watch_id}'. Register first.",
        }

    try:
        new_findings = json.loads(data.get("new_findings", "[]"))
    except json.JSONDecodeError:
        new_findings = []

    # Refresh TTL + update last_audit
    pipe = r.pipeline()
    pipe.hset(key, mapping={
        "last_audit":   now_iso,
        "new_findings": json.dumps([]),   # clear after delivery
    })
    pipe.expire(key, _TTL_90D)
    await pipe.execute()

    return {
        "action":          "check",
        "watch_id":        watch_id,
        "found":           True,
        "has_new_findings": bool(new_findings),
        "new_findings":    new_findings,
        "sbom_hash":       data.get("sbom_hash", ""),
        "component_count": len(json.loads(data.get("component_list", "[]"))),
        "call_back_in":    "7d",
    }


async def _handle_sbom_deregister(r, watch_id: str) -> dict:
    key    = f"{_SBOM_WATCH_PREFIX}{watch_id}"
    exists = await r.exists(key)
    pipe   = r.pipeline()
    pipe.delete(key)
    pipe.srem(_SBOM_WATCH_INDEX, watch_id)
    await pipe.execute()
    return {
        "action":      "deregister",
        "watch_id":    watch_id,
        "deregistered": bool(exists),
        "message":     f"SBOM watch '{watch_id}' {'deregistered' if exists else 'not found (already removed)'}.",
    }


# ── SBOM parsing (delegated to _sbom_utils — Sprint 8B) ───────────────────────

from datanexus.tools._sbom_utils import extract_purls as _extract_purls_new


def _extract_purls(sbom_str: str) -> tuple[list[str], str]:
    """
    Parse a CycloneDX or SPDX JSON SBOM and return (purls, format_name).
    Raises ValueError if format is unrecognised or no components found.
    """
    try:
        raw = json.loads(sbom_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    # Detect format
    if raw.get("bomFormat") == "CycloneDX":
        return _extract_cyclonedx_purls(raw), "CycloneDX"
    if raw.get("spdxVersion", "").startswith("SPDX-"):
        return _extract_spdx_purls(sbom_str), "SPDX"

    raise ValueError("Unrecognised SBOM format — expected CycloneDX or SPDX JSON.")


def _extract_cyclonedx_purls(raw: dict) -> list[str]:
    """Extract PURLs from a CycloneDX BOM dict using cyclonedx-python-lib."""
    from cyclonedx.model.bom import Bom
    bom = Bom.from_json(data=raw)
    return [str(c.purl) for c in bom.components if c.purl]


def _extract_spdx_purls(sbom_str: str) -> list[str]:
    """Extract PURLs from an SPDX 2.3 JSON SBOM using spdx-tools."""
    import tempfile, os
    from spdx_tools.spdx.parser.parse_anything import parse_file

    with tempfile.NamedTemporaryFile(
        suffix=".spdx.json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        f.write(sbom_str)
        fname = f.name

    try:
        doc = parse_file(fname)
        purls = []
        for pkg in doc.packages:
            for ref in pkg.external_references:
                if "purl" in str(ref.reference_type).lower():
                    purls.append(ref.locator)
        return purls
    finally:
        try:
            os.unlink(fname)
        except OSError:
            pass


# ── OSV audit ─────────────────────────────────────────────────────────────────

async def _audit_purls(purls: list[str]) -> list[dict]:
    """
    Run OSV.dev batch audit for a list of PURLs.
    Returns list of {purl, critical_cve_count, high_cve_count, vuln_ids, status}.
    """
    from datanexus.tools._security_utils import _fetch_vulns

    async def _audit_one(purl: str) -> dict:
        # Parse PURL into (package, ecosystem, version)
        try:
            parts = _parse_purl(purl)
            if not parts:
                return {"purl": purl, "critical_cve_count": 0, "high_cve_count": 0, "vuln_ids": [], "status": "UNSUPPORTED_PURL"}
            pkg, eco, ver = parts
            result = await _fetch_vulns(pkg, eco, ver or "")
            result["purl"] = purl
            return result
        except Exception as exc:
            return {"purl": purl, "critical_cve_count": 0, "high_cve_count": 0, "vuln_ids": [], "status": "ERROR", "error": str(exc)}

    results = await asyncio.gather(*[_audit_one(p) for p in purls[:50]], return_exceptions=True)
    return [
        r if not isinstance(r, Exception) else {"purl": "", "status": "ERROR"}
        for r in results
    ]


def _parse_purl(purl: str) -> Optional[tuple]:
    """
    Parse a Package URL into (name, ecosystem, version).
    Supports pkg:pypi/*, pkg:npm/*, pkg:cargo/*, pkg:golang/*.
    Returns None for unsupported types.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    # Format: pkg:type/[namespace/]name@version
    rest = purl[4:]   # strip "pkg:"
    slash = rest.find("/")
    if slash < 0:
        return None
    ptype = rest[:slash].lower()
    remainder = rest[slash + 1:]

    # Split version
    at = remainder.rfind("@")
    if at >= 0:
        name    = remainder[:at]
        version = remainder[at + 1:]
    else:
        name    = remainder
        version = ""

    # Handle namespace/name (e.g. npm scoped packages)
    # Take only the last segment as name for plain packages
    eco_map = {"pypi": "pypi", "npm": "npm", "cargo": "cargo", "golang": "go", "maven": "maven"}
    ecosystem = eco_map.get(ptype)
    if not ecosystem:
        return None

    # Strip qualifiers (? suffix) and subpath (# suffix)
    version = version.split("?")[0].split("#")[0]
    name    = name.split("?")[0].split("#")[0]

    return name, ecosystem, version


# ── Markdown builder ───────────────────────────────────────────────────────────

def _build_sbom_markdown(data: dict, watch_id: str, action: str) -> str:
    lines = [f"## SBOM Watch: `{watch_id}` — {action.upper()}", ""]

    if action == "register":
        gng = data.get("go_no_go", "?")
        icon = "✓" if gng == "GO" else "✗"
        lines += [
            f"**Decision:** {icon} `{gng}`",
            f"**Components:** {data.get('component_count', 0)}",
            f"**Critical Issues:** {data.get('critical_issues', 0)}",
            f"**Format:** {data.get('sbom_format', 'unknown')}",
            f"**SHA-256:** `{data.get('sbom_hash', '')[:16]}...`",
        ]
        if data.get("call_back_in"):
            lines.append(f"**Call back in:** {data['call_back_in']}")

    elif action == "check":
        if not data.get("found"):
            lines.append("⚠ SBOM watch not found — register first.")
        else:
            has_new = data.get("has_new_findings", False)
            findings = data.get("new_findings", [])
            lines += [
                f"**New findings:** {'Yes' if has_new else 'None since last audit'}",
                f"**Call back in:** {data.get('call_back_in', '7d')}",
            ]
            if findings:
                lines += ["", "**New Findings:**"]
                for f2 in findings[:10]:
                    lines.append(f"  - `{f2.get('purl', '?')}` — {f2.get('vuln_id', '?')}")

    elif action == "deregister":
        icon = "✓" if data.get("deregistered") else "~"
        lines.append(f"**Status:** {icon} {data.get('message', '')}")

    lines += ["", f"*{_SBOM_DISCLAIMER}*"]
    return "\n".join(lines)
