"""
datanexus/tools/t07.py — T07 Domain & DNS Intelligence tool.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 4, T07 entry

Exactly 4 data functions. Shared infrastructure tools (report_feedback,
report_mcpize_link) are registered ONCE in main.py — NOT here.

Data sources:
  Primary:   IANA RDAP — rdap.iana.org — no key, no auth
             Modern structured replacement for WHOIS
  Secondary: crt.sh Certificate Transparency — crt.sh/json — no key
  Supporting: Cloudflare DNS over HTTPS — cloudflare-dns.com/dns-query — no key

Hard stop (absolute — never violate):
  Do NOT add active probing, address enumeration, known-weakness checks,
  force-based lookups, or any active interrogation beyond passive DNS
  and RDAP registry queries. Security tooling territory — ToS risk on all sources.

Cache TTL: 14400 seconds (4 hours)
Circuit breaker source IDs: "iana_rdap", "crt_sh", "cloudflare_doh"
"""

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastmcp import FastMCP

from datanexus.core.audit import (
    AuditContext,
    make_params_hash,
    standard_response_fields,
)
from datanexus.core.cache import (
    compute_payload_hash,
    get_cached,
    set_cached,
)
from datanexus.core.circuit_breaker import (
    get_staleness_notice,
    is_tripped,
    record_failure_sync,
    record_success_sync,
)
from datanexus.core.schema import ErrorCode, error_response
from payment.entitlement import verify_entitlement
from datanexus.core.timeout import with_timeout
from datanexus.analytics import track_tool_call, track_tool_error

log = logging.getLogger("datanexus.tools.t07")

mcp = FastMCP("datanexus-t07")

# ── Constants ─────────────────────────────────────────────────────────────────

T07_TTL = 14400  # 4 hours — spec requirement

DISCLAIMER = (
    "Domain and DNS data sourced from IANA RDAP, crt.sh Certificate "
    "Transparency, and Cloudflare DNS. DataNexus does not warrant "
    "completeness. Registration data reflects public registry records only."
)

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CRT_SH_URL         = "https://crt.sh/"
CF_DOH_URL         = "https://cloudflare-dns.com/dns-query"

_HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_HEADERS      = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_DOH_HEADERS  = {**_HEADERS, "Accept": "application/dns-json"}

# Bootstrap cache TTL: 24 hours (updated infrequently by IANA)
_BOOTSTRAP_TTL = 86400

# Sprint 4 — new upstream constants
_HT_REVERSE_IP_URL  = "https://api.hackertarget.com/reverseiplookup/"
_HT_QUOTA_TTL       = 25 * 3600    # 25h — covers daily reset window
_HT_DAILY_LIMIT     = 100
_SUBDOMAINS_TTL     = 24 * 3600    # 24h — spec requirement
_REVERSE_IP_TTL     = 24 * 3600    # 24h — spec requirement
_CRT_SUBDOMAINS_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# DKIM selectors to check (10 common ones per spec)
_DKIM_SELECTORS = [
    "mail", "google", "selector1", "selector2", "dkim",
    "k1", "k2", "amazonses", "mandrill", "mailchimp",
]

# Canary patterns — same set as DataNexusResponse._no_injection
_INJECTION_PATTERNS = (
    "ignore previous",
    "you are now",
    "system:",
    "<script",
    "<iframe",
    "forget your instructions",
    "new persona",
    "disregard",
)


def _validate_canary(markdown_output: str) -> None:
    """Raise ValueError if any injection pattern is found in markdown_output."""
    lower = markdown_output.lower()
    for pattern in _INJECTION_PATTERNS:
        if pattern.lower() in lower:
            raise ValueError(
                f"Canary: injection pattern '{pattern}' detected in "
                "markdown_output — response blocked."
            )


def _incr_calls(tool_id: str) -> None:
    """Increment datanexus:calls:{tool_id}:{today} telemetry counter."""
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    r = _get_redis()
    if r is None:
        return
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"datanexus:calls:{tool_id}:{today}"
    try:
        r.incr(key)
        r.expire(key, 35 * 86400)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 1 — fetch_domain_rdap
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T07")
async def fetch_domain_rdap(domain: str) -> dict:
    """Fetch domain registration details via IANA RDAP (the modern structured replacement for WHOIS). Read-only. No side effects. Idempotent. domain: Domain name without protocol e.g. example.com not https://example.com. Required. Returns registrar, registration date, expiry date, nameservers, and registrant info where publicly available. Use this when you need registration metadata. Use domain_fetch_ssl_certificate_chain instead when you need certificate history. Use domain_fetch_dns_records instead when you need live DNS resolution. Verified source: IANA RDAP. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_fetch_domain_rdap", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        domain_clean = domain.strip().lower().lstrip("www.").lstrip("https://").lstrip("http://")
        # Strip any trailing path
        domain_clean = domain_clean.split("/")[0]
        params = {"domain": domain_clean}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")
            phash = make_params_hash(params)

            cached = get_cached("T07", phash)
            if cached:
                ctx.set_cache_hit(True)
                log.info("t07.fetch_domain_rdap cache_hit domain=%s", domain_clean)
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

            if is_tripped("iana_rdap"):
                archive = get_cached("T07", phash + "_archive")
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
                return {
                    "tool_id":         "T07",
                    "data":            archive or {},
                    "markdown_output": "IANA RDAP temporarily unavailable. "
                                       "Serving archived data.",
                    "staleness_notice": get_staleness_notice(
                        "iana_rdap",
                        (archive or {}).get("data_as_of", "unknown"),
                    ),
                    "disclaimer":  DISCLAIMER,
                    "cache_hit":   False,
                    "sha256_hash": "",
                    **standard_response_fields(ctx.query_hash, "", False),
                }

            try:
                result = await _fetch_rdap(domain_clean)
            except httpx.TimeoutException:
                record_failure_sync("iana_rdap")
                return error_response(
                    ErrorCode.UPSTREAM_TIMEOUT,
                    "IANA RDAP timed out. Try again shortly.",
                    ctx.query_hash, 30, False,
                )
            except Exception:
                record_failure_sync("iana_rdap")
                log.exception("t07.fetch_domain_rdap error domain=%s", domain_clean)
                return error_response(
                    ErrorCode.INTERNAL_ERROR,
                    "An internal error occurred. Please try again.",
                    ctx.query_hash, 0, False,
                )

            if not result:
                return error_response(
                    ErrorCode.NOT_FOUND,
                    f"Domain '{domain_clean}' not found in RDAP registry. "
                    "The domain may not be registered or the registry may be unsupported.",
                    ctx.query_hash, 0, True,
                )

            raw_bytes    = json.dumps(result).encode()
            payload_hash = compute_payload_hash(raw_bytes)
            data_as_of   = datetime.now(timezone.utc).isoformat()
            markdown     = _build_rdap_markdown(result, domain_clean)
            _validate_canary(markdown)

            payload = {
                "tool_id":         "T07",
                "source_url":      f"https://rdap.iana.org/domain/{domain_clean}",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            result,
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            set_cached("T07", phash, payload, T07_TTL)
            set_cached("T07", phash + "_archive", payload, T07_TTL * 6)
            ctx.set_cache_hit(False)
            record_success_sync("iana_rdap")

            log.info("t07.fetch_domain_rdap ok domain=%s registrar=%s",
                     domain_clean, result.get("registrar", ""))
            _out = {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="fetch_domain_rdap",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — fetch_ssl_certificate_chain
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T07")
async def fetch_ssl_certificate_chain(domain: str) -> dict:
    """Fetch SSL certificate history for a domain from Certificate Transparency logs. Read-only. No side effects. Idempotent. domain: Domain name without protocol e.g. github.com. Required. Does not support IP addresses or wildcard domains. Returns issuer, subject, validity period, and Subject Alternative Names for each logged cert. Use this to detect unexpected certificate issuance or audit certificate history. Use domain_fetch_domain_rdap instead when you need registration data not certificate data. Verified source: crt.sh Certificate Transparency. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_fetch_ssl_certificate_chain", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        domain_clean = domain.strip().lower().lstrip("www.").split("/")[0]
        params = {"domain": domain_clean, "query_type": "cert_chain"}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")
            phash = make_params_hash(params)

            cached = get_cached("T07", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        True,
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            if is_tripped("crt_sh"):
                _error_code = "CIRCUIT_OPEN"
                return error_response(
                    ErrorCode.CIRCUIT_OPEN,
                    "crt.sh Certificate Transparency temporarily unavailable. Try again later.",
                    ctx.query_hash, 300, False,
                )

            try:
                certs = await _fetch_crt_sh(domain_clean, limit=10)
            except httpx.TimeoutException:
                record_failure_sync("crt_sh")
                return error_response(
                    ErrorCode.UPSTREAM_TIMEOUT,
                    "crt.sh timed out. Try again shortly.",
                    ctx.query_hash, 30, False,
                )
            except Exception:
                record_failure_sync("crt_sh")
                log.exception("t07.fetch_ssl_certificate_chain error domain=%s", domain_clean)
                return error_response(
                    ErrorCode.INTERNAL_ERROR,
                    "An internal error occurred. Please try again.",
                    ctx.query_hash, 0, False,
                )

            data_as_of   = datetime.now(timezone.utc).isoformat()
            raw_bytes    = json.dumps(certs).encode()
            payload_hash = compute_payload_hash(raw_bytes)
            markdown     = _build_cert_markdown(certs, domain_clean)
            _validate_canary(markdown)

            payload = {
                "tool_id":         "T07",
                "source_url":      f"https://crt.sh/?q={domain_clean}&output=json",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            {"domain": domain_clean, "certificates": certs, "count": len(certs)},
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            set_cached("T07", phash, payload, T07_TTL)
            ctx.set_cache_hit(False)
            record_success_sync("crt_sh")

            log.info("t07.fetch_ssl_certificate_chain ok domain=%s certs=%d",
                     domain_clean, len(certs))
            _out = {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="fetch_ssl_certificate_chain",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_dns_records
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T07")
async def fetch_dns_records(domain: str, record_types: list) -> dict:
    """Fetch current DNS records for a domain via Cloudflare DNS over HTTPS. Read-only. No side effects. Idempotent. domain: Domain name without protocol e.g. cloudflare.com. Required. record_types: List of DNS record types to fetch. Required. Valid values: A, AAAA, MX, TXT, NS, CNAME, SOA. Example: ["A", "MX", "TXT"]. Returns all matching records currently in effect. Use this when you need live DNS resolution. Use domain_fetch_domain_rdap instead when you need registration metadata not DNS records. Verified source: Cloudflare DoH. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_fetch_dns_records", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        domain_clean  = domain.strip().lower().split("/")[0]
        # Normalise and deduplicate record types — uppercase, max 10
        valid_types = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV"}
        types_clean = list({t.upper() for t in (record_types or ["A"]) if t.upper() in valid_types})[:10]
        if not types_clean:
            types_clean = ["A"]

        params = {"domain": domain_clean, "record_types": sorted(types_clean)}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")
            phash = make_params_hash(params)

            cached = get_cached("T07", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        True,
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            if is_tripped("cloudflare_doh"):
                _error_code = "CIRCUIT_OPEN"
                return error_response(
                    ErrorCode.CIRCUIT_OPEN,
                    "Cloudflare DNS temporarily unavailable. Try again later.",
                    ctx.query_hash, 300, False,
                )

            try:
                records = await _fetch_dns_records(domain_clean, types_clean)
            except httpx.TimeoutException:
                record_failure_sync("cloudflare_doh")
                return error_response(
                    ErrorCode.UPSTREAM_TIMEOUT,
                    "Cloudflare DNS timed out. Try again shortly.",
                    ctx.query_hash, 30, False,
                )
            except Exception:
                record_failure_sync("cloudflare_doh")
                log.exception("t07.fetch_dns_records error domain=%s", domain_clean)
                return error_response(
                    ErrorCode.INTERNAL_ERROR,
                    "An internal error occurred. Please try again.",
                    ctx.query_hash, 0, False,
                )

            data_as_of   = datetime.now(timezone.utc).isoformat()
            raw_bytes    = json.dumps(records).encode()
            payload_hash = compute_payload_hash(raw_bytes)
            markdown     = _build_dns_markdown(records, domain_clean, types_clean)
            _validate_canary(markdown)

            types_found = [t for t, recs in records.items() if recs]
            payload = {
                "tool_id":         "T07",
                "source_url":      CF_DOH_URL,
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            {"domain": domain_clean, "records": records, "types_found": types_found},
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            set_cached("T07", phash, payload, T07_TTL)
            ctx.set_cache_hit(False)
            record_success_sync("cloudflare_doh")

            log.info("t07.fetch_dns_records ok domain=%s types=%s",
                     domain_clean, types_found)
            _out = {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="fetch_dns_records",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — fetch_domain_history
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T07")
async def fetch_domain_history(domain: str) -> dict:
    """Fetch historical SSL certificate issuance for a domain from Certificate Transparency logs. Read-only. No side effects. Idempotent. domain: Domain name without protocol e.g. example.com. Required. Returns all past certificates with issuer, validity dates, and SANs in reverse chronological order. Use this to detect domain hijacking or audit unexpected historical certificate issuance. Use domain_fetch_ssl_certificate_chain instead when you only need the current certificate chain. Verified source: crt.sh Certificate Transparency. 4-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_fetch_domain_history", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        domain_clean = domain.strip().lower().lstrip("www.").split("/")[0]
        params = {"domain": domain_clean, "query_type": "history"}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")
            phash = make_params_hash(params)

            cached = get_cached("T07", phash)
            if cached:
                ctx.set_cache_hit(True)
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        True,
                    ),
                    "cache_hit": True,
                }
                _success = True
                _cache_hit = True
                return _out

            if is_tripped("crt_sh"):
                _error_code = "CIRCUIT_OPEN"
                return error_response(
                    ErrorCode.CIRCUIT_OPEN,
                    "crt.sh Certificate Transparency temporarily unavailable. Try again later.",
                    ctx.query_hash, 300, False,
                )

            try:
                # Broader wildcard query to capture all subdomains' historical certs
                history = await _fetch_crt_sh(f"%.{domain_clean}", limit=50)
                if not history:
                    # Fallback to exact domain
                    history = await _fetch_crt_sh(domain_clean, limit=50)
            except httpx.TimeoutException:
                record_failure_sync("crt_sh")
                return error_response(
                    ErrorCode.UPSTREAM_TIMEOUT,
                    "crt.sh timed out. Try again shortly.",
                    ctx.query_hash, 30, False,
                )
            except Exception:
                record_failure_sync("crt_sh")
                log.exception("t07.fetch_domain_history error domain=%s", domain_clean)
                return error_response(
                    ErrorCode.INTERNAL_ERROR,
                    "An internal error occurred. Please try again.",
                    ctx.query_hash, 0, False,
                )

            data_as_of   = datetime.now(timezone.utc).isoformat()
            raw_bytes    = json.dumps(history).encode()
            payload_hash = compute_payload_hash(raw_bytes)
            markdown     = _build_history_markdown(history, domain_clean)
            _validate_canary(markdown)

            payload = {
                "tool_id":         "T07",
                "source_url":      f"https://crt.sh/?q=%.{domain_clean}&output=json",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     payload_hash,
                "data":            {"domain": domain_clean, "certificate_events": history, "count": len(history)},
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            set_cached("T07", phash, payload, T07_TTL)
            ctx.set_cache_hit(False)
            record_success_sync("crt_sh")

            log.info("t07.fetch_domain_history ok domain=%s events=%d",
                     domain_clean, len(history))
            _out = {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = bool(_out.get("cache_hit", False))
            return _out
    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="fetch_domain_history",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 5 — fetch_subdomains  (Sprint 4)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T07")
async def fetch_subdomains(domain: str) -> dict:
    """Enumerate subdomains for a domain via Certificate Transparency logs. Read-only. No side effects. Idempotent. domain: Domain name without protocol e.g. anthropic.com. Required. Returns deduplicated list of known subdomains from crt.sh CT logs. crt.sh is a free replacement for SecurityTrails subdomain enumeration ($200/month). Results are cached 24h — second call returns in under 500ms. First call may be slower (crt.sh is 5-30s). Circuit breaker trips after 3 timeouts or 5xx errors within 600s. Verified source: crt.sh Certificate Transparency. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_fetch_subdomains", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        domain_clean = domain.strip().lower().lstrip("www.").split("/")[0]
        params = {"domain": domain_clean, "query_type": "subdomains"}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")

            # ── 1. Cache-first (datanexus:subdomains:{domain}, TTL 24h) ──────────
            # get_cached("subdomains", domain_clean) → key datanexus:subdomains:{domain}
            cached = get_cached("subdomains", domain_clean)
            if cached:
                ctx.set_cache_hit(True)
                _cache_hit = True
                _success = True
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                return _out

            # ── 2. Circuit breaker ────────────────────────────────────────────────
            if is_tripped("crt_sh"):
                ctx.set_error(ErrorCode.CIRCUIT_OPEN)
                _error_code = "CIRCUIT_OPEN"
                return error_response(
                    error_code=ErrorCode.CIRCUIT_OPEN,
                    message="crt.sh temporarily unavailable, try again in 15 minutes.",
                    query_hash=ctx.query_hash,
                    retry_after=900,
                    ingest_healthy=False,
                    upstream="crt.sh",
                    retryable=True,
                )

            # ── 3. Live fetch from crt.sh (30s timeout) ───────────────────────────
            try:
                async with httpx.AsyncClient(
                    timeout=_CRT_SUBDOMAINS_TIMEOUT,
                    headers=_HEADERS,
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(
                        CRT_SH_URL,
                        params={"q": f"%.{domain_clean}", "output": "json"},
                    )
                    if resp.status_code in (429, 500, 502, 503, 504):
                        record_failure_sync("crt_sh")
                        return error_response(
                            error_code=ErrorCode.UPSTREAM_UNAVAILABLE,
                            message=f"crt.sh returned HTTP {resp.status_code}. Try again later.",
                            query_hash=ctx.query_hash,
                            retry_after=60,
                            ingest_healthy=False,
                            upstream="crt.sh",
                            retryable=True,
                        )
                    resp.raise_for_status()
                    try:
                        raw_data = resp.json()
                    except Exception:
                        raw_data = []
            except httpx.TimeoutException:
                record_failure_sync("crt_sh")
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="crt.sh timed out (>30s). Try again — result will be cached on success.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                    upstream="crt.sh",
                    retryable=True,
                )
            except Exception:
                record_failure_sync("crt_sh")
                log.exception("t07.fetch_subdomains error domain=%s", domain_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                    upstream="crt.sh",
                    retryable=True,
                )

            record_success_sync("crt_sh")

            # Deduplicate, sort, strip wildcards
            seen: set = set()
            subdomains = []
            if isinstance(raw_data, list):
                for entry in raw_data:
                    name_val = entry.get("name_value", "") or entry.get("common_name", "")
                    for name in name_val.split("\n"):
                        name = name.strip().lower()
                        if not name or name.startswith("*") or name == domain_clean:
                            continue
                        if name.endswith(f".{domain_clean}") and name not in seen:
                            seen.add(name)
                            subdomains.append(name)
            subdomains = sorted(subdomains)

            data_as_of = datetime.now(timezone.utc).isoformat()
            latency_ms = int((time.monotonic() - _t0) * 1000)
            result = {
                "domain":     domain_clean,
                "subdomains": subdomains,
                "count":      len(subdomains),
                "sources":    ["crt.sh"],
                "status":     "fresh",
                "latency_ms": latency_ms,
            }
            markdown = _build_subdomains_markdown(result)
            _validate_canary(markdown)

            payload = {
                "tool_id":         "T07",
                "source_url":      f"https://crt.sh/?q=%.{domain_clean}&output=json",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     compute_payload_hash(json.dumps(result).encode()),
                "data":            result,
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            # Store in datanexus:subdomains:{domain} (TTL 24h)
            set_cached("subdomains", domain_clean, payload, _SUBDOMAINS_TTL)
            ctx.set_cache_hit(False)

            log.info("t07.fetch_subdomains ok domain=%s count=%d latency_ms=%d",
                     domain_clean, len(subdomains), latency_ms)
            _out = {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            _cache_hit = False
            return _out

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="fetch_subdomains",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 6 — check_email_security  (Sprint 4)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T07")
async def check_email_security(domain: str) -> dict:
    """Assess email security posture for a domain: SPF, DMARC, and DKIM. Read-only. No side effects. Idempotent. domain: Domain name without protocol e.g. google.com. Required. Returns scored assessment of SPF policy, DMARC policy, and DKIM selector presence. Each component scored 0-10; overall grade A-F. SPF -all = 10, ~all = 7, ?all = 4, none = 2, +all = 0. DMARC p=reject = 10, quarantine = 7, none = 4, absent = 0 (bonus +1 for rua set, capped at 10). DKIM: any selector found = 10, none found = 0. Checks 10 common DKIM selectors in parallel. Verified source: Cloudflare DoH. No cache (live DNS). If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_check_email_security", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        domain_clean = domain.strip().lower().split("/")[0]
        params = {"domain": domain_clean, "query_type": "email_security"}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")

            if is_tripped("cloudflare_doh"):
                _error_code = "CIRCUIT_OPEN"
                return error_response(
                    error_code=ErrorCode.CIRCUIT_OPEN,
                    message="Cloudflare DNS temporarily unavailable. Try again later.",
                    query_hash=ctx.query_hash,
                    retry_after=300,
                    ingest_healthy=False,
                    upstream="cloudflare-dns.com",
                    retryable=True,
                )

            # Fetch SPF, DMARC, and DKIM selectors concurrently
            try:
                spf_task   = _fetch_dns_records(domain_clean, ["TXT"])
                dmarc_task = _fetch_dns_records(f"_dmarc.{domain_clean}", ["TXT"])
                dkim_task  = _fetch_dkim_selectors(domain_clean, _DKIM_SELECTORS)

                spf_records, dmarc_records, dkim_found = await asyncio.gather(
                    spf_task, dmarc_task, dkim_task, return_exceptions=True,
                )
            except Exception:
                record_failure_sync("cloudflare_doh")
                log.exception("t07.check_email_security error domain=%s", domain_clean)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                    upstream="cloudflare-dns.com",
                    retryable=True,
                )

            # Handle gather exceptions (treat as no records)
            if isinstance(spf_records, Exception):
                spf_records = {}
            if isinstance(dmarc_records, Exception):
                dmarc_records = {}
            if isinstance(dkim_found, Exception):
                dkim_found = []

            # ── SPF scoring ───────────────────────────────────────────────────
            spf_txt_records = spf_records.get("TXT", []) if isinstance(spf_records, dict) else []
            spf_record = next(
                (r["data"] for r in spf_txt_records if "v=spf1" in r.get("data", "").lower()),
                None,
            )
            spf_score, spf_policy = _score_spf(spf_record)

            # ── DMARC scoring ─────────────────────────────────────────────────
            dmarc_txt_records = dmarc_records.get("TXT", []) if isinstance(dmarc_records, dict) else []
            dmarc_record = next(
                (r["data"] for r in dmarc_txt_records if "v=dmarc1" in r.get("data", "").lower()),
                None,
            )
            dmarc_score, dmarc_policy, dmarc_rua = _score_dmarc(dmarc_record)

            # ── DKIM scoring ──────────────────────────────────────────────────
            dkim_selectors = dkim_found if isinstance(dkim_found, list) else []
            dkim_score = 10 if dkim_selectors else 0
            dkim_note  = (
                "" if dkim_selectors
                else "no common selectors found — DKIM may use a non-standard selector not checked"
            )

            # ── Overall grade ─────────────────────────────────────────────────
            overall_score = (spf_score + dmarc_score + dkim_score) / 3.0
            overall_grade = _score_to_grade(overall_score)

            record_success_sync("cloudflare_doh")

            assessment = {
                "domain":    domain_clean,
                "spf":       {
                    "present": spf_record is not None,
                    "policy":  spf_policy,
                    "score":   spf_score,
                    "record":  (spf_record or "")[:200],
                },
                "dmarc":     {
                    "present": dmarc_record is not None,
                    "policy":  dmarc_policy,
                    "rua":     dmarc_rua,
                    "score":   dmarc_score,
                    "record":  (dmarc_record or "")[:200],
                },
                "dkim":      {
                    "selectors_found": dkim_selectors,
                    "score":           dkim_score,
                    "note":            dkim_note,
                },
                "overall_score": round(overall_score, 2),
                "overall_grade": overall_grade,
            }

            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown   = _build_email_security_markdown(assessment)
            _validate_canary(markdown)

            out = {
                "tool_id":         "T07",
                "source_url":      CF_DOH_URL,
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     compute_payload_hash(json.dumps(assessment).encode()),
                "data":            assessment,
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
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
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="check_email_security",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 7 — fetch_reverse_ip  (Sprint 4)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T07")
async def fetch_reverse_ip(domain_or_ip: str) -> dict:
    """Find domains co-hosted on the same IP address (reverse IP lookup). Read-only. No side effects. Idempotent. domain_or_ip: Domain name (e.g. shared.dreamhost.com) or IPv4 address (e.g. 1.2.3.4). Required. If a domain is given, it is first resolved to its IPv4 A record. IPv6-only domains are not supported. Returns list of co-hosted domains on the same IP. Useful for identifying shared hosting risk and mapping corporate infrastructure. Daily quota guard: 100 calls/day free tier. Verified source: HackerTarget API. 24-hour cache. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="domain_fetch_reverse_ip", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    _cache_hit = False
    try:
        raw_input = domain_or_ip.strip()
        params    = {"domain_or_ip": raw_input}

        async with AuditContext("T07", params, "1.0") as ctx:
            _incr_calls("T07")

            # ── Resolve domain to IPv4 if needed ─────────────────────────────────
            _IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            if _IPV4_RE.match(raw_input):
                ip = raw_input
                ip_note = ""
            else:
                domain_clean = raw_input.lower().lstrip("www.").split("/")[0]
                try:
                    dns_result = await _fetch_dns_records(domain_clean, ["A", "AAAA"])
                except Exception:
                    dns_result = {}

                a_records    = dns_result.get("A", []) if isinstance(dns_result, dict) else []
                aaaa_records = dns_result.get("AAAA", []) if isinstance(dns_result, dict) else []

                if not a_records and aaaa_records:
                    return error_response(
                        error_code=ErrorCode.IPV6_NOT_SUPPORTED,
                        message=(
                            "Reverse IP lookup requires IPv4; "
                            "this domain only has AAAA records."
                        ),
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                        upstream="hackertarget.com",
                        retryable=False,
                    )
                if not a_records:
                    return error_response(
                        error_code=ErrorCode.NOT_FOUND,
                        message=f"No A records found for '{domain_clean}'.",
                        query_hash=ctx.query_hash,
                        retry_after=0,
                        ingest_healthy=True,
                        upstream="cloudflare-dns.com",
                        retryable=False,
                    )
                ip = a_records[0]["data"].strip()
                ip_note = (
                    f"domain has {len(a_records)} A records, using first"
                    if len(a_records) > 1 else ""
                )

            # ── Cache check (datanexus:ht:ip:{ip}, TTL 24h) ──────────────────────
            cached = get_cached("ht:ip", ip)
            if cached:
                ctx.set_cache_hit(True)
                _cache_hit = True
                _success = True
                _out = {
                    **cached,
                    **standard_response_fields(
                        ctx.query_hash,
                        cached.get("data_as_of", ""),
                        cached.get("ingest_healthy", True),
                    ),
                    "cache_hit": True,
                }
                return _out

            # ── Quota guard (Redis counter datanexus:ht:daily_count:{YYYY-MM-DD}) ─
            day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            from datanexus.core.cache import _get_redis as _cache_redis
            _r = _cache_redis()
            quota_exceeded = False
            if _r is not None:
                try:
                    count_key = f"datanexus:ht:daily_count:{day_key}"
                    current   = _r.get(count_key)
                    if current is not None and int(current) >= _HT_DAILY_LIMIT:
                        quota_exceeded = True
                except Exception:
                    pass

            if quota_exceeded:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_RATE_LIMITED,
                    message=(
                        "HackerTarget daily quota reached (100/day). "
                        "Try again tomorrow."
                    ),
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                    upstream="hackertarget.com",
                    retryable=False,
                )

            # ── Live fetch from HackerTarget (plain-text response) ────────────────
            try:
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True,
                ) as client:
                    resp = await client.get(
                        _HT_REVERSE_IP_URL,
                        params={"q": ip},
                    )
                    if resp.status_code == 429:
                        return error_response(
                            error_code=ErrorCode.UPSTREAM_RATE_LIMITED,
                            message="HackerTarget rate limit hit. Try again later.",
                            query_hash=ctx.query_hash,
                            retry_after=3600,
                            ingest_healthy=True,
                            upstream="hackertarget.com",
                            retryable=True,
                        )
                    resp.raise_for_status()
                    raw_text = resp.text.strip()
            except httpx.TimeoutException:
                return error_response(
                    error_code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="HackerTarget timed out. Try again shortly.",
                    query_hash=ctx.query_hash,
                    retry_after=30,
                    ingest_healthy=False,
                    upstream="hackertarget.com",
                    retryable=True,
                )
            except Exception:
                log.exception("t07.fetch_reverse_ip error ip=%s", ip)
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="An internal error occurred. Please try again.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                    upstream="hackertarget.com",
                    retryable=True,
                )

            # Parse newline-separated plain-text domain list
            domains = [
                line.strip() for line in raw_text.splitlines()
                if line.strip() and not line.strip().startswith("error")
            ]

            # Increment daily quota counter after successful parse
            if _r is not None:
                try:
                    count_key = f"datanexus:ht:daily_count:{day_key}"
                    _r.incr(count_key)
                    _r.expire(count_key, _HT_QUOTA_TTL)
                except Exception:
                    pass

            result = {
                "ip":      ip,
                "domains": domains,
                "count":   len(domains),
                "source":  "hackertarget.com",
                "note":    ip_note,
            }
            data_as_of = datetime.now(timezone.utc).isoformat()
            markdown   = _build_reverse_ip_markdown(result)
            _validate_canary(markdown)

            payload = {
                "tool_id":         "T07",
                "source_url":      f"{_HT_REVERSE_IP_URL}?q={ip}",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": None,
                "sha256_hash":     compute_payload_hash(json.dumps(result).encode()),
                "data":            result,
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  True,
            }

            # Store by IP (datanexus:ht:ip:{ip}, TTL 24h)
            set_cached("ht:ip", ip, payload, _REVERSE_IP_TTL)
            ctx.set_cache_hit(False)

            log.info("t07.fetch_reverse_ip ok ip=%s domains=%d", ip, len(domains))
            _out = {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}
            _success = True
            return _out

    except Exception as e:
        _error_code = getattr(e, "error_code", type(e).__name__)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T07",
            tool_name="fetch_reverse_ip",
            success=_success,
            latency_ms=_ms,
            cache_hit=_cache_hit,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# UPSTREAM FETCH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def _get_rdap_bootstrap() -> dict:
    bootstrap = get_cached("T07", "rdap_bootstrap")
    if bootstrap:
        return bootstrap
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True
    ) as client:
        resp = await client.get(RDAP_BOOTSTRAP_URL)
        resp.raise_for_status()
        bootstrap = resp.json()
    set_cached("T07", "rdap_bootstrap", bootstrap, _BOOTSTRAP_TTL)
    return bootstrap


def _find_rdap_url(tld: str, bootstrap: dict) -> str:
    """Return the first RDAP base URL for a given TLD from bootstrap data."""
    for tlds, urls in bootstrap.get("services", []):
        if tld.lower() in [t.lower() for t in tlds]:
            return urls[0].rstrip("/")
    # Unknown TLD — use rdap.org universal lookup
    return "https://rdap.org"


async def _fetch_rdap(domain: str) -> Optional[dict]:
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain

    try:
        bootstrap = await _get_rdap_bootstrap()
        base_url  = _find_rdap_url(tld, bootstrap)
    except Exception:
        base_url = "https://rdap.org"

    url = f"{base_url}/domain/{domain}"
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True
    ) as client:
        resp = await client.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        raw = resp.json()

    return _normalise_rdap(raw, domain)


def _normalise_rdap(raw: dict, domain: str) -> dict:
    """Extract structured fields from a raw RDAP domain response."""
    # Events: registration, expiration, last changed
    events: dict[str, str] = {}
    for ev in raw.get("events", []):
        action = ev.get("eventAction", "")
        date   = ev.get("eventDate", "")
        if action and date:
            events[action] = date[:10]  # date part only (YYYY-MM-DD)

    # Entities: registrar and registrant
    registrar   = ""
    registrant  = ""
    for entity in raw.get("entities", []):
        roles = entity.get("roles", [])
        name  = ""
        vcard = entity.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    name = str(prop[3])
                    break
        if not name:
            name = entity.get("handle", "")
        if "registrar" in roles and not registrar:
            registrar = name
        if "registrant" in roles and not registrant:
            registrant = name

    # Nameservers
    nameservers = [
        ns.get("ldhName", "") for ns in raw.get("nameservers", [])
        if ns.get("ldhName")
    ]

    # Status
    status = raw.get("status", [])
    if isinstance(status, str):
        status = [status]

    return {
        "domain":            domain,
        "handle":            raw.get("handle", ""),
        "status":            status,
        "registrar":         registrar,
        "registrant":        registrant,
        "registration_date": events.get("registration", ""),
        "expiry_date":       events.get("expiration", ""),
        "last_changed":      events.get("last changed", events.get("last update of RDAP database", "")),
        "nameservers":       nameservers,
        "source":            "IANA RDAP",
    }


async def _fetch_crt_sh(query: str, limit: int = 10) -> list:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),  # crt.sh can be slow; was 20s
        headers=_HEADERS,
        follow_redirects=True,
    ) as client:
        resp = await client.get(
            CRT_SH_URL,
            params={"q": query, "output": "json"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        try:
            data = resp.json()
        except Exception:
            return []

    if not isinstance(data, list):
        return []

    # Deduplicate by certificate serial / subject and limit
    seen_ids: set = set()
    certs = []
    for entry in data:
        cert_id = entry.get("id") or entry.get("serial_number", "")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)
        certs.append({
            "id":           entry.get("id", ""),
            "logged_at":    (entry.get("logged_at") or "")[:10],
            "not_before":   (entry.get("not_before") or "")[:10],
            "not_after":    (entry.get("not_after") or "")[:10],
            "common_name":  entry.get("common_name", ""),
            "issuer_name":  entry.get("issuer_name", ""),
            "name_value":   entry.get("name_value", ""),
        })
        if len(certs) >= limit:
            break

    return certs


async def _fetch_dns_records(domain: str, record_types: list) -> dict:
    results: dict[str, list] = {}

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_DOH_HEADERS, follow_redirects=True
    ) as client:
        for rtype in record_types:
            try:
                resp = await client.get(
                    CF_DOH_URL,
                    params={"name": domain, "type": rtype},
                )
                resp.raise_for_status()
                data = resp.json()

                answers = []
                for ans in data.get("Answer", []):
                    answers.append({
                        "name":  ans.get("name", ""),
                        "type":  rtype,
                        "ttl":   ans.get("TTL", 0),
                        "data":  ans.get("data", ""),
                    })
                results[rtype] = answers

            except Exception as exc:
                log.warning("t07._fetch_dns_records type=%s error=%s", rtype, exc)
                results[rtype] = []

    return results


# ══════════════════════════════════════════════════════════════════════════════
# MARKDOWN BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def _build_rdap_markdown(result: dict, domain: str) -> str:
    reg_date = result.get("registration_date", "")
    exp_date = result.get("expiry_date", "")
    changed  = result.get("last_changed", "")
    registrar   = result.get("registrar", "")
    registrant  = result.get("registrant", "")
    status      = ", ".join(result.get("status", [])) or "unknown"
    nameservers = result.get("nameservers", [])

    lines = [
        f"## {domain.upper()} — RDAP Registration",
        f"**Status:** {status}",
        "",
        "### Registry Details",
        "| Field | Value |",
        "|-------|-------|",
    ]
    if registrar:
        lines.append(f"| Registrar | {registrar} |")
    if registrant:
        lines.append(f"| Registrant | {registrant} |")
    if reg_date:
        lines.append(f"| Registration Date | {reg_date} |")
    if exp_date:
        lines.append(f"| Expiry Date | {exp_date} |")
    if changed:
        lines.append(f"| Last Changed | {changed} |")

    if nameservers:
        lines.append("")
        lines.append("### Nameservers")
        for ns in nameservers:
            lines.append(f"- {ns}")

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_cert_markdown(certs: list, domain: str) -> str:
    lines = [
        f"## SSL Certificate Chain — {domain}",
        f"Found **{len(certs)}** certificate record(s) in CT logs.\n",
    ]

    if not certs:
        lines.append("No certificate records found in Certificate Transparency logs.")
    else:
        lines.append("| Logged | Not Before | Not After | Issuer | Common Name |")
        lines.append("|--------|------------|-----------|--------|-------------|")
        for c in certs:
            issuer_short = c.get("issuer_name", "")[:40]
            lines.append(
                f"| {c.get('logged_at','')} "
                f"| {c.get('not_before','')} "
                f"| {c.get('not_after','')} "
                f"| {issuer_short} "
                f"| {c.get('common_name','')} |"
            )

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_dns_markdown(records: dict, domain: str, requested: list) -> str:
    lines = [
        f"## DNS Records — {domain}",
        f"Record types requested: {', '.join(requested)}\n",
    ]

    for rtype, answers in records.items():
        if not answers:
            lines.append(f"**{rtype}:** No records found.")
            continue
        lines.append(f"### {rtype} Records")
        lines.append("| Name | TTL | Value |")
        lines.append("|------|-----|-------|")
        for ans in answers:
            lines.append(
                f"| {ans.get('name','')} "
                f"| {ans.get('ttl','')} "
                f"| {ans.get('data','')} |"
            )
        lines.append("")

    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_history_markdown(history: list, domain: str) -> str:
    lines = [
        f"## SSL Certificate History — {domain}",
        f"Found **{len(history)}** certificate event(s) in CT logs.\n",
    ]

    if not history:
        lines.append("No historical certificate records found.")
    else:
        lines.append("| Logged | Valid From | Valid To | Issuer | Name/SAN |")
        lines.append("|--------|------------|----------|--------|----------|")
        for c in history[:25]:  # cap display at 25 rows
            issuer_short = c.get("issuer_name", "")[:35]
            name = (c.get("common_name") or c.get("name_value", ""))[:40]
            lines.append(
                f"| {c.get('logged_at','')} "
                f"| {c.get('not_before','')} "
                f"| {c.get('not_after','')} "
                f"| {issuer_short} "
                f"| {name} |"
            )
        if len(history) > 25:
            lines.append(f"\n*…and {len(history)-25} more records (showing most recent 25).*")

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 4 UPSTREAM FETCH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def _fetch_dkim_selectors(domain: str, selectors: list) -> list:
    """Check 10 common DKIM selectors in parallel. Returns list of found selector names."""
    async def _check_one(selector: str) -> Optional[str]:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=3.0),
                headers=_DOH_HEADERS,
                follow_redirects=True,
            ) as client:
                resp = await client.get(
                    CF_DOH_URL,
                    params={"name": dkim_domain, "type": "TXT"},
                )
                resp.raise_for_status()
                data = resp.json()
                answers = data.get("Answer", [])
                if answers:
                    return selector
        except Exception:
            pass
        return None

    tasks = [_check_one(sel) for sel in selectors]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, str)]


def _score_spf(record: Optional[str]) -> tuple:
    """Score SPF record 0-10. Returns (score, policy_str)."""
    if not record:
        return 2, "absent"
    record_lower = record.lower()
    if "+all" in record_lower:
        return 0, "+all (open relay — no restriction)"
    if "~all" in record_lower:
        return 7, "~all (softfail)"
    if "?all" in record_lower:
        return 4, "?all (neutral)"
    if "-all" in record_lower:
        return 10, "-all (hard fail — recommended)"
    return 5, "present (no explicit all mechanism)"


def _score_dmarc(record: Optional[str]) -> tuple:
    """Score DMARC record 0-10. Returns (score, policy_str, rua_present_bool)."""
    if not record:
        return 0, "absent", False

    record_lower = record.lower()
    p_match = re.search(r"p=(\w+)", record_lower)
    policy  = p_match.group(1) if p_match else ""

    if policy == "reject":
        score = 10
        policy_str = "p=reject (recommended)"
    elif policy == "quarantine":
        score = 7
        policy_str = "p=quarantine"
    elif policy == "none":
        score = 4
        policy_str = "p=none (monitoring only)"
    else:
        score = 2
        policy_str = f"present (unrecognized policy: {policy})"

    rua_present = "rua=" in record_lower
    if rua_present and score < 10:
        score = min(10, score + 1)

    return score, policy_str, rua_present


def _score_to_grade(score: float) -> str:
    """Convert a 0-10 score to A-F grade."""
    if score >= 8:
        return "A"
    if score >= 6:
        return "B"
    if score >= 4:
        return "C"
    if score >= 2:
        return "D"
    return "F"


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 4 MARKDOWN BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def _build_subdomains_markdown(result: dict) -> str:
    domain  = result.get("domain", "")
    subs    = result.get("subdomains", [])
    count   = result.get("count", len(subs))
    latency = result.get("latency_ms", 0)

    lines = [
        f"## Subdomains — {domain}",
        f"Found **{count}** subdomain(s) via Certificate Transparency logs.",
        f"Source: crt.sh | Latency: {latency}ms\n",
    ]

    if not subs:
        lines.append("No subdomains found in CT logs. The domain may be new or use wildcards only.")
    else:
        for sub in subs[:100]:
            lines.append(f"- `{sub}`")
        if count > 100:
            lines.append(f"\n*…and {count - 100} more (showing first 100).*")

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_email_security_markdown(assessment: dict) -> str:
    domain = assessment.get("domain", "")
    spf    = assessment.get("spf", {})
    dmarc  = assessment.get("dmarc", {})
    dkim   = assessment.get("dkim", {})
    grade  = assessment.get("overall_grade", "?")
    score  = assessment.get("overall_score", 0)

    lines = [
        f"## Email Security — {domain}",
        f"**Overall Grade: {grade}** (avg score: {score:.1f}/10)\n",
        "### SPF",
        f"- **Present:** {'Yes' if spf.get('present') else 'No'}",
        f"- **Policy:** {spf.get('policy', 'n/a')}",
        f"- **Score:** {spf.get('score', 0)}/10",
    ]
    if spf.get("record"):
        lines.append(f"- **Record:** `{spf['record']}`")

    lines += [
        "",
        "### DMARC",
        f"- **Present:** {'Yes' if dmarc.get('present') else 'No'}",
        f"- **Policy:** {dmarc.get('policy', 'n/a')}",
        f"- **RUA (aggregate reports):** {'Yes' if dmarc.get('rua') else 'No'}",
        f"- **Score:** {dmarc.get('score', 0)}/10",
    ]
    if dmarc.get("record"):
        lines.append(f"- **Record:** `{dmarc['record']}`")

    dkim_sels = dkim.get("selectors_found", [])
    lines += [
        "",
        "### DKIM",
        f"- **Selectors found:** {', '.join(dkim_sels) if dkim_sels else 'none'}",
        f"- **Score:** {dkim.get('score', 0)}/10",
    ]
    if dkim.get("note"):
        lines.append(f"- **Note:** {dkim['note']}")

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_reverse_ip_markdown(result: dict) -> str:
    ip      = result.get("ip", "")
    domains = result.get("domains", [])
    count   = result.get("count", len(domains))
    note    = result.get("note", "")

    lines = [
        f"## Reverse IP — {ip}",
        f"Found **{count}** co-hosted domain(s) via HackerTarget.",
    ]
    if note:
        lines.append(f"*{note}*")
    lines.append("")

    if not domains:
        lines.append("No co-hosted domains found for this IP.")
    else:
        for d in domains[:100]:
            lines.append(f"- `{d}`")
        if count > 100:
            lines.append(f"\n*…and {count - 100} more (showing first 100).*")

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)
