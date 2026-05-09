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

import json
import logging
import re
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
    record_failure,
    record_success,
)
from datanexus.core.schema import ErrorCode, error_response
from payment.entitlement import verify_entitlement

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
@verify_entitlement("T07")
async def fetch_domain_rdap(domain: str) -> dict:
    """
    Fetch domain registration details via IANA RDAP (modern WHOIS replacement).
    Returns registrar, registration date, expiry date, nameservers, and
    registrant info (where public) in AI-Ready Markdown.
    Verified source: IANA RDAP. Data freshness: 4-hour cache. Token-efficient.
    Example: fetch_domain_rdap('stripe.com')
    Returns: registry data only — passive lookup, no active probing.
    """
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
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    cached.get("ingest_healthy", True),
                ),
                "cache_hit": True,
            }

        if is_tripped("iana_rdap"):
            archive = get_cached("T07", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
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
            record_failure("iana_rdap")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "IANA RDAP timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure("iana_rdap")
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
        record_success("iana_rdap")

        log.info("t07.fetch_domain_rdap ok domain=%s registrar=%s",
                 domain_clean, result.get("registrar", ""))
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — fetch_ssl_certificate_chain
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T07")
async def fetch_ssl_certificate_chain(domain: str) -> dict:
    """
    Fetch SSL certificate history for any domain from Certificate Transparency logs.
    Returns issuer, subject, validity dates, and SANs in AI-Ready Markdown.
    Verified source: crt.sh Certificate Transparency.
    Data freshness: 4-hour cache. Token-efficient.
    Example: fetch_ssl_certificate_chain('github.com')
    Returns: certificate registry data only — passive lookup.
    """
    domain_clean = domain.strip().lower().lstrip("www.").split("/")[0]
    params = {"domain": domain_clean, "query_type": "cert_chain"}

    async with AuditContext("T07", params, "1.0") as ctx:
        _incr_calls("T07")
        phash = make_params_hash(params)

        cached = get_cached("T07", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    True,
                ),
                "cache_hit": True,
            }

        if is_tripped("crt_sh"):
            return error_response(
                ErrorCode.CIRCUIT_OPEN,
                "crt.sh Certificate Transparency temporarily unavailable. Try again later.",
                ctx.query_hash, 300, False,
            )

        try:
            certs = await _fetch_crt_sh(domain_clean, limit=10)
        except httpx.TimeoutException:
            record_failure("crt_sh")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "crt.sh timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure("crt_sh")
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
        record_success("crt_sh")

        log.info("t07.fetch_ssl_certificate_chain ok domain=%s certs=%d",
                 domain_clean, len(certs))
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_dns_records
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T07")
async def fetch_dns_records(domain: str, record_types: list) -> dict:
    """
    Fetch DNS records for any domain via Cloudflare DNS over HTTPS.
    Returns A, AAAA, MX, TXT, NS, CNAME records as structured AI-Ready Markdown.
    Verified source: Cloudflare DoH. Token-efficient.
    Data freshness: 4-hour cache.
    Example: fetch_dns_records('cloudflare.com', ['A', 'MX', 'TXT'])
    Returns: DNS registry data only — passive lookup, no active interrogation.
    """
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
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    True,
                ),
                "cache_hit": True,
            }

        if is_tripped("cloudflare_doh"):
            return error_response(
                ErrorCode.CIRCUIT_OPEN,
                "Cloudflare DNS temporarily unavailable. Try again later.",
                ctx.query_hash, 300, False,
            )

        try:
            records = await _fetch_dns_records(domain_clean, types_clean)
        except httpx.TimeoutException:
            record_failure("cloudflare_doh")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "Cloudflare DNS timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure("cloudflare_doh")
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
        record_success("cloudflare_doh")

        log.info("t07.fetch_dns_records ok domain=%s types=%s",
                 domain_clean, types_found)
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — fetch_domain_history
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@verify_entitlement("T07")
async def fetch_domain_history(domain: str) -> dict:
    """
    Fetch historical SSL certificate issuance for a domain from Certificate
    Transparency logs. Useful for detecting domain ownership changes or
    unexpected certificate issuance events over time.
    Verified source: crt.sh. Token-efficient.
    Data freshness: 4-hour cache.
    Example: fetch_domain_history('example.com')
    Returns: certificate log history only — passive CT log lookup.
    """
    domain_clean = domain.strip().lower().lstrip("www.").split("/")[0]
    params = {"domain": domain_clean, "query_type": "history"}

    async with AuditContext("T07", params, "1.0") as ctx:
        _incr_calls("T07")
        phash = make_params_hash(params)

        cached = get_cached("T07", phash)
        if cached:
            ctx.set_cache_hit(True)
            return {
                **cached,
                **standard_response_fields(
                    ctx.query_hash,
                    cached.get("data_as_of", ""),
                    True,
                ),
                "cache_hit": True,
            }

        if is_tripped("crt_sh"):
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
            record_failure("crt_sh")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "crt.sh timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure("crt_sh")
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
        record_success("crt_sh")

        log.info("t07.fetch_domain_history ok domain=%s events=%d",
                 domain_clean, len(history))
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# UPSTREAM FETCH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def _get_rdap_bootstrap() -> dict:
    """Fetch and cache the IANA RDAP bootstrap for DNS TLD→server mapping."""
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
    """Fetch RDAP registration data for a domain, routing via IANA bootstrap."""
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
    """Fetch certificate records from crt.sh CT logs."""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(20.0, connect=5.0),
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
    """Fetch multiple DNS record types from Cloudflare DoH in parallel."""
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
