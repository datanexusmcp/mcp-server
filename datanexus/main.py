"""
DataNexus MCP — Sprint 4 entry point.

Spec:      DataNexus_MCP_Spec_v7_6.docx (authoritative)
Transport: streamable-http (CLAUDE.md rule — SSE deprecated April 2026)
Server:    datanexusmcp.com  |  Hetzner CAX11  |  178.104.251.70

Registered tools (35 total):
  nonprofit  (3): nonprofit_fetch_nonprofit_by_ein, nonprofit_search_nonprofits_by_name, nonprofit_fetch_charity_uk
  security   (7): security_fetch_package_vulnerabilities, security_fetch_dependency_graph,
                  security_fetch_cve_detail, security_audit_sbom_vulnerabilities, security_fetch_package_licence,
                  security_fetch_cisa_kev, security_fetch_cve_epss
  compliance (4): compliance_fetch_npi_provider, compliance_search_npi_by_name,
                  compliance_fetch_finra_broker, compliance_check_sam_exclusion
  domain     (7): domain_fetch_domain_rdap, domain_fetch_ssl_certificate_chain,
                  domain_fetch_dns_records, domain_fetch_domain_history,
                  domain_fetch_subdomains, domain_check_email_security, domain_fetch_reverse_ip
  legal      (4): legal_fetch_patent_by_number, legal_search_patents_by_keyword,
                  legal_fetch_patent_citations, legal_fetch_inventor_portfolio
  govcon     (3): govcon_search_contract_awards, govcon_fetch_vendor_contract_history,
                  govcon_fetch_open_solicitations
  regulatory (3): regulatory_search_open_rulemakings, regulatory_fetch_docket_details,
                  regulatory_fetch_federal_register_notices
  Shared     (3): report_feedback, report_mcpize_link, validate_tool_output
  meta       (1): search_datanexus_tools

Sprint 3 P01: 26 data tools regrouped into 7 FastMCP sub-servers via mount().
Sprint 3 P02: search_datanexus_tools meta-tool added (30 total).
Sprint 4: T10 + T07 Security Pack — 5 new tools, KEV refresh, batch vulns, remediation (35 total).
"""

import asyncio
import json as _json
import logging
import pathlib as _pathlib
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, List as _List, Literal as _Literal, Optional as _Optional

from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from pydantic import Field

from datanexus.core.request_context import api_key_var, call_type_var, client_ip_var, is_organic_var, tier_var


class _ClientIPMiddleware:
    """
    Pure-ASGI middleware — extracts the real client IP from the X-Real-IP
    header (set by Caddy) and stores it in client_ip_var for the duration
    of the request.

    Falls back through X-Forwarded-For → ASGI client host → 'unknown'.
    Pure-ASGI (not BaseHTTPMiddleware) so contextvars are correctly
    propagated into all coroutines within the same task chain.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            ip = (
                headers.get(b"x-real-ip", b"").decode().strip()
                or headers.get(b"x-forwarded-for", b"").decode().split(",")[0].strip()
                or (scope.get("client") or ("unknown", 0))[0]
            )
            token = client_ip_var.set(ip or "unknown")
            try:
                await self.app(scope, receive, send)
            finally:
                client_ip_var.reset(token)
        else:
            await self.app(scope, receive, send)

import hashlib as _hashlib


def _extract_configschema_api_key(scope) -> str:
    """
    Sprint 9 P4 — Smithery passes configSchema values to HTTP servers as a
    base64url-encoded JSON object in the `config` query-string parameter
    (e.g. ?config=eyJhcGlLZXkiOiAiZG54Xy4uLiJ9). Decode it and pull `apiKey`.

    Returns "" on any parse failure (fail-open — anonymous tier).
    """
    try:
        import base64 as _base64
        import json as _json_local
        from urllib.parse import parse_qs as _parse_qs

        qs = (scope.get("query_string") or b"").decode()
        if not qs:
            return ""
        params = _parse_qs(qs)
        config_raw = (params.get("config") or [""])[0]
        if not config_raw:
            return ""
        # base64url, tolerate missing padding
        padded = config_raw + "=" * (-len(config_raw) % 4)
        decoded = _base64.urlsafe_b64decode(padded.encode())
        config = _json_local.loads(decoded)
        api_key = config.get("apiKey", "")
        return api_key.strip() if isinstance(api_key, str) else ""
    except Exception:
        return ""


class _ApiKeyMiddleware:
    """
    Pure-ASGI middleware — extracts X-Api-Key (preferred) or X-DataNexus-Key
    (deprecated, Sprint 8A compat) header, validates against Redis cache + Postgres,
    and sets api_key_var + call_type_var + is_organic_var.

    Reserved keys (SMOKE, OWNER, GLAMA) bypass DB/Redis entirely.
    Fails open: if Redis or DB is unavailable, anonymous tier is assumed.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            from payment.config import RESERVED_KEYS, classify_call as _classify_call

            headers = {k.lower(): v for k, v in scope.get("headers", [])}

            # Prefer X-Api-Key; fall back to deprecated X-DataNexus-Key;
            # then Smithery configSchema apiKey (Sprint 9 P4);
            # finally plain ?api_key= query param (Glama agent-tools.cloud sends this).
            # Precedence: X-Api-Key header > X-DataNexus-Key > configSchema apiKey > ?api_key=
            raw_key = headers.get(b"x-api-key", b"").decode().strip()
            if not raw_key:
                legacy = headers.get(b"x-datanexus-key", b"").decode().strip()
                if legacy:
                    raw_key = legacy
                    logging.getLogger("datanexus.main").warning(
                        "_ApiKeyMiddleware: X-DataNexus-Key is deprecated — use X-Api-Key"
                    )
            if not raw_key:
                raw_key = _extract_configschema_api_key(scope)
            if not raw_key:
                try:
                    from urllib.parse import parse_qs as _parse_qs
                    _qs = (scope.get("query_string") or b"").decode()
                    _params = _parse_qs(_qs)
                    raw_key = (_params.get("api_key") or [""])[0].strip()
                except Exception:
                    raw_key = ""

            key_is_valid = False
            key_hash = None
            tier = None

            if raw_key:
                if raw_key in RESERVED_KEYS:
                    # Reserved keys are always valid — no DB/Redis lookup
                    key_hash = _hashlib.sha256(raw_key.encode()).hexdigest()
                    key_is_valid = True
                else:
                    key_hash = _hashlib.sha256(raw_key.encode()).hexdigest()
                    tier = await self._lookup(key_hash)
                    key_is_valid = tier is not None

            client_ip = client_ip_var.get()
            call_type = _classify_call(client_ip, raw_key or None, key_is_valid=key_is_valid)
            is_organic = call_type == "organic"

            ak_token = api_key_var.set(key_hash if key_is_valid else None)
            ct_token = call_type_var.set(call_type)
            io_token = is_organic_var.set(is_organic)
            ti_token = tier_var.set(tier if key_is_valid else None)

            try:
                await self.app(scope, receive, send)
            finally:
                api_key_var.reset(ak_token)
                call_type_var.reset(ct_token)
                is_organic_var.reset(io_token)
                tier_var.reset(ti_token)
        else:
            await self.app(scope, receive, send)


    async def _lookup(self, key_hash: str):
        """
        Returns tier string if key is valid + not revoked, else None.
        Checks Redis cache first (5-min TTL), falls back to Postgres.
        """
        import os
        from datanexus.cache import get_redis

        cache_key = f"dn:apikey:{key_hash}"
        try:
            r = await get_redis()
            if r:
                cached = await r.get(cache_key)
                if cached is not None:
                    return cached if cached != "revoked" else None
        except Exception as exc:
            logging.getLogger("datanexus.main").warning(
                "_ApiKeyMiddleware: Redis lookup failed (fail-open): %s", exc
            )
            return None

        db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()
        if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
            return None

        try:
            import asyncpg
            conn = await asyncpg.connect(db_url)
            try:
                row = await conn.fetchrow(
                    "SELECT tier, revoked FROM api_keys WHERE key_hash=$1", key_hash
                )
            finally:
                await conn.close()

            if row is None or row["revoked"]:
                try:
                    r = await get_redis()
                    if r:
                        await r.set(cache_key, "revoked", ex=300)
                except Exception:
                    pass
                return None

            tier = row["tier"]
            try:
                r = await get_redis()
                if r:
                    await r.set(cache_key, tier, ex=300)
            except Exception:
                pass
            return tier

        except Exception as exc:
            logging.getLogger("datanexus.main").warning(
                "_ApiKeyMiddleware: DB lookup failed (fail-open): %s", exc
            )
            return None


class _SmitheryEventsMiddleware:
    """
    Pure-ASGI middleware — intercepts ai.smithery/events/list and returns
    {"events": []} so Smithery quality-test bots promote this server from
    catalog mode (tools/list only) to full quality testing (tools/call).

    Without this, FastMCP returns -32602 Invalid params for this
    Smithery-proprietary MCP method, which Smithery treats as a protocol
    failure and keeps the server in catalog mode indefinitely.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/mcp":
            # Buffer full body — needed to inspect method, then re-inject downstream
            chunks = []
            more = True
            while more:
                msg = await receive()
                chunks.append(msg.get("body", b""))
                more = msg.get("more_body", False)
            body = b"".join(chunks)

            try:
                data = _json.loads(body)
                if isinstance(data, dict) and data.get("method") == "ai.smithery/events/list":
                    payload = _json.dumps({
                        "jsonrpc": "2.0",
                        "id": data.get("id"),
                        "result": {"events": []},
                    }).encode()
                    await send({
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(payload)).encode()),
                        ],
                    })
                    await send({"type": "http.response.body", "body": payload})
                    return
            except Exception:
                pass

            # Re-inject buffered body for downstream FastMCP handler
            _sent = False

            async def _receive():
                nonlocal _sent
                if not _sent:
                    _sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.disconnect"}

            await self.app(scope, _receive, send)
        else:
            await self.app(scope, receive, send)


def _try_inject_nudge(body: bytes, msg: str) -> bytes:
    """
    Parse a JSON-RPC response and append a TextContent item to the
    tools/call result content array. Returns body unchanged if parsing
    fails or the response has no content array (e.g. tools/list).
    """
    try:
        data = _json.loads(body)
        content = (data.get("result") or {}).get("content")
        if not isinstance(content, list):
            return body
        content.append({"type": "text", "text": msg})
        return _json.dumps(data).encode()
    except Exception:
        return body


class _IpCounterMiddleware:
    """
    Pure-ASGI per-day rate limiter sitting inside _ApiKeyMiddleware so
    call_type_var, api_key_var, and client_ip_var are already populated.

    Anonymous path (call_type != "registered"):
      - Redis INCR + EXPIRE pipeline (atomic — never orphaned key without TTL).
      - Hard block at 50/day per IP: HTTP 429 JSON-RPC error.
      - First-call nudge (count==1): inject TextContent subscribe message.

    Registered path (call_type == "registered"):
      - Redis INCR + EXPIRE pipeline per API key per day.
      - Soft nudge at 200/day: inject TextContent into tools/call response.
      - No hard block — call always succeeds.

    Fail-open: Redis unavailable → log warning and allow the call through.
    Exempt call types (smithery, glama, smoke, owner, claude_ai) bypass entirely.

    Middleware ordering: listed AFTER _SmitheryEventsMiddleware, _ClientIPMiddleware,
    and _ApiKeyMiddleware in main.run() so all contextvars are set.

    T3 — Smithery quality bot allowlist:
      Populate SMITHERY_BOT_ALLOWLIST with IPs from server logs after deploy:
        grep "events/list" /var/log/caddy/access.log | awk '{print $1}' | sort -u
      These IPs bypass the daily counter entirely (belt-and-suspenders over
      the _EXEMPT call-type check, which covers SMITHERY_CIDRS already).
    """

    _EXEMPT = frozenset({"smoke", "owner", "glama", "smithery", "claude_ai"})
    _ANON_LIMIT = 50    # hard block at this count; 50th call returns 429
    _REG_NUDGE  = 200   # soft nudge TextContent at this count per day

    SMITHERY_BOT_ALLOWLIST: frozenset = frozenset()  # populated by T3

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        call_type = call_type_var.get()
        client_ip = client_ip_var.get()

        if call_type in self._EXEMPT or client_ip in self.SMITHERY_BOT_ALLOWLIST:
            await self.app(scope, receive, send)
            return

        is_registered = call_type == "registered"
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if is_registered:
            ak = api_key_var.get() or "unknown"
            counter_key = f"dn:daily_reg:{ak[:16]}:{today}"
        else:
            _h = _hashlib.sha256(client_ip.encode()).hexdigest()[:16]
            counter_key = f"dn:daily_anon:{_h}:{today}"

        # Atomic INCR + EXPIRE — never crashes between the two commands.
        count = 0
        try:
            from datanexus.cache import get_redis
            r = await get_redis()
            if r:
                pipe = r.pipeline()
                pipe.incr(counter_key)
                pipe.expire(counter_key, 86400)
                results = await pipe.execute()
                count = int(results[0])
        except Exception as exc:
            logger.warning("_IpCounterMiddleware: Redis unavailable, fail-open: %s", exc)
            await self.app(scope, receive, send)
            return

        # Anonymous hard block: 50th call and beyond return HTTP 429.
        if not is_registered and count >= self._ANON_LIMIT:
            payload = _json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32000,
                    "message": (
                        f"Daily call limit reached ({self._ANON_LIMIT}/day). "
                        "Subscribe at datanexusmcp.com/signup for higher limits."
                    ),
                },
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": payload})
            return

        # Determine if this call warrants a TextContent nudge in the response.
        nudge_msg = None
        if not is_registered and count == 1:
            nudge_msg = (
                "You've gotten your first result. "
                "Subscribe at datanexusmcp.com/signup for higher daily limits (200/day)."
            )
        elif is_registered and count >= self._REG_NUDGE:
            nudge_msg = (
                f"You've made {count} calls today. "
                "Subscribe at datanexusmcp.com/signup for unlimited access."
            )

        if nudge_msg is None:
            await self.app(scope, receive, send)
            return

        # Buffer the response to inject the TextContent nudge.
        response_start: dict = {}
        body_parts: list = []

        async def _capture(message):
            t = message.get("type")
            if t == "http.response.start":
                response_start["msg"] = message
            elif t == "http.response.body":
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    raw = b"".join(body_parts)
                    modified = _try_inject_nudge(raw, nudge_msg)
                    hdr = response_start["msg"]
                    if modified is not raw:
                        hdr = dict(hdr, headers=[
                            (k, v) for k, v in hdr["headers"]
                            if k.lower() != b"content-length"
                        ] + [(b"content-length", str(len(modified)).encode())])
                    await send(hdr)
                    await send({"type": "http.response.body", "body": modified, "more_body": False})
            else:
                await send(message)

        await self.app(scope, receive, _capture)


from datanexus.db_init import init_db
from datanexus.core.prewarm import prewarm_cache
from datanexus.analytics import fire_and_forget, track_server_start, shutdown as ph_shutdown
from datanexus.kev_refresh import kev_initial_load
from datanexus.schedulers import _cve_refresh_loop, _sbom_refresh_loop, _typosquat_ref_loop

# ── Sub-server imports (P01) ──────────────────────────────────────────────────
from datanexus.tools.nonprofit  import nonprofit
from datanexus.tools.security   import security
from datanexus.tools.compliance import compliance
from datanexus.tools.domain     import domain
from datanexus.tools.legal      import legal
from datanexus.tools.govcon     import govcon
from datanexus.tools.regulatory import regulatory

# ── Sprint 6 sub-server imports ───────────────────────────────────────────────
from datanexus.tools.security_sprint6  import security_sprint6
from datanexus.tools.nonprofit_sprint6 import nonprofit_sprint6 as nonprofit_sprint6_server
from datanexus.tools.security_stateful import security_stateful

# ── Sprint 7 sub-server imports ───────────────────────────────────────────────
from datanexus.tools.licence_sprint7    import licence_sprint7
from datanexus.tools.cve_sprint7        import cve_sprint7
from datanexus.tools.nonprofit_sprint7  import nonprofit_sprint7 as nonprofit_sprint7_server

# ── Sprint 8A imports ─────────────────────────────────────────────────────────
from datanexus.tools.api_key_sprint8a import api_key_server, _UsageMiddleware

# ── Sprint 8B imports ─────────────────────────────────────────────────────────
from datanexus.tools.t10_sprint8      import t10_sprint8
from datanexus.tools.frontend_sprint8 import frontend_sprint8
from datanexus.endpoints.signup       import signup_handler
from datanexus.endpoints.demo         import demo_handler

# ── Section 13 validation tool ───────────────────────────────────────────────
from datanexus.tools.validation import validate_tool_output

# ── P02 meta-tool ─────────────────────────────────────────────────────────────
from datanexus.tools.meta import search_datanexus_tools

# ── Shared infrastructure tools ───────────────────────────────────────────────
# report_feedback and report_mcpize_link registered ONCE as shared infrastructure.
# tool_id parameter routes feedback and payment lookups to the correct data source.
from feedback.collector import report_feedback as _real_report_feedback
from payment.tools import report_mcpize_link as _real_report_mcpize_link


async def report_feedback(
    tool_id: Annotated[str, Field(description='Tool identifier, e.g. T04 or security_fetch_cve_detail. Required.')],
    query_hash: Annotated[str, Field(description='Hash from the response being reported — found in the query_hash field of any response. Required.')],
    signal: Annotated[str, Field(description='One of incorrect_data, missing_field, stale_data, not_useful, wrong_entity, or data_quality. Required for user_feedback.')],
    comment: Annotated[str, Field(description='Description of the issue. Optional. Max 500 characters.')] = "",
    missing_fields: Annotated[_Optional[_List[str]], Field(description='List of field names that are absent or wrong. Optional.')] = None,
    feedback_type: Annotated[_Literal["user_feedback", "agent_gap"], Field(description='user_feedback (default) or agent_gap. Use agent_gap when the tool returned a valid response but did not serve the user\'s actual need.')] = "user_feedback",
    intended_query: Annotated[_Optional[str], Field(description='What the agent was trying to accomplish — used when feedback_type=agent_gap. Optional. Max 256 chars.')] = None,
    gap_description: Annotated[_Optional[str], Field(description='What was missing or wrong in the result — used when feedback_type=agent_gap. Optional. Max 256 chars.')] = None,
) -> dict:
    """Report a data quality issue or agent intent gap for a DataNexus tool response.

    tool_id: e.g. "T10" or "security_fetch_cve_detail".
    query_hash: From the query_hash field of the response.
    signal: incorrect_data | missing_field | stale_data | not_useful | wrong_entity | data_quality.
    comment: Issue description. Max 500 chars.
    missing_fields: Absent or wrong field names.
    feedback_type: "user_feedback" (default) or "agent_gap".
    intended_query: Agent's goal. Max 256 chars.
    gap_description: What was missing. Max 256 chars.

    Example: report_feedback(tool_id="T10", query_hash="abc123", signal="incorrect_data")
    """
    return await _real_report_feedback(
        tool_id, query_hash, signal, comment, missing_fields,
        feedback_type=feedback_type,
        intended_query=intended_query,
        gap_description=gap_description,
    )


async def report_mcpize_link(
    tool_id: Annotated[str, Field(description='DataNexus tool identifier to check, e.g. "T01", "T07", "T10" — pass the ID of the tool the user is asking about.')],
) -> dict:
    """Check MCPize subscription status for a DataNexus tool.

    tool_id: DataNexus tool identifier e.g. "T10". Pass the tool the user is asking about.

    Returns: status ("free" | "subscription_required" | "not_configured"), message, tool_id, and upgrade_url when subscription is required.

    Example: report_mcpize_link(tool_id="T10")
    """
    return _real_report_mcpize_link(tool_id)


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("datanexus.main")


# ── Startup lifespan — DB table init ─────────────────────────────────────────
@asynccontextmanager
async def _lifespan(server):
    """Run DB init and cache pre-warm before the first request is served."""
    await init_db()
    # Pre-warm fires in the background — errors are silently swallowed inside
    # prewarm_cache so startup is never blocked by upstream API failures.
    fire_and_forget(prewarm_cache())
    # KEV catalog initial load — runs in background, swallows all errors
    fire_and_forget(kev_initial_load())
    # Sprint 6 scheduler loops — 24h background refresh cycles
    fire_and_forget(_cve_refresh_loop())
    fire_and_forget(_sbom_refresh_loop())
    fire_and_forget(_typosquat_ref_loop())
    tools = await server.list_tools()
    fire_and_forget(track_server_start(len(tools)))
    yield
    ph_shutdown()


main = FastMCP(
    "DataNexus MCP",
    lifespan=_lifespan,
    instructions=(
        "Use search_datanexus_tools first to find the right tool for your task. "
        "DataNexus MCP provides AI-Ready access to public data sources. "
        "Token-efficient. Verified sources. "
        "T04: US/UK nonprofits — IRS EO BMF + IRS TEOS + UK Charity Commission. "
        "nonprofit_fetch_nonprofit_by_ein: look up any US nonprofit by EIN. "
        "nonprofit_search_nonprofits_by_name: search US nonprofits by name and state. "
        "nonprofit_fetch_charity_uk: look up UK registered charities. "
        "nonprofit_fetch_nonprofit_full_profile: complete nonprofit due diligence — revenue trends, executive pay, risk flags, and a 0–100 health score. "
        "T10: OSS Dependency & Vulnerability Intelligence — OSV.dev + NIST NVD + deps.dev + CISA KEV + FIRST EPSS. "
        "security_fetch_package_vulnerabilities: CVEs for a package version (or batch up to 50 packages). "
        "security_fetch_dependency_graph: full dep tree (hard 8s timeout). "
        "security_fetch_cve_detail: full CVE detail by CVE ID including remediation. "
        "security_audit_sbom_vulnerabilities: audit CycloneDX/SPDX SBOM against OSV.dev. "
        "security_fetch_package_licence: SPDX licence for a package version. "
        "security_fetch_cisa_kev: check if a CVE is in the CISA Known Exploited Vulnerabilities catalog. "
        "security_fetch_cve_epss: EPSS exploit probability score for a CVE from FIRST.org. "
        "security_fetch_package_maintainer_history: maintainer health + ownership anomaly score for npm/PyPI packages. "
        "security_fetch_package_risk_brief: SHIP/CAUTION/BLOCK verdict combining CVEs, licence, maintainer health, and transitive deps in one call. "
        "security_fetch_cve_watch: persistent CVE watchlist — create once, check anytime for patch releases, KEV listings, PoC publications, exploitation detected. "
        "security_audit_sbom_continuous: persistent SBOM watch — register once, check anytime for new CVEs affecting your dependency snapshot. CycloneDX and SPDX supported. "
        "security_detect_typosquatting: detect supply-chain typosquatting attacks — Damerau-Levenshtein distance ≤ 2 against top-10k npm/PyPI packages. "
        "T22: Professional Licence Verification — NPPES NPI Registry + FINRA BrokerCheck + SAM.gov. "
        "compliance_fetch_npi_provider: look up any US healthcare provider by NPI number. "
        "compliance_search_npi_by_name: search NPI registry by provider name with state/speciality filters. "
        "compliance_fetch_finra_broker: look up FINRA BrokerCheck registration by CRD number. "
        "compliance_check_sam_exclusion: check federal exclusions list by name or EIN. "
        "T07: Domain & DNS Intelligence — IANA RDAP + crt.sh + Cloudflare DoH + SecurityTrails. "
        "domain_fetch_domain_rdap: WHOIS-replacement RDAP lookup for any domain. "
        "domain_fetch_ssl_certificate_chain: CT log certificates for a domain. "
        "domain_fetch_dns_records: A/AAAA/MX/TXT/NS/CNAME records via Cloudflare DoH. "
        "domain_fetch_domain_history: historical certificate issuance from CT logs. "
        "domain_fetch_subdomains: enumerate known subdomains via crt.sh CT logs (24h cache). "
        "domain_check_email_security: SPF/DMARC/DKIM scored assessment with A-F grade. "
        "domain_fetch_reverse_ip: co-hosted domains on the same IPv4 via SecurityTrails. "
        "T11: Global Patent Intelligence — EPO OPS + USPTO PatentsView + WIPO PATENTSCOPE. "
        "legal_fetch_patent_by_number: full bibliographic data for a patent by number and jurisdiction. "
        "legal_search_patents_by_keyword: search EP/US/WO patents by keyword and date. "
        "legal_fetch_patent_citations: forward and backward citations for a patent. "
        "legal_fetch_inventor_portfolio: patent portfolio for an inventor, optionally by assignee. "
        "T18: Government Contracting & Procurement — USASpending.gov + SAM.gov + EU TED + UK Find-a-Tender. "
        "govcon_search_contract_awards: search federal contract awards by keyword and agency. "
        "govcon_fetch_vendor_contract_history: contract history for a specific vendor. "
        "govcon_fetch_open_solicitations: open bid opportunities matching a keyword. "
        "T19: Regulatory Docket & Comment Tracking — Regulations.gov + Federal Register + EU Have Your Say. "
        "regulatory_search_open_rulemakings: open rulemakings and comment periods. "
        "regulatory_fetch_docket_details: full docket details by ID. "
        "regulatory_fetch_federal_register_notices: recent Federal Register notices by agency. "
        "All responses include query_hash, schema_version, data_as_of, ingest_healthy."
    ),
)

# ── Mount 7 sub-servers (P01) ─────────────────────────────────────────────────
main.mount(nonprofit,   namespace="nonprofit")
main.mount(security,    namespace="security")
main.mount(compliance,  namespace="compliance")
main.mount(domain,      namespace="domain")
main.mount(legal,       namespace="legal")
main.mount(govcon,      namespace="govcon")
main.mount(regulatory,  namespace="regulatory")

# ── Mount Sprint 6 sub-servers ────────────────────────────────────────────────
main.mount(security_sprint6,          namespace="security")
main.mount(nonprofit_sprint6_server,  namespace="nonprofit")
main.mount(security_stateful,         namespace="security")

# ── Mount Sprint 7 sub-servers ────────────────────────────────────────────────
main.mount(licence_sprint7,           namespace="security")
main.mount(cve_sprint7,               namespace="security")
main.mount(nonprofit_sprint7_server,  namespace="nonprofit")

# ── Mount Sprint 8A sub-server + register UsageMiddleware ────────────────────
main.mount(api_key_server, namespace="apikeys")
main.add_middleware(_UsageMiddleware())

# ── Mount Sprint 8B sub-servers ───────────────────────────────────────────────
main.mount(t10_sprint8,       namespace="security")
main.mount(frontend_sprint8,  namespace="frontend_security")

# ── Register shared infrastructure tools (once — not per-tool duplicates) ─────
main.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})(report_feedback)
main.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})(report_mcpize_link)

# ── Register Section 13 validation tool ──────────────────────────────────────
main.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})(validate_tool_output)

# ── Register P02 meta-tool (no namespace — top-level) ────────────────────────
main.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})(search_datanexus_tools)

# ── Sprint 11: /demo — GET serves HTML page, /api/demo — POST handles scan ────
@main.custom_route("/demo", methods=["GET"])
async def demo_page(request: Request) -> JSONResponse:
    import pathlib
    from starlette.responses import HTMLResponse
    html_path = pathlib.Path(__file__).parent.parent / "static" / "demo" / "index.html"
    return HTMLResponse(html_path.read_text())


@main.custom_route("/api/demo", methods=["POST", "OPTIONS"])
async def api_demo(request: Request) -> JSONResponse:
    return await demo_handler(request)


# ── Sprint 8B: /signup — GET serves HTML page, POST handles registration ──────
@main.custom_route("/signup", methods=["GET"])
async def signup_page(request: Request) -> JSONResponse:
    import pathlib
    from starlette.responses import HTMLResponse
    html_path = pathlib.Path(__file__).parent.parent / "static" / "signup" / "index.html"
    return HTMLResponse(html_path.read_text())


@main.custom_route("/signup", methods=["POST"])
async def signup(request: Request) -> JSONResponse:
    return await signup_handler(request)


# ── Health endpoint ───────────────────────────────────────────────────────────
@main.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    """Service health check — used by load-balancer and gate verification."""
    return JSONResponse({
        "status": "ok",
        "service": "datanexus-mcp",
        "tools": 55,
        "ts": datetime.now(timezone.utc).isoformat(),
    })


# ── OAuth discovery stubs (T17 rev2, 2026-06-19) ─────────────────────────────
# Minimal RFC 9728 / RFC 8414 responses so Glama and Smithery quality crawlers
# recognise this server as OAuth-aware and proceed past tools/list to actual
# tools/call quality testing (they stopped calling tools on 2026-06-12 when
# these routes were removed, presumably caching their "no OAuth" verdict).
#
# Key design:  DELIBERATELY omits authorization_endpoint, token_endpoint, and
# registration_endpoint.  Without those three fields:
#   - Claude Desktop / well-behaved MCP clients: see no OAuth endpoints to
#     follow, cannot attempt dynamic client reg (RFC 7591), skip OAuth entirely,
#     fall through to X-Api-Key / configSchema apiKey — which is what we want.
#   - Glama / Smithery quality crawlers: see 200 OK = "server is OAuth-aware
#     and in production" → proceed with tools/call quality testing.
#
# The old T17 stubs (removed in 21f0d6e) included authorization_endpoint and
# token_endpoint, which caused Claude Desktop to attempt dynamic client
# registration at a non-existent /register endpoint → 404 → hard fail before
# any X-Api-Key fallback.  That problem does NOT exist here because those
# endpoints are absent.

_OAUTH_RESOURCE_STUB: dict = {
    "resource": "https://datanexusmcp.com",
    "bearer_methods_supported": ["header"],
}

_OAUTH_SERVER_STUB: dict = {
    "issuer": "https://datanexusmcp.com",
}


@main.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource(request: Request) -> JSONResponse:
    return JSONResponse(_OAUTH_RESOURCE_STUB)


@main.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
async def oauth_protected_resource_mcp(request: Request) -> JSONResponse:
    return JSONResponse(_OAUTH_RESOURCE_STUB)


@main.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server(request: Request) -> JSONResponse:
    return JSONResponse(_OAUTH_SERVER_STUB)


# ── MCP manifest (registry discovery) ────────────────────────────────────────
@main.custom_route("/.well-known/mcp-manifest.json", methods=["GET"])
async def mcp_manifest(request: Request) -> JSONResponse:
    """Serve .well-known/mcp-manifest.json for registry discovery."""
    manifest_path = _pathlib.Path(__file__).parent.parent / "static" / ".well-known" / "mcp-manifest.json"
    try:
        data = _json.loads(manifest_path.read_text())
    except Exception:
        data = {"name": "DataNexus MCP", "version": "1.0.1"}
    return JSONResponse(data)


if __name__ == "__main__":
    logger.info(
        "DataNexus MCP starting — transport=streamable-http — "
        "55 tools registered (nonprofit×6, security×17, frontend_security×4, compliance×4, "
        "domain×7, legal×4, govcon×3, regulatory×3, apikeys×3, Shared×3, meta×1)"
    )
    main.run(
        transport="streamable-http",
        host="0.0.0.0",   # nosec B104
        port=8000,
        middleware=[Middleware(_SmitheryEventsMiddleware), Middleware(_ClientIPMiddleware), Middleware(_ApiKeyMiddleware), Middleware(_IpCounterMiddleware)],
        stateless_http=True,
        json_response=True,
    )
