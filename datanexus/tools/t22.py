"""
datanexus/tools/t22.py — T22 Professional Licence Verification tool.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 5, T22 entry

Exactly 4 data functions (flag-resolved: fetch_npi_provider, search_npi_by_name,
fetch_finra_broker, check_sam_exclusion). Shared infrastructure tools
(report_feedback, report_mcpize_link) are registered ONCE in main.py — NOT here.

Data sources:
  Primary:   NPPES NPI Registry (CMS) — no key required
             npiregistry.cms.hhs.gov/api/
  Secondary: FINRA BrokerCheck API — FINRA_API_KEY from env
             api.finra.org — if key absent: NPPES-only with note
  Supporting: SAM.gov Exclusions — SAM_GOV_API_KEY from env
             api.sam.gov/exclusions/v1/api

Hard stop (absolute — never violate):
  Do NOT add licence status judgements, hiring suitability decisions, or
  employment endorsements. Returns only: licence found / not found / status
  as registered in official registry.

Cache TTL: 86400 seconds (24 hours)
Circuit breaker source IDs: "nppes", "finra", "sam_exclusions"
"""

import json
import logging
import os
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
    record_failure_sync,
    record_success_sync,
)
from datanexus.core.schema import ErrorCode, error_response
from payment.entitlement import verify_entitlement
from datanexus.core.timeout import with_timeout

log = logging.getLogger("datanexus.tools.t22")

mcp = FastMCP("datanexus-t22")

# ── Constants ─────────────────────────────────────────────────────────────────

T22_TTL = 86400  # 24 hours — spec requirement

DISCLAIMER = (
    "Licence status sourced from NPPES NPI Registry, FINRA BrokerCheck, "
    "and SAM.gov public registries. DataNexus does not verify current standing "
    "or suitability for any role. Verify with issuing authority before making "
    "employment or engagement decisions."
)

NPPES_API    = "https://npiregistry.cms.hhs.gov/api/"
FINRA_API    = "https://api.finra.org/data/group/registration/name/brokerCheck"
SAM_EXCL_API = "https://api.sam.gov/exclusions/v1/api"

_FINRA_KEY = os.environ.get("FINRA_API_KEY", "")
_SAM_KEY   = os.environ.get("SAM_GOV_API_KEY", "")

_HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

_NPI_RE = re.compile(r"^\d{10}$")

# ── Canary injection patterns (same set as DataNexusResponse._no_injection) ───
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
# DATA TOOL 1 — fetch_npi_provider
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T22")
async def fetch_npi_provider(npi_number: str) -> dict:
    """Use this to verify a US healthcare provider by their NPI number.
    Provide the 10-digit NPI number.
    Returns provider name, credential, speciality, and active status."""
    npi_clean = npi_number.strip().replace("-", "")
    params = {"npi_number": npi_clean}

    async with AuditContext("T22", params, "1.0") as ctx:
        _incr_calls("T22")
        phash = make_params_hash(params)

        # ── Cache check ───────────────────────────────────────────────────────
        cached = get_cached("T22", phash)
        if cached:
            ctx.set_cache_hit(True)
            log.info("t22.fetch_npi_provider cache_hit npi=%s", npi_clean)
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
        if is_tripped("nppes"):
            archive = get_cached("T22", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return {
                "tool_id":         "T22",
                "data":            archive or {},
                "markdown_output": "NPPES Registry temporarily unavailable. "
                                   "Serving archived data.",
                "staleness_notice": get_staleness_notice(
                    "nppes",
                    (archive or {}).get("data_as_of", "unknown"),
                ),
                "disclaimer":  DISCLAIMER,
                "cache_hit":   False,
                "sha256_hash": "",
                **standard_response_fields(ctx.query_hash, "", False),
            }

        # ── Live fetch ────────────────────────────────────────────────────────
        try:
            result = await _fetch_npi_by_number(npi_clean)
        except httpx.TimeoutException:
            record_failure_sync("nppes")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "NPPES Registry timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure_sync("nppes")
            log.exception("t22.fetch_npi_provider unexpected error npi=%s", npi_clean)
            return error_response(
                ErrorCode.INTERNAL_ERROR,
                "An internal error occurred. Please try again.",
                ctx.query_hash, 0, False,
            )

        if not result:
            return error_response(
                ErrorCode.NOT_FOUND,
                f"NPI {npi_clean} not found in NPPES registry. "
                "Verify the NPI number and try again.",
                ctx.query_hash, 0, True,
            )

        raw_bytes    = json.dumps(result).encode()
        payload_hash = compute_payload_hash(raw_bytes)
        data_as_of   = datetime.now(timezone.utc).isoformat()
        markdown     = _build_npi_markdown(result)
        _validate_canary(markdown)

        payload = {
            "tool_id":         "T22",
            "source_url":      NPPES_API,
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

        set_cached("T22", phash, payload, T22_TTL)
        set_cached("T22", phash + "_archive", payload, T22_TTL * 4)
        ctx.set_cache_hit(False)
        record_success_sync("nppes")

        log.info("t22.fetch_npi_provider ok npi=%s name=%s",
                 npi_clean, result.get("display_name", ""))
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 2 — search_npi_by_name
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T22")
async def search_npi_by_name(
    name: str,
    state: str = "",
    speciality: str = "",
) -> dict:
    """Use this to find a healthcare provider by name when you do not have their NPI.
    Provide name and optional state or speciality.
    Returns matching providers with NPI numbers for precise lookup."""
    name_clean  = name.strip()
    state_clean = state.strip().upper()
    spec_clean  = speciality.strip()
    params = {"name": name_clean, "state": state_clean, "speciality": spec_clean}

    async with AuditContext("T22", params, "1.0") as ctx:
        _incr_calls("T22")
        phash = make_params_hash(params)

        cached = get_cached("T22", phash)
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

        if is_tripped("nppes"):
            return error_response(
                ErrorCode.CIRCUIT_OPEN,
                "NPPES Registry temporarily unavailable. Try again later.",
                ctx.query_hash, 300, False,
            )

        try:
            results = await _search_npi(name_clean, state_clean, spec_clean, limit=10)
        except httpx.TimeoutException:
            record_failure_sync("nppes")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "NPPES Registry timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure_sync("nppes")
            log.exception("t22.search_npi_by_name unexpected error name=%s", name_clean)
            return error_response(
                ErrorCode.INTERNAL_ERROR,
                "An internal error occurred. Please try again.",
                ctx.query_hash, 0, False,
            )

        data_as_of   = datetime.now(timezone.utc).isoformat()
        raw_bytes    = json.dumps(results).encode()
        payload_hash = compute_payload_hash(raw_bytes)
        markdown     = _build_search_markdown(results, name, state_clean, spec_clean)
        _validate_canary(markdown)

        payload = {
            "tool_id":         "T22",
            "source_url":      NPPES_API,
            "fetch_timestamp": data_as_of,
            "cache_hit":       False,
            "staleness_notice": None,
            "sha256_hash":     payload_hash,
            "data":            {"results": results, "count": len(results)},
            "markdown_output": markdown,
            "disclaimer":      DISCLAIMER,
            "data_as_of":      data_as_of,
            "ingest_healthy":  True,
        }

        set_cached("T22", phash, payload, T22_TTL)
        ctx.set_cache_hit(False)
        record_success_sync("nppes")

        log.info("t22.search_npi_by_name results=%d name=%s state=%s",
                 len(results), name_clean, state_clean)
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 3 — fetch_finra_broker
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T22")
async def fetch_finra_broker(crd_number: str) -> dict:
    """Use this to verify a financial broker or advisor is registered with FINRA.
    Provide their name or CRD number.
    Returns registration status, licences held, and disclosure history."""
    crd_clean = crd_number.strip().lstrip("0") or "0"
    params = {"crd_number": crd_clean}

    async with AuditContext("T22", params, "1.0") as ctx:
        _incr_calls("T22")
        phash = make_params_hash(params)

        cached = get_cached("T22", phash)
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

        # ── FINRA key check — skip FINRA, return note if not configured ────────
        if not _FINRA_KEY:
            data_as_of   = datetime.now(timezone.utc).isoformat()
            note = (
                "FINRA_API_KEY not configured. "
                "FINRA BrokerCheck data unavailable. "
                "Use fetch_npi_provider() for NPI-registered healthcare professionals. "
                "Contact your administrator to configure FINRA API access."
            )
            markdown = (
                f"## FINRA BrokerCheck — CRD {crd_clean}\n\n"
                f"**Source limitation:** {note}\n\n"
                f"*{DISCLAIMER}*"
            )
            _validate_canary(markdown)
            raw_bytes    = note.encode()
            payload_hash = compute_payload_hash(raw_bytes)

            payload = {
                "tool_id":         "T22",
                "source_url":      "https://developer.finra.org",
                "fetch_timestamp": data_as_of,
                "cache_hit":       False,
                "staleness_notice": "FINRA_API_KEY not set — FINRA data unavailable.",
                "sha256_hash":     payload_hash,
                "data":            {"crd_number": crd_clean, "source_limitation": note},
                "markdown_output": markdown,
                "disclaimer":      DISCLAIMER,
                "data_as_of":      data_as_of,
                "ingest_healthy":  False,
            }
            set_cached("T22", phash, payload, T22_TTL)
            ctx.set_cache_hit(False)
            return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, False)}

        # ── Circuit breaker ───────────────────────────────────────────────────
        if is_tripped("finra"):
            archive = get_cached("T22", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return {
                "tool_id":         "T22",
                "data":            archive or {},
                "markdown_output": "FINRA BrokerCheck temporarily unavailable. "
                                   "Serving archived data.",
                "staleness_notice": get_staleness_notice(
                    "finra",
                    (archive or {}).get("data_as_of", "unknown"),
                ),
                "disclaimer":  DISCLAIMER,
                "cache_hit":   False,
                "sha256_hash": "",
                **standard_response_fields(ctx.query_hash, "", False),
            }

        try:
            result = await _fetch_finra_crd(crd_clean)
        except httpx.TimeoutException:
            record_failure_sync("finra")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "FINRA BrokerCheck timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure_sync("finra")
            log.exception("t22.fetch_finra_broker unexpected error crd=%s", crd_clean)
            return error_response(
                ErrorCode.INTERNAL_ERROR,
                "An internal error occurred. Please try again.",
                ctx.query_hash, 0, False,
            )

        if not result:
            return error_response(
                ErrorCode.NOT_FOUND,
                f"CRD {crd_clean} not found in FINRA BrokerCheck.",
                ctx.query_hash, 0, True,
            )

        raw_bytes    = json.dumps(result).encode()
        payload_hash = compute_payload_hash(raw_bytes)
        data_as_of   = datetime.now(timezone.utc).isoformat()
        markdown     = _build_finra_markdown(result)
        _validate_canary(markdown)

        payload = {
            "tool_id":         "T22",
            "source_url":      "https://api.finra.org",
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

        set_cached("T22", phash, payload, T22_TTL)
        set_cached("T22", phash + "_archive", payload, T22_TTL * 4)
        ctx.set_cache_hit(False)
        record_success_sync("finra")

        log.info("t22.fetch_finra_broker ok crd=%s", crd_clean)
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# DATA TOOL 4 — check_sam_exclusion
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
@with_timeout
@verify_entitlement("T22")
async def check_sam_exclusion(name_or_ein: str) -> dict:
    """Use this to check whether a person or company is excluded from US federal contracting.
    Provide their name or EIN.
    Returns whether they appear on the SAM.gov exclusions list."""
    query_clean = name_or_ein.strip()
    params = {"name_or_ein": query_clean}

    async with AuditContext("T22", params, "1.0") as ctx:
        _incr_calls("T22")
        phash = make_params_hash(params)

        cached = get_cached("T22", phash)
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

        if is_tripped("sam_exclusions"):
            archive = get_cached("T22", phash + "_archive")
            ctx.set_error(ErrorCode.CIRCUIT_OPEN)
            return {
                "tool_id":         "T22",
                "data":            archive or {},
                "markdown_output": "SAM.gov temporarily unavailable. "
                                   "Serving archived data.",
                "staleness_notice": get_staleness_notice(
                    "sam_exclusions",
                    (archive or {}).get("data_as_of", "unknown"),
                ),
                "disclaimer":  DISCLAIMER,
                "cache_hit":   False,
                "sha256_hash": "",
                **standard_response_fields(ctx.query_hash, "", False),
            }

        try:
            result = await _check_sam_exclusion_live(query_clean)
        except httpx.TimeoutException:
            record_failure_sync("sam_exclusions")
            return error_response(
                ErrorCode.UPSTREAM_TIMEOUT,
                "SAM.gov timed out. Try again shortly.",
                ctx.query_hash, 30, False,
            )
        except Exception:
            record_failure_sync("sam_exclusions")
            log.exception("t22.check_sam_exclusion unexpected error query=%s", query_clean)
            return error_response(
                ErrorCode.INTERNAL_ERROR,
                "An internal error occurred. Please try again.",
                ctx.query_hash, 0, False,
            )

        data_as_of   = datetime.now(timezone.utc).isoformat()
        raw_bytes    = json.dumps(result).encode()
        payload_hash = compute_payload_hash(raw_bytes)
        markdown     = _build_sam_exclusion_markdown(result, query_clean)
        _validate_canary(markdown)

        payload = {
            "tool_id":         "T22",
            "source_url":      SAM_EXCL_API,
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

        set_cached("T22", phash, payload, T22_TTL)
        set_cached("T22", phash + "_archive", payload, T22_TTL * 4)
        ctx.set_cache_hit(False)
        record_success_sync("sam_exclusions")

        log.info("t22.check_sam_exclusion ok query=%s found=%s",
                 query_clean, result.get("exclusion_found", False))
        return {**payload, **standard_response_fields(ctx.query_hash, data_as_of, True)}


# ══════════════════════════════════════════════════════════════════════════════
# UPSTREAM FETCH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def _fetch_npi_by_number(npi: str) -> Optional[dict]:
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True
    ) as client:
        resp = await client.get(
            NPPES_API,
            params={"number": npi, "version": "2.1"},
        )
        resp.raise_for_status()
        data = resp.json()

    results = data.get("results", [])
    if not results:
        return None
    return _normalise_npi_record(results[0])


async def _search_npi(
    name: str,
    state: str,
    speciality: str,
    limit: int = 10,
) -> list:
    params: dict = {"version": "2.1", "limit": str(limit)}

    # Split name into first/last if space present, else search as organization name
    parts = name.strip().split(None, 1)
    if len(parts) == 2:
        params["first_name"] = parts[0]
        params["last_name"]  = parts[1]
    elif len(parts) == 1:
        # Try as last name first, then org name
        params["last_name"] = parts[0]

    if state:
        params["state"] = state
    if speciality:
        params["taxonomy_description"] = speciality

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True
    ) as client:
        resp = await client.get(NPPES_API, params=params)
        resp.raise_for_status()
        data = resp.json()

    return [_normalise_npi_record(r) for r in data.get("results", [])]


async def _fetch_finra_crd(crd: str) -> Optional[dict]:
    headers = {**_HEADERS, "Authorization": f"Bearer {_FINRA_KEY}"}
    url = f"{FINRA_API}/individual/{crd}"

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=headers, follow_redirects=True
    ) as client:
        resp = await client.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return _normalise_finra_record(resp.json(), crd)


async def _check_sam_exclusion_live(query: str) -> dict:
    # Determine if query looks like an EIN (digits + optional dash)
    ein_digits = query.replace("-", "").strip()
    is_ein = ein_digits.isdigit() and len(ein_digits) == 9

    params: dict = {"api_key": _SAM_KEY}
    if is_ein:
        params["taxIdentificationNumber"] = ein_digits
    else:
        params["searchTerm"] = query

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True
    ) as client:
        resp = await client.get(SAM_EXCL_API, params=params)
        resp.raise_for_status()
        data = resp.json()

    exclusions = data.get("exclusionList", []) or data.get("exclusions", []) or []
    if exclusions:
        first = exclusions[0]
        return {
            "exclusion_found":    True,
            "query":              query,
            "exclusion_count":    len(exclusions),
            "exclusion_type":     first.get("exclusionType", ""),
            "agency":             first.get("agencyName", ""),
            "classification":     first.get("classification", ""),
            "active_date":        first.get("activationDate", ""),
            "termination_date":   first.get("terminationDate", ""),
            "source":             "SAM.gov Exclusions",
        }
    return {
        "exclusion_found":  False,
        "query":            query,
        "exclusion_count":  0,
        "source":           "SAM.gov Exclusions",
    }


# ══════════════════════════════════════════════════════════════════════════════
# NORMALISATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _normalise_npi_record(raw: dict) -> dict:
    """Extract GDPR-safe, hard-stop-compliant fields from a raw NPPES result."""
    basic  = raw.get("basic", {})
    addrs  = raw.get("addresses", [])
    taxons = raw.get("taxonomies", [])

    # Build display name (individual or organisation)
    enum_type = raw.get("enumeration_type", "")
    if enum_type == "NPI-2":
        display_name = basic.get("organization_name", "").strip()
    else:
        parts = [
            basic.get("first_name", ""),
            basic.get("middle_name", ""),
            basic.get("last_name", ""),
            basic.get("credential", ""),
        ]
        display_name = " ".join(p for p in parts if p).strip()

    # Practice address (first location address preferred)
    practice = next(
        (a for a in addrs if a.get("address_purpose") == "LOCATION"),
        addrs[0] if addrs else {},
    )

    # Primary taxonomy (where primary=True)
    primary_taxon = next(
        (t for t in taxons if t.get("primary")),
        taxons[0] if taxons else {},
    )

    return {
        "npi":             raw.get("number", ""),
        "enumeration_type": enum_type,
        "display_name":    display_name,
        "status":          basic.get("status", ""),
        "credential":      basic.get("credential", ""),
        "taxonomy_code":   primary_taxon.get("code", ""),
        "taxonomy_desc":   primary_taxon.get("desc", ""),
        "taxonomy_state":  primary_taxon.get("state", ""),
        "taxonomy_license": primary_taxon.get("license", ""),
        "practice_city":   practice.get("city", ""),
        "practice_state":  practice.get("state", ""),
        "practice_zip":    practice.get("postal_code", ""),
        "enumeration_date": basic.get("enumeration_date", ""),
        "last_updated":    basic.get("last_updated", ""),
        "source":          "NPPES NPI Registry",
    }


def _normalise_finra_record(raw: dict, crd: str) -> Optional[dict]:
    """Extract fields from FINRA BrokerCheck response."""
    if not raw:
        return None
    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        return None

    src = hits[0].get("_source", hits[0])
    return {
        "crd_number":          crd,
        "individual_name":     src.get("ind_firstname", "") + " " + src.get("ind_lastname", ""),
        "registration_status": src.get("ind_bc_scope", ""),
        "disclosures_count":   src.get("ind_disclosures_count", 0),
        "qualifications_count": src.get("ind_iac_count", 0),
        "current_employers":   src.get("ind_current_employer", ""),
        "source":              "FINRA BrokerCheck",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MARKDOWN BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def _build_npi_markdown(result: dict) -> str:
    name   = result.get("display_name", "Unknown")
    npi    = result.get("npi", "")
    status = result.get("status", "")
    taxon  = result.get("taxonomy_desc", "")
    code   = result.get("taxonomy_code", "")
    city   = result.get("practice_city", "")
    state  = result.get("practice_state", "")
    lic    = result.get("taxonomy_license", "")
    lic_st = result.get("taxonomy_state", "")
    enum_d = result.get("enumeration_date", "")
    upd    = result.get("last_updated", "")

    status_label = "Active" if status == "A" else (status or "Unknown")

    lines = [
        f"## {name}",
        f"**NPI:** {npi}  |  **Status:** {status_label}",
        "",
    ]
    if taxon:
        lines.append(f"**Primary Speciality:** {taxon}")
    if code:
        lines.append(f"**Taxonomy Code:** {code}")
    if lic:
        lines.append(f"**State Licence:** {lic} ({lic_st})")
    if city or state:
        lines.append(f"**Practice Location:** {city}, {state}")
    if enum_d:
        lines.append(f"**NPI Issued:** {enum_d}")
    if upd:
        lines.append(f"**Last Updated:** {upd}")
    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_search_markdown(
    results: list, name: str, state: str, speciality: str
) -> str:
    header = f"## NPI Registry Search: '{name}'"
    if state:
        header += f" | State: {state}"
    if speciality:
        header += f" | Speciality: {speciality}"
    lines = [header, f"Found **{len(results)}** result(s).\n"]

    if not results:
        lines.append("No providers found matching the search criteria.")
    else:
        lines.append("| NPI | Name | Speciality | City | State | Status |")
        lines.append("|-----|------|------------|------|-------|--------|")
        for r in results:
            status_label = "Active" if r.get("status") == "A" else (r.get("status") or "—")
            lines.append(
                f"| {r.get('npi','')} "
                f"| {r.get('display_name','')} "
                f"| {r.get('taxonomy_desc','')} "
                f"| {r.get('practice_city','')} "
                f"| {r.get('practice_state','')} "
                f"| {status_label} |"
            )

    lines.append(f"\n*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_finra_markdown(result: dict) -> str:
    name   = result.get("individual_name", "Unknown").strip()
    crd    = result.get("crd_number", "")
    status = result.get("registration_status", "")
    disc   = result.get("disclosures_count", 0)
    quals  = result.get("qualifications_count", 0)
    empl   = result.get("current_employers", "")

    lines = [
        f"## {name}",
        f"**CRD Number:** {crd}  |  **Registration Status:** {status or 'See FINRA BrokerCheck'}",
        "",
    ]
    if quals:
        lines.append(f"**Qualifications on File:** {quals}")
    if disc is not None:
        lines.append(f"**Disclosures on File:** {disc}")
    if empl:
        lines.append(f"**Current Employer(s):** {empl}")
    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)


def _build_sam_exclusion_markdown(result: dict, query: str) -> str:
    found = result.get("exclusion_found", False)
    count = result.get("exclusion_count", 0)

    lines = [f"## SAM.gov Exclusion Check: '{query}'\n"]

    if found:
        lines.append(f"**Status: FOUND on federal exclusions list** ({count} record(s))\n")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        for field, label in [
            ("exclusion_type", "Exclusion Type"),
            ("agency", "Excluding Agency"),
            ("classification", "Classification"),
            ("active_date", "Active Date"),
            ("termination_date", "Termination Date"),
        ]:
            val = result.get(field, "")
            if val:
                lines.append(f"| {label} | {val} |")
    else:
        lines.append("**Status: NOT FOUND on federal exclusions list**\n")
        lines.append("No active federal exclusions found for this query.")

    lines.append("")
    lines.append(f"*{DISCLAIMER}*")
    return "\n".join(lines)
