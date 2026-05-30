"""
datanexus/tools/cve_sprint7.py — Sprint 7 CVE aggregator tool.

Tools:
  fetch_cve_risk_summary — instant CVE risk verdict combining CVSS, CISA KEV,
                           and EPSS in one parallel call.

Verdict table (evaluate IN ORDER — FIRST MATCH WINS):
  1. UNKNOWN:         all three inputs are null (all upstreams down)
  2. CRITICAL_EXPLOIT: kev_listed == true OR epss_score >= 0.7
  3. HIGH_RISK:       cvss_score >= 9.0 OR (epss_score >= 0.3 AND cvss_score >= 7.0)
  4. MODERATE:        cvss_score >= 4.0
  5. LOW:             otherwise (at least one input non-null, no higher threshold met)

UNKNOWN fires FIRST — not LOW — because LOW means "checked, low risk."
When all upstreams are down, we cannot make any determination. (D2 fix)

Circuit breakers imported from _circuit_breakers.py. Never defined here.
"""

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import pybreaker
from fastmcp import FastMCP

from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import track_tool_call
from datanexus.tools._cve_utils import (
    _fetch_cve_detail_util,
    _fetch_cisa_kev_util,
    _fetch_cve_epss_util,
)
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.cve_sprint7")

cve_sprint7 = FastMCP("DataNexus CVE Sprint7")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_DISCLAIMER = (
    "CVE data sourced from NIST NVD, CISA KEV, and FIRST EPSS. "
    "DataNexus does not warrant completeness. "
    "Verify with your security team before making patch decisions."
)

# Vendor advisory domains that confirm patch availability
_PATCH_ALLOWLIST = {
    "github.com",
    "access.redhat.com",
    "security.debian.org",
    "ubuntu.com",
    "lists.apache.org",
    "msrc.microsoft.com",
    "portal.msrc.microsoft.com",
    "support.microsoft.com",
    "oracle.com",
    "cisco.com",
    "kb.cert.org",
    "tools.cisco.com",
}

_PATCH_PATH_PATTERNS = [
    "/advisories",
    "/security",
    "/security-alerts",
    "/security/advisories",
]


def _is_patch_url(url: str) -> bool:
    """Return True if a URL domain+path matches the vendor advisory allowlist."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().lstrip("www.")
        path = parsed.path.lower()
        # github.com/advisories or github.com/*/security
        if host == "github.com":
            return "/advisories" in path or path.rstrip("/").endswith("/security")
        # support.microsoft.com/*/security
        if host == "support.microsoft.com":
            return "/security" in path
        # oracle.com/security-alerts
        if host == "oracle.com":
            return "/security-alerts" in path
        # cisco.com/security/advisories or tools.cisco.com/security/center
        if host in ("cisco.com", "tools.cisco.com"):
            return "/security" in path
        # remaining allowlist domains — any path counts
        for allowed in _PATCH_ALLOWLIST:
            if host == allowed or host.endswith("." + allowed):
                return True
    except Exception:
        pass
    return False


def _derive_patch_available(references: list[dict]) -> Optional[bool]:
    """
    Parse NVD references for patch-confirming URLs.
    Returns True if found, None if not (null ≠ false per spec).
    """
    for ref in references:
        url = ref.get("url", "")
        if url and _is_patch_url(url):
            return True
    return None


def _extract_ecosystems(configurations: list) -> list[str]:
    """Extract affected ecosystems from NVD CPE configurations."""
    ecosystems = set()
    cpe_to_eco = {
        "npm": "npm", "node": "npm",
        "pypi": "pypi", "python": "pypi",
        "golang": "go",
        "rust": "cargo", "cargo": "cargo",
        "java": "maven", "maven": "maven",
    }
    for node_group in configurations:
        for node in node_group.get("nodes", [node_group]):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "").lower()
                parts = cpe.split(":")
                if len(parts) > 4:
                    product = parts[4]
                    for key, eco in cpe_to_eco.items():
                        if key in product:
                            ecosystems.add(eco)
    return sorted(ecosystems)


def _build_verdict(
    cvss_score: Optional[float],
    kev_listed: Optional[bool],
    epss_score: Optional[float],
) -> str:
    """
    Evaluate verdict IN ORDER — first match wins. (D2 fix)
    1. UNKNOWN:          all three inputs are null
    2. CRITICAL_EXPLOIT: kev_listed == true OR epss_score >= 0.7
    3. HIGH_RISK:        cvss_score >= 9.0 OR (epss >= 0.3 AND cvss >= 7.0)
    4. MODERATE:         cvss_score >= 4.0
    5. LOW:              otherwise (at least one non-null, no higher threshold met)
    """
    if cvss_score is None and kev_listed is None and epss_score is None:
        return "UNKNOWN"
    if kev_listed is True or (epss_score is not None and epss_score >= 0.7):
        return "CRITICAL_EXPLOIT"
    if (
        (cvss_score is not None and cvss_score >= 9.0)
        or (epss_score is not None and epss_score >= 0.3 and cvss_score is not None and cvss_score >= 7.0)
    ):
        return "HIGH_RISK"
    if cvss_score is not None and cvss_score >= 4.0:
        return "MODERATE"
    return "LOW"


def _build_tldr(verdict: str, kev_listed: Optional[bool], cvss_score: Optional[float]) -> str:
    if verdict == "UNKNOWN":
        return "Risk assessment unavailable — all upstream sources unreachable."
    if verdict == "CRITICAL_EXPLOIT":
        if kev_listed:
            return "Actively exploited (CISA KEV). Patch immediately."
        return "High exploitation probability (EPSS ≥ 0.7). Patch immediately."
    if verdict == "HIGH_RISK":
        return f"High risk (CVSS {cvss_score or '?'}). Patch as soon as possible."
    if verdict == "MODERATE":
        return f"Moderate risk (CVSS {cvss_score or '?'}). Schedule patching."
    return "Low risk. Monitor for changes."


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — fetch_cve_risk_summary
# ══════════════════════════════════════════════════════════════════════════════

@cve_sprint7.tool()
@with_timeout
@verify_entitlement("T10")
async def fetch_cve_risk_summary(cve_id: str) -> dict:
    """Instant CVE risk verdict. Combines CVSS severity, CISA KEV exploitation status, and EPSS probability in one parallel call. Returns CRITICAL_EXPLOIT, HIGH_RISK, MODERATE, LOW, or UNKNOWN verdict with patch availability from vendor advisories. UNKNOWN means all upstream sources were unreachable — not that risk is low. Rate limit: 60/minute. No auth required. For security engineers triaging vulnerabilities after fetch_cve_watch fires. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="security_fetch_cve_risk_summary", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        cve_clean = cve_id.strip().upper()
        params = {"cve_id": cve_clean}

        async with AuditContext("T10", params, "1.0") as ctx:
            if not _CVE_RE.match(cve_clean):
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="Invalid CVE ID format. Expected CVE-YYYY-NNNNN (e.g. CVE-2021-44228).",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            # ── Parallel upstream calls ───────────────────────────────────────
            cve_detail, kev_status, epss_result = await asyncio.gather(
                _fetch_cve_detail_util(cve_clean),
                _fetch_cisa_kev_util(cve_clean),
                _fetch_cve_epss_util(cve_clean),
                return_exceptions=True,
            )

            # ── Extract values (null when upstream raised) ────────────────────
            nvd_status   = "OK"
            cisa_status  = "OK"
            epss_status  = "OK"

            cvss_score:   Optional[float] = None
            kev_listed:   Optional[bool]  = None
            epss_score:   Optional[float] = None
            references:   list            = []
            configurations: list          = []

            if isinstance(cve_detail, Exception):
                nvd_status = "CIRCUIT_OPEN" if isinstance(cve_detail, pybreaker.CircuitBreakerError) else "ERROR"
                log.warning("fetch_cve_risk_summary NVD error cve=%s: %s", cve_clean, cve_detail)
            else:
                cvss_score      = cve_detail.get("cvss_score")
                references      = cve_detail.get("references", [])
                configurations  = cve_detail.get("configurations", [])

            if isinstance(kev_status, Exception):
                cisa_status = "CIRCUIT_OPEN" if isinstance(kev_status, pybreaker.CircuitBreakerError) else "ERROR"
                log.warning("fetch_cve_risk_summary CISA error cve=%s: %s", cve_clean, kev_status)
            else:
                kev_listed = kev_status.get("kev_listed")

            if isinstance(epss_result, Exception):
                epss_status = "CIRCUIT_OPEN" if isinstance(epss_result, pybreaker.CircuitBreakerError) else "ERROR"
                log.warning("fetch_cve_risk_summary EPSS error cve=%s: %s", cve_clean, epss_result)
            else:
                epss_score = epss_result.get("epss_score")

            # ── Derived fields ────────────────────────────────────────────────
            patch_available    = _derive_patch_available(references)
            affected_ecosystems = _extract_ecosystems(configurations)
            verdict            = _build_verdict(cvss_score, kev_listed, epss_score)
            tldr               = _build_tldr(verdict, kev_listed, cvss_score)

            data_as_of = datetime.now(timezone.utc).isoformat()
            data = {
                "cve_id":              cve_clean,
                "verdict":             verdict,
                "cvss_score":          cvss_score,
                "kev_listed":          kev_listed,
                "epss_score":          epss_score,
                "patch_available":     patch_available,
                "affected_ecosystems": affected_ecosystems,
                "tldr":                tldr,
                "upstream_status": {
                    "nvd":  nvd_status,
                    "cisa": cisa_status,
                    "epss": epss_status,
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
        log.exception("fetch_cve_risk_summary error cve=%s", cve_id)
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        asyncio.create_task(track_tool_call(
            tool_id="T10",
            tool_name="fetch_cve_risk_summary",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))
