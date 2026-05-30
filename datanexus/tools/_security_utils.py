"""
datanexus/tools/_security_utils.py — Shared utility functions for security tools.

Extracted for Sprint 6: fetch_package_risk_brief calls these directly.
HTTP self-calls are forbidden per SPRINT6_PROMPT.md PRE-3.

Callers:
  fetch_package_vulnerabilities  → thin MCP wrapper
  fetch_package_licence          → thin MCP wrapper
  fetch_package_risk_brief       → aggregator (calls all 3 in asyncio.gather)
"""

import logging
import os
from typing import Optional
from urllib.parse import quote

import httpx
import pybreaker

from datanexus.tools._circuit_breakers import (
    _nvd_breaker,
    _depsdev_breaker,
    _osv_breaker,
)

log = logging.getLogger("datanexus.tools._security_utils")

# ── HTTP constants ─────────────────────────────────────────────────────────────

_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT      = httpx.Timeout(8.0, connect=5.0)
_OSV_QUERY    = "https://api.osv.dev/v1/query"
_DEPS_DEV     = "https://api.deps.dev/v3alpha"

# ── Ecosystem maps ─────────────────────────────────────────────────────────────

_DEPS_SYSTEM: dict[str, str] = {
    "pypi":      "PYPI",
    "npm":       "NPM",
    "maven":     "MAVEN",
    "go":        "GO",
    "cargo":     "CARGO",
    "crates.io": "CARGO",
    "nuget":     "NUGET",
    "rubygems":  "RUBYGEMS",
}

_OSV_ECOSYSTEM: dict[str, str] = {
    "pypi":      "PyPI",
    "npm":       "npm",
    "maven":     "Maven",
    "go":        "Go",
    "cargo":     "crates.io",
    "nuget":     "NuGet",
    "rubygems":  "RubyGems",
}

# ── Licence risk buckets ───────────────────────────────────────────────────────

_COPYLEFT = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "MPL-2.0", "EUPL-1.2", "CDDL-1.0", "CPL-1.0",
}

_INCOMPATIBLE_KEYWORDS = {
    "UNLICENSED", "PROPRIETARY", "SEE LICENSE IN",
    "COMMERCIAL", "ALL RIGHTS RESERVED",
}


def _classify_licence(licences: list[str]) -> str:
    """Map SPDX licence list → 'PERMISSIVE' | 'COPYLEFT' | 'INCOMPATIBLE' | 'UNKNOWN'."""
    if not licences:
        return "UNKNOWN"
    normalized = [lic.strip().upper() for lic in licences]
    for lic in normalized:
        for keyword in _INCOMPATIBLE_KEYWORDS:
            if keyword in lic:
                return "INCOMPATIBLE"
    for lic in licences:
        if lic.strip() in _COPYLEFT:
            return "COPYLEFT"
    return "PERMISSIVE"


# ── Version resolution ─────────────────────────────────────────────────────────

async def _resolve_version(package: str, ecosystem: str) -> Optional[str]:
    """Resolve latest version from PyPI or npm registry. Returns None on failure."""
    eco = ecosystem.lower()
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            if eco == "pypi":
                resp = await client.get(f"https://pypi.org/pypi/{quote(package, safe='')}/json")
                resp.raise_for_status()
                return resp.json().get("info", {}).get("version")
            if eco == "npm":
                resp = await client.get(f"https://registry.npmjs.org/{quote(package, safe='')}")
                resp.raise_for_status()
                return resp.json().get("dist-tags", {}).get("latest")
    except Exception as exc:
        log.warning("_resolve_version failed pkg=%s eco=%s: %s", package, ecosystem, exc)
    return None


# ── Core utility: vulnerabilities ──────────────────────────────────────────────

async def _fetch_vulns(package: str, ecosystem: str, version: str) -> dict:
    """
    Fetch CVE counts for a package@version from OSV.dev.

    Returns:
        {
            "critical_cve_count": int | None,
            "high_cve_count": int | None,
            "vuln_ids": list[str],
            "status": "OK" | "ERROR" | "CIRCUIT_OPEN",
        }
    """
    osv_eco = _OSV_ECOSYSTEM.get(ecosystem.lower(), ecosystem)
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": osv_eco},
    }

    async def _call() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.post(_OSV_QUERY, json=payload)
            resp.raise_for_status()
            return resp.json()

    try:
        raw = await _osv_breaker.call_async(_call)
        vulns = raw.get("vulns", [])
        critical = 0
        high = 0
        ids = []
        for v in vulns:
            sev = v.get("severity") or {}
            # Try aliases for CVE IDs
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    ids.append(alias)
                    break
            else:
                ids.append(v.get("id", ""))
            level = sev.get("level", "").upper()
            if level == "CRITICAL":
                critical += 1
            elif level == "HIGH":
                high += 1
        return {
            "critical_cve_count": critical,
            "high_cve_count":     high,
            "vuln_ids":           ids[:20],
            "status":             "OK",
        }
    except pybreaker.CircuitBreakerError:
        log.warning("_fetch_vulns circuit open pkg=%s", package)
        return {"critical_cve_count": None, "high_cve_count": None, "vuln_ids": [], "status": "CIRCUIT_OPEN"}
    except Exception as exc:
        log.warning("_fetch_vulns error pkg=%s: %s", package, exc)
        return {"critical_cve_count": None, "high_cve_count": None, "vuln_ids": [], "status": "ERROR"}


# ── Core utility: licence ──────────────────────────────────────────────────────

async def _fetch_licence(package: str, ecosystem: str, version: Optional[str] = None) -> dict:
    """
    Fetch SPDX licence and classify risk from deps.dev.

    Returns:
        {
            "licences": list[str],
            "licence_risk": "PERMISSIVE" | "COPYLEFT" | "INCOMPATIBLE" | "UNKNOWN",
            "status": "OK" | "ERROR" | "CIRCUIT_OPEN",
        }
    """
    eco = ecosystem.lower()
    deps_system = _DEPS_SYSTEM.get(eco, eco.upper())

    resolved = version
    if not resolved:
        resolved = await _resolve_version(package, ecosystem)
    if not resolved:
        return {"licences": [], "licence_risk": "UNKNOWN", "status": "ERROR"}

    pkg_enc = quote(package, safe="")
    ver_enc = quote(resolved, safe="")
    url = f"{_DEPS_DEV}/systems/{deps_system}/packages/{pkg_enc}/versions/{ver_enc}"

    async def _call() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    try:
        raw = await _depsdev_breaker.call_async(_call)
        licences = raw.get("licenses", [])
        return {
            "licences":     licences,
            "licence_risk": _classify_licence(licences),
            "status":       "OK",
        }
    except pybreaker.CircuitBreakerError:
        log.warning("_fetch_licence circuit open pkg=%s", package)
        return {"licences": [], "licence_risk": "UNKNOWN", "status": "CIRCUIT_OPEN"}
    except Exception as exc:
        log.warning("_fetch_licence error pkg=%s: %s", package, exc)
        return {"licences": [], "licence_risk": "UNKNOWN", "status": "ERROR"}


# ── Core utility: deps.dev transitive count ────────────────────────────────────

async def _fetch_depsdev(package: str, ecosystem: str, version: str) -> dict:
    """
    Fetch transitive dependency count from deps.dev.

    Returns:
        {
            "transitive_count": int | None,
            "status": "OK" | "ERROR" | "CIRCUIT_OPEN",
        }
    """
    eco = ecosystem.lower()
    deps_system = _DEPS_SYSTEM.get(eco, eco.upper())
    pkg_enc = quote(package, safe="")
    ver_enc = quote(version, safe="")
    url = (
        f"{_DEPS_DEV}/systems/{deps_system}/packages/{pkg_enc}"
        f"/versions/{ver_enc}/dependencies"
    )

    async def _call() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    try:
        raw = await _depsdev_breaker.call_async(_call)
        nodes = raw.get("nodes", [])
        indirect = [n for n in nodes if n.get("relation") != "SELF"]
        return {"transitive_count": len(indirect), "status": "OK"}
    except pybreaker.CircuitBreakerError:
        log.warning("_fetch_depsdev circuit open pkg=%s", package)
        return {"transitive_count": None, "status": "CIRCUIT_OPEN"}
    except Exception as exc:
        log.warning("_fetch_depsdev error pkg=%s: %s", package, exc)
        return {"transitive_count": None, "status": "ERROR"}
