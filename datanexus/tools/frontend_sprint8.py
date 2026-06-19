"""
datanexus/tools/frontend_sprint8.py — Sprint 8B frontend security wedge (T20).

Tools:
  frontend_security_detect_typosquatting    — DL-distance vs top-500 frontend corpus
  frontend_security_audit_manifest          — package.json → SHIP/CAUTION/BLOCK
  frontend_security_audit_ci_pipeline       — CI config secret + lockfile scanner
  frontend_security_fetch_package_risk_brief — npm-scoped wrapper with UI signals
"""

import asyncio
import json
import logging
import pathlib
import re
import time
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from pydantic import Field

import httpx
from fastmcp import FastMCP

from datanexus.core.audit import AuditContext, standard_response_fields
from datanexus.core.schema import ErrorCode, error_response
from datanexus.core.timeout import with_timeout
from datanexus.analytics import fire_and_forget, track_tool_call
from datanexus.tools.security_sprint6 import _damerau_levenshtein
from datanexus.tools._security_utils import _fetch_vulns, _fetch_licence, _resolve_version
from datanexus.tools._maintainer_utils import _fetch_maintainer_history
from payment.entitlement import verify_entitlement

log = logging.getLogger("datanexus.tools.frontend_sprint8")

frontend_sprint8 = FastMCP("datanexus-frontend-sprint8")

_DISCLAIMER = (
    "Security data sourced from OSV.dev, deps.dev, npm registry. "
    "DataNexus does not warrant completeness. "
    "Verify with your security team before making decisions."
)

_HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_SBOM_SIZE_LIMIT = 512_000  # 500 KB

# Load frontend corpus (top-500 npm packages) — lazy loaded once
_FRONTEND_CORPUS: Optional[list] = None

_CORPUS_PATH = pathlib.Path(__file__).parent.parent.parent / "data" / "frontend_corpus.json"


def _get_frontend_corpus() -> list:
    global _FRONTEND_CORPUS
    if _FRONTEND_CORPUS is None:
        try:
            with open(_CORPUS_PATH) as f:
                _FRONTEND_CORPUS = json.load(f)
        except Exception as exc:
            log.warning("frontend_sprint8: corpus load failed: %s", exc)
            _FRONTEND_CORPUS = []
    return _FRONTEND_CORPUS


# UI component library name prefixes for is_ui_component detection
_UI_PREFIXES = (
    "react-", "@radix-ui/", "@mui/", "@material-ui/",
    "vue-", "svelte-", "@angular/", "@chakra-ui/",
    "@headlessui/", "@tailwindcss/", "@emotion/",
    "@storybook/", "storybook-", "@shadcn/",
)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — frontend_security_detect_typosquatting
# ══════════════════════════════════════════════════════════════════════════════

@frontend_sprint8.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T20")
async def detect_typosquatting(
    package_name: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    ecosystem: Annotated[Literal["npm", "pypi"], Field(description="Package ecosystem: npm or pypi. Default npm.")] = "npm",
) -> dict:
    """Typosquatting detection optimised for the top 500 frontend packages (React, Vite, Axios, Lodash, etc.). Fewer false positives than a full npm scan. For backend packages, use security_detect_typosquatting instead. package_name: Package name to check. Required. ecosystem: npm or pypi — default npm. Uses Damerau-Levenshtein distance ≤ 2 against a curated frontend-package corpus. Returns is_likely_typosquat, closest_match, distance, and risk_level (LOW/MEDIUM/HIGH). Read-only. No side effects. Idempotent. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="frontend_security_detect_typosquatting", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        pkg = package_name.strip().lower()
        if not pkg:
            return {"status": "error", "error_code": "VALIDATION_ERROR", "message": "package_name must not be empty."}

        params = {"package_name": pkg, "ecosystem": ecosystem}

        async with AuditContext("T20", params, "1.0") as ctx:
            corpus = _get_frontend_corpus()
            if not corpus:
                return error_response(
                    error_code=ErrorCode.INTERNAL_ERROR,
                    message="Frontend corpus unavailable. Try security_detect_typosquatting instead.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=False,
                )

            best_match = None
            best_dist  = 99

            for ref_name in corpus:
                if ref_name == pkg:
                    data_as_of = datetime.now(timezone.utc).isoformat()
                    _success = True
                    return {
                        "status":             "ok",
                        "tool_id":            "T20",
                        "is_likely_typosquat": False,
                        "package_name":        pkg,
                        "closest_match":       pkg,
                        "distance":            0,
                        "similarity_score":    1.0,
                        "risk_level":          "LOW",
                        "message":             f"'{pkg}' is a known frontend package.",
                        "disclaimer":          _DISCLAIMER,
                        **standard_response_fields(ctx.query_hash, data_as_of, True),
                    }
                dist = _damerau_levenshtein(pkg, ref_name)
                if dist < best_dist:
                    best_dist  = dist
                    best_match = ref_name

            data_as_of = datetime.now(timezone.utc).isoformat()

            is_typosquat = best_dist is not None and best_dist <= 2
            if best_dist == 1:
                risk = "HIGH"
            elif best_dist == 2:
                risk = "MEDIUM"
            else:
                risk = "LOW"
                is_typosquat = False

            sim = max(0.0, round(1.0 - (best_dist or 0) / max(len(pkg), 1), 2))

            _success = True
            return {
                "status":              "ok",
                "tool_id":             "T20",
                "is_likely_typosquat": is_typosquat,
                "package_name":        pkg,
                "closest_match":       best_match,
                "distance":            best_dist,
                "similarity_score":    sim,
                "risk_level":          risk,
                "corpus_size":         len(corpus),
                "disclaimer":          _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
    except Exception as exc:
        _error_code = type(exc).__name__
        log.exception("frontend_security_detect_typosquatting error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T20",
            tool_name="frontend_security_detect_typosquatting",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — frontend_security_audit_manifest
# ══════════════════════════════════════════════════════════════════════════════

@frontend_sprint8.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T20")
async def audit_manifest(
    manifest: Annotated[str, Field(description="Contents of package.json as a string. Required. 500 KB max.")],
    lockfile: Annotated[Optional[str], Field(description="Contents of package-lock.json or yarn.lock. Optional.")] = None,
) -> dict:
    """Audit a frontend package.json for security risks — returns a single SHIP/CAUTION/BLOCK verdict with licence risks and abandonment signals. Different from security_fetch_package_vulnerabilities which audits a single package — this takes your full package.json. manifest: Contents of package.json as a string. Required. 500 KB max. lockfile: Contents of package-lock.json or yarn.lock (optional). If provided, audits pinned versions; otherwise audits semver ranges. BLOCK: any critical CVE in direct deps OR GPL-3.0 in commercial context. CAUTION: high CVE count ≥ 2 OR copyleft licence OR direct dep abandoned > 18 months. Sources: OSV.dev (CVEs), deps.dev (licences), npm registry (abandonment). Read-only. No side effects. Idempotent. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="frontend_security_audit_manifest", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        if len(manifest.encode()) > _SBOM_SIZE_LIMIT:
            return {"verdict": "ERROR", "error": "manifest exceeds 500 KB size limit."}

        try:
            pkg_json = json.loads(manifest)
        except json.JSONDecodeError as exc:
            return {"verdict": "ERROR", "error": f"Invalid JSON in manifest: {exc}"}

        import hashlib
        manifest_hash = hashlib.sha256(manifest.encode()).hexdigest()[:16]
        params = {"manifest_hash": manifest_hash}

        async with AuditContext("T20", params, "1.0") as ctx:
            # Extract direct deps
            direct_deps = {}
            direct_deps.update(pkg_json.get("dependencies", {}))
            direct_deps.update(pkg_json.get("devDependencies", {}))

            if not direct_deps:
                return {
                    "status":   "ok",
                    "tool_id":  "T20",
                    "verdict":  "SHIP",
                    "message":  "No dependencies found in manifest.",
                    "critical_cves":     0,
                    "high_cves":         0,
                    "licence_risks":     [],
                    "abandoned_packages":[],
                    "total_packages":    0,
                    **standard_response_fields(ctx.query_hash, datetime.now(timezone.utc).isoformat(), True),
                }

            # Resolve pinned versions from lockfile if provided
            pinned = {}
            if lockfile:
                pinned = _extract_pinned_versions(lockfile)

            packages = []
            for name, semver in list(direct_deps.items())[:100]:
                version = pinned.get(name) or _strip_semver_prefix(semver)
                packages.append({"name": name, "version": version, "ecosystem": "npm"})

            sem = asyncio.Semaphore(10)

            async def _audit_one(pkg):
                try:
                    vulns = await _fetch_vulns(pkg["name"], "npm", pkg["version"])
                    return ("vulns", pkg["name"], vulns)
                except Exception as exc:
                    return ("vulns", pkg["name"], None)

            async def _licence_one(pkg):
                try:
                    lic = await _fetch_licence(pkg["name"], "npm")
                    return ("licence", pkg["name"], lic)
                except Exception:
                    return ("licence", pkg["name"], None)

            results = await asyncio.gather(
                *[_audit_one(p) for p in packages],
                *[_licence_one(p) for p in packages],
                return_exceptions=True,
            )

            vuln_map = {}
            lic_map  = {}
            for r in results:
                if isinstance(r, Exception):
                    continue
                kind, name, data = r
                if kind == "vulns":
                    vuln_map[name] = data
                else:
                    lic_map[name] = data

            critical_cves = 0
            high_cves     = 0
            cve_details   = []
            licence_risks = []
            abandoned     = []

            _now = datetime.now(timezone.utc)
            _18m_ago = _now - _TIMEDELTA_18M

            for pkg in packages:
                name    = pkg["name"]
                version = pkg["version"]
                vulns   = vuln_map.get(name)
                lic     = lic_map.get(name)

                if vulns:
                    c = vulns.get("critical_cve_count") or 0
                    h = vulns.get("high_cve_count") or 0
                    critical_cves += c
                    high_cves     += h
                    if c > 0 or h > 0:
                        cve_details.append({
                            "name":     name,
                            "version":  version,
                            "critical": c,
                            "high":     h,
                        })

                if lic:
                    lic_id = lic.get("licence_id", "")
                    lic_risk = lic.get("licence_risk", "")
                    if lic_id in ("GPL-3.0", "AGPL-3.0", "GPL-2.0"):
                        licence_risks.append({"name": name, "licence": lic_id, "risk": "INCOMPATIBLE"})
                    elif lic_risk in ("COPYLEFT", "HIGH"):
                        licence_risks.append({"name": name, "licence": lic_id, "risk": "COPYLEFT"})

                    last_release_str = lic.get("last_release_date", "")
                    if last_release_str:
                        try:
                            lr = datetime.fromisoformat(last_release_str)
                            if lr < _18m_ago:
                                abandoned.append({"name": name, "last_release": last_release_str})
                        except ValueError:
                            pass

            # Verdict logic
            incompatible_licences = {r["name"] for r in licence_risks if r["risk"] == "INCOMPATIBLE"}
            copyleft_licences     = {r["name"] for r in licence_risks if r["risk"] == "COPYLEFT"}

            if critical_cves > 0 or incompatible_licences:
                verdict = "BLOCK"
            elif high_cves >= 2 or copyleft_licences or abandoned:
                verdict = "CAUTION"
            else:
                verdict = "SHIP"

            data_as_of = _now.isoformat()
            _success = True
            return {
                "status":              "ok",
                "tool_id":             "T20",
                "verdict":             verdict,
                "critical_cves":       critical_cves,
                "high_cves":           high_cves,
                "cve_details":         cve_details,
                "licence_risks":       licence_risks,
                "abandoned_packages":  abandoned,
                "total_packages":      len(packages),
                "disclaimer":          _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
    except Exception as exc:
        _error_code = type(exc).__name__
        log.exception("frontend_security_audit_manifest error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T20",
            tool_name="frontend_security_audit_manifest",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


_TIMEDELTA_18M = __import__("datetime").timedelta(days=548)  # ~18 months


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — frontend_security_audit_ci_pipeline
# ══════════════════════════════════════════════════════════════════════════════

# Secret patterns — literal values only, NOT env var refs (${{ secrets.X }} is safe)
_SECRET_PATTERNS = [
    (re.compile(r'\bAKIA[A-Z0-9]{16}\b'),           "AWS_ACCESS_KEY",        "CRITICAL"),
    (re.compile(r'\bghp_[a-zA-Z0-9]{36}\b'),        "GITHUB_TOKEN",          "CRITICAL"),
    (re.compile(r'\bsk_live_[a-zA-Z0-9]{24}\b'),    "STRIPE_LIVE_KEY",       "CRITICAL"),
    (re.compile(r'\bghs_[a-zA-Z0-9]{36}\b'),        "GITHUB_SERVER_TOKEN",   "CRITICAL"),
    (re.compile(r'\b[0-9a-f]{64}\b'),               "HEX64_SECRET_PATTERN",  "HIGH"),
]

# Safe indirect reference patterns — do NOT flag these
_SAFE_REF_RE = re.compile(r'\$\{\{.*?secrets\..*?\}\}|\$\{\{.*?env\..*?\}\}')


@frontend_sprint8.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T20")
async def audit_ci_pipeline(
    config: Annotated[str, Field(description="Raw YAML/TOML content of your CI config. Required. 500 KB max.")],
    config_type: Annotated[Literal["github_actions", "vercel", "netlify"], Field(description="CI config type: github_actions, vercel, or netlify. Default github_actions.")] = "github_actions",
) -> dict:
    """Scan GitHub Actions, Vercel, or Netlify CI configs for exposed secrets, missing lockfile enforcement, and unpinned dependencies. Paste your config content — no filesystem access required. config: Raw YAML/TOML content of your CI config. Required. 500 KB max. config_type: github_actions (full check suite), vercel, or netlify (secrets only in Sprint 8). Returns risk_level (LOW/MEDIUM/HIGH/CRITICAL), findings list with severity and line hints. NOTE: ${{ secrets.FOO }} and ${{ env.FOO }} references are NOT flagged — only literal secret values. Read-only. No side effects. Idempotent. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="frontend_security_audit_ci_pipeline", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        if len(config.encode()) > _SBOM_SIZE_LIMIT:
            return {"risk_level": "ERROR", "error": "Config exceeds 500 KB size limit."}

        import hashlib
        config_hash = hashlib.sha256(config.encode()).hexdigest()[:16]
        # Config is security-sensitive — redact from AuditContext
        params = {"config_hash": config_hash, "config_type": config_type, "config": "[REDACTED]"}

        async with AuditContext("T20", params, "1.0") as ctx:
            findings = _scan_config(config, config_type)

            severities = [f["severity"] for f in findings]
            if "CRITICAL" in severities:
                risk = "CRITICAL"
            elif "HIGH" in severities:
                risk = "HIGH"
            elif "MEDIUM" in severities:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            data_as_of = datetime.now(timezone.utc).isoformat()
            _success = True
            return {
                "status":        "ok",
                "tool_id":       "T20",
                "risk_level":    risk,
                "config_type":   config_type,
                "findings":      findings,
                "finding_count": len(findings),
                "disclaimer":    _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
    except Exception as exc:
        _error_code = type(exc).__name__
        log.exception("frontend_security_audit_ci_pipeline error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T20",
            tool_name="frontend_security_audit_ci_pipeline",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — frontend_security_fetch_package_risk_brief
# ══════════════════════════════════════════════════════════════════════════════

@frontend_sprint8.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@with_timeout
@verify_entitlement("T20")
async def fetch_package_risk_brief(
    package_name: Annotated[str, Field(description="Package name e.g. requests. Required.")],
    version: Annotated[Optional[str], Field(description="Package version e.g. 2.28.0. Optional.")] = None,
) -> dict:
    """SHIP/CAUTION/BLOCK risk brief for an npm package with frontend-specific context. Wraps security_fetch_package_risk_brief restricted to npm, and adds weekly_downloads and is_ui_component signals. package_name: npm package name. Required. version: Optional pinned version — latest resolved if omitted. Returns verdict, CVE counts, licence risk, maintainer health, weekly_downloads, is_ui_component. Use security_fetch_package_risk_brief for non-npm ecosystems. Read-only. No side effects. Idempotent. Sources: OSV.dev, deps.dev, npm registry. If this tool's response does not serve the user's need, call report_feedback with feedback_type="agent_gap", tool_id="frontend_security_fetch_package_risk_brief", intended_query="{what the user needed}", gap_description="{what was missing or wrong in the result}"."""
    _t0 = time.monotonic()
    _success = False
    _error_code = None
    try:
        pkg = package_name.strip()
        ver = version.strip() if version else None
        params = {"package_name": pkg, "version": ver or ""}

        async with AuditContext("T20", params, "1.0") as ctx:
            if not pkg:
                return error_response(
                    error_code=ErrorCode.VALIDATION_ERROR,
                    message="package_name must not be empty.",
                    query_hash=ctx.query_hash,
                    retry_after=0,
                    ingest_healthy=True,
                )

            resolved_version = ver
            if not resolved_version:
                resolved_version = await _resolve_version(pkg, "npm") or "latest"

            vulns_r, licence_r, maintainer_r, downloads_r = await asyncio.gather(
                _fetch_vulns(pkg, "npm", resolved_version),
                _fetch_licence(pkg, "npm"),
                _fetch_maintainer_history(pkg, "npm"),
                _fetch_weekly_downloads(pkg),
                return_exceptions=True,
            )

            vulns      = vulns_r      if not isinstance(vulns_r, Exception)      else None
            licence    = licence_r    if not isinstance(licence_r, Exception)    else None
            maintainer = maintainer_r if not isinstance(maintainer_r, Exception) else None
            weekly_dl  = downloads_r  if not isinstance(downloads_r, Exception)  else None

            critical_cve = vulns.get("critical_cve_count") if vulns else None
            high_cve     = vulns.get("high_cve_count")     if vulns else None
            lic_risk     = licence.get("licence_risk")      if licence else None
            maint_health = maintainer.get("maintainer_health") if maintainer else None

            verdict, reasoning = _compute_verdict(critical_cve, high_cve, lic_risk, maint_health)

            is_ui = any(pkg.startswith(prefix) for prefix in _UI_PREFIXES)

            data_as_of = datetime.now(timezone.utc).isoformat()
            _success = True
            return {
                "status":               "ok",
                "tool_id":              "T20",
                "ecosystem":            "npm",
                "package_name":         pkg,
                "resolved_version":     resolved_version,
                "verdict":              verdict,
                "reasoning":            reasoning,
                "critical_cve_count":   critical_cve,
                "high_cve_count":       high_cve,
                "licence_risk":         lic_risk,
                "maintainer_health":    maint_health,
                "frontend_specific_signals": {
                    "is_ui_component":  is_ui,
                    "weekly_downloads": weekly_dl,
                },
                "disclaimer":           _DISCLAIMER,
                **standard_response_fields(ctx.query_hash, data_as_of, True),
            }
    except Exception as exc:
        _error_code = type(exc).__name__
        log.exception("frontend_security_fetch_package_risk_brief error")
        raise
    finally:
        _ms = int((time.monotonic() - _t0) * 1000)
        fire_and_forget(track_tool_call(
            tool_id="T20",
            tool_name="frontend_security_fetch_package_risk_brief",
            success=_success,
            latency_ms=_ms,
            cache_hit=False,
            error_code=_error_code,
        ))


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _fetch_weekly_downloads(package_name: str) -> Optional[int]:
    """Fetch last-week download count from npm registry. Returns None on failure."""
    try:
        url = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True) as c:
            resp = await c.get(url)
            if resp.status_code == 200:
                return resp.json().get("downloads")
    except Exception:
        pass
    return None


def _compute_verdict(
    critical_cve_count, high_cve_count, licence_risk, maintainer_health
) -> tuple[str, str]:
    """Replicate the verdict logic from security_sprint6._compute_verdict."""
    try:
        from datanexus.tools.security_sprint6 import _compute_verdict as _cv
        return _cv(critical_cve_count, high_cve_count, licence_risk, maintainer_health)
    except Exception:
        pass
    # Fallback
    if critical_cve_count and critical_cve_count > 0:
        return "BLOCK", "Critical CVE found in package."
    if high_cve_count and high_cve_count >= 2:
        return "CAUTION", "Multiple high-severity CVEs found."
    return "SHIP", "No critical issues detected."


def _strip_semver_prefix(ver: str) -> str:
    """Strip ^ ~ >= <= prefixes from semver strings."""
    return ver.lstrip("^~>=<").split(" ")[0].split(",")[0].strip()


def _extract_pinned_versions(lockfile: str) -> dict[str, str]:
    """Extract name→version from package-lock.json (v2/v3) or yarn.lock."""
    pinned = {}
    try:
        data = json.loads(lockfile)
        # package-lock.json v2/v3
        pkgs = data.get("packages", {})
        for path, info in pkgs.items():
            if path.startswith("node_modules/"):
                name = path[len("node_modules/"):]
                pinned[name] = info.get("version", "")
        return pinned
    except json.JSONDecodeError:
        pass
    # yarn.lock: simple regex extraction
    pattern = re.compile(r'^"?(.+?)@[^:]+:\n\s+version "([^"]+)"', re.MULTILINE)
    for m in pattern.finditer(lockfile):
        pinned[m.group(1)] = m.group(2)
    return pinned


def _scan_config(config: str, config_type: str) -> list[dict]:
    """Run security checks on CI config content. Returns list of findings."""
    findings = []
    lines = config.splitlines()

    # Check 1: Exposed secrets (literal values only — NOT ${{ secrets.X }})
    for i, line in enumerate(lines, 1):
        # Skip lines that only contain safe indirect references
        safe_line = _SAFE_REF_RE.sub("", line)
        for pattern, secret_type, severity in _SECRET_PATTERNS:
            if pattern.search(safe_line):
                findings.append({
                    "type":           "EXPOSED_SECRET",
                    "severity":       severity,
                    "line_hint":      i,
                    "secret_type":    secret_type,
                    "recommendation": f"Move {secret_type} to ${{{{ secrets.YOUR_SECRET }}}} — never hard-code credentials.",
                })
                break  # one finding per line

    if config_type not in ("github_actions",):
        return findings  # vercel/netlify: secrets only in Sprint 8

    # Check 2: Unverified npm installs (should use npm ci)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.search(r'\bnpm install\b', stripped) and not re.search(r'npm ci\b|--package-lock-only', stripped):
            findings.append({
                "type":           "UNVERIFIED_NPM_INSTALL",
                "severity":       "MEDIUM",
                "line_hint":      i,
                "recommendation": "Replace 'npm install' with 'npm ci' to enforce lockfile and prevent dependency drift.",
            })

    # Check 3: Missing lockfile enforcement (no npm ci or --frozen-lockfile)
    full_text = config
    has_npm_ci = bool(re.search(r'\bnpm ci\b', full_text))
    has_frozen = bool(re.search(r'--frozen-lockfile|--immutable', full_text))
    if not has_npm_ci and not has_frozen:
        if re.search(r'\bnpm install\b|\byarn install\b|\bpnpm install\b', full_text):
            findings.append({
                "type":           "MISSING_LOCKFILE_ENFORCEMENT",
                "severity":       "MEDIUM",
                "line_hint":      None,
                "recommendation": "Use 'npm ci', 'yarn --frozen-lockfile', or 'pnpm install --frozen-lockfile' to enforce deterministic builds.",
            })

    # Check 4: Unpinned action versions (uses: owner/repo@vX.Y.Z instead of SHA)
    action_re = re.compile(r'uses:\s+([^\s@]+)@([^\s#]+)')
    sha_re    = re.compile(r'^[0-9a-f]{40}$')
    for i, line in enumerate(lines, 1):
        m = action_re.search(line)
        if m:
            ref = m.group(2).strip()
            if not sha_re.match(ref):
                findings.append({
                    "type":           "UNPINNED_ACTION",
                    "severity":       "MEDIUM",
                    "line_hint":      i,
                    "action":         m.group(1),
                    "ref":            ref,
                    "recommendation": f"Pin to a full commit SHA instead of '{ref}' to prevent supply-chain attacks.",
                })

    # Check 5: Overly broad permissions
    perm_re = re.compile(r'permissions:\s*(write-all|write_all)', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        if perm_re.search(line):
            findings.append({
                "type":           "OVERLY_BROAD_PERMISSIONS",
                "severity":       "HIGH",
                "line_hint":      i,
                "recommendation": "Replace 'write-all' with minimal required permissions per job.",
            })

    return findings
