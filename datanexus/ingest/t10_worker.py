"""
datanexus/ingest/t10_worker.py — T10 ingest worker.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 12.5 / Phase 3 Step A

One worker:
  OSVPopularPackagesWorker — pre-seeds 50 packages every 3600s

Sources:
  Google OSV.dev API — api.osv.dev/v1 — no key required, public API
  Apache 2.0 licence — commercial use permitted.

Hard stops:
  - NEVER store exploit code, PoC payloads, or attack vector executables.
  - Store ONLY: vuln IDs, aliases, summaries, severity levels, fixed versions,
    advisory URLs.
  - TTL: 3600s — CVEs published continuously.
"""

import asyncio
import json
import logging

import httpx

from datanexus.core.cache import set_cached, compute_payload_hash
from datanexus.core.circuit_breaker import record_failure, record_success
from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t10")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

_HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}

# ── Pre-seed manifest — 50 packages across 4 ecosystems ──────────────────────
# Extend from spec base list to reach 50 total.
_SEED_PACKAGES: dict[str, list[str]] = {
    # PyPI — 19 packages
    "PyPI": [
        "requests", "flask", "django", "numpy", "pandas",
        "fastapi", "pydantic", "sqlalchemy", "celery", "boto3",
        "cryptography", "pillow", "urllib3", "aiohttp", "httpx",
        "setuptools", "six", "certifi", "charset-normalizer",
    ],
    # npm — 19 packages
    "npm": [
        "express", "lodash", "axios", "react", "next",
        "webpack", "typescript", "jest", "eslint", "chalk",
        "moment", "async", "semver", "minimist", "tar",
        "dotenv", "uuid", "commander", "yargs",
    ],
    # Maven — 7 packages (groupId:artifactId notation for OSV)
    "Maven": [
        "org.apache.logging.log4j:log4j-core",
        "org.springframework:spring-core",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.apache.commons:commons-lang3",
        "com.google.guava:guava",
        "org.hibernate:hibernate-core",
        "org.springframework.boot:spring-boot",
    ],
    # Go — 5 packages
    "Go": [
        "github.com/gin-gonic/gin",
        "golang.org/x/net",
        "github.com/gorilla/mux",
        "github.com/dgrijalva/jwt-go",
        "github.com/sirupsen/logrus",
    ],
}
# Total: 19 + 19 + 7 + 5 = 50 packages


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ── OSVPopularPackagesWorker ──────────────────────────────────────────────────

class OSVPopularPackagesWorker(IngestBase):
    """
    Pre-fetches vulnerability data for 50 popular packages from OSV.dev.

    On cache miss at tool call time, tools perform a live OSV.dev query.
    This worker warms the cache hourly so most tool calls hit cache.

    Key: datanexus:T10:pkg:{ecosystem}:{package}:all
    TTL: 3600s (CVE data changes continuously — never increase this TTL).
    Schedule: every 3600 seconds.

    Data source: Google OSV.dev (Apache 2.0)
    No API key required. Commercial use permitted.

    Hard stop: NEVER cache exploit code, PoC payloads, or attack vectors
    in executable form. Cached data ONLY: IDs, summaries, severity levels,
    fixed versions, advisory URLs.
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T10",
            source_id="osv_dev",
            ttl_seconds=3600,
            schedule_seconds=3600,
        )

    async def fetch(self) -> bytes:
        """Pre-seed all 50 packages. Returns last raw response bytes."""
        seeded = 0
        last_raw = b""

        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            headers=_HTTP_HEADERS,
            follow_redirects=True,
        ) as client:
            for ecosystem, packages in _SEED_PACKAGES.items():
                for pkg in packages:
                    try:
                        raw = await _query_osv_all_versions(
                            client, pkg, ecosystem
                        )
                        if raw is not None:
                            safe = _strip_unsafe_fields(raw)
                            set_cached(
                                "T10",
                                f"pkg:{ecosystem}:{pkg}:all",
                                safe,
                                self.ttl_seconds,
                            )
                            seeded += 1
                            last_raw = json.dumps(safe).encode()[:512]
                            log.info(json.dumps({
                                "ts": _iso_now(),
                                "event": "osv_seeded",
                                "tool": self.tool_id,
                                "ecosystem": ecosystem,
                                "pkg": pkg,
                                "vuln_count": len(safe.get("vulns", [])),
                            }))
                        # Respect OSV.dev — brief pause between requests
                        await asyncio.sleep(0.15)

                    except Exception as exc:
                        log.warning(json.dumps({
                            "ts": _iso_now(),
                            "event": "osv_seed_error",
                            "tool": self.tool_id,
                            "ecosystem": ecosystem,
                            "pkg": pkg,
                            "error": str(exc),
                        }))
                        continue

        if seeded == 0:
            raise RuntimeError(
                "OSVPopularPackagesWorker: no packages could be seeded"
            )

        log.info(json.dumps({
            "ts": _iso_now(),
            "event": "osv_preseed_complete",
            "tool": self.tool_id,
            "seeded": seeded,
        }))
        return last_raw or b"ok"


# ── OSV.dev helpers ───────────────────────────────────────────────────────────

async def query_osv_for_version(
    client: httpx.AsyncClient,
    package: str,
    version: str,
    ecosystem: str,
) -> dict:
    """
    Query OSV.dev for vulnerabilities affecting a specific package version.

    Returns safe dict with vuln list.  Never returns executable exploit content.
    """
    payload = {
        "version": version,
        "package": {
            "name": package,
            "ecosystem": _normalise_osv_ecosystem(ecosystem),
        },
    }
    resp = await client.post(OSV_QUERY_URL, json=payload)
    if resp.status_code == 404:
        return {"vulns": [], "source": "OSV.dev"}
    resp.raise_for_status()
    raw = resp.json()
    return _strip_unsafe_fields(raw)


async def _query_osv_all_versions(
    client: httpx.AsyncClient,
    package: str,
    ecosystem: str,
) -> dict | None:
    """
    Query OSV.dev for ALL vulnerabilities affecting any version of a package.
    Used by the pre-seeder worker.
    """
    payload = {
        "package": {
            "name": package,
            "ecosystem": _normalise_osv_ecosystem(ecosystem),
        },
    }
    resp = await client.post(OSV_QUERY_URL, json=payload)
    if resp.status_code == 404:
        return {"vulns": [], "source": "OSV.dev"}
    resp.raise_for_status()
    return _strip_unsafe_fields(resp.json())


def _strip_unsafe_fields(osv_response: dict) -> dict:
    """
    Extract ONLY safe vulnerability metadata. Strip any executable content.

    NEVER returns: exploit code, PoC details, attack commands, raw
    database_specific fields that may contain exploit references.

    Returns ONLY: IDs, aliases, summaries, severity levels, affected
    version ranges, fixed versions, advisory URLs.
    """
    safe_vulns = []
    for vuln in osv_response.get("vulns", []):
        # Severity — extract level and CVSS vector only (not executable)
        severity = _extract_severity(vuln)

        # Affected ranges — fixed versions only (no exploit detail)
        affected = _extract_affected(vuln)

        # References — advisory URLs only (never PoC links)
        refs = _extract_safe_refs(vuln)

        safe_vulns.append({
            "id":             vuln.get("id", ""),
            "aliases":        [
                a for a in vuln.get("aliases", [])
                if a.startswith("CVE-") or a.startswith("GHSA-")
            ],
            "summary":        vuln.get("summary", "")[:500],
            "severity":       severity,
            "affected":       affected,
            "references":     refs,
            "published":      vuln.get("published", ""),
            "modified":       vuln.get("modified", ""),
        })

    return {
        "vulns":       _dedup_by_alias(safe_vulns),
        "source":      "OSV.dev",
        "fetched_at":  _iso_now(),
    }


def _extract_severity(vuln: dict) -> dict:
    """
    Extract CVSS severity level and vector. No executable content.

    Priority order:
      1. CVSS_V3 / CVSS_V2 entry in severity[] → compute level via _cvss_level()
      2. If _cvss_level() still returns UNKNOWN, fall back to
         database_specific.severity (GHSA records always populate this field).
      3. Last resort: database_specific.severity with empty vector.
    """
    db        = vuln.get("database_specific", {})
    db_level  = str(db.get("severity", "")).upper()
    _valid    = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}

    for sev in vuln.get("severity", []):
        sev_type  = sev.get("type", "")
        sev_score = sev.get("score", "")
        if sev_type in ("CVSS_V3", "CVSS_V2"):
            level = _cvss_level(sev_score)
            # Bug fix: when vector parse yields UNKNOWN, use database_specific.severity
            # which GHSA records always populate with the authoritative human label.
            if level == "UNKNOWN" and db_level in _valid:
                level = db_level
            return {
                "type":   sev_type,
                "vector": sev_score,
                "level":  level,
            }

    # Fallback: database_specific severity string (no vector available)
    return {"type": "label", "vector": "", "level": db_level or "UNKNOWN"}


def _score_to_level(score: float) -> str:
    """Map a CVSS numeric base score to a severity label (CVSS 3.x spec thresholds)."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _cvss_level(vector: str) -> str:
    """
    Derive severity label from a CVSS vector string or numeric score.

    Handles three input forms:
      1. Bare numeric score:  "7.5"  → HIGH
      2. CVSS v3.x vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
         → full CVSS 3.x base-score formula (RFC 3.1 §7.1)
      3. CVSS v2 vector:     "AV:N/AC:L/Au:N/C:P/I:P/A:P"
         → simplified CIA-sum heuristic (sufficient for label derivation)
    """
    import math

    if not vector:
        return "UNKNOWN"

    # ── Form 1: bare numeric score ────────────────────────────────────────────
    try:
        return _score_to_level(float(vector))
    except (ValueError, TypeError):
        pass

    # ── Parse metrics dict from vector string ─────────────────────────────────
    # Strip "CVSS:3.x/" prefix if present
    raw = vector.upper()
    for prefix in ("CVSS:3.1/", "CVSS:3.0/", "CVSS:2.0/"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break

    metrics: dict[str, str] = {}
    for part in raw.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

    if not metrics:
        return "UNKNOWN"

    # ── Form 2: CVSS v3.x — full base-score formula ───────────────────────────
    if "AV" in metrics and "AC" in metrics and "S" in metrics:
        _cia      = {"N": 0.00, "L": 0.22, "H": 0.56}
        c_v  = _cia.get(metrics.get("C",  "N"), 0.0)
        i_v  = _cia.get(metrics.get("I",  "N"), 0.0)
        a_v  = _cia.get(metrics.get("A",  "N"), 0.0)

        iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)
        if iss == 0.0:
            return "NONE"

        scope_changed = metrics.get("S", "U") == "C"
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15.0)
        else:
            impact = 6.42 * iss

        _av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        _ac = {"L": 0.77, "H": 0.44}
        _pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
        _pr_c = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
        _ui   = {"N": 0.85, "R": 0.62}

        av_v  = _av.get(metrics.get("AV", "L"), 0.55)
        ac_v  = _ac.get(metrics.get("AC", "L"), 0.77)
        pr_v  = (_pr_c if scope_changed else _pr_u).get(metrics.get("PR", "N"), 0.85)
        ui_v  = _ui.get(metrics.get("UI", "N"), 0.85)

        exploit = 8.22 * av_v * ac_v * pr_v * ui_v

        if scope_changed:
            raw_score = min(1.08 * (impact + exploit), 10.0)
        else:
            raw_score = min(impact + exploit, 10.0)

        # CVSS 3.x rounds up to nearest 0.1
        base = math.ceil(raw_score * 10.0) / 10.0
        return _score_to_level(base)

    # ── Form 3: CVSS v2 — simplified CIA heuristic ───────────────────────────
    _v2_cia = {"N": 0.0, "P": 0.275, "C": 0.660}
    c_v = _v2_cia.get(metrics.get("C", "N"), 0.0)
    i_v = _v2_cia.get(metrics.get("I", "N"), 0.0)
    a_v = _v2_cia.get(metrics.get("A", "N"), 0.0)
    iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)
    impact_v2 = 10.41 * iss

    _av2 = {"N": 1.0, "A": 0.646, "L": 0.395}
    _ac2 = {"L": 0.71, "M": 0.61, "H": 0.35}
    _au2 = {"N": 0.704, "S": 0.56, "M": 0.45}
    av_v2 = _av2.get(metrics.get("AV", "L"), 0.395)
    ac_v2 = _ac2.get(metrics.get("AC", "L"), 0.71)
    au_v2 = _au2.get(metrics.get("AU", "N"), 0.704)
    exploit_v2 = 20.0 * av_v2 * ac_v2 * au_v2

    f_impact = 0.0 if iss == 0.0 else 1.176
    base_v2 = math.ceil(((0.6 * impact_v2) + (0.4 * exploit_v2) - 1.5) * f_impact * 10) / 10
    return _score_to_level(max(0.0, base_v2))


def _dedup_by_alias(vulns: list[dict]) -> list[dict]:
    """
    Suppress PYSEC records that are duplicate aliases of GHSA records.

    Bug fix: OSV returns both a GHSA record (complete: summary + severity) and
    a PYSEC record (incomplete: empty summary, no severity) for the same CVE.
    When a PYSEC entry shares a CVE- alias with a GHSA entry, the PYSEC is a
    lower-quality duplicate and is suppressed in favour of the canonical GHSA.

    Rule: if a PYSEC-* record has at least one CVE- alias that also appears
    in any GHSA-* record's alias list, drop the PYSEC record.
    """
    # Collect every CVE alias that is already covered by a GHSA record
    ghsa_cve_aliases: set[str] = set()
    for v in vulns:
        if v["id"].startswith("GHSA-"):
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    ghsa_cve_aliases.add(alias)

    deduped: list[dict] = []
    suppressed: list[str] = []
    for v in vulns:
        if v["id"].startswith("PYSEC-"):
            pysec_cves = {a for a in v.get("aliases", []) if a.startswith("CVE-")}
            if pysec_cves & ghsa_cve_aliases:
                suppressed.append(v["id"])
                continue   # drop the duplicate
        deduped.append(v)

    if suppressed:
        log.debug("t10_worker: suppressed duplicate PYSEC records %s", suppressed)

    return deduped


def _extract_affected(vuln: dict) -> list:
    """Extract affected version ranges and fixed versions only."""
    result = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        ranges = []
        for r in aff.get("ranges", []):
            events = [
                {k: v for k, v in e.items() if k in ("introduced", "fixed", "last_affected")}
                for e in r.get("events", [])
            ]
            ranges.append({"type": r.get("type", ""), "events": events})
        result.append({
            "ecosystem":  pkg.get("ecosystem", ""),
            "name":       pkg.get("name", ""),
            "ranges":     ranges,
        })
    return result


def _extract_safe_refs(vuln: dict) -> list:
    """Extract advisory and fix URLs only. Skip any PoC/exploit links."""
    safe_types = {"ADVISORY", "WEB", "PACKAGE", "REPORT", "FIX", "ARTICLE"}
    skip_keywords = ("exploit", "poc", "proof-of-concept", "payload", "shellcode")

    refs = []
    for ref in vuln.get("references", []):
        ref_type = ref.get("type", "").upper()
        url      = ref.get("url", "")
        url_lower = url.lower()
        if any(kw in url_lower for kw in skip_keywords):
            continue
        if ref_type in safe_types or ref_type == "":
            refs.append({"type": ref_type, "url": url})

    return refs[:10]   # cap at 10 references per vuln


def _normalise_osv_ecosystem(ecosystem: str) -> str:
    """Normalise user-supplied ecosystem name to OSV.dev canonical form."""
    _MAP = {
        "pypi":      "PyPI",
        "npm":       "npm",
        "maven":     "Maven",
        "go":        "Go",
        "cargo":     "crates.io",
        "crates.io": "crates.io",
        "nuget":     "NuGet",
        "rubygems":  "RubyGems",
        "packagist": "Packagist",
        "hex":       "Hex",
    }
    return _MAP.get(ecosystem.lower(), ecosystem)
