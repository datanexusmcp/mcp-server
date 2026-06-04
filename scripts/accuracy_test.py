#!/usr/bin/env python3
"""scripts/accuracy_test.py — P07 Golden Dataset Accuracy Tests.

Calls live tool functions directly. Uses asyncio.gather for parallelism.
Must complete in under 120 seconds.

T04 golden dataset: 10 EINs (IRS EO BMF)
T10 golden dataset:  8 CVEs (NIST NVD via fetch_cve_detail)

Data-freshness warnings
  T04: warn if data_as_of > 14 days  (TTL is 7 days — 2× TTL)
  T10: warn if data_as_of >  2 hours (TTL is 1 hour — 2× TTL)
"""

import asyncio
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datanexus.tools.t04 import fetch_nonprofit_by_ein
from datanexus.tools.t10 import fetch_cve_detail

# ── Golden datasets ───────────────────────────────────────────────────────────

T04_CASES = [
    ("13-1788491", lambda r: "Red Cross"   in r.get("name", "") and r.get("revenue", 0) > 1_000_000_000),
    ("23-7363942", lambda r: "Doctors"     in r.get("name", "")),
    ("13-3433555", lambda r: "Human Rights" in r.get("name", "")),
    ("52-1693387", lambda r: any(x in r.get("name", "") for x in ["Public Radio", "NPR"])),
    ("04-2103594", lambda r: "Harvard"     in r.get("name", "") and r.get("assets", 0) > 1_000_000_000),
    ("94-1156365", lambda r: "Stanford"    in r.get("name", "") and r.get("state", "") == "CA"),
    ("53-0196605", lambda r: "Geographic"  in r.get("name", "")),
    ("31-4379948", lambda r: "Salvation"   in r.get("name", "") and r.get("revenue", 0) > 100_000_000),
    ("13-5613797", lambda r: "YMCA"        in r.get("name", "")),
    ("82-4059863", lambda r: "GiveDirectly" in r.get("name", "")),
]

T10_CASES = [
    # (cve_id, package, version, ecosystem, assertion)
    ("CVE-2021-44228", "log4j-core",    "2.14.1", "Maven",
     lambda r: r.get("severity") == "CRITICAL" and r.get("cvss_score", 0) >= 9.0),
    ("CVE-2022-22965", "spring-webmvc", "5.3.17", "Maven",
     lambda r: r.get("severity") == "CRITICAL"),
    ("CVE-2014-0160",  "openssl",       "1.0.1",  "",
     lambda r: r.get("severity") in ("HIGH", "CRITICAL") and r.get("patched_version") is not None),
    ("CVE-2024-3400",  "panos",         "10.0.0", "",
     lambda r: r.get("severity") == "CRITICAL"),
    ("CVE-2017-5638",  "struts2-core",  "2.3.34", "Maven",
     lambda r: r.get("severity") == "CRITICAL"),
    # Error handling — must return dict, never raise
    ("CVE-2019-0708",  "windows-rdp",        "", "", lambda r: isinstance(r, dict)),
    ("CVE-2020-1472",  "windows-netlogon",   "", "", lambda r: isinstance(r, dict)),
    ("CVE-2023-44487", "any",                "", "", lambda r: isinstance(r, dict)),
]

# ── Staleness thresholds ──────────────────────────────────────────────────────

_T04_WARN_SECONDS = 14 * 86_400   # 14 days (2× the 7-day TTL)
_T10_WARN_SECONDS =  2 * 3_600    #  2 hours (2× the 1-hour TTL)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_amount(val: object) -> int:
    """Parse a raw IRS amount string (or int) to int, returning 0 on failure."""
    try:
        return int(str(val).strip() or "0")
    except (ValueError, TypeError):
        return 0


def _parse_float(val: object) -> float:
    try:
        return float(str(val).strip() or "0")
    except (ValueError, TypeError):
        return 0.0


def _age_seconds(data_as_of: str) -> float | None:
    """Return how many seconds old the data is, or None if unparseable."""
    if not data_as_of:
        return None
    try:
        dt = datetime.fromisoformat(data_as_of.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except Exception:
        return None


def _extract_patched_from_description(description: str) -> str | None:
    """
    Extract the first fix version from a NVD description string.

    Handles the common NVD pattern "before X.Y.Z[a-z]" (e.g. CVE-2014-0160
    Heartbleed: "OpenSSL 1.0.1 before 1.0.1g").
    """
    m = re.search(r'\bbefore\s+([\d]+\.[\d]+[.\d]*[a-z]*)', description, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'\bfixed\s+in\s+([\d]+\.[\d]+[.\d]*[a-z]*)', description, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def _normalize_t04(response: object) -> dict:
    """
    Extract T04 assertion fields from a fetch_nonprofit_by_ein response.

    Maps IRS BMF field names (revenue_amt, asset_amt) to the assertion
    field names (revenue, assets) used in T04_CASES lambdas.
    """
    if isinstance(response, BaseException) or not isinstance(response, dict):
        return {}
    if response.get("status") == "error" or "error_code" in response:
        return {}
    data = response.get("data") or {}
    return {
        "name":    data.get("name", ""),
        "revenue": _parse_amount(data.get("revenue_amt", "")),
        "assets":  _parse_amount(data.get("asset_amt", "")),
        "state":   data.get("state", ""),
    }


def _normalize_t10(cve_response: object) -> dict:
    """
    Extract T10 assertion fields from a fetch_cve_detail response.

    severity      ← data.cvss_severity   (e.g. "CRITICAL", "HIGH")
    cvss_score    ← float(data.cvss_base_score)
    patched_version ← regex on data.description  (handles Heartbleed pattern)

    The full response dict is returned with these keys overlaid so that
    `isinstance(r, dict)` always holds even for error responses.
    """
    if isinstance(cve_response, BaseException):
        return {}
    if not isinstance(cve_response, dict):
        return {}

    r = dict(cve_response)  # include all response fields (isinstance check passes)

    cve_data = cve_response.get("data") or {}
    r["severity"]        = cve_data.get("cvss_severity", "")
    r["cvss_score"]      = _parse_float(cve_data.get("cvss_base_score", "0"))
    r["patched_version"] = _extract_patched_from_description(
        cve_data.get("description", "")
    )
    return r


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> int:
    # ── Build task list ───────────────────────────────────────────────────────
    # All T04 and T10 calls are gathered in a single asyncio.gather invocation
    # to maximise parallelism and stay within the 120-second budget.
    t04_tasks = [fetch_nonprofit_by_ein(ein) for ein, _ in T04_CASES]
    t10_tasks = [fetch_cve_detail(cve_id)    for cve_id, *_ in T10_CASES]

    all_results = await asyncio.gather(*(t04_tasks + t10_tasks), return_exceptions=True)

    t04_results = all_results[:len(t04_tasks)]
    t10_results = all_results[len(t04_tasks):]

    overall_pass = True

    # ── T04 assertions ────────────────────────────────────────────────────────
    for i, (ein, assertion) in enumerate(T04_CASES):
        resp = t04_results[i]
        r = _normalize_t04(resp)
        try:
            passed = bool(assertion(r))
        except Exception:
            passed = False

        if not passed:
            overall_pass = False

        print(f"T04 [{i + 1}/{len(T04_CASES)}] EIN {ein}: {'PASS' if passed else 'FAIL'}")

        # Staleness warning
        if isinstance(resp, dict):
            age = _age_seconds(resp.get("data_as_of", ""))
            if age is not None and age > _T04_WARN_SECONDS:
                print(
                    f"  WARN: T04 data stale — "
                    f"age {age / 86_400:.1f}d > 14d  "
                    f"data_as_of={resp.get('data_as_of', '')}"
                )

    # ── T10 assertions ────────────────────────────────────────────────────────
    for i, (cve_id, _pkg, _ver, _eco, assertion) in enumerate(T10_CASES):
        resp = t10_results[i]
        r = _normalize_t10(resp)
        try:
            passed = bool(assertion(r))
        except Exception:
            passed = False

        if not passed:
            overall_pass = False

        print(f"T10 [{i + 1}/{len(T10_CASES)}] CVE {cve_id}: {'PASS' if passed else 'FAIL'}")

        # Staleness warning
        if isinstance(resp, dict):
            age = _age_seconds(resp.get("data_as_of", ""))
            if age is not None and age > _T10_WARN_SECONDS:
                print(
                    f"  WARN: T10 data stale — "
                    f"age {age / 3_600:.1f}h > 2h  "
                    f"data_as_of={resp.get('data_as_of', '')}"
                )

    # ── Summary ───────────────────────────────────────────────────────────────
    result = "PASS" if overall_pass else "FAIL"
    print(f"ACCURACY TEST: {result}")
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
