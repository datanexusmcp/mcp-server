"""
Smoke tests for Sprint 7 fetch_cve_risk_summary.

⚠️ T03-S01 IS A P0 BLOCKER — tool must NOT register until this passes.
It verifies the D2 fix: all-null upstreams → verdict=UNKNOWN (not LOW).

Tests:
  T03-S01: smoke_cve_risk_summary_all_null_returns_unknown  ← P0 BLOCKER
  smoke_cve_risk_summary_critical_exploit_kev
  smoke_cve_risk_summary_high_risk_cvss
  smoke_cve_risk_summary_invalid_id
  smoke_cve_risk_summary_partial_upstream_down
  smoke_cve_risk_summary_patch_available
  smoke_cve_risk_summary_no_allowlist_match
"""

import asyncio
from unittest.mock import patch, AsyncMock

import pytest
import pybreaker

from datanexus.tools.cve_sprint7 import fetch_cve_risk_summary
import datanexus.tools.cve_sprint7 as mod


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _data(resp: dict) -> dict:
    return resp.get("data", resp)


def _make_breaker_error():
    return pybreaker.CircuitBreakerError("circuit open")


# ── T03-S01: P0 BLOCKER ────────────────────────────────────────────────────────

def test_T03_S01_all_null_returns_unknown():
    """
    ⚠️ P0 BLOCKER — D2 regression test.

    When NVD + CISA + EPSS all raise CircuitBreakerError,
    verdict MUST be "UNKNOWN" — NOT "LOW".

    LOW means "checked, low risk."
    UNKNOWN means "could not determine — all sources down."
    """
    async def nvd_down(cve_id):   raise _make_breaker_error()
    async def cisa_down(cve_id):  raise _make_breaker_error()
    async def epss_down(cve_id):  raise _make_breaker_error()

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_down), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=cisa_down), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_down):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    assert resp["status"] == "ok"
    d = _data(resp)
    assert d["verdict"] == "UNKNOWN", (
        f"D2 regression: expected 'UNKNOWN' when all upstreams down, got '{d['verdict']}'. "
        "LOW means 'checked, low risk' — not 'could not determine'."
    )
    assert d["cvss_score"] is None
    assert d["kev_listed"] is None
    assert d["epss_score"] is None
    assert d["upstream_status"]["nvd"]  == "CIRCUIT_OPEN"
    assert d["upstream_status"]["cisa"] == "CIRCUIT_OPEN"
    assert d["upstream_status"]["epss"] == "CIRCUIT_OPEN"


# ── Remaining smoke tests ──────────────────────────────────────────────────────

def test_smoke_cve_risk_summary_critical_exploit_kev():
    """kev_listed=True → verdict=CRITICAL_EXPLOIT regardless of CVSS."""
    async def nvd_ok(cve_id):  return {"cvss_score": 7.5, "references": [], "configurations": [], "description": ""}
    async def kev_yes(cve_id): return {"kev_listed": True}
    async def epss_ok(cve_id): return {"epss_score": 0.2}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_yes), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_ok):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["verdict"] == "CRITICAL_EXPLOIT"
    assert d["kev_listed"] is True


def test_smoke_cve_risk_summary_critical_exploit_epss():
    """epss_score >= 0.7 → verdict=CRITICAL_EXPLOIT."""
    async def nvd_ok(cve_id):  return {"cvss_score": 5.0, "references": [], "configurations": [], "description": ""}
    async def kev_no(cve_id):  return {"kev_listed": False}
    async def epss_high(cve_id): return {"epss_score": 0.85}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_high):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["verdict"] == "CRITICAL_EXPLOIT"


def test_smoke_cve_risk_summary_high_risk_cvss():
    """cvss_score=9.5, kev=False, epss=0.1 → HIGH_RISK."""
    async def nvd_ok(cve_id):  return {"cvss_score": 9.5, "references": [], "configurations": [], "description": ""}
    async def kev_no(cve_id):  return {"kev_listed": False}
    async def epss_low(cve_id): return {"epss_score": 0.1}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_low):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["verdict"] == "HIGH_RISK"
    assert d["cvss_score"] == 9.5


def test_smoke_cve_risk_summary_invalid_id():
    """Non-CVE string → INVALID_PARAMS (status=error)."""
    resp = _run(fetch_cve_risk_summary("not-a-cve"))
    assert resp["status"] == "error"


def test_smoke_cve_risk_summary_partial_upstream_down():
    """NVD down, CISA+EPSS OK → verdict returned (not error), nvd=CIRCUIT_OPEN."""
    async def nvd_down(cve_id):  raise _make_breaker_error()
    async def kev_yes(cve_id):   return {"kev_listed": True}
    async def epss_ok(cve_id):   return {"epss_score": 0.5}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_down), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_yes), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_ok):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    assert resp["status"] == "ok"
    d = _data(resp)
    assert d["upstream_status"]["nvd"] == "CIRCUIT_OPEN"
    assert d["verdict"] != "UNKNOWN"  # CISA+EPSS provided data
    assert d["verdict"] == "CRITICAL_EXPLOIT"  # kev=True wins


def test_smoke_cve_risk_summary_patch_available():
    """NVD refs include github.com/advisories URL → patch_available=True."""
    async def nvd_ok(cve_id):
        return {
            "cvss_score": 7.0,
            "references": [{"url": "https://github.com/advisories/GHSA-abc123", "tags": []}],
            "configurations": [],
            "description": "",
        }
    async def kev_no(cve_id):   return {"kev_listed": False}
    async def epss_low(cve_id): return {"epss_score": 0.05}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_low):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["patch_available"] is True


def test_smoke_cve_risk_summary_no_allowlist_match():
    """NVD refs include only nvd.nist.gov → patch_available=None (not False)."""
    async def nvd_ok(cve_id):
        return {
            "cvss_score": 7.0,
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "tags": []}],
            "configurations": [],
            "description": "",
        }
    async def kev_no(cve_id):   return {"kev_listed": False}
    async def epss_low(cve_id): return {"epss_score": 0.05}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_low):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    # nvd.nist.gov is NOT in the allowlist — must be null, not False
    assert d["patch_available"] is None, (
        f"nvd.nist.gov must NOT set patch_available=True. Got: {d['patch_available']}"
    )


def test_smoke_cve_risk_summary_moderate():
    """cvss=6.0, kev=False, epss=0.05 → MODERATE."""
    async def nvd_ok(cve_id):   return {"cvss_score": 6.0, "references": [], "configurations": [], "description": ""}
    async def kev_no(cve_id):   return {"kev_listed": False}
    async def epss_low(cve_id): return {"epss_score": 0.05}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_low):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["verdict"] == "MODERATE"


def test_smoke_cve_risk_summary_low():
    """cvss=3.0, kev=False, epss=0.01 → LOW."""
    async def nvd_ok(cve_id):   return {"cvss_score": 3.0, "references": [], "configurations": [], "description": ""}
    async def kev_no(cve_id):   return {"kev_listed": False}
    async def epss_low(cve_id): return {"epss_score": 0.01}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_low):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["verdict"] == "LOW"


def test_smoke_verdict_table_kev_false_not_null():
    """kev_listed=False (explicitly checked, not in KEV) should not trigger UNKNOWN."""
    async def nvd_ok(cve_id):   return {"cvss_score": 2.0, "references": [], "configurations": [], "description": ""}
    async def kev_no(cve_id):   return {"kev_listed": False}
    async def epss_low(cve_id): return {"epss_score": 0.01}

    with patch.object(mod, "_fetch_cve_detail_util", side_effect=nvd_ok), \
         patch.object(mod, "_fetch_cisa_kev_util",   side_effect=kev_no), \
         patch.object(mod, "_fetch_cve_epss_util",   side_effect=epss_low):
        resp = _run(fetch_cve_risk_summary("CVE-2021-44228"))

    d = _data(resp)
    assert d["verdict"] != "UNKNOWN"
    assert d["verdict"] == "LOW"
