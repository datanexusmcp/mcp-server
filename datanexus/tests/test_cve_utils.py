"""
Unit tests for datanexus/tools/_cve_utils.py — PRE-1 requirement.

All HTTP is mocked. Tests verify:
  test_cve_detail_util_returns_cvss_score
  test_cisa_kev_util_returns_bool_field
  test_cve_epss_util_returns_float_0_to_1
"""

import asyncio
import importlib
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pybreaker


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _fresh_module():
    """Reload _cve_utils so the in-process KEV cache is reset between tests."""
    mod_name = "datanexus.tools._cve_utils"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import datanexus.tools._cve_utils as m
    return m


# ── NVD mock responses ─────────────────────────────────────────────────────────

_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}
                    ]
                },
                "references": [
                    {"url": "https://github.com/advisories/GHSA-abc", "tags": ["Patch"]},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "tags": ["Third Party Advisory"]},
                ],
                "configurations": [],
            }
        }
    ]
}

_KEV_RESPONSE = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24"},
        {"cveID": "CVE-2020-1234",  "dateAdded": "2020-01-01", "dueDate": "2020-02-01"},
    ]
}

_EPSS_RESPONSE = {
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.997", "date": "2026-05-29"}
    ],
    "version": "v2023.03.01",
}


def _mock_httpx_response(json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_cve_detail_util_returns_cvss_score():
    """_fetch_cve_detail_util must return cvss_score as float from NVD response."""
    m = _fresh_module()

    async def fake_call_async(fn):
        return _NVD_RESPONSE

    with patch.object(m._nvd_breaker, "call_async", side_effect=fake_call_async):
        result = _run(m._fetch_cve_detail_util("CVE-2021-44228"))

    assert result["cvss_score"] == 10.0, f"Expected 10.0, got {result['cvss_score']}"
    assert isinstance(result["cvss_score"], float)
    assert len(result["references"]) == 2
    assert result["description"] == "Log4Shell RCE"


def test_cisa_kev_util_returns_bool_field():
    """_fetch_cisa_kev_util must return kev_listed=True for known CVE, False for unknown."""
    m = _fresh_module()
    m._kev_catalog_cache = None  # ensure cold start

    async def fake_call_async(fn):
        return _KEV_RESPONSE["vulnerabilities"]

    with patch.object(m._cisa_breaker, "call_async", side_effect=fake_call_async):
        result_known   = _run(m._fetch_cisa_kev_util("CVE-2021-44228"))
        result_unknown = _run(m._fetch_cisa_kev_util("CVE-9999-9999"))

    assert result_known["kev_listed"] is True
    assert result_unknown["kev_listed"] is False
    assert isinstance(result_known["kev_listed"], bool)


def test_cve_epss_util_returns_float_0_to_1():
    """_fetch_cve_epss_util must return epss_score as float between 0.0 and 1.0."""
    m = _fresh_module()

    async def fake_call_async(fn):
        return _EPSS_RESPONSE

    with patch.object(m._epss_breaker, "call_async", side_effect=fake_call_async):
        result = _run(m._fetch_cve_epss_util("CVE-2021-44228"))

    assert "epss_score" in result
    score = result["epss_score"]
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0, f"Expected 0.0–1.0, got {score}"
    assert score == pytest.approx(0.975)


def test_cve_detail_util_raises_on_circuit_open():
    """_fetch_cve_detail_util must propagate CircuitBreakerError for caller to handle."""
    m = _fresh_module()

    async def fake_call_async(fn):
        raise pybreaker.CircuitBreakerError("open")

    with patch.object(m._nvd_breaker, "call_async", side_effect=fake_call_async):
        with pytest.raises(pybreaker.CircuitBreakerError):
            _run(m._fetch_cve_detail_util("CVE-2021-44228"))


def test_cve_epss_util_raises_when_not_found():
    """_fetch_cve_epss_util must raise ValueError when CVE not in EPSS database."""
    m = _fresh_module()

    async def fake_call_async(fn):
        return {"data": [], "version": "v2023"}

    with patch.object(m._epss_breaker, "call_async", side_effect=fake_call_async):
        with pytest.raises(ValueError, match="not found in EPSS"):
            _run(m._fetch_cve_epss_util("CVE-9999-9999"))
