"""
Smoke tests for Sprint 7 nonprofit tools.

Tests:
  search_nonprofits_by_category:
    smoke_search_nonprofits_education_ca       → list non-empty (live)
    smoke_search_nonprofits_raw_ntee_code      → category="B" same as "education"
    smoke_search_nonprofits_invalid_category   → INVALID_PARAMS
    smoke_search_nonprofits_empty_category     → INVALID_PARAMS
    smoke_search_nonprofits_truncated          → 25 returned + truncated=True (mock)

  fetch_nonprofit_financial_trends:
    smoke_nonprofit_trends_insufficient_data   → INSUFFICIENT_DATA, cagr=None
    smoke_nonprofit_trends_growing             → GROWING
    smoke_nonprofit_trends_zero_expenses       → reserve_months=None (no crash)
    smoke_nonprofit_trends_real_ein            → Red Cross, revenue_trend non-empty (live)
"""

import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
import pybreaker

from datanexus.tools.nonprofit_sprint7 import (
    search_nonprofits_by_category,
    fetch_nonprofit_financial_trends,
)
import datanexus.tools.nonprofit_sprint7 as mod


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _data(resp):
    return resp.get("data", resp)


def _make_org(totrevenue=1_000_000, totfuncexpns=800_000, totprgmrevnue=700_000,
              netassetsend=200_000, name="Test Org", ein="123456789", ntee="B"):
    return {
        "ein": ein, "name": name, "city": "Sacramento", "state": "CA",
        "ntee_code": ntee, "totrevenue": totrevenue, "totfuncexpns": totfuncexpns,
        "totprgmrevnue": totprgmrevnue, "netassetsend": netassetsend,
        "totassetsend": 300_000,
    }


def _make_filing(year, revenue, expenses=None, program=None, net_assets=None):
    return {
        "tax_prd_yr": year,
        "totrevenue": revenue,
        "totfuncexpns": int(revenue * 0.8) if expenses is None else expenses,
        "totprgmrevnue": int(revenue * 0.7) if program is None else program,
        "netassetsend": net_assets,
    }


# ── search_nonprofits_by_category ─────────────────────────────────────────────

def test_smoke_search_nonprofits_invalid_category():
    """Unrecognized category → INVALID_PARAMS."""
    resp = _run(search_nonprofits_by_category("foobar"))
    assert resp["status"] == "error"


def test_smoke_search_nonprofits_empty_category():
    """Empty category → INVALID_PARAMS."""
    resp = _run(search_nonprofits_by_category(""))
    assert resp["status"] == "error"


def test_smoke_search_nonprofits_invalid_state():
    """3-char state code → INVALID_PARAMS."""
    resp = _run(search_nonprofits_by_category("education", state="CAL"))
    assert resp["status"] == "error"


def test_smoke_search_nonprofits_raw_ntee_code():
    """Raw NTEE letter 'B' should produce same result shape as category='education'."""
    mock_raw = {"organizations": [_make_org()]}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp_b    = _run(search_nonprofits_by_category("B"))
        resp_edu  = _run(search_nonprofits_by_category("education"))

    assert resp_b["status"] == "ok"
    assert resp_edu["status"] == "ok"
    assert _data(resp_b)["ntee_code"] == "B"
    assert _data(resp_edu)["ntee_code"] == "B"


def test_smoke_search_nonprofits_truncated():
    """Mock 30 results → 25 returned + truncated=True."""
    orgs = [_make_org(ein=str(i), name=f"Org {i}") for i in range(30)]
    mock_raw = {"organizations": orgs}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(search_nonprofits_by_category("education"))

    assert resp["status"] == "ok"
    d = _data(resp)
    assert d["result_count"] == 25
    assert d["truncated"] is True
    assert len(d["organizations"]) == 25


def test_smoke_search_nonprofits_returns_org_fields():
    """Returned orgs should have required fields (ein, name, city, state, ntee_code)."""
    mock_raw = {"organizations": [
        {"ein": "123456789", "strein": "12-3456789", "name": "Test School",
         "city": "Sacramento", "state": "CA", "ntee_code": "B20",
         "raw_ntee_code": "B", "have_filings": True}
    ]}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(search_nonprofits_by_category("education"))

    d = _data(resp)
    assert len(d["organizations"]) == 1
    org = d["organizations"][0]
    assert org["name"] == "Test School"
    assert org["state"] == "CA"
    # health_score is null — search endpoint doesn't return financial data
    assert org["health_score"] is None


def test_smoke_search_nonprofits_education_ca():
    """Live smoke: education category → non-empty list (state filtered client-side)."""
    resp = _run(search_nonprofits_by_category("education"))
    assert resp["status"] == "ok"
    d = _data(resp)
    assert d["result_count"] > 0, "Expected at least one education nonprofit"
    assert len(d["organizations"]) > 0
    # health_score is null from search endpoint (financial fields not returned)
    assert all(o["health_score"] is None for o in d["organizations"])


# ── fetch_nonprofit_financial_trends ─────────────────────────────────────────

def test_smoke_nonprofit_trends_insufficient_data():
    """Single filing → trend_direction=INSUFFICIENT_DATA, cagr=None."""
    mock_raw = {
        "organization": {"name": "One-Year Org"},
        "filings_with_data": [_make_filing(2023, 1_000_000)],
    }

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(fetch_nonprofit_financial_trends("131837418"))

    assert resp["status"] == "ok"
    d = _data(resp)
    assert d["trend_direction"] == "INSUFFICIENT_DATA"
    assert d["cagr"] is None
    assert d["revenue_trend"] == []


def test_smoke_nonprofit_trends_growing():
    """Mock CAGR > 5% → trend_direction=GROWING."""
    filings = [
        _make_filing(2021, 1_000_000),
        _make_filing(2022, 1_100_000),
        _make_filing(2023, 1_210_000),  # CAGR ≈ 10%
    ]
    mock_raw = {"organization": {"name": "Growing Org"}, "filings_with_data": filings}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(fetch_nonprofit_financial_trends("131837418", years=3))

    assert resp["status"] == "ok"
    d = _data(resp)
    assert d["trend_direction"] == "GROWING"
    assert d["cagr"] is not None
    assert d["cagr"] > 0.05


def test_smoke_nonprofit_trends_declining():
    """Mock CAGR < -5% → trend_direction=DECLINING."""
    filings = [
        _make_filing(2021, 1_000_000),
        _make_filing(2022,   900_000),
        _make_filing(2023,   810_000),  # CAGR ≈ -10%
    ]
    mock_raw = {"organization": {"name": "Declining Org"}, "filings_with_data": filings}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(fetch_nonprofit_financial_trends("131837418", years=3))

    d = _data(resp)
    assert d["trend_direction"] == "DECLINING"
    assert d["cagr"] < -0.05


def test_smoke_nonprofit_trends_volatile():
    """Consecutive +30% then -25% changes → VOLATILE."""
    filings = [
        _make_filing(2021, 1_000_000),
        _make_filing(2022, 1_300_000),  # +30%
        _make_filing(2023,   975_000),  # -25%
    ]
    mock_raw = {"organization": {"name": "Volatile Org"}, "filings_with_data": filings}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(fetch_nonprofit_financial_trends("131837418", years=3))

    d = _data(resp)
    assert d["trend_direction"] == "VOLATILE"


def test_smoke_nonprofit_trends_zero_expenses():
    """totfuncexpns=0 → reserve_months=None (no division by zero crash)."""
    filings = [
        _make_filing(2022, 1_000_000, expenses=0, net_assets=500_000),
        _make_filing(2023, 1_100_000, expenses=0, net_assets=600_000),
    ]
    mock_raw = {"organization": {"name": "No-Expense Org"}, "filings_with_data": filings}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(fetch_nonprofit_financial_trends("131837418", years=2))

    assert resp["status"] == "ok"
    d = _data(resp)
    for yr in d["asset_trend"]:
        assert yr["reserve_months"] is None, "reserve_months must be None when expenses=0"


def test_smoke_nonprofit_trends_years_slicing():
    """5 filings available, years=3 → only 3 most recent used."""
    filings = [_make_filing(y, 1_000_000 + y * 10_000) for y in range(2019, 2024)]
    mock_raw = {"organization": {"name": "Sliced Org"}, "filings_with_data": filings}

    async def fake_call_async(fn):
        return mock_raw

    with patch.object(mod._propublica_breaker, "call_async", side_effect=fake_call_async):
        resp = _run(fetch_nonprofit_financial_trends("131837418", years=3))

    d = _data(resp)
    assert d["years_requested"] == 3
    assert d["years_available"] == 3
    years_in_trend = [e["year"] for e in d["revenue_trend"]]
    assert max(years_in_trend) == 2023
    assert min(years_in_trend) == 2021


def test_smoke_nonprofit_trends_real_ein():
    """Live smoke: Red Cross EIN → revenue_trend non-empty."""
    resp = _run(fetch_nonprofit_financial_trends("131837418", years=5))
    assert resp["status"] == "ok"
    d = _data(resp)
    assert len(d["revenue_trend"]) > 0, "Expected revenue trend data for Red Cross"
    assert d["trend_direction"] in (
        "GROWING", "STABLE", "DECLINING", "VOLATILE", "INSUFFICIENT_DATA"
    )
