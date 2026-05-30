"""
Unit tests for datanexus/tools/_nonprofit_utils.py — PRE-3 requirement.

Tests:
  test_health_score_formula_correct
  test_health_score_zero_revenue_returns_none
  test_sprint6_refactor_still_works
"""

from datanexus.tools._nonprofit_utils import calculate_health_score


def test_health_score_formula_correct():
    """
    Verify weights sum to 100 and formula produces expected result.
    Using a known-good org: 80% programme ratio, 70% expense ratio,
    10% revenue growth, 3 months reserve.
    """
    totrevenue    = 1_000_000.0
    totfuncexpns  =   700_000.0   # expense_ratio = 0.7
    totprgmrevnue =   800_000.0   # programme_ratio = 0.8
    netassetsend  =   175_000.0   # reserve_months = 175000 / (700000/12) = 3.0
    prev_revenue  =   909_090.9   # delta ≈ +10% → growth_score = 1.0

    score = calculate_health_score(
        totrevenue=totrevenue,
        totfuncexpns=totfuncexpns,
        totprgmrevnue=totprgmrevnue,
        netassetsend=netassetsend,
        prev_revenue=prev_revenue,
    )

    # Programme:  0.8 * 40 = 32.0
    # Efficiency: (1 - 0.7) * 30 = 9.0
    # Growth:     1.0 * 20 = 20.0  (clamped at 1.0)
    # Reserve:    min(3/6, 1.0) * 10 = 5.0
    # Total: 66.0
    assert score is not None
    assert abs(score - 66.0) < 0.5, f"Expected ~66.0, got {score}"


def test_health_score_max_possible():
    """Maximum score (all components at ceiling) should not exceed 100."""
    score = calculate_health_score(
        totrevenue=1_000_000.0,
        totfuncexpns=100_000.0,    # expense_ratio = 0.1 → (1-0.1)*30 = 27
        totprgmrevnue=1_000_000.0, # programme_ratio = 1.0 → 40
        netassetsend=1_000_000.0,  # reserve_months = 120 → capped at 1.0 → 10
        prev_revenue=800_000.0,    # delta = +25% → clamped to 1.0 → 20
    )
    assert score is not None
    assert score <= 100.0, f"Score exceeded 100: {score}"


def test_health_score_zero_revenue_returns_none():
    """calculate_health_score must return None when totrevenue == 0."""
    result = calculate_health_score(
        totrevenue=0.0,
        totfuncexpns=500_000.0,
        totprgmrevnue=400_000.0,
        netassetsend=200_000.0,
    )
    assert result is None


def test_health_score_zero_expenses_does_not_crash():
    """Zero expenses must not cause division by zero."""
    score = calculate_health_score(
        totrevenue=1_000_000.0,
        totfuncexpns=0.0,
        totprgmrevnue=800_000.0,
        netassetsend=0.0,
    )
    # reserve_months and expense_ratio sub-scores skipped; programme sub-score computed
    assert score is not None
    assert score > 0


def test_sprint6_refactor_still_works():
    """
    After refactor, _parse_propublica must produce same health_score
    as the inline formula it replaced.

    We compute the expected value manually using the same inputs and
    verify _parse_propublica returns it.
    """
    from unittest.mock import MagicMock, patch
    from datanexus.tools.nonprofit_sprint6 import _parse_propublica

    # Build a mock ProPublica response with known financial values
    filing = {
        "totrevenue":    "1000000",
        "totfuncexpns":  "700000",
        "totprgmrevnue": "800000",
        "netassetsend":  "175000",
        "tax_prd_yr":    "2023",
        "employees":     [],
        "late_tax_period": None,
        "related_org_flag": None,
    }
    prev_filing = {"totrevenue": "909091"}

    raw = {
        "organization": {"name": "Test Org"},
        "filings_with_data": [filing, prev_filing],
    }

    result = _parse_propublica(raw)

    assert result["status"] == "OK"
    score = result["health_score"]
    assert score is not None
    # Expected score using same formula as test_health_score_formula_correct ≈ 66
    assert abs(score - 66.0) < 1.0, f"Sprint 6 refactor changed the score: {score}"
