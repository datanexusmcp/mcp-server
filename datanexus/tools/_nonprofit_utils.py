"""
datanexus/tools/_nonprofit_utils.py — Shared nonprofit utility functions.

Extracted for Sprint 7 (plan-eng-review D5 — single source of truth).
Called by nonprofit_sprint6.py (Sprint 6) and Sprint 7 nonprofit tools.
The formula must not be inlined or duplicated anywhere else.

OQ1 resolved (PRE-4 curl verification 2026-05-29):
  Endpoint: /api/v2/organizations/{ein}.json (NOT /filings.json — that 404s)
  Response: top-level keys include "filings_with_data" — a list of annual filing dicts.
  Each filing is PRE-COMPUTED with named fields: totrevenue, totfuncexpns,
  totprgmrevnue, netassetsend, tax_prd_yr, etc. NOT raw IRS 990 JSON.
  No _parse_990_annual_fields() function needed — direct dict access is sufficient.
  netassetsend may be None for some organizations (observed on Red Cross EIN).
"""

from typing import Optional


def calculate_health_score(
    totrevenue: float,
    totfuncexpns: float,
    totprgmrevnue: float,
    netassetsend: float,
    prev_revenue: Optional[float] = None,
) -> Optional[float]:
    """
    Compute the DataNexus nonprofit health score (0–100).

    Weights:
      programme_ratio   × 40  (how much spending goes to the mission)
      (1 - expense_ratio) × 30  (efficiency: lower overhead = better)
      revenue_growth_score × 20 (year-over-year growth, capped at ±10%)
      reserve_months_score × 10 (financial runway, capped at 6 months)

    Returns None if totrevenue == 0 (division by zero guard).
    Individual sub-scores are omitted when their inputs are None or zero.
    """
    if not totrevenue:
        return None

    sub_scores = []

    # Programme ratio = programme expenses / total revenue
    if totprgmrevnue is not None:
        programme_ratio = totprgmrevnue / totrevenue
        sub_scores.append(programme_ratio * 40)

    # Expense ratio = total expenses / total revenue
    if totfuncexpns is not None:
        expense_ratio = totfuncexpns / totrevenue
        sub_scores.append((1 - min(expense_ratio, 1.0)) * 30)

    # Revenue growth score: -10% → 0.0, +10% → 1.0, clamped to [0, 1]
    if prev_revenue and prev_revenue > 0 and totrevenue is not None:
        delta = (totrevenue - prev_revenue) / prev_revenue
        revenue_growth_score = max(0.0, min(1.0, (delta + 0.1) / 0.2))
        sub_scores.append(revenue_growth_score * 20)

    # Reserve months = net assets / (expenses / 12); capped at 6 months for score
    if totfuncexpns and totfuncexpns > 0 and netassetsend is not None:
        reserve_months = netassetsend / (totfuncexpns / 12)
        reserve_months_score = min(reserve_months / 6, 1.0)
        sub_scores.append(reserve_months_score * 10)

    if not sub_scores:
        return None

    return round(sum(sub_scores), 1)
