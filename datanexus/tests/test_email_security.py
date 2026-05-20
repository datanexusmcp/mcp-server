"""
datanexus/tests/test_email_security.py — Unit tests for Sprint 4 email security scoring.

Tests _score_spf, _score_dmarc, _score_to_grade boundary logic from t07.py.
Run with: pytest datanexus/tests/test_email_security.py -v
"""

import pytest
from datanexus.tools.t07 import _score_spf, _score_dmarc, _score_to_grade


# ── SPF scoring ───────────────────────────────────────────────────────────────

class TestScoreSpf:
    def test_absent_returns_2(self):
        score, policy = _score_spf(None)
        assert score == 2
        assert "absent" in policy

    def test_empty_string_returns_2(self):
        score, policy = _score_spf("")
        assert score == 2

    def test_plus_all_returns_0(self):
        score, policy = _score_spf("v=spf1 include:_spf.google.com +all")
        assert score == 0
        assert "+all" in policy

    def test_softfail_returns_7(self):
        score, policy = _score_spf("v=spf1 include:_spf.google.com ~all")
        assert score == 7
        assert "~all" in policy

    def test_neutral_returns_4(self):
        score, policy = _score_spf("v=spf1 ?all")
        assert score == 4
        assert "?all" in policy

    def test_hard_fail_returns_10(self):
        score, policy = _score_spf("v=spf1 include:mailgun.org -all")
        assert score == 10
        assert "-all" in policy

    def test_spf_no_all_mechanism_returns_5(self):
        score, policy = _score_spf("v=spf1 include:_spf.google.com")
        assert score == 5

    def test_case_insensitive(self):
        score, _ = _score_spf("v=SPF1 -ALL")
        assert score == 10


# ── DMARC scoring ─────────────────────────────────────────────────────────────

class TestScoreDmarc:
    def test_absent_returns_0(self):
        score, policy, rua = _score_dmarc(None)
        assert score == 0
        assert "absent" in policy
        assert rua is False

    def test_empty_returns_0(self):
        score, policy, rua = _score_dmarc("")
        assert score == 0

    def test_p_none_returns_4(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=none;")
        assert score == 4
        assert "p=none" in policy
        assert rua is False

    def test_p_none_with_rua_returns_5(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=none; rua=mailto:dmarc@example.com")
        assert score == 5
        assert rua is True

    def test_p_quarantine_returns_7(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=quarantine;")
        assert score == 7

    def test_p_quarantine_with_rua_returns_8(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com;")
        assert score == 8
        assert rua is True

    def test_p_reject_returns_10(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=reject;")
        assert score == 10

    def test_p_reject_with_rua_capped_at_10(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com;")
        assert score == 10  # capped, not 11

    def test_unrecognized_policy_returns_2(self):
        score, policy, rua = _score_dmarc("v=DMARC1; p=unknown;")
        assert score == 2

    def test_case_insensitive(self):
        score, _, _ = _score_dmarc("V=DMARC1; P=REJECT;")
        assert score == 10


# ── Grade boundaries ──────────────────────────────────────────────────────────

class TestScoreToGrade:
    @pytest.mark.parametrize("score,expected", [
        (10.0, "A"),
        (8.0,  "A"),
        (7.99, "B"),
        (6.0,  "B"),
        (5.99, "C"),
        (4.0,  "C"),
        (3.99, "D"),
        (2.0,  "D"),
        (1.99, "F"),
        (0.0,  "F"),
    ])
    def test_grade_boundaries(self, score, expected):
        assert _score_to_grade(score) == expected

    def test_typical_good_domain(self):
        # SPF -all (10) + DMARC reject+rua (10) + DKIM found (10) → avg 10 → A
        assert _score_to_grade(10.0) == "A"

    def test_typical_bad_domain(self):
        # SPF absent (2) + DMARC absent (0) + DKIM none (0) → avg 0.67 → F
        avg = (2 + 0 + 0) / 3.0
        assert _score_to_grade(avg) == "F"
