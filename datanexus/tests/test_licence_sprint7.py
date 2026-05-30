"""
Smoke tests for Sprint 7 licence tools — PRE requirement before registration.

Tests:
  fetch_licence_analysis:
    smoke_fetch_licence_analysis_mit        → risk_level=PERMISSIVE, spdx_api=N/A
    smoke_fetch_licence_analysis_gpl3       → risk_level=STRONG_COPYLEFT
    smoke_fetch_licence_analysis_agpl       → risk_level=INCOMPATIBLE, mentions proprietary
    smoke_fetch_licence_analysis_unknown    → risk_level=UNKNOWN, plain_english=None

  audit_licence_compatibility:
    smoke_audit_licence_compat_compatible   → COMPATIBLE
    smoke_audit_licence_compat_conflict     → CONFLICT (GPL-3.0-only + Apache-2.0)
    smoke_audit_licence_compat_no_http      → upstream_status.spdx_api=N/A
    smoke_audit_licence_compat_max_limit    → INVALID_PARAMS (51 items)
    smoke_audit_licence_compat_mixed_input  → INVALID_PARAMS

All tests mock HTTP so they don't need live network.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pybreaker

from datanexus.tools.licence_sprint7 import (
    fetch_licence_analysis,
    audit_licence_compatibility,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _result(resp: dict) -> dict:
    """Extract the data payload from a tool response."""
    return resp.get("data", resp)


# ── fetch_licence_analysis smoke tests ────────────────────────────────────────

def test_smoke_fetch_licence_analysis_mit():
    """MIT is in the static bundle → spdx_api=N/A, risk_level=PERMISSIVE."""
    resp = _run(fetch_licence_analysis("MIT"))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["risk_level"] == "PERMISSIVE"
    assert d["upstream_status"]["spdx_api"] == "N/A"
    assert d["plain_english"] is not None
    assert d["osi_approved"] is True


def test_smoke_fetch_licence_analysis_gpl3():
    """GPL-3.0-only is in static bundle → risk_level=STRONG_COPYLEFT."""
    resp = _run(fetch_licence_analysis("GPL-3.0-only"))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["risk_level"] == "STRONG_COPYLEFT"


def test_smoke_fetch_licence_analysis_agpl():
    """AGPL-3.0-or-later is in static bundle → INCOMPATIBLE, mentions proprietary."""
    resp = _run(fetch_licence_analysis("AGPL-3.0-or-later"))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["risk_level"] == "INCOMPATIBLE"
    assert "proprietary" in d["plain_english"].lower(), (
        "plain_english must mention 'proprietary'"
    )
    assert "INCOMPATIBLE" in d["tldr"]


def test_smoke_fetch_licence_analysis_unknown():
    """Unknown SPDX ID → DEGRADED response: risk_level=UNKNOWN, plain_english=None."""
    import datanexus.tools.licence_sprint7 as mod

    async def fake_breaker(fn):
        return {}  # simulates 404 from SPDX API

    with patch.object(mod._spdx_breaker, "call_async", side_effect=fake_breaker):
        resp = _run(fetch_licence_analysis("SSPL-99.0-imaginary"))

    assert resp["status"] == "ok"  # NOT an error — spec says return DEGRADED
    d = _result(resp)
    assert d["risk_level"] == "UNKNOWN"
    assert d["plain_english"] is None
    assert d["osi_approved"] is None


def test_smoke_fetch_licence_analysis_empty_id():
    """Empty spdx_id → VALIDATION_ERROR."""
    resp = _run(fetch_licence_analysis(""))
    assert resp["status"] == "error"


# ── audit_licence_compatibility smoke tests ───────────────────────────────────

def test_smoke_audit_licence_compat_compatible():
    """MIT + Apache-2.0 via spdx_ids path → COMPATIBLE."""
    resp = _run(audit_licence_compatibility(spdx_ids=["MIT", "Apache-2.0"]))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["compatibility"] == "COMPATIBLE"
    assert d["conflicts"] == []


def test_smoke_audit_licence_compat_conflict():
    """GPL-3.0-only + Apache-2.0 → CONFLICT."""
    resp = _run(audit_licence_compatibility(spdx_ids=["GPL-3.0-only", "Apache-2.0"]))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["compatibility"] == "CONFLICT"
    assert len(d["conflicts"]) >= 1


def test_smoke_audit_licence_compat_no_http():
    """spdx_ids path must not make HTTP calls → upstream_status.spdx_api=N/A."""
    resp = _run(audit_licence_compatibility(spdx_ids=["MIT", "BSD-3-Clause"]))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["upstream_status"]["spdx_api"] == "N/A"


def test_smoke_audit_licence_compat_max_limit():
    """51 spdx_ids → INVALID_PARAMS."""
    ids = ["MIT"] * 51
    resp = _run(audit_licence_compatibility(spdx_ids=ids))
    assert resp["status"] == "error"


def test_smoke_audit_licence_compat_mixed_input():
    """Both packages and spdx_ids → INVALID_PARAMS."""
    resp = _run(audit_licence_compatibility(
        packages=[{"package_name": "requests", "ecosystem": "pypi"}],
        spdx_ids=["MIT"],
    ))
    assert resp["status"] == "error"


def test_smoke_audit_licence_compat_empty_list():
    """Empty spdx_ids → INVALID_PARAMS."""
    resp = _run(audit_licence_compatibility(spdx_ids=[]))
    assert resp["status"] == "error"


def test_smoke_audit_licence_compat_agpl_conflict():
    """AGPL-3.0-or-later + MIT → CONFLICT in proprietary context."""
    resp = _run(audit_licence_compatibility(spdx_ids=["AGPL-3.0-or-later", "MIT"]))
    assert resp["status"] == "ok"
    d = _result(resp)
    assert d["compatibility"] == "CONFLICT"


def test_smoke_audit_licence_compat_recommended_action_copyleft():
    """Compatible set with copyleft → recommended_action mentions share-alike."""
    resp = _run(audit_licence_compatibility(spdx_ids=["MIT", "LGPL-2.1-or-later"]))
    assert resp["status"] == "ok"
    d = _result(resp)
    # LGPL + MIT is COMPATIBLE but LGPL is copyleft → action should note share-alike
    assert d["compatibility"] == "COMPATIBLE"
    assert "share-alike" in d["recommended_action"].lower() or "lgpl" in d["recommended_action"].lower()
