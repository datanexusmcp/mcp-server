"""
datanexus/tests/test_t10_sprint8.py — Sprint 8B backend tools (15 paths)

Tests cover:
  - audit_sbom_license_policy: PASS, WARN, BLOCK, malformed SBOM, custom policy,
                                unlisted licence defaults to WARN, size limit
  - fetch_cve_watch_status: empty watch_ids, Redis unavailable, no cursor (30-day window),
                             with events newer than cursor, no new events
  - _sbom_utils: extract_components round-trip, parse_purl
  - fetch_dependency_graph: cvs_filtered_transitive_deps field present
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════════════════════
# _sbom_utils
# ══════════════════════════════════════════════════════════════════════════════

def test_parse_purl_npm():
    from datanexus.tools._sbom_utils import parse_purl
    result = parse_purl("pkg:npm/lodash@4.17.21")
    assert result == ("lodash", "npm", "4.17.21")


def test_parse_purl_pypi():
    from datanexus.tools._sbom_utils import parse_purl
    result = parse_purl("pkg:pypi/requests@2.28.0")
    assert result == ("requests", "pypi", "2.28.0")


def test_parse_purl_unsupported_returns_none():
    from datanexus.tools._sbom_utils import parse_purl
    assert parse_purl("pkg:hex/poison@1.0.0") is None


def test_extract_components_cyclonedx():
    from datanexus.tools._sbom_utils import extract_components

    sbom = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"purl": "pkg:npm/lodash@4.17.21", "name": "lodash", "version": "4.17.21"},
            {"purl": "pkg:pypi/requests@2.28.0", "name": "requests", "version": "2.28.0"},
        ],
    })

    # The cyclonedx-python-lib may not be installed in tests; test the fallback path
    with patch("datanexus.tools._sbom_utils._extract_cyclonedx_purls",
               return_value=["pkg:npm/lodash@4.17.21", "pkg:pypi/requests@2.28.0"]):
        components, fmt = extract_components(sbom)

    assert fmt == "CycloneDX"
    assert len(components) == 2
    assert components[0]["name"] == "lodash"
    assert components[1]["ecosystem"] == "pypi"


def test_extract_components_malformed_returns_error():
    from datanexus.tools._sbom_utils import extract_components

    with pytest.raises(ValueError, match="Unrecognised"):
        extract_components(json.dumps({"notAnSbom": True}))


# ══════════════════════════════════════════════════════════════════════════════
# audit_sbom_license_policy
# ══════════════════════════════════════════════════════════════════════════════

def _make_sbom(purls: list) -> str:
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [{"purl": p} for p in purls],
    })


def test_audit_sbom_license_policy_pass():
    from datanexus.tools.t10_sprint8 import audit_sbom_license_policy

    async def _run():
        sbom = _make_sbom(["pkg:npm/lodash@4.17.21"])
        with patch("datanexus.tools.t10_sprint8.extract_components",
                   return_value=([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}], "CycloneDX")), \
             patch("datanexus.tools.t10_sprint8._fetch_licence_for_component",
                   return_value=["MIT"]):
            return await audit_sbom_license_policy(sbom=sbom)

    result = run(_run())
    assert result["verdict"] == "PASS"
    assert result["blocked_packages"] == []


def test_audit_sbom_license_policy_block_gpl():
    from datanexus.tools.t10_sprint8 import audit_sbom_license_policy

    async def _run():
        sbom = _make_sbom(["pkg:npm/gpl-lib@1.0.0"])
        with patch("datanexus.tools.t10_sprint8.extract_components",
                   return_value=([{"name": "gpl-lib", "version": "1.0.0", "ecosystem": "npm"}], "CycloneDX")), \
             patch("datanexus.tools.t10_sprint8._fetch_licence_for_component",
                   return_value=["GPL-3.0"]):
            return await audit_sbom_license_policy(sbom=sbom)

    result = run(_run())
    assert result["verdict"] == "BLOCK"
    assert len(result["blocked_packages"]) == 1
    assert result["blocked_packages"][0]["licence"] == "GPL-3.0"


def test_audit_sbom_license_policy_unlisted_defaults_to_warn():
    from datanexus.tools.t10_sprint8 import audit_sbom_license_policy

    async def _run():
        sbom = _make_sbom(["pkg:npm/custom-lib@1.0.0"])
        with patch("datanexus.tools.t10_sprint8.extract_components",
                   return_value=([{"name": "custom-lib", "version": "1.0.0", "ecosystem": "npm"}], "CycloneDX")), \
             patch("datanexus.tools.t10_sprint8._fetch_licence_for_component",
                   return_value=["Custom-Proprietary-1.0"]):
            return await audit_sbom_license_policy(sbom=sbom)

    result = run(_run())
    assert result["verdict"] == "WARN"
    assert len(result["warned_packages"]) == 1


def test_audit_sbom_license_policy_malformed_sbom():
    from datanexus.tools.t10_sprint8 import audit_sbom_license_policy

    async def _run():
        return await audit_sbom_license_policy(sbom='{"not":"sbom"}')

    result = run(_run())
    assert result["verdict"] == "ERROR"
    assert "error" in result


def test_audit_sbom_license_policy_size_limit():
    from datanexus.tools.t10_sprint8 import audit_sbom_license_policy

    async def _run():
        big_sbom = "x" * 600_000
        return await audit_sbom_license_policy(sbom=big_sbom)

    result = run(_run())
    assert result["verdict"] == "ERROR"
    assert "500 KB" in result["error"]


def test_audit_sbom_license_policy_custom_policy():
    from datanexus.tools.t10_sprint8 import audit_sbom_license_policy

    async def _run():
        sbom = _make_sbom(["pkg:npm/lodash@4.17.21"])
        custom_policy = {"block": ["MIT"], "warn": [], "allow": []}
        with patch("datanexus.tools.t10_sprint8.extract_components",
                   return_value=([{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}], "CycloneDX")), \
             patch("datanexus.tools.t10_sprint8._fetch_licence_for_component",
                   return_value=["MIT"]):
            return await audit_sbom_license_policy(sbom=sbom, policy=custom_policy)

    result = run(_run())
    assert result["verdict"] == "BLOCK"
    assert result["policy_applied"]["block"] == ["MIT"]


# ══════════════════════════════════════════════════════════════════════════════
# fetch_cve_watch_status
# ══════════════════════════════════════════════════════════════════════════════

def test_fetch_cve_watch_status_empty_list():
    from datanexus.tools.t10_sprint8 import fetch_cve_watch_status

    async def _run():
        return await fetch_cve_watch_status(watch_ids=[])

    result = run(_run())
    assert result["status"] == "error"
    assert "MISSING_PARAMS" in result["error_code"]


def test_fetch_cve_watch_status_redis_unavailable():
    from datanexus.tools.t10_sprint8 import fetch_cve_watch_status

    async def _run():
        with patch("datanexus.tools.t10_sprint8.get_redis", return_value=None):
            return await fetch_cve_watch_status(watch_ids=["watch-1"])

    result = run(_run())
    assert result["status"] == "error"
    assert "REDIS" in result["error_code"]


def test_fetch_cve_watch_status_no_cursor_uses_30d_window():
    from datanexus.tools.t10_sprint8 import fetch_cve_watch_status
    from datanexus.core.request_context import api_key_var

    async def _run():
        api_key_var.set(None)

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)  # no cursor
        mock_redis.hgetall = AsyncMock(return_value={
            "cve_ids": '["CVE-2024-0001"]',
            "events": json.dumps([{
                "cve_id": "CVE-2024-0001",
                "event_type": "new_patch",
                "event_date": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
                "summary": "Patch released",
            }]),
        })
        mock_redis.set = AsyncMock()

        with patch("datanexus.tools.t10_sprint8.get_redis", return_value=mock_redis):
            return await fetch_cve_watch_status(watch_ids=["watch-1"])

    result = run(_run())
    assert result["status"] == "ok"
    assert len(result["watches_with_new_events"]) == 1


def test_fetch_cve_watch_status_cursor_filters_old_events():
    from datanexus.tools.t10_sprint8 import fetch_cve_watch_status
    from datanexus.core.request_context import api_key_var

    async def _run():
        api_key_var.set(None)

        # Cursor is yesterday — event from 10 days ago should not appear
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=yesterday)
        mock_redis.hgetall = AsyncMock(return_value={
            "cve_ids": '["CVE-2024-0002"]',
            "events": json.dumps([{
                "cve_id": "CVE-2024-0002",
                "event_type": "kev_listed",
                "event_date": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
                "summary": "Added to CISA KEV",
            }]),
        })
        mock_redis.set = AsyncMock()

        with patch("datanexus.tools.t10_sprint8.get_redis", return_value=mock_redis):
            return await fetch_cve_watch_status(watch_ids=["watch-2"])

    result = run(_run())
    assert result["status"] == "ok"
    assert result["watches_with_new_events"] == []


# ══════════════════════════════════════════════════════════════════════════════
# fetch_dependency_graph — cvs_filtered field
# ══════════════════════════════════════════════════════════════════════════════

def test_fetch_dependency_graph_has_cvs_filtered_field():
    """_fetch_dep_graph_live result must include cvs_filtered_transitive_deps."""
    from datanexus.tools.t10 import _fetch_dep_graph_live

    async def _run():
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "lodash", "version": "4.17.21"}, "relation": "DIRECT"},
                {"versionKey": {"system": "NPM", "name": "semver", "version": "7.3.8"}, "relation": "INDIRECT"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        # Patch OSV batch call to return no CVEs
        mock_osv_resp = MagicMock()
        mock_osv_resp.status_code = 200
        mock_osv_resp.json.return_value = {"results": [{"vulns": []}]}
        mock_client.post = AsyncMock(return_value=mock_osv_resp)

        return await _fetch_dep_graph_live(mock_client, "NPM", "lodash", "4.17.21")

    result = run(_run())
    assert "cvs_filtered_transitive_deps" in result
    assert isinstance(result["cvs_filtered_transitive_deps"], list)
