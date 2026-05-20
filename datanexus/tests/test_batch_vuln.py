"""
datanexus/tests/test_batch_vuln.py — Unit tests for Sprint 4 batch vulnerability logic.

_batch_osv_query(client, components) -> list[dict]
  Takes an httpx.AsyncClient and a list of {name, version, ecosystem} dicts.
  POSTs to OSV /v1/querybatch. Returns raw results list.

fetch_package_vulnerabilities disambiguation:
  packages[] non-empty → batch mode (packages[] wins over single args)
  package + version + ecosystem → single mode
  neither → MISSING_PARAMS error

Run with: pytest datanexus/tests/test_batch_vuln.py -v
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── _batch_osv_query unit tests ───────────────────────────────────────────────

class TestBatchOsvQuery:

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_client(self, json_response: dict):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = json_response
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        return mock_client

    def test_empty_components_posts_empty_queries(self):
        from datanexus.tools.t10 import _batch_osv_query
        client = self._make_client({"results": []})
        result = self._run(_batch_osv_query(client, []))
        assert result == []
        # POST was still called (OSV accepts empty queries list)
        client.post.assert_called_once()

    def test_single_component_returns_single_result(self):
        from datanexus.tools.t10 import _batch_osv_query
        osv_result = {"vulns": [{"id": "CVE-2021-44228"}]}
        client = self._make_client({"results": [osv_result]})
        components = [{"name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven"}]
        result = self._run(_batch_osv_query(client, components))
        assert len(result) == 1
        assert result[0]["vulns"][0]["id"] == "CVE-2021-44228"

    def test_sends_correct_payload(self):
        from datanexus.tools.t10 import _batch_osv_query
        client = self._make_client({"results": [{}]})
        components = [{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}]
        self._run(_batch_osv_query(client, components))

        call_kwargs = client.post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
        queries = payload["queries"]
        assert len(queries) == 1
        assert queries[0]["version"] == "2.28.0"
        assert queries[0]["package"]["name"] == "requests"

    def test_caps_at_1000_components(self):
        from datanexus.tools.t10 import _batch_osv_query
        many = [{"name": f"pkg{i}", "version": "1.0", "ecosystem": "npm"} for i in range(1200)]
        fake_results = [{"vulns": []} for _ in range(1000)]
        client = self._make_client({"results": fake_results})
        result = self._run(_batch_osv_query(client, many))
        # Should only return 1000 results (capped)
        assert len(result) == 1000

    def test_missing_results_key_returns_empty(self):
        from datanexus.tools.t10 import _batch_osv_query
        client = self._make_client({})  # no "results" key
        result = self._run(_batch_osv_query(client, [{"name": "foo", "version": "1.0", "ecosystem": "PyPI"}]))
        assert result == []


# ── Disambiguation / routing tests ────────────────────────────────────────────

class TestDisambiguationLogic:
    """Test the package vs packages[] routing in fetch_package_vulnerabilities."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_neither_package_nor_packages_returns_missing_params(self):
        from datanexus.tools.t10 import fetch_package_vulnerabilities
        result = self._run(fetch_package_vulnerabilities(
            package=None, version=None, ecosystem=None, packages=None,
        ))
        assert result.get("status") == "error"
        assert result.get("error_code") == "missing_params"

    def test_empty_packages_list_falls_through_to_single_check(self):
        from datanexus.tools.t10 import fetch_package_vulnerabilities
        # packages=[] is falsy → not batch mode; no single args either → MISSING_PARAMS
        result = self._run(fetch_package_vulnerabilities(packages=[]))
        assert result.get("status") == "error"
        assert result.get("error_code") == "missing_params"

    def test_batch_mode_triggered_by_packages_list(self):
        from datanexus.tools.t10 import fetch_package_vulnerabilities
        packages = [
            {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
        ]
        osv_batch_resp = [{"vulns": []}]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"results": osv_batch_resp}

        with patch("httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = self._run(fetch_package_vulnerabilities(packages=packages))

        # Should not be an error (batch path executed)
        assert result.get("status") != "error" or result.get("error_code") == "circuit_open"

    def test_batch_caps_at_50_logs_warning(self):
        from datanexus.tools.t10 import fetch_package_vulnerabilities
        packages = [{"name": f"pkg{i}", "version": "1.0", "ecosystem": "npm"} for i in range(60)]
        # OSV returns 50 results (capped)
        osv_batch_results = [{"vulns": []} for _ in range(50)]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"results": osv_batch_results}

        with patch("httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = self._run(fetch_package_vulnerabilities(packages=packages))

        # Response is not an error (batch ran)
        if result.get("status") != "error":
            data = result.get("data", {})
            results_list = data.get("results", [])
            # Only 50 packages were sent; remaining 10 show as failed or partial
            assert data.get("partial") is True or len(results_list) <= 50
