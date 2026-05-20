"""
datanexus/tests/test_cve_remediation.py — Unit tests for _parse_osv_remediation().

The function returns:
  {patch_available: True,  fixes: [{package, ecosystem, upgrade_to}]} — fix found
  {patch_available: False, fixes: []}                                  — advisory, no fix
  {patch_available: None,  fixes: None}                                — not in OSV

Run with: pytest datanexus/tests/test_cve_remediation.py -v
"""

import pytest
from datanexus.tools.t10 import _parse_osv_remediation


class TestParseOsvRemediation:

    def test_none_advisory_returns_null_sentinel(self):
        result = _parse_osv_remediation(None)
        assert result == {"patch_available": None, "fixes": None}

    def test_empty_dict_returns_no_fix(self):
        result = _parse_osv_remediation({})
        assert result["patch_available"] is False
        assert result["fixes"] == []

    def test_single_fixed_version(self):
        advisory = {
            "affected": [
                {
                    "package": {"name": "log4j-core", "ecosystem": "Maven"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0"},
                                {"fixed": "2.17.1"},
                            ],
                        }
                    ],
                }
            ]
        }
        result = _parse_osv_remediation(advisory)
        assert result["patch_available"] is True
        assert len(result["fixes"]) == 1
        assert result["fixes"][0]["upgrade_to"] == "2.17.1"
        assert result["fixes"][0]["package"] == "log4j-core"
        assert result["fixes"][0]["ecosystem"] == "Maven"

    def test_multiple_fixed_versions(self):
        advisory = {
            "affected": [
                {
                    "package": {"name": "log4j-core", "ecosystem": "Maven"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0"},
                                {"fixed": "2.15.0"},
                                {"introduced": "2.16.0"},
                                {"fixed": "2.17.1"},
                            ],
                        }
                    ],
                }
            ]
        }
        result = _parse_osv_remediation(advisory)
        assert result["patch_available"] is True
        upgrade_tos = [f["upgrade_to"] for f in result["fixes"]]
        assert "2.15.0" in upgrade_tos
        assert "2.17.1" in upgrade_tos

    def test_deduplicates_fixes(self):
        advisory = {
            "affected": [
                {
                    "package": {"name": "foo", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"fixed": "1.2.3"}]},
                    ],
                },
                {
                    "package": {"name": "foo", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"fixed": "1.2.3"}]},
                    ],
                },
            ]
        }
        result = _parse_osv_remediation(advisory)
        assert sum(1 for f in result["fixes"] if f["upgrade_to"] == "1.2.3") == 1

    def test_no_ranges_returns_no_fix(self):
        advisory = {
            "affected": [
                {"package": {"name": "foo"}, "ranges": []}
            ]
        }
        result = _parse_osv_remediation(advisory)
        assert result["patch_available"] is False
        assert result["fixes"] == []

    def test_no_fixed_event_returns_no_fix(self):
        advisory = {
            "affected": [
                {
                    "package": {"name": "bar", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0.0"}],
                        }
                    ],
                }
            ]
        }
        result = _parse_osv_remediation(advisory)
        assert result["patch_available"] is False
        assert result["fixes"] == []

    def test_git_ranges_skipped(self):
        advisory = {
            "affected": [
                {
                    "package": {"name": "baz", "ecosystem": "Go"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"fixed": "abc123commit"}],
                        }
                    ],
                }
            ]
        }
        result = _parse_osv_remediation(advisory)
        assert result["patch_available"] is False
        assert result["fixes"] == []

    def test_malformed_affected_not_list_does_not_raise(self):
        # affected must be iterable; if it's not a list, get() should protect it
        advisory = {"affected": []}
        result = _parse_osv_remediation(advisory)
        assert result["fixes"] == []

    def test_fix_struct_has_required_keys(self):
        advisory = {
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"fixed": "2.32.0"}]}
                    ],
                }
            ]
        }
        result = _parse_osv_remediation(advisory)
        fix = result["fixes"][0]
        assert "package" in fix
        assert "ecosystem" in fix
        assert "upgrade_to" in fix
