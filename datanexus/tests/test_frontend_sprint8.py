"""
datanexus/tests/test_frontend_sprint8.py — Sprint 8B frontend tools (20 paths)

Tests cover:
  - frontend_security_detect_typosquatting: known package, typosquat, no corpus
  - frontend_security_audit_manifest: SHIP, BLOCK, CAUTION, empty deps, malformed
  - frontend_security_audit_ci_pipeline: secrets NOT flagged for ${{ secrets.X }},
      exposed literal AWS key, unpinned action, missing npm ci, overly broad perms,
      vercel config (secrets only), empty config
  - frontend_security_fetch_package_risk_brief: npm-only, is_ui_component detection,
      weekly_downloads field present
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════════════════════
# frontend_security_detect_typosquatting
# ══════════════════════════════════════════════════════════════════════════════

def test_detect_typosquatting_known_package_not_typosquat():
    from datanexus.tools.frontend_sprint8 import detect_typosquatting as frontend_security_detect_typosquatting

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._get_frontend_corpus",
                   return_value=["react", "lodash", "axios"]):
            return await frontend_security_detect_typosquatting(package_name="react")

    result = run(_run())
    assert result["is_likely_typosquat"] is False
    assert result["distance"] == 0


def test_detect_typosquatting_close_match_flagged():
    from datanexus.tools.frontend_sprint8 import detect_typosquatting as frontend_security_detect_typosquatting

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._get_frontend_corpus",
                   return_value=["react", "lodash", "axios"]):
            return await frontend_security_detect_typosquatting(package_name="axois")  # typo of axios

    result = run(_run())
    assert result["is_likely_typosquat"] is True
    assert result["closest_match"] == "axios"
    assert result["distance"] <= 2


def test_detect_typosquatting_distant_package_not_flagged():
    from datanexus.tools.frontend_sprint8 import detect_typosquatting as frontend_security_detect_typosquatting

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._get_frontend_corpus",
                   return_value=["react", "lodash", "axios"]):
            return await frontend_security_detect_typosquatting(package_name="completely-different-pkg-xyz")

    result = run(_run())
    assert result["is_likely_typosquat"] is False
    assert result["risk_level"] == "LOW"


def test_detect_typosquatting_corpus_unavailable_returns_error():
    from datanexus.tools.frontend_sprint8 import detect_typosquatting as frontend_security_detect_typosquatting

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._get_frontend_corpus", return_value=[]):
            return await frontend_security_detect_typosquatting(package_name="react")

    result = run(_run())
    assert result["status"] == "error"


# ══════════════════════════════════════════════════════════════════════════════
# frontend_security_audit_manifest
# ══════════════════════════════════════════════════════════════════════════════

def test_audit_manifest_ship_clean_package():
    from datanexus.tools.frontend_sprint8 import audit_manifest as frontend_security_audit_manifest

    manifest = json.dumps({"dependencies": {"react": "^18.0.0"}})

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._fetch_vulns",
                   return_value={"critical_cve_count": 0, "high_cve_count": 0}), \
             patch("datanexus.tools.frontend_sprint8._fetch_licence",
                   return_value={"licence_id": "MIT", "licence_risk": "LOW"}), \
             patch("datanexus.tools.frontend_sprint8._resolve_version", return_value="18.2.0"):
            return await frontend_security_audit_manifest(manifest=manifest)

    result = run(_run())
    assert result["verdict"] == "SHIP"
    assert result["critical_cves"] == 0


def test_audit_manifest_block_critical_cve():
    from datanexus.tools.frontend_sprint8 import audit_manifest as frontend_security_audit_manifest

    manifest = json.dumps({"dependencies": {"vulnerable-pkg": "^1.0.0"}})

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._fetch_vulns",
                   return_value={"critical_cve_count": 2, "high_cve_count": 1}), \
             patch("datanexus.tools.frontend_sprint8._fetch_licence",
                   return_value={"licence_id": "MIT", "licence_risk": "LOW"}), \
             patch("datanexus.tools.frontend_sprint8._resolve_version", return_value="1.0.0"):
            return await frontend_security_audit_manifest(manifest=manifest)

    result = run(_run())
    assert result["verdict"] == "BLOCK"


def test_audit_manifest_caution_high_cves():
    from datanexus.tools.frontend_sprint8 import audit_manifest as frontend_security_audit_manifest

    manifest = json.dumps({"dependencies": {"risky-pkg": "^2.0.0"}})

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._fetch_vulns",
                   return_value={"critical_cve_count": 0, "high_cve_count": 3}), \
             patch("datanexus.tools.frontend_sprint8._fetch_licence",
                   return_value={"licence_id": "MIT", "licence_risk": "LOW"}), \
             patch("datanexus.tools.frontend_sprint8._resolve_version", return_value="2.0.0"):
            return await frontend_security_audit_manifest(manifest=manifest)

    result = run(_run())
    assert result["verdict"] == "CAUTION"


def test_audit_manifest_empty_deps_ship():
    from datanexus.tools.frontend_sprint8 import audit_manifest as frontend_security_audit_manifest

    manifest = json.dumps({"name": "my-app", "version": "1.0.0"})

    async def _run():
        return await frontend_security_audit_manifest(manifest=manifest)

    result = run(_run())
    assert result["verdict"] == "SHIP"
    assert result["total_packages"] == 0


def test_audit_manifest_malformed_json():
    from datanexus.tools.frontend_sprint8 import audit_manifest as frontend_security_audit_manifest

    async def _run():
        return await frontend_security_audit_manifest(manifest="not-json{")

    result = run(_run())
    assert result["verdict"] == "ERROR"


# ══════════════════════════════════════════════════════════════════════════════
# frontend_security_audit_ci_pipeline
# ══════════════════════════════════════════════════════════════════════════════

def test_audit_ci_safe_secret_ref_not_flagged():
    """${{ secrets.FOO }} must NOT be flagged as an exposed secret."""
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    config = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abc1234def5678901234567890123456789012ab
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="github_actions")

    result = run(_run())
    # None of the findings should be EXPOSED_SECRET
    secret_findings = [f for f in result["findings"] if f["type"] == "EXPOSED_SECRET"]
    assert secret_findings == [], f"Safe refs flagged: {secret_findings}"


def test_audit_ci_literal_aws_key_flagged():
    """Literal AKIA... key must be flagged as CRITICAL."""
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    config = """
name: CI
env:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
"""

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="github_actions")

    result = run(_run())
    secret_findings = [f for f in result["findings"] if f["type"] == "EXPOSED_SECRET"]
    assert len(secret_findings) >= 1
    assert secret_findings[0]["severity"] == "CRITICAL"
    assert result["risk_level"] == "CRITICAL"


def test_audit_ci_unpinned_action_flagged():
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    config = """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
"""

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="github_actions")

    result = run(_run())
    unpinned = [f for f in result["findings"] if f["type"] == "UNPINNED_ACTION"]
    assert len(unpinned) >= 1
    assert unpinned[0]["ref"] == "v4"


def test_audit_ci_pinned_sha_not_flagged():
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    sha = "a" * 40  # valid 40-char hex SHA
    config = f"""
jobs:
  build:
    steps:
      - uses: actions/checkout@{sha}
      - run: npm ci
"""

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="github_actions")

    result = run(_run())
    unpinned = [f for f in result["findings"] if f["type"] == "UNPINNED_ACTION"]
    assert unpinned == []


def test_audit_ci_missing_lockfile_enforcement():
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    config = """
jobs:
  build:
    steps:
      - run: npm install
"""

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="github_actions")

    result = run(_run())
    lockfile_findings = [f for f in result["findings"] if f["type"] in (
        "MISSING_LOCKFILE_ENFORCEMENT", "UNVERIFIED_NPM_INSTALL"
    )]
    assert len(lockfile_findings) >= 1


def test_audit_ci_overly_broad_permissions():
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    config = """
permissions: write-all
jobs:
  build:
    steps:
      - run: npm ci
"""

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="github_actions")

    result = run(_run())
    perm_findings = [f for f in result["findings"] if f["type"] == "OVERLY_BROAD_PERMISSIONS"]
    assert len(perm_findings) >= 1
    assert perm_findings[0]["severity"] == "HIGH"


def test_audit_ci_vercel_secrets_only():
    """Vercel/Netlify config type: only secrets checked in Sprint 8."""
    from datanexus.tools.frontend_sprint8 import audit_ci_pipeline as frontend_security_audit_ci_pipeline

    config = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

    async def _run():
        return await frontend_security_audit_ci_pipeline(config=config, config_type="vercel")

    result = run(_run())
    secret_findings = [f for f in result["findings"] if f["type"] == "EXPOSED_SECRET"]
    # Other checks should NOT run for vercel
    other_findings = [f for f in result["findings"] if f["type"] != "EXPOSED_SECRET"]
    assert len(secret_findings) >= 1
    assert other_findings == []


# ══════════════════════════════════════════════════════════════════════════════
# frontend_security_fetch_package_risk_brief
# ══════════════════════════════════════════════════════════════════════════════

def test_fetch_package_risk_brief_ui_component_detection():
    from datanexus.tools.frontend_sprint8 import fetch_package_risk_brief as frontend_security_fetch_package_risk_brief

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._fetch_vulns",
                   return_value={"critical_cve_count": 0, "high_cve_count": 0}), \
             patch("datanexus.tools.frontend_sprint8._fetch_licence",
                   return_value={"licence_id": "MIT", "licence_risk": "LOW"}), \
             patch("datanexus.tools.frontend_sprint8._fetch_maintainer_history",
                   return_value={"maintainer_health": "HEALTHY"}), \
             patch("datanexus.tools.frontend_sprint8._fetch_weekly_downloads",
                   return_value=5_000_000), \
             patch("datanexus.tools.frontend_sprint8._resolve_version", return_value="18.2.0"):
            return await frontend_security_fetch_package_risk_brief(
                package_name="react-datepicker"
            )

    result = run(_run())
    assert result["status"] == "ok"
    assert result["frontend_specific_signals"]["is_ui_component"] is True  # react- prefix
    assert result["frontend_specific_signals"]["weekly_downloads"] == 5_000_000


def test_fetch_package_risk_brief_non_ui_component():
    from datanexus.tools.frontend_sprint8 import fetch_package_risk_brief as frontend_security_fetch_package_risk_brief

    async def _run():
        with patch("datanexus.tools.frontend_sprint8._fetch_vulns",
                   return_value={"critical_cve_count": 0, "high_cve_count": 0}), \
             patch("datanexus.tools.frontend_sprint8._fetch_licence",
                   return_value={"licence_id": "MIT", "licence_risk": "LOW"}), \
             patch("datanexus.tools.frontend_sprint8._fetch_maintainer_history",
                   return_value={"maintainer_health": "HEALTHY"}), \
             patch("datanexus.tools.frontend_sprint8._fetch_weekly_downloads",
                   return_value=100_000), \
             patch("datanexus.tools.frontend_sprint8._resolve_version", return_value="1.0.0"):
            return await frontend_security_fetch_package_risk_brief(package_name="lodash")

    result = run(_run())
    assert result["frontend_specific_signals"]["is_ui_component"] is False
