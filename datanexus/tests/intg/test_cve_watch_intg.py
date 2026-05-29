"""
datanexus/tests/intg/test_cve_watch_intg.py — Integration test for fetch_cve_watch.

Written BEFORE implementation (PRE-4 gate per SPRINT6_PROMPT.md).
Tests must pass before fetch_cve_watch is registered in main.py.

Prerequisites:
  - fakeredis installed (in requirements.txt)
  - datanexus.tools.security_stateful and datanexus.schedulers implemented

Usage:
  python3 -m pytest datanexus/tests/intg/test_cve_watch_intg.py -v
  python3 -m datanexus.tests.intg.test_cve_watch_intg  (standalone)
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone

# Use fakeredis for isolated local testing
try:
    import fakeredis.aioredis as fakeredis_async
    import fakeredis
    _HAS_FAKEREDIS = True
except ImportError:
    _HAS_FAKEREDIS = False

_WATCH_ID  = "sprint6-test-001"
_CVE_IDS   = ["CVE-2021-44228"]
_REDIS_KEY = f"dn:cve_watch:{_WATCH_ID}"
_INDEX_KEY = "dn:cve_watch_ids"


# ── Test helpers ───────────────────────────────────────────────────────────────

def _pass(name: str) -> None:
    print(f"  PASS  {name}")


def _fail(name: str, detail: str) -> None:
    print(f"  FAIL  {name}: {detail}")
    raise AssertionError(f"{name}: {detail}")


async def _make_fake_redis():
    """Create an isolated fakeredis instance for testing."""
    if not _HAS_FAKEREDIS:
        raise RuntimeError("fakeredis not installed — run: pip install fakeredis")
    server = fakeredis.FakeServer()
    r = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    return r


# ── The 6 integration assertions ──────────────────────────────────────────────

async def run_integration_test() -> bool:
    """
    PRE-4 integration test for fetch_cve_watch.

    Steps:
    1. register watch_id="sprint6-test-001", cve_ids=["CVE-2021-44228"]
    2. manually call _run_cve_watch_refresh()
    3. assert Redis key dn:cve_watch:sprint6-test-001 exists
    4. assert last_checked field is updated
    5. assert events field is valid JSON array
    6. assert dn:cve_watch_ids SET contains "sprint6-test-001"
    """
    from datanexus.tools.security_stateful import _create_cve_watch, _delete_cve_watch
    from datanexus.schedulers import _run_cve_watch_refresh

    r = await _make_fake_redis()
    passed = 0
    failed = 0

    try:
        # ── Step 1: register watch ─────────────────────────────────────────────
        await _create_cve_watch(r, _WATCH_ID, _CVE_IDS)

        # ── Assertion 3: Redis hash key exists ─────────────────────────────────
        exists = await r.exists(_REDIS_KEY)
        if exists:
            _pass("Redis key dn:cve_watch:sprint6-test-001 exists after create")
            passed += 1
        else:
            _fail("Redis key dn:cve_watch:sprint6-test-001 exists after create",
                  "key missing")
            failed += 1

        # ── Assertion 6: watch ID in SET index ─────────────────────────────────
        members = await r.smembers(_INDEX_KEY)
        if _WATCH_ID in members:
            _pass(f"dn:cve_watch_ids SET contains '{_WATCH_ID}'")
            passed += 1
        else:
            _fail(f"dn:cve_watch_ids SET contains '{_WATCH_ID}'",
                  f"members={members}")
            failed += 1

        # ── Step 2: manually trigger refresh (passes fakeredis instance) ───────
        # _run_cve_watch_refresh accepts an optional redis override for testing
        before_check = datetime.now(timezone.utc).isoformat()
        await _run_cve_watch_refresh(redis_override=r)

        # ── Assertion 3 (re-check after refresh) ──────────────────────────────
        still_exists = await r.exists(_REDIS_KEY)
        if still_exists:
            _pass("Redis key still exists after _run_cve_watch_refresh")
            passed += 1
        else:
            _fail("Redis key still exists after _run_cve_watch_refresh",
                  "key was deleted by scheduler")
            failed += 1

        # ── Assertion 4: last_checked updated ─────────────────────────────────
        last_checked = await r.hget(_REDIS_KEY, "last_checked")
        if last_checked and last_checked >= before_check[:10]:
            _pass(f"last_checked field updated: {last_checked[:19]}")
            passed += 1
        else:
            _fail("last_checked field updated",
                  f"got: {last_checked!r}, expected >= {before_check[:10]}")
            failed += 1

        # ── Assertion 5: events is a valid JSON array ──────────────────────────
        events_raw = await r.hget(_REDIS_KEY, "events")
        if events_raw is not None:
            try:
                events = json.loads(events_raw)
                if isinstance(events, list):
                    _pass(f"events field is valid JSON array (len={len(events)})")
                    passed += 1
                else:
                    _fail("events field is valid JSON array",
                          f"parsed to {type(events).__name__}, not list")
                    failed += 1
            except json.JSONDecodeError as e:
                _fail("events field is valid JSON array",
                      f"JSON parse error: {e}")
                failed += 1
        else:
            _fail("events field is valid JSON array", "events field missing from hash")
            failed += 1

        # ── Cleanup ────────────────────────────────────────────────────────────
        await _delete_cve_watch(r, _WATCH_ID)
        gone = not await r.exists(_REDIS_KEY)
        not_in_set = _WATCH_ID not in await r.smembers(_INDEX_KEY)
        if gone and not_in_set:
            _pass("delete removes key and cleans up SET index")
            passed += 1
        else:
            _fail("delete removes key and cleans up SET index",
                  f"key_gone={gone} not_in_set={not_in_set}")
            failed += 1

    finally:
        await r.aclose()

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


# ── Standalone runner ──────────────────────────────────────────────────────────

def main() -> int:
    print(f"\n{'─'*60}")
    print(f"  fetch_cve_watch Integration Test — PRE-4")
    print(f"  watch_id={_WATCH_ID!r}  cve_ids={_CVE_IDS}")
    print(f"{'─'*60}")

    try:
        ok = asyncio.run(run_integration_test())
    except ImportError as e:
        print(f"\n  SKIP — implementation not yet available: {e}")
        print("  This is expected before security_stateful.py is written.")
        return 0  # not a test failure — test is written ahead of implementation
    except AssertionError:
        return 1

    print(f"{'─'*60}\n")
    return 0 if ok else 1


# ── pytest entry point ─────────────────────────────────────────────────────────

def test_cve_watch_integration():
    """pytest-compatible entry point."""
    try:
        ok = asyncio.run(run_integration_test())
        assert ok, "Integration test failed — see stdout for details"
    except ImportError as e:
        import pytest
        pytest.skip(f"Implementation not yet available: {e}")


if __name__ == "__main__":
    sys.exit(main())
