"""
datanexus/tests/test_api_key_sprint8a.py — Sprint 8A test suite (22 paths)

Tests cover:
  - record_usage(): api_key_hash kwarg accepted, existing callers unaffected
  - _ApiKeyMiddleware: no header, valid key, revoked key, non-http scope
  - _UsageMiddleware: tier, counter injection, hint/warning thresholds,
                      PAYMENT_ENABLED true/false, Redis fail-open
  - generate_api_key: success, rate limit, invalid email
  - rotate_api_key: success, key not found
  - revoke_api_key: success, cache invalidated

Pattern: same asyncio.get_event_loop().run_until_complete() pattern as
existing tests in this repo (no pytest-asyncio required).
"""

import asyncio
import hashlib
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════════════════
# 1. record_usage() — new keyword arg
# ═══════════════════════════════════════════════════════

def test_record_usage_accepts_api_key_hash_kwarg():
    """record_usage() must not raise TypeError when api_key_hash is passed."""
    from datanexus.core.usage_recorder import record_usage

    async def _run():
        with patch("datanexus.core.usage_recorder._get_pool", return_value=None):
            await record_usage(
                tool_id="T10",
                session_id="sess-123",
                tool_input={"pkg": "requests"},
                client_ip="1.2.3.4",
                success=True,
                api_key_hash="abc123",
            )

    run(_run())


def test_record_usage_without_api_key_hash_still_works():
    """Existing callers omitting api_key_hash must still work."""
    from datanexus.core.usage_recorder import record_usage

    async def _run():
        with patch("datanexus.core.usage_recorder._get_pool", return_value=None):
            await record_usage(
                tool_id="T04",
                session_id="sess-456",
                tool_input={"ein": "123456789"},
                client_ip="1.2.3.4",
                success=True,
            )

    run(_run())


# ═══════════════════════════════════════════════════════
# 2. _ApiKeyMiddleware — header extraction
# ═══════════════════════════════════════════════════════

def test_api_key_middleware_no_header_sets_none():
    from datanexus.main import _ApiKeyMiddleware
    from datanexus.core.request_context import api_key_var

    received = {}

    async def _run():
        async def fake_app(scope, receive, send):
            received["val"] = api_key_var.get()

        mw = _ApiKeyMiddleware(fake_app)
        await mw({"type": "http", "headers": []}, None, None)

    run(_run())
    assert received["val"] is None


def test_api_key_middleware_valid_key_sets_hash():
    from datanexus.main import _ApiKeyMiddleware
    from datanexus.core.request_context import api_key_var

    raw = "dnx_" + "a" * 64
    expected_hash = _sha(raw)
    received = {}

    async def _run():
        async def fake_app(scope, receive, send):
            received["val"] = api_key_var.get()

        mw = _ApiKeyMiddleware(fake_app)

        async def mock_lookup(self, key_hash):
            return "free"

        with patch.object(_ApiKeyMiddleware, "_lookup", mock_lookup):
            scope = {
                "type": "http",
                "headers": [(b"x-datanexus-key", raw.encode())],
            }
            await mw(scope, None, None)

    run(_run())
    assert received["val"] == expected_hash


def test_api_key_middleware_revoked_key_sets_none():
    from datanexus.main import _ApiKeyMiddleware
    from datanexus.core.request_context import api_key_var

    received = {}

    async def _run():
        async def fake_app(scope, receive, send):
            received["val"] = api_key_var.get()

        mw = _ApiKeyMiddleware(fake_app)

        async def mock_lookup(self, key_hash):
            return None  # revoked / not found

        with patch.object(_ApiKeyMiddleware, "_lookup", mock_lookup):
            scope = {
                "type": "http",
                "headers": [(b"x-datanexus-key", b"dnx_revoked")],
            }
            await mw(scope, None, None)

    run(_run())
    assert received["val"] is None


def test_api_key_middleware_non_http_scope_passes_through():
    from datanexus.main import _ApiKeyMiddleware

    called = {}

    async def _run():
        async def fake_app(scope, receive, send):
            called["ok"] = True

        mw = _ApiKeyMiddleware(fake_app)
        await mw({"type": "lifespan"}, None, None)

    run(_run())
    assert called.get("ok") is True


# ═══════════════════════════════════════════════════════
# 3. _UsageMiddleware — tier logic + counter injection
# ═══════════════════════════════════════════════════════

def _make_usage_result(count: int, api_key_hash=None, ip="1.2.3.4",
                       payment_enabled="false"):
    """Run _UsageMiddleware.on_call_tool and return the ToolResult."""
    from fastmcp.tools.base import ToolResult as CallToolResult
    from datanexus.tools.api_key_sprint8a import _UsageMiddleware
    from datanexus.core.request_context import api_key_var, client_ip_var

    dummy = CallToolResult(content="ok")

    async def _run():
        api_key_var.set(api_key_hash)
        client_ip_var.set(ip)

        # pipeline() is synchronous in aioredis; execute() is async
        mock_pipeline = MagicMock()
        mock_pipeline.incr = MagicMock()
        mock_pipeline.ttl = MagicMock()
        mock_pipeline.execute = AsyncMock(return_value=[count, 1000])

        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)
        mock_redis.expire = AsyncMock()

        async def fake_get_redis():
            return mock_redis

        mw = _UsageMiddleware()

        async def fake_next(ctx):
            return dummy

        with patch("datanexus.tools.api_key_sprint8a.get_redis", fake_get_redis), \
             patch.dict(os.environ, {"PAYMENT_ENABLED": payment_enabled}):
            return await mw.on_call_tool(MagicMock(), fake_next)

    return run(_run())


def test_usage_middleware_anonymous_tier_injects_usage():
    result = _make_usage_result(count=5, api_key_hash=None)
    assert result.structured_content is not None
    assert result.structured_content["usage"]["tier"] == "anonymous"
    assert result.structured_content["usage"]["limit"] == 10
    assert result.structured_content["usage"]["calls_this_month"] == 5


def test_usage_middleware_registered_tier_limit_500():
    result = _make_usage_result(count=10, api_key_hash=_sha("dnx_testkey"))
    assert result.structured_content["usage"]["tier"] == "registered"
    assert result.structured_content["usage"]["limit"] == 500


def test_usage_middleware_hint_appears_at_threshold():
    result = _make_usage_result(count=3, api_key_hash=None)  # 3 > hint_at=2
    assert "upgrade_hint" in result.structured_content
    assert "limit_warning" not in result.structured_content


def test_usage_middleware_warning_appears_at_limit():
    result = _make_usage_result(count=10, api_key_hash=None)  # == limit
    assert "limit_warning" in result.structured_content
    assert "upgrade_hint" not in result.structured_content


def test_usage_middleware_payment_enabled_hard_gate():
    """PAYMENT_ENABLED=true + count > limit → isError ToolResult."""
    result = _make_usage_result(count=11, api_key_hash=None, payment_enabled="true")
    assert result.structured_content["error"] == "rate_limit_exceeded"


def test_usage_middleware_payment_disabled_serves_over_limit():
    """PAYMENT_ENABLED=false → serve even when count >= limit."""
    result = _make_usage_result(count=15, api_key_hash=None, payment_enabled="false")
    assert result.structured_content is not None
    assert "limit_warning" in result.structured_content


def test_usage_middleware_redis_down_fails_open():
    """Redis unavailable → return tool result unchanged."""
    from fastmcp.tools.base import ToolResult as CallToolResult
    from datanexus.tools.api_key_sprint8a import _UsageMiddleware
    from datanexus.core.request_context import api_key_var, client_ip_var

    dummy = CallToolResult(content="data")

    async def _run():
        api_key_var.set(None)
        client_ip_var.set("1.2.3.4")

        async def redis_raises():
            raise ConnectionError("Redis down")

        mw = _UsageMiddleware()

        async def fake_next(ctx):
            return dummy

        with patch("datanexus.tools.api_key_sprint8a.get_redis", side_effect=ConnectionError("Redis down")):
            return await mw.on_call_tool(MagicMock(), fake_next)

    result = run(_run())
    assert result is dummy  # unchanged — fail open


# ═══════════════════════════════════════════════════════
# 4. generate_api_key tool
# ═══════════════════════════════════════════════════════

def test_generate_api_key_success():
    from datanexus.tools.api_key_sprint8a import generate_api_key
    from datanexus.core.request_context import client_ip_var

    async def _run():
        client_ip_var.set("1.2.3.4")

        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.expire = AsyncMock()
        mock_redis.set = AsyncMock()

        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.execute = AsyncMock()

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=mock_conn)
        mock_pool.close = AsyncMock()

        with patch("datanexus.tools.api_key_sprint8a.get_redis", return_value=mock_redis), \
             patch("datanexus.tools.api_key_sprint8a._get_pool", return_value=mock_pool):
            return await generate_api_key("user@example.com")

    result = run(_run())
    assert result["status"] == "ok"
    assert result["api_key"].startswith("dnx_")
    assert len(result["api_key"]) == 68  # "dnx_" + 64 hex chars
    assert "will not be shown again" in result["message"]


def test_generate_api_key_rate_limit():
    from datanexus.tools.api_key_sprint8a import generate_api_key
    from datanexus.core.request_context import client_ip_var

    async def _run():
        client_ip_var.set("1.2.3.4")
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=4)  # > limit of 3
        mock_redis.expire = AsyncMock()

        with patch("datanexus.tools.api_key_sprint8a.get_redis", return_value=mock_redis):
            return await generate_api_key("user@example.com")

    result = run(_run())
    assert result["status"] == "error"
    assert result["error_code"] == "rate_limit_exceeded"


def test_generate_api_key_invalid_email():
    from datanexus.tools.api_key_sprint8a import generate_api_key
    from datanexus.core.request_context import client_ip_var

    async def _run():
        client_ip_var.set("1.2.3.4")
        return await generate_api_key("not-an-email")

    result = run(_run())
    assert result["status"] == "error"
    assert result["error_code"] == "invalid_email"


# ═══════════════════════════════════════════════════════
# 5. rotate_api_key tool
# ═══════════════════════════════════════════════════════

def test_rotate_api_key_success():
    from datanexus.tools.api_key_sprint8a import rotate_api_key

    async def _run():
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.set = AsyncMock()

        mock_txn = AsyncMock()
        mock_txn.__aenter__ = AsyncMock(return_value=None)
        mock_txn.__aexit__ = AsyncMock(return_value=False)

        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.fetchrow = AsyncMock(return_value={"tier": "free"})
        mock_conn.execute = AsyncMock()
        mock_conn.transaction = MagicMock(return_value=mock_txn)

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=mock_conn)
        mock_pool.close = AsyncMock()

        with patch("datanexus.tools.api_key_sprint8a.get_redis", return_value=mock_redis), \
             patch("datanexus.tools.api_key_sprint8a._get_pool", return_value=mock_pool):
            return await rotate_api_key("dnx_" + "b" * 64)

    result = run(_run())
    assert result["status"] == "ok"
    assert result["api_key"].startswith("dnx_")


def test_rotate_api_key_not_found():
    from datanexus.tools.api_key_sprint8a import rotate_api_key

    async def _run():
        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.fetchrow = AsyncMock(return_value=None)

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=mock_conn)
        mock_pool.close = AsyncMock()

        with patch("datanexus.tools.api_key_sprint8a._get_pool", return_value=mock_pool):
            return await rotate_api_key("dnx_" + "c" * 64)

    result = run(_run())
    assert result["status"] == "error"
    assert result["error_code"] == "key_not_found"


# ═══════════════════════════════════════════════════════
# 6. revoke_api_key tool
# ═══════════════════════════════════════════════════════

def test_revoke_api_key_success():
    from datanexus.tools.api_key_sprint8a import revoke_api_key

    async def _run():
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock()

        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.execute = AsyncMock()

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=mock_conn)
        mock_pool.close = AsyncMock()

        with patch("datanexus.tools.api_key_sprint8a.get_redis", return_value=mock_redis), \
             patch("datanexus.tools.api_key_sprint8a._get_pool", return_value=mock_pool):
            return await revoke_api_key("dnx_" + "d" * 64)

    result = run(_run())
    assert result["status"] == "revoked"


def test_revoke_api_key_cache_invalidated():
    """Redis DEL must be called with the correct dn:apikey:{hash} key."""
    from datanexus.tools.api_key_sprint8a import revoke_api_key

    raw = "dnx_" + "e" * 64
    expected_cache_key = f"dn:apikey:{_sha(raw)}"
    deleted_keys = []

    async def _run():
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(side_effect=lambda k: deleted_keys.append(k))

        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.execute = AsyncMock()

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=mock_conn)
        mock_pool.close = AsyncMock()

        with patch("datanexus.tools.api_key_sprint8a.get_redis", return_value=mock_redis), \
             patch("datanexus.tools.api_key_sprint8a._get_pool", return_value=mock_pool):
            await revoke_api_key(raw)

    run(_run())
    assert expected_cache_key in deleted_keys
