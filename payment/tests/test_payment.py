"""
payment/tests/test_payment.py — Phase 5 acceptance tests.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 10 Table 133

10 acceptance criteria:
  AC-01  MCPIZE_ACTIVE=false → passthrough on all calls
  AC-02  402 when no entitlement + MCPIZE_ACTIVE=true
  AC-03  Valid entitlement key → call passes through
  AC-04  Grace period warning included in response
  AC-05  Grace expiry → hard 402 cutoff
  AC-06  Redis error → fail open, call succeeds
  AC-07  Wrong webhook signature → 401, no Redis write
  AC-08  subscription.cancelled → both keys deleted
  AC-09  Empty MCPIZE_URL → free passthrough
  AC-10  report_mcpize_link free mode → status='free'

All tests use fakeredis (real Redis not required).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import pytest
import fakeredis

import payment.config as _cfg
from payment.entitlement import verify_entitlement, _set_redis_client, _set_caller_id
from payment.tools import report_mcpize_link


# ── Helpers ────────────────────────────────────────────────────────────────────

TOOL_ID   = "T04"
CALLER_ID = "test-caller-001"
TEST_URL  = "https://mcpize.io/tools/t04"


def _make_redis() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


def _signed_body(payload: dict, secret: str) -> tuple[bytes, str]:
    body = json.dumps(payload).encode()
    sig  = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return body, sig


@pytest.fixture(autouse=True)
def reset_config():
    """Restore config to safe defaults after every test."""
    orig_active  = _cfg.MCPIZE_ACTIVE
    orig_urls    = dict(_cfg.MCPIZE_URLS)
    orig_secret  = _cfg.MCPIZE_WEBHOOK_SECRET
    yield
    _cfg.MCPIZE_ACTIVE        = orig_active
    _cfg.MCPIZE_URLS.update(orig_urls)
    _cfg.MCPIZE_WEBHOOK_SECRET = orig_secret
    # Reset entitlement module state
    _set_redis_client(None)
    _set_caller_id(None)


# ── Decorated dummy tool ───────────────────────────────────────────────────────

def _make_dummy_tool(tool_id: str = TOOL_ID):
    """Create a fresh decorated async dummy that returns {'result': 'ok'}."""
    @verify_entitlement(tool_id)
    async def _dummy(**kwargs):
        return {"result": "ok"}
    return _dummy


# ═══════════════════════════════════════════════════════════════════════════════
# AC-01  MCPIZE_ACTIVE=false → passthrough on all calls
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC01PassthroughFreeWindow:

    def test_passthrough_no_entitlement_key(self):
        """AC-01: free window active, no key → still gets through."""
        _cfg.MCPIZE_ACTIVE = False
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}

    def test_passthrough_with_empty_redis(self):
        """AC-01: free window, Redis empty → passthrough."""
        _cfg.MCPIZE_ACTIVE = False
        _set_caller_id(CALLER_ID)
        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}


# ═══════════════════════════════════════════════════════════════════════════════
# AC-02  402 when no entitlement + MCPIZE_ACTIVE=true
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC02PaymentRequired:

    def test_402_no_entitlement(self):
        """AC-02: active + URL set + no key → 402 error dict."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result["status"]     == "error"
        assert result["error_code"] == "payment_required"
        assert result["upgrade_url"] == TEST_URL
        assert result["tool_id"]    == TOOL_ID

    def test_402_contains_upgrade_url(self):
        """AC-02: 402 response carries the correct upgrade_url."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert "upgrade_url" in result
        assert result["upgrade_url"] == TEST_URL


# ═══════════════════════════════════════════════════════════════════════════════
# AC-03  Valid entitlement key → call passes through
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC03ValidEntitlement:

    def test_entitlement_key_allows_call(self):
        """AC-03: entitlement key present → call succeeds, no grace_warning."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        r.setex(_cfg.key_entitlement(TOOL_ID, CALLER_ID), 3600, "1")
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}
        assert "grace_warning" not in result

    def test_entitlement_key_with_long_ttl(self):
        """AC-03: annual TTL entitlement → still passes through."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        r.setex(_cfg.key_entitlement(TOOL_ID, CALLER_ID), 366 * 86400, "1")
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}


# ═══════════════════════════════════════════════════════════════════════════════
# AC-04  Grace period warning included in response
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC04GraceWarning:

    def test_grace_key_injects_warning(self):
        """AC-04: grace key present → call succeeds + grace_warning in result."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        r.setex(_cfg.key_grace(TOOL_ID, CALLER_ID), _cfg.GRACE_TTL, "1")
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result.get("result") == "ok"
        assert "grace_warning" in result
        assert "grace period" in result["grace_warning"].lower()

    def test_grace_warning_contains_upgrade_url(self):
        """AC-04: grace_warning text includes the upgrade URL."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        r.setex(_cfg.key_grace(TOOL_ID, CALLER_ID), _cfg.GRACE_TTL, "1")
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert TEST_URL in result["grace_warning"]


# ═══════════════════════════════════════════════════════════════════════════════
# AC-05  Grace expiry → hard 402 cutoff
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC05GraceExpiry:

    def test_no_grace_key_no_entitlement_gives_402(self):
        """AC-05: grace key expired (absent) + no entitlement → 402."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        # Intentionally do NOT set grace or entitlement key
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result["status"]     == "error"
        assert result["error_code"] == "payment_required"

    def test_expired_grace_key_not_in_redis_gives_402(self):
        """AC-05: explicitly delete grace key, confirm 402."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        r = _make_redis()
        grace_key = _cfg.key_grace(TOOL_ID, CALLER_ID)
        r.setex(grace_key, 1, "1")
        r.delete(grace_key)   # simulate expiry
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result["error_code"] == "payment_required"


# ═══════════════════════════════════════════════════════════════════════════════
# AC-06  Redis error → fail open, call succeeds
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC06RedisFailOpen:

    def test_redis_none_fails_open(self):
        """AC-06: Redis unavailable (None) → call succeeds (fail open)."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        _set_redis_client(None)
        # Force _get_redis() to return None by passing a broken URL
        import payment.entitlement as _ent
        orig_url = _ent._REDIS_URL
        _ent._REDIS_URL = "redis://127.0.0.1:1"   # nothing running there
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}

        _ent._REDIS_URL = orig_url

    def test_redis_exception_fails_open(self):
        """AC-06: Redis raises during check → fail open."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL

        class BrokenRedis:
            def exists(self, *a, **kw):
                raise RuntimeError("simulated Redis failure")

        _set_redis_client(BrokenRedis())   # type: ignore[arg-type]
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}


# ═══════════════════════════════════════════════════════════════════════════════
# AC-07  Wrong webhook signature → 401, no Redis write
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC07WebhookSignature:

    @pytest.fixture(autouse=True)
    def webhook_setup(self):
        import payment.webhook as wh
        self.wh = wh
        self.r  = _make_redis()
        wh._set_redis_client(self.r)
        _cfg.MCPIZE_WEBHOOK_SECRET = "webhook-secret-xyz"
        yield
        wh._set_redis_client(None)
        _cfg.MCPIZE_WEBHOOK_SECRET = ""

    def _client(self):
        from httpx import AsyncClient, ASGITransport
        return AsyncClient(
            transport=ASGITransport(app=self.wh.app),
            base_url="http://test",
        )

    def test_wrong_signature_returns_401(self):
        """AC-07: bad sig → 401."""
        async def _run():
            body = json.dumps({"event": "payment.confirmed",
                               "tool_id": "T04", "caller_id": "u1"}).encode()
            async with self._client() as c:
                resp = await c.post("/webhooks/mcpize",
                    content=body,
                    headers={"X-MCPize-Signature": "sha256=" + "0"*64,
                             "Content-Type": "application/json"})
            return resp
        resp = asyncio.get_event_loop().run_until_complete(_run())
        assert resp.status_code == 401

    def test_wrong_signature_no_redis_write(self):
        """AC-07: bad sig → entitlement key NOT written."""
        async def _run():
            body = json.dumps({"event": "payment.confirmed",
                               "tool_id": "T04", "caller_id": "u1"}).encode()
            async with self._client() as c:
                await c.post("/webhooks/mcpize",
                    content=body,
                    headers={"X-MCPize-Signature": "sha256=" + "0"*64,
                             "Content-Type": "application/json"})
        asyncio.get_event_loop().run_until_complete(_run())
        assert not self.r.exists(_cfg.key_entitlement("T04", "u1"))

    def test_missing_signature_returns_401(self):
        """AC-07: no sig header → 401."""
        async def _run():
            body = json.dumps({"event": "payment.confirmed",
                               "tool_id": "T04", "caller_id": "u1"}).encode()
            async with self._client() as c:
                resp = await c.post("/webhooks/mcpize",
                    content=body,
                    headers={"Content-Type": "application/json"})
            return resp
        resp = asyncio.get_event_loop().run_until_complete(_run())
        assert resp.status_code == 401

    def test_correct_signature_returns_200(self):
        """AC-07 (positive): correct sig → 200 ok."""
        async def _run():
            body = json.dumps({"event": "payment.confirmed",
                               "tool_id": "T04", "caller_id": "u2"}).encode()
            sig = "sha256=" + hmac.new(
                b"webhook-secret-xyz", body, hashlib.sha256
            ).hexdigest()
            async with self._client() as c:
                resp = await c.post("/webhooks/mcpize",
                    content=body,
                    headers={"X-MCPize-Signature": sig,
                             "Content-Type": "application/json"})
            return resp
        resp = asyncio.get_event_loop().run_until_complete(_run())
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# AC-08  subscription.cancelled → both keys deleted
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC08SubscriptionCancelled:

    @pytest.fixture(autouse=True)
    def webhook_setup(self):
        import payment.webhook as wh
        self.wh = wh
        self.r  = _make_redis()
        wh._set_redis_client(self.r)
        _cfg.MCPIZE_WEBHOOK_SECRET = ""   # dev mode — skip sig check
        yield
        wh._set_redis_client(None)

    def _client(self):
        from httpx import AsyncClient, ASGITransport
        return AsyncClient(
            transport=ASGITransport(app=self.wh.app),
            base_url="http://test",
        )

    def test_cancelled_deletes_entitlement_and_grace(self):
        """AC-08: subscription.cancelled removes both Redis keys."""
        # Pre-populate both keys
        ent_key   = _cfg.key_entitlement("T04", "u-cancel")
        grace_key = _cfg.key_grace("T04", "u-cancel")
        self.r.setex(ent_key,   3600, "1")
        self.r.setex(grace_key, 3600, "1")
        assert self.r.exists(ent_key)
        assert self.r.exists(grace_key)

        async def _run():
            body = json.dumps({"event": "subscription.cancelled",
                               "tool_id": "T04", "caller_id": "u-cancel"}).encode()
            async with self._client() as c:
                resp = await c.post("/webhooks/mcpize",
                    content=body,
                    headers={"Content-Type": "application/json"})
            return resp

        resp = asyncio.get_event_loop().run_until_complete(_run())
        assert resp.status_code == 200
        assert not self.r.exists(ent_key),   "entitlement key must be deleted"
        assert not self.r.exists(grace_key), "grace key must be deleted"


# ═══════════════════════════════════════════════════════════════════════════════
# AC-09  Empty MCPIZE_URL → free passthrough
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC09EmptyUrl:

    def test_empty_url_passthrough_even_when_active(self):
        """AC-09: MCPIZE_ACTIVE=True but URL empty → tool runs freely."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = ""   # not yet listed

        r = _make_redis()
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result == {"result": "ok"}

    def test_empty_url_no_402(self):
        """AC-09: empty URL never produces payment_required."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = ""

        r = _make_redis()
        _set_redis_client(r)
        _set_caller_id(CALLER_ID)

        tool = _make_dummy_tool()
        result = asyncio.get_event_loop().run_until_complete(tool())
        assert result.get("error_code") != "payment_required"


# ═══════════════════════════════════════════════════════════════════════════════
# AC-10  report_mcpize_link free mode → status='free'
# ═══════════════════════════════════════════════════════════════════════════════

class TestAC10ReportMcpizeLink:

    def test_free_mode_returns_free(self):
        """AC-10: MCPIZE_ACTIVE=False → status='free'."""
        _cfg.MCPIZE_ACTIVE = False
        result = report_mcpize_link(TOOL_ID)
        assert result["status"] == "free"

    def test_free_mode_message_present(self):
        """AC-10: free status includes a human-readable message."""
        _cfg.MCPIZE_ACTIVE = False
        result = report_mcpize_link(TOOL_ID)
        assert "message" in result
        assert len(result["message"]) > 0

    def test_subscription_required_scenario(self):
        """AC-10 (contrast): active + URL → subscription_required."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = TEST_URL
        result = report_mcpize_link(TOOL_ID)
        assert result["status"] == "subscription_required"
        assert result["upgrade_url"] == TEST_URL

    def test_not_configured_scenario(self):
        """AC-10 (contrast): active + URL empty → not_configured."""
        _cfg.MCPIZE_ACTIVE = True
        _cfg.MCPIZE_URLS[TOOL_ID] = ""
        result = report_mcpize_link(TOOL_ID)
        assert result["status"] == "not_configured"
