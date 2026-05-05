"""
feedback/tests/test_feedback_system.py — Full test suite for the Phase 4 Feedback System.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 9.6 / Section 11.6 Step 13

Ten test classes:
  1.  TestFeedbackConfig        — Constants and Redis key functions.
  2.  TestFeedbackModels        — Pydantic v2 model validation.
  3.  TestFeedbackRecord        — FeedbackRecord construction and defaults.
  4.  TestAuditHelpers          — make_params_hash + standard_response_fields.
  5.  TestPreClassifier         — classify_missing_field + classify_record.
  6.  TestCollectorDedup        — 100-identical-calls dedup invariant.
  7.  TestCollectorRouting      — BUG → alerts:immediate, IMPROVEMENT → fb:queue.
  8.  TestUpstreamMonitor       — schema_fingerprint + change detection.
  9.  TestDashboardEndpoints    — GET / + GET /api/summary + GET /api/health.
  10. TestCLICommands           — fb_control status + pause + resume.

Run: pytest feedback/tests/ -v
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import fakeredis
import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient
from pydantic import ValidationError

# ── shared fixture ─────────────────────────────────────────────────────────────

@pytest.fixture()
def fake_redis():
    """Fresh fakeredis instance for each test."""
    return fakeredis.FakeRedis(decode_responses=True)


def _run(coro):
    """Run a coroutine synchronously (avoids pytest-asyncio dependency)."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════════════════════
# 1. TestFeedbackConfig
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedbackConfig:
    def test_agents_active_is_bool(self):
        from feedback.config import FEEDBACK_AGENTS_ACTIVE
        assert isinstance(FEEDBACK_AGENTS_ACTIVE, bool)

    def test_agents_active_defaults_false(self):
        from feedback.config import FEEDBACK_AGENTS_ACTIVE
        # In tests FEEDBACK_AGENTS_ACTIVE env var is unset → must be False
        assert FEEDBACK_AGENTS_ACTIVE is False

    def test_feedback_enabled_tools(self):
        from feedback.config import FEEDBACK_ENABLED_TOOLS
        assert "T04" in FEEDBACK_ENABLED_TOOLS
        assert "T10" in FEEDBACK_ENABLED_TOOLS

    def test_implicit_only_tools(self):
        from feedback.config import IMPLICIT_ONLY_TOOLS, FEEDBACK_ENABLED_TOOLS
        assert not (IMPLICIT_ONLY_TOOLS & FEEDBACK_ENABLED_TOOLS), (
            "A tool cannot be in both FEEDBACK_ENABLED_TOOLS and IMPLICIT_ONLY_TOOLS"
        )

    def test_bug_signals_non_empty(self):
        from feedback.config import BUG_SIGNALS
        assert len(BUG_SIGNALS) >= 3

    def test_improvement_signals_non_empty(self):
        from feedback.config import IMPROVEMENT_SIGNALS
        assert len(IMPROVEMENT_SIGNALS) >= 3

    def test_signals_disjoint(self):
        from feedback.config import BUG_SIGNALS, IMPROVEMENT_SIGNALS
        assert not (BUG_SIGNALS & IMPROVEMENT_SIGNALS), (
            "A signal cannot be both a bug and an improvement"
        )

    def test_key_functions_return_strings(self):
        from feedback.config import (
            key_feedback, key_feedback_list, key_audit, key_digest,
            key_dedup, key_alerts_immediate, key_feedback_queue, key_pause,
        )
        assert key_feedback("T04", "abc")   == "feedback:T04:abc"
        assert key_feedback_list("T04")     == "feedback_list:T04"
        assert key_audit("xyz")             == "audit:xyz"
        assert key_digest("T04", "2026-01-01") == "digest:T04:2026-01-01"
        assert key_dedup("T04", "qh", "s") == "fb:dedup:T04:qh:s"
        assert key_alerts_immediate()       == "fb:alerts:immediate"
        assert key_feedback_queue()         == "fb:queue"
        assert key_pause()                  == "fb:pause"

    def test_dedup_window_positive(self):
        from feedback.config import DEDUP_WINDOW_SECS
        assert DEDUP_WINDOW_SECS == 60


# ══════════════════════════════════════════════════════════════════════════════
# 2. TestFeedbackModels
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedbackModels:
    def test_valid_feedback_input(self):
        from feedback.models import FeedbackInput
        fi = FeedbackInput(tool_id="T04", query_hash="a" * 32, signal="not_useful")
        assert fi.tool_id == "T04"
        assert fi.signal == "not_useful"

    def test_invalid_tool_id_raises(self):
        from feedback.models import FeedbackInput
        with pytest.raises(ValidationError) as exc_info:
            FeedbackInput(tool_id="T99", query_hash="x" * 16, signal="not_useful")
        assert "T99" in str(exc_info.value)

    def test_invalid_signal_raises(self):
        from feedback.models import FeedbackInput
        with pytest.raises(ValidationError):
            FeedbackInput(tool_id="T04", query_hash="x" * 16, signal="unknown_signal")

    def test_missing_field_requires_missing_fields(self):
        from feedback.models import FeedbackInput
        with pytest.raises(ValidationError) as exc_info:
            FeedbackInput(
                tool_id="T04", query_hash="x" * 16,
                signal="missing_field", missing_fields=None,
            )
        assert "missing_fields" in str(exc_info.value)

    def test_missing_field_with_list_valid(self):
        from feedback.models import FeedbackInput
        fi = FeedbackInput(
            tool_id="T04", query_hash="x" * 16,
            signal="missing_field", missing_fields=["ein"],
        )
        assert fi.missing_fields == ["ein"]

    def test_comment_stripped(self):
        from feedback.models import FeedbackInput
        fi = FeedbackInput(
            tool_id="T04", query_hash="x" * 16,
            signal="helpful", comment="  spaces  ",
        )
        assert fi.comment == "spaces"

    def test_comment_max_length(self):
        from feedback.models import FeedbackInput
        with pytest.raises(ValidationError):
            FeedbackInput(
                tool_id="T04", query_hash="x" * 16,
                signal="helpful", comment="x" * 1001,
            )

    def test_query_hash_min_length(self):
        from feedback.models import FeedbackInput
        with pytest.raises(ValidationError):
            FeedbackInput(tool_id="T04", query_hash="short", signal="helpful")

    def test_audit_record_fields(self):
        from feedback.models import AuditRecord
        ar = AuditRecord(
            tool_id="T04", query_hash="a" * 32, params_hash="b" * 32,
            response_time_ms=42, cache_hit=True,
        )
        assert ar.tool_id == "T04"
        assert ar.response_time_ms == 42
        assert ar.cache_hit is True

    def test_digest_item_date_format(self):
        from feedback.models import DigestItem
        with pytest.raises(ValidationError):
            DigestItem(tool_id="T04", date="not-a-date")
        di = DigestItem(tool_id="T04", date="2026-05-01")
        assert di.date == "2026-05-01"


# ══════════════════════════════════════════════════════════════════════════════
# 3. TestFeedbackRecord
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedbackRecord:
    def test_from_input_copies_fields(self):
        from feedback.models import FeedbackInput, FeedbackRecord
        fi = FeedbackInput(tool_id="T04", query_hash="a" * 32, signal="helpful")
        rec = FeedbackRecord.from_input(fi)
        assert rec.tool_id    == "T04"
        assert rec.signal     == "helpful"
        assert rec.query_hash == "a" * 32

    def test_record_has_uuid(self):
        from feedback.models import FeedbackInput, FeedbackRecord
        fi  = FeedbackInput(tool_id="T04", query_hash="a" * 32, signal="helpful")
        rec = FeedbackRecord.from_input(fi)
        assert len(rec.record_id) == 36   # UUID4

    def test_record_default_classification(self):
        from feedback.models import FeedbackInput, FeedbackRecord
        fi  = FeedbackInput(tool_id="T04", query_hash="a" * 32, signal="helpful")
        rec = FeedbackRecord.from_input(fi)
        assert rec.classification == "pending"
        assert rec.score          == 0.0

    def test_record_json_roundtrip(self):
        from feedback.models import FeedbackInput, FeedbackRecord
        fi   = FeedbackInput(tool_id="T10", query_hash="b" * 32, signal="not_useful")
        rec  = FeedbackRecord.from_input(fi)
        raw  = rec.model_dump_json()
        rec2 = FeedbackRecord.model_validate_json(raw)
        assert rec2.record_id == rec.record_id
        assert rec2.signal    == rec.signal


# ══════════════════════════════════════════════════════════════════════════════
# 4. TestAuditHelpers
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditHelpers:
    def test_make_params_hash_order_independent(self):
        from feedback.audit import make_params_hash
        h1 = make_params_hash({"b": 2, "a": 1})
        h2 = make_params_hash({"a": 1, "b": 2})
        assert h1 == h2

    def test_make_params_hash_different_inputs(self):
        from feedback.audit import make_params_hash
        h1 = make_params_hash({"a": 1})
        h2 = make_params_hash({"a": 2})
        assert h1 != h2

    def test_make_params_hash_returns_32_chars(self):
        from feedback.audit import make_params_hash
        h = make_params_hash({"x": "y"})
        assert len(h) == 32

    def test_standard_response_fields_exactly_4_keys(self):
        from feedback.audit import standard_response_fields
        srf = standard_response_fields("hash123", "2026-05-01", True)
        assert len(srf) == 4

    def test_standard_response_fields_key_names(self):
        from feedback.audit import standard_response_fields
        srf = standard_response_fields("h", "2026-04-30", True)
        assert set(srf.keys()) == {
            "query_hash", "schema_version", "data_as_of", "ingest_healthy"
        }

    def test_standard_response_fields_values(self):
        from feedback.audit import standard_response_fields
        srf = standard_response_fields("myhash", "2026-05-01", False)
        assert srf["query_hash"]     == "myhash"
        assert srf["data_as_of"]     == "2026-05-01"
        assert srf["ingest_healthy"] is False


# ══════════════════════════════════════════════════════════════════════════════
# 5. TestPreClassifier
# ══════════════════════════════════════════════════════════════════════════════

class TestPreClassifier:
    def test_classify_missing_field_known(self):
        from feedback.pre_classifier import classify_missing_field
        assert classify_missing_field("T04", "ein") == "already_implemented"

    def test_classify_missing_field_unknown(self):
        from feedback.pre_classifier import classify_missing_field
        assert classify_missing_field("T04", "xyz_unknown_99") == "needs_human_review"

    def test_classify_missing_field_t10_known(self):
        from feedback.pre_classifier import classify_missing_field
        assert classify_missing_field("T10", "cve_id") == "already_implemented"

    def test_classify_missing_field_unknown_tool(self):
        from feedback.pre_classifier import classify_missing_field
        # Unknown tool → unknown field → needs_human_review
        assert classify_missing_field("T99", "ein") == "needs_human_review"

    def test_classify_record_inactive(self):
        from feedback.pre_classifier import classify_record
        from feedback.models import FeedbackRecord
        rec = FeedbackRecord(tool_id="T04", query_hash="a" * 32, signal="not_useful")
        # FEEDBACK_AGENTS_ACTIVE=false in test env
        classification, score = classify_record(rec)
        assert classification == "pending"
        assert score == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 6. TestCollectorDedup
# ══════════════════════════════════════════════════════════════════════════════

class TestCollectorDedup:
    def test_100_identical_calls_one_entry(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import key_feedback_list
        try:
            for _ in range(100):
                result = _run(cmod.report_feedback("T04", "a" * 32, "not_useful"))
                assert result == {"status": "recorded"}
            members = fake_redis.zrange(key_feedback_list("T04"), 0, -1)
            assert len(members) == 1, f"Expected 1 entry, got {len(members)}"
        finally:
            cmod._set_redis_client(None)

    def test_vote_count_equals_call_count(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import key_feedback_list, key_feedback
        try:
            for _ in range(50):
                _run(cmod.report_feedback("T04", "b" * 32, "incorrect_data"))
            rids = fake_redis.zrange(key_feedback_list("T04"), 0, -1)
            vote_count = int(fake_redis.hget(key_feedback("T04", rids[0]), "vote_count") or 0)
            assert vote_count == 50
        finally:
            cmod._set_redis_client(None)

    def test_always_returns_recorded(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        try:
            # Invalid tool_id — should still return recorded
            result = _run(cmod.report_feedback("T99", "x" * 32, "not_useful"))
            assert result == {"status": "recorded"}
        finally:
            cmod._set_redis_client(None)

    def test_different_signals_create_separate_entries(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import key_feedback_list
        try:
            _run(cmod.report_feedback("T04", "c" * 32, "not_useful"))
            _run(cmod.report_feedback("T04", "c" * 32, "incorrect_data"))
            members = fake_redis.zrange(key_feedback_list("T04"), 0, -1)
            assert len(members) == 2
        finally:
            cmod._set_redis_client(None)


# ══════════════════════════════════════════════════════════════════════════════
# 7. TestCollectorRouting
# ══════════════════════════════════════════════════════════════════════════════

class TestCollectorRouting:
    def test_bug_signal_to_alerts_immediate(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import key_alerts_immediate, key_feedback_queue
        try:
            _run(cmod.report_feedback("T04", "d" * 32, "not_useful"))
            assert fake_redis.llen(key_alerts_immediate()) == 1
            assert fake_redis.llen(key_feedback_queue())   == 0
        finally:
            cmod._set_redis_client(None)

    def test_improvement_signal_to_queue(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import key_alerts_immediate, key_feedback_queue
        try:
            _run(cmod.report_feedback("T10", "e" * 32, "helpful"))
            assert fake_redis.llen(key_feedback_queue())   == 1
            assert fake_redis.llen(key_alerts_immediate()) == 0
        finally:
            cmod._set_redis_client(None)

    def test_paused_collector_discards(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import key_pause, key_feedback_list
        fake_redis.setex(key_pause(), 60, "1")
        try:
            _run(cmod.report_feedback("T04", "f" * 32, "not_useful"))
            members = fake_redis.zrange(key_feedback_list("T04"), 0, -1)
            assert len(members) == 0
        finally:
            cmod._set_redis_client(None)

    def test_all_bug_signals_route_to_alerts(self, fake_redis):
        import feedback.collector as cmod
        cmod._set_redis_client(fake_redis)
        from feedback.config import BUG_SIGNALS, key_alerts_immediate
        try:
            for i, sig in enumerate(sorted(BUG_SIGNALS)):
                qh = str(i).zfill(32)
                # missing_field signal requires missing_fields list
                mf = ["ein"] if sig == "missing_field" else None
                _run(cmod.report_feedback("T04", qh, sig, missing_fields=mf))
            assert fake_redis.llen(key_alerts_immediate()) == len(BUG_SIGNALS)
        finally:
            cmod._set_redis_client(None)


# ══════════════════════════════════════════════════════════════════════════════
# 8. TestUpstreamMonitor
# ══════════════════════════════════════════════════════════════════════════════

class TestUpstreamMonitor:
    def test_fingerprint_order_independent(self):
        from feedback.upstream_monitor import schema_fingerprint
        fp1 = schema_fingerprint({"a": 1, "b": 2})
        fp2 = schema_fingerprint({"b": 2, "a": 1})
        assert fp1 == fp2

    def test_fingerprint_type_sensitive(self):
        from feedback.upstream_monitor import schema_fingerprint
        fp1 = schema_fingerprint({"a": 1})
        fp2 = schema_fingerprint({"a": "hello"})
        assert fp1 != fp2

    def test_fingerprint_key_sensitive(self):
        from feedback.upstream_monitor import schema_fingerprint
        fp1 = schema_fingerprint({"a": 1})
        fp2 = schema_fingerprint({"b": 1})
        assert fp1 != fp2

    def test_fingerprint_returns_32_chars(self):
        from feedback.upstream_monitor import schema_fingerprint
        fp = schema_fingerprint({"x": [1, 2, 3], "y": {"nested": True}})
        assert len(fp) == 32

    def test_fingerprint_nested_dict(self):
        from feedback.upstream_monitor import schema_fingerprint
        fp1 = schema_fingerprint({"a": {"b": 1, "c": 2}})
        fp2 = schema_fingerprint({"a": {"c": 2, "b": 1}})
        assert fp1 == fp2

    def test_schema_change_detection(self, fake_redis):
        from feedback.upstream_monitor import (
            check_and_update_fingerprint, _set_redis_client,
        )
        _set_redis_client(fake_redis)
        try:
            schema_v1 = {"status": "ok", "data": {}}
            schema_v2 = {"status": "ok", "data": {}, "new_field": 0}  # added field
            # First call stores fingerprint
            r1 = check_and_update_fingerprint("test_source", schema_v1)
            assert r1 is True   # no change (first observation)
            # Same schema → no change
            r2 = check_and_update_fingerprint("test_source", schema_v1)
            assert r2 is True
            # Changed schema → change detected
            r3 = check_and_update_fingerprint("test_source", schema_v2)
            assert r3 is False
        finally:
            _set_redis_client(None)


# ══════════════════════════════════════════════════════════════════════════════
# 9. TestDashboardEndpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboardEndpoints:
    @pytest.fixture(autouse=True)
    def inject_redis(self, fake_redis):
        from feedback.dashboard import server as srv
        srv._set_redis_client(fake_redis)
        yield
        srv._set_redis_client(None)

    def test_index_returns_200_html(self):
        from feedback.dashboard.server import app
        client = TestClient(app)
        r = client.get("/")
        assert r.status_code == 200
        assert r.text.strip().startswith("<!DOCTYPE html")

    def test_index_has_agent_status_banner(self):
        from feedback.dashboard.server import app
        client = TestClient(app)
        r = client.get("/")
        assert "agent-status-banner" in r.text

    def test_api_summary_has_required_keys(self):
        from feedback.dashboard.server import app
        client = TestClient(app)
        r    = client.get("/api/summary")
        data = r.json()
        assert r.status_code == 200
        assert "summary" in data
        assert "tools"   in data

    def test_api_summary_tools_contains_enabled(self):
        from feedback.dashboard.server import app
        from feedback.config import FEEDBACK_ENABLED_TOOLS
        client = TestClient(app)
        data = client.get("/api/summary").json()
        for tool_id in FEEDBACK_ENABLED_TOOLS:
            assert tool_id in data["tools"]

    def test_api_health_returns_ok(self):
        from feedback.dashboard.server import app
        client = TestClient(app)
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_api_feedback_returns_dict(self):
        from feedback.dashboard.server import app
        client = TestClient(app)
        r    = client.get("/api/feedback")
        data = r.json()
        assert r.status_code == 200
        assert "feedback" in data


# ══════════════════════════════════════════════════════════════════════════════
# 10. TestCLICommands
# ══════════════════════════════════════════════════════════════════════════════

class TestCLICommands:
    @pytest.fixture(autouse=True)
    def inject_redis(self, fake_redis):
        import feedback.cli.fb_control as fb_mod
        fb_mod._get_redis = lambda: fake_redis
        self._fake_redis = fake_redis
        yield

    def test_status_exits_0(self):
        from feedback.cli.fb_control import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0

    def test_status_output_is_valid_json(self):
        from feedback.cli.fb_control import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        data = json.loads(result.output)
        assert "queues" in data
        assert "feedback_counts" in data

    def test_pause_sets_key(self):
        from feedback.cli.fb_control import cli
        from feedback.config import key_pause
        runner = CliRunner()
        result = runner.invoke(cli, ["pause"])
        assert result.exit_code == 0
        assert self._fake_redis.exists(key_pause())

    def test_resume_removes_key(self):
        from feedback.cli.fb_control import cli
        from feedback.config import key_pause
        runner = CliRunner()
        self._fake_redis.setex(key_pause(), 60, "1")
        result = runner.invoke(cli, ["resume"])
        assert result.exit_code == 0
        assert not self._fake_redis.exists(key_pause())

    def test_flush_requires_confirm(self):
        from feedback.cli.fb_control import cli
        runner = CliRunner()
        # Without --confirm should fail
        result = runner.invoke(cli, ["flush"])
        assert result.exit_code != 0

    def test_flush_with_confirm(self):
        from feedback.cli.fb_control import cli
        from feedback.config import key_feedback_queue
        runner = CliRunner()
        self._fake_redis.lpush(key_feedback_queue(), "item1", "item2")
        result = runner.invoke(cli, ["flush", "--confirm"])
        assert result.exit_code == 0
        assert self._fake_redis.llen(key_feedback_queue()) == 0

    def test_digest_outputs_json(self):
        from feedback.cli.fb_control import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["digest"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "tools" in data
        assert "date"  in data
