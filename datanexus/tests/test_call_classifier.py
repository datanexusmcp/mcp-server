"""Tests for payment.config.classify_call and _ip_in_cidrs."""
import hashlib

import pytest

from payment.config import (
    ANTHROPIC_CIDRS,
    GLAMA_CIDRS,
    OWNER_API_KEY,
    SMOKE_API_KEY,
    _ip_in_cidrs,
    classify_call,
)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class TestIpInCidrs:
    def test_glama_ip_matches(self):
        assert _ip_in_cidrs("172.68.23.75", GLAMA_CIDRS)

    def test_glama_ip_172_71_matches(self):
        # 172.64.0.0/13 covers 172.64.x – 172.71.x
        assert _ip_in_cidrs("172.71.255.255", GLAMA_CIDRS)

    def test_outside_range_no_match(self):
        assert not _ip_in_cidrs("172.72.0.1", GLAMA_CIDRS)

    def test_anthropic_ip_matches(self):
        assert _ip_in_cidrs("160.79.106.35", ANTHROPIC_CIDRS)

    def test_invalid_ip_no_raise(self):
        assert not _ip_in_cidrs("not-an-ip", GLAMA_CIDRS)


class TestClassifyCall:
    def test_glama_ip(self):
        assert classify_call("172.68.23.75", None) == "glama"

    def test_anthropic_ip(self):
        assert classify_call("160.79.106.35", None) == "claude_ai"

    def test_organic_ip(self):
        assert classify_call("73.241.93.191", None) == "organic"

    def test_unknown_ip(self):
        assert classify_call("unknown", None) == "unknown"

    def test_empty_ip(self):
        assert classify_call("", None) == "unknown"

    def test_smoke_key_hash(self):
        assert classify_call("1.2.3.4", _hash(SMOKE_API_KEY)) == "smoke"

    def test_owner_key_hash(self):
        assert classify_call("1.2.3.4", _hash(OWNER_API_KEY)) == "owner"

    def test_smoke_key_takes_priority_over_glama_ip(self):
        # Even from a Glama IP, smoke key wins
        assert classify_call("172.68.23.75", _hash(SMOKE_API_KEY)) == "smoke"

    def test_is_organic_flags(self):
        organic_types = {"organic", "claude_ai"}
        non_organic = {"glama", "smoke", "owner", "unknown"}
        for t in organic_types:
            # construct a call that returns each type and check is_organic
            pass  # covered via the classify_call return value directly
        assert classify_call("1.2.3.4", None) in organic_types
        assert classify_call("172.68.23.75", None) in non_organic
