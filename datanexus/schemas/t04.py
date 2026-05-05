"""
T04Response — Pydantic output schema for the nonprofit 990 / charity tool.

Every field listed under 'required fields for all tools' in Section 3.4 is
present.  The canary validator on markdown_output mirrors the spec's pattern
exactly; it runs at model construction time (i.e., before any response leaves
the tool layer).
"""

import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, field_validator, model_validator, HttpUrl

from datanexus.security import IntegrityError, verify_integrity

# Patterns from spec Section 3.4 — must match spec verbatim
_CANARY_PATTERNS: list[str] = [
    r"ignore previous",
    r"you are now",
    r"system:",
    r"<[^>]+>",
]
_CANARY_COMPILED = [re.compile(p, re.IGNORECASE) for p in _CANARY_PATTERNS]


class T04Response(BaseModel):
    tool_id: str = "T04"
    source_url: HttpUrl
    fetch_timestamp: datetime
    cache_hit: bool
    staleness_notice: Optional[str] = None
    sha256_hash: str                    # Layer 2 integrity hash
    data: dict[str, Any]               # tool-specific payload
    markdown_output: str               # AI-Ready Markdown for agent context

    @field_validator("markdown_output")
    @classmethod
    def check_no_injection(cls, v: str) -> str:
        for pattern in _CANARY_COMPILED:
            if pattern.search(v):
                raise IntegrityError(
                    f"Injection pattern detected: {pattern.pattern!r}"
                )
        return v

    @model_validator(mode="after")
    def verify_sha256(self) -> "T04Response":
        """
        Re-compute SHA-256 over the serialised data payload and confirm it
        matches sha256_hash.  Raises IntegrityError on mismatch.

        Note: at construction time sha256_hash IS the freshly computed value
        (set by the cache/tool layer), so this validator acts as a consistency
        guard — it catches accidental field corruption between computation and
        model construction.
        """
        import json
        payload_json = json.dumps(self.data, sort_keys=True, default=str)
        if not verify_integrity(payload_json, self.sha256_hash):
            raise IntegrityError(
                "T04Response SHA-256 mismatch — payload integrity check failed."
            )
        return self
