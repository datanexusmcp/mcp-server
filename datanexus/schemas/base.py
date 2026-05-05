"""Shared Pydantic response model for all DataNexus tools."""

import json
import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, HttpUrl, field_validator, model_validator

from datanexus.security import IntegrityError, verify_integrity

_CANARY = [re.compile(p, re.IGNORECASE) for p in [
    r"ignore previous", r"you are now", r"system:", r"<[^>]+>",
]]


class DataNexusResponse(BaseModel):
    tool_id: str
    source_url: str          # str to tolerate RDAP/non-standard URL shapes
    fetch_timestamp: datetime
    cache_hit: bool
    staleness_notice: Optional[str] = None
    sha256_hash: str
    data: dict[str, Any]
    markdown_output: str

    @field_validator("markdown_output")
    @classmethod
    def check_no_injection(cls, v: str) -> str:
        for p in _CANARY:
            if p.search(v):
                raise IntegrityError(f"Injection pattern: {p.pattern!r}")
        return v

    @model_validator(mode="after")
    def verify_sha256(self) -> "DataNexusResponse":
        s = json.dumps(self.data, sort_keys=True, default=str)
        if not verify_integrity(s, self.sha256_hash):
            raise IntegrityError("SHA-256 mismatch — payload integrity check failed.")
        return self
