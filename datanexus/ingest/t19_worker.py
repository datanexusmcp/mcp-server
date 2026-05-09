"""
datanexus/ingest/t19_worker.py — T19 Regulatory Docket & Comment Tracking ingest worker.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 5, T19 entry

Worker:
  RegulationsGovWorker — pre-seeds top rulemaking keyword categories.
  Schedule: 21600 seconds (6 hours)
  TTL:      14400 seconds (4 hours — matches cache TTL)

Rate limit awareness:
  Regulations.gov free tier: 1,000 req/day.
  21600s schedule = 4 runs/day. With ~10 keywords per run = 40 req/day.
  Well within the 1,000 req/day free tier limit.

Does NOT collect non-public, access-controlled, or restricted docket data.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx

from datanexus.core.cache import set_cached
from datanexus.core.circuit_breaker import record_failure, record_success
from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t19")

REGS_GOV_URL = "https://api.regulations.gov/v4/dockets"
T19_TTL      = 14400   # 4 hours
_SCHEDULE    = 21600   # 6 hours — rate limit awareness: 4 runs/day × 10 kw = 40 req/day

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Top keyword categories to pre-seed (one request each per run)
_SEED_KEYWORDS = [
    "artificial intelligence",
    "data privacy",
    "cybersecurity",
    "financial services",
    "environmental",
    "healthcare",
    "telecommunications",
    "consumer protection",
    "cryptocurrency",
    "immigration",
]


class RegulationsGovWorker(IngestBase):
    """
    Pre-seeds top rulemaking keyword searches every 6 hours.

    Runs at 21600s intervals (not 14400s) to stay within
    Regulations.gov 1,000 req/day free tier. With 10 keywords
    per run and 4 runs/day, total daily API calls = 40 req/day.
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T19",
            source_id="regulations_gov",
            ttl_seconds=T19_TTL,
            schedule_seconds=_SCHEDULE,  # 21600 — rate limit awareness
        )

    async def fetch(self) -> bytes:
        """Pre-seed top regulatory keyword categories."""
        api_key = os.environ.get("REGULATIONS_GOV_KEY", "")
        if not api_key:
            log.warning(json.dumps({
                "ts":    _iso_now(),
                "event": "t19_key_missing",
                "msg":   "REGULATIONS_GOV_KEY not set — skipping ingest",
            }))
            return b"{}"

        seeded = 0
        headers = {**_HEADERS, "X-Api-Key": api_key}

        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
            for keyword in _SEED_KEYWORDS:
                try:
                    resp = await client.get(
                        REGS_GOV_URL,
                        params={
                            "filter[searchTerm]": keyword,
                            "filter[docketType]": "Rulemaking",
                            "page[size]": 10,
                            "sort": "lastModifiedDate",
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    from datanexus.core.audit import make_params_hash
                    from datanexus.core.validator import validate_payload
                    cache_params = {"keyword": keyword, "agency": "", "status": "open"}
                    phash = make_params_hash(cache_params)
                    cleaned, issues = validate_payload("T19", data)
                    if cleaned is not None:
                        set_cached("T19", phash, cleaned, T19_TTL)
                        seeded += 1
                        record_success("regulations_gov")

                    log.info(json.dumps({
                        "ts":      _iso_now(),
                        "event":   "t19_keyword_seeded",
                        "keyword": keyword,
                        "results": len(data.get("data", [])),
                    }))
                    # 2s delay between requests — polite pacing within free tier
                    await asyncio.sleep(2.0)

                except Exception as exc:
                    log.warning(json.dumps({
                        "ts":      _iso_now(),
                        "event":   "t19_seed_failed",
                        "keyword": keyword,
                        "error":   str(exc),
                    }))
                    record_failure("regulations_gov")

        log.info(json.dumps({
            "ts":     _iso_now(),
            "event":  "t19_ingest_complete",
            "seeded": seeded,
        }))
        return json.dumps({"seeded": seeded}).encode()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    worker = RegulationsGovWorker()
    asyncio.run(worker.run_forever())
