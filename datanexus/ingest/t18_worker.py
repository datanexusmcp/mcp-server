"""
datanexus/ingest/t18_worker.py — T18 Government Contracting & Procurement ingest worker.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 5, T18 entry

Worker:
  USASpendingWorker — pre-seeds top contract award categories.
  Schedule: 14400 seconds (4 hours — matches cache TTL)
  TTL:      14400 seconds

Pre-seeds common keyword searches so the first live query hits cache.
Does NOT collect classified or access-controlled contract data.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import httpx

from datanexus.core.cache import set_cached
from datanexus.core.circuit_breaker import record_failure, record_success
from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t18")

USASPENDING_AWARDS_URL = "https://api.usaspending.gov/api/v2/search/spending_by_award/"
T18_TTL   = 14400  # 4 hours
_SCHEDULE = 14400  # 4 hours

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Top keyword categories to pre-seed
_SEED_KEYWORDS = [
    "cybersecurity",
    "information technology",
    "cloud services",
    "software development",
    "professional services",
    "logistics",
    "healthcare",
    "construction",
    "research and development",
    "facilities management",
]


class USASpendingWorker(IngestBase):
    """
    Pre-seeds top contract award keyword searches every 4 hours.

    Caches USASpending.gov results for common procurement keywords
    so tool queries hit the cache on first call. Politely paced
    with 1s delay between fetches.
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T18",
            source_id="usaspending",
            ttl_seconds=T18_TTL,
            schedule_seconds=_SCHEDULE,
        )

    async def fetch(self) -> bytes:
        """Pre-seed top keyword categories."""
        seeded = 0
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HEADERS
        ) as client:
            for keyword in _SEED_KEYWORDS:
                try:
                    payload = {
                        "filters": {"keywords": [keyword]},
                        "fields": [
                            "Award ID", "Recipient Name", "Award Amount",
                            "Awarding Agency", "Award Type", "NAICS Code",
                            "Start Date", "End Date",
                        ],
                        "page": 1,
                        "limit": 10,
                        "sort": "Award Amount",
                        "order": "desc",
                        "subawards": False,
                    }
                    resp = await client.post(USASPENDING_AWARDS_URL, json=payload)
                    resp.raise_for_status()
                    data = resp.json()

                    from datanexus.core.audit import make_params_hash
                    from datanexus.core.validator import validate_payload
                    params = {"keyword": keyword, "agency": "", "date_from": "", "jurisdiction": "US"}
                    phash = make_params_hash(params)
                    cleaned, issues = validate_payload("T18", data)
                    if cleaned is not None:
                        set_cached("T18", phash, cleaned, T18_TTL)
                        seeded += 1
                        record_success("usaspending")

                    log.info(json.dumps({
                        "ts":      _iso_now(),
                        "event":   "t18_keyword_seeded",
                        "keyword": keyword,
                        "results": len(data.get("results", [])),
                    }))
                    await asyncio.sleep(1.0)  # polite pacing

                except Exception as exc:
                    log.warning(json.dumps({
                        "ts":      _iso_now(),
                        "event":   "t18_seed_failed",
                        "keyword": keyword,
                        "error":   str(exc),
                    }))
                    record_failure("usaspending")

        log.info(json.dumps({
            "ts":    _iso_now(),
            "event": "t18_ingest_complete",
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
    worker = USASpendingWorker()
    asyncio.run(worker.run_forever())
