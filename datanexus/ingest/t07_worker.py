"""
datanexus/ingest/t07_worker.py — T07 Domain & DNS Intelligence ingest worker.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 4, T07 entry

Worker:
  DomainRDAPWorker — pre-warms RDAP bootstrap and common domains.
  Schedule: 14400 seconds (4 hours — matches cache TTL)
  TTL:      14400 seconds

Pre-warms the IANA RDAP bootstrap mapping so cold starts do not add latency.
Does NOT perform active probing or address enumeration.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import httpx

from datanexus.core.cache import set_cached
from datanexus.core.circuit_breaker import record_failure, record_success
from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t07")

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
T07_TTL            = 14400   # 4 hours
_BOOTSTRAP_TTL     = 86400   # 24 hours
_SCHEDULE          = 14400   # 4 hours

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class DomainRDAPWorker(IngestBase):
    """
    Refreshes the IANA RDAP bootstrap cache every 4 hours.

    The bootstrap maps TLDs to their RDAP server URLs. Pre-caching it means
    the first real tool call for any domain resolves the RDAP endpoint from
    Redis rather than making a live IANA request. IANA updates this file
    infrequently; 4-hour refresh is conservative and safe.
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T07",
            source_id="iana_rdap",
            ttl_seconds=T07_TTL,
            schedule_seconds=_SCHEDULE,
        )

    async def fetch(self) -> bytes:
        """Fetch IANA RDAP bootstrap and store in Redis."""
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True
        ) as client:
            resp = await client.get(RDAP_BOOTSTRAP_URL)
            resp.raise_for_status()
            raw = resp.content
            data = resp.json()

        # Store bootstrap under the same key as the tool uses
        set_cached("T07", "rdap_bootstrap", data, _BOOTSTRAP_TTL)
        record_success("iana_rdap")

        tld_count = sum(len(tlds) for tlds, _ in data.get("services", []))
        log.info(json.dumps({
            "ts":        _iso_now(),
            "event":     "t07_rdap_bootstrap_refreshed",
            "tld_count": tld_count,
            "bytes":     len(raw),
        }))

        return raw


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    worker = DomainRDAPWorker()
    asyncio.run(worker.run_forever())
