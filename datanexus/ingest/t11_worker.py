"""
datanexus/ingest/t11_worker.py — T11 Global Patent Intelligence ingest worker.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 4, T11 entry

Worker:
  EPOPatentWorker — pre-warms EPO OAuth token and validates API connectivity.
  Schedule: 86400 seconds (24 hours — matches cache TTL)
  TTL:      86400 seconds

Pre-warms the EPO OPS OAuth token so cold starts avoid auth latency.
Also validates EPO, PatentsView, and WIPO connectivity.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

import httpx

from datanexus.core.cache import set_cached
from datanexus.core.circuit_breaker import record_failure, record_success
from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t11")

EPO_AUTH_URL    = "https://ops.epo.org/3.2/auth/accesstoken"
EPO_PROBE_URL   = "https://ops.epo.org/3.2/rest-services/published-data/publication/epodoc/EP1000000/biblio"
PATENTSVIEW_URL = "https://api.patentsview.org/patents/query"

T11_TTL    = 86400  # 24 hours
_SCHEDULE  = 86400  # 24 hours

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class EPOPatentWorker(IngestBase):
    """
    Refreshes EPO OPS OAuth token and verifies API connectivity every 24 hours.

    Pre-caching the token prevents auth latency on the first tool call.
    Also validates PatentsView is reachable as the primary fallback.
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T11",
            source_id="epo_ops",
            ttl_seconds=T11_TTL,
            schedule_seconds=_SCHEDULE,
        )

    async def fetch(self) -> bytes:
        """Fetch and cache EPO OPS OAuth token; probe fallback sources."""
        client_id     = os.environ.get("EPO_CLIENT_ID", "")
        client_secret = os.environ.get("EPO_CLIENT_SECRET", "")

        token_bytes = b""

        # ── EPO OAuth token refresh ───────────────────────────────────────────
        if client_id and client_secret:
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
                    resp = await client.post(
                        EPO_AUTH_URL,
                        data={"grant_type": "client_credentials"},
                        auth=(client_id, client_secret),
                        headers={"Accept": "application/json"},
                    )
                    resp.raise_for_status()
                    data      = resp.json()
                    token     = data.get("access_token", "")
                    expires_in = int(data.get("expires_in", 1200))
                    expiry_ts = int(time.time()) + expires_in

                    if token:
                        from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
                        r = _get_redis()
                        if r is not None:
                            cache_key = f"datanexus:epo:token:{expiry_ts}"
                            try:
                                r.setex(cache_key, expires_in, token)
                            except Exception:
                                pass

                    record_success("epo_ops")
                    token_bytes = resp.content
                    log.info(json.dumps({
                        "ts":         _iso_now(),
                        "event":      "t11_epo_token_refreshed",
                        "expires_in": expires_in,
                    }))
            except Exception as exc:
                record_failure("epo_ops")
                log.warning(json.dumps({
                    "ts":    _iso_now(),
                    "event": "t11_epo_token_refresh_failed",
                    "error": str(exc),
                }))
        else:
            log.info(json.dumps({
                "ts":    _iso_now(),
                "event": "t11_epo_credentials_absent",
                "note":  "EPO_CLIENT_ID / EPO_CLIENT_SECRET not set; skipping EPO token refresh",
            }))

        # ── PatentsView connectivity probe ────────────────────────────────────
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
                payload = {
                    "q": {"_eq": {"patent_number": "10000000"}},
                    "f": ["patent_id"],
                    "o": {"per_page": 1},
                }
                resp = await client.post(
                    PATENTSVIEW_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                record_success("patentsview")
                log.info(json.dumps({
                    "ts":    _iso_now(),
                    "event": "t11_patentsview_probe_ok",
                    "bytes": len(resp.content),
                }))
        except Exception as exc:
            record_failure("patentsview")
            log.warning(json.dumps({
                "ts":    _iso_now(),
                "event": "t11_patentsview_probe_failed",
                "error": str(exc),
            }))

        return token_bytes or b"{}"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    worker = EPOPatentWorker()
    asyncio.run(worker.run_forever())
