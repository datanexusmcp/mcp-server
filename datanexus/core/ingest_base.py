"""
datanexus/core/ingest_base.py — Base class for all ingest workers.

Spec: DataNexus_MCP_Spec_v7_3.docx  Phase 1 / ingest_base.py

Rules (CLAUDE.md):
- No module-level dicts. No lru_cache. State must be in Redis.
- run_forever NEVER crashes the process — catches ALL exceptions.
- Every run logs structured JSON to stdout/stderr.

Subclass pattern:
    class IRSBMFWorker(IngestBase):
        def __init__(self):
            super().__init__('T04', 'irs_bmf', 604800, 86400)

        async def fetch(self) -> bytes:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(IRS_BMF_URL)
                resp.raise_for_status()
                return resp.content
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

from datanexus.core.cache import compute_payload_hash, set_cached
from datanexus.core.circuit_breaker import record_failure, record_success
from datanexus.core.validator import validate_payload

log = logging.getLogger("datanexus.core.ingest_base")


class IngestBase:
    """
    Base ingest worker. Subclasses override fetch() only.

    Args:
        tool_id:          Tool this worker feeds (e.g. 'T04')
        source_id:        Circuit-breaker source ID (e.g. 'irs_bmf')
        ttl_seconds:      Redis cache TTL for stored payload
        schedule_seconds: Sleep interval between fetch cycles
    """

    def __init__(
        self,
        tool_id: str,
        source_id: str,
        ttl_seconds: int,
        schedule_seconds: int,
    ) -> None:
        self.tool_id          = tool_id
        self.source_id        = source_id
        self.ttl_seconds      = ttl_seconds
        self.schedule_seconds = schedule_seconds

    async def fetch(self) -> bytes:
        """
        Override in subclass. Must return raw upstream response bytes.
        Raise any exception on failure — run_forever will catch it.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.fetch() must be overridden."
        )

    async def run_forever(self) -> None:
        """
        Infinite ingest loop: sleep → fetch → hash → cache → log.

        On success:
          - compute_payload_hash of raw bytes
          - set_cached with tool_id, source_id as params_hash key
          - record_success(source_id)
          - log structured JSON: status='ok'

        On ANY exception:
          - record_failure(source_id)
          - log structured JSON: status='error'
          - NEVER crash the process

        Never raises. Runs until process is killed.
        """
        log.info(json.dumps({
            "ts":     _iso_now(),
            "event":  "ingest_worker_started",
            "tool":   self.tool_id,
            "source": self.source_id,
            "ttl":    self.ttl_seconds,
            "schedule_seconds": self.schedule_seconds,
        }))

        while True:
            await asyncio.sleep(self.schedule_seconds)
            try:
                raw: bytes = await self.fetch()
                payload_hash = compute_payload_hash(raw)

                # ── Phase 1 validation — before caching ──────────────────────
                # Attempt to parse raw bytes as JSON and run deterministic rules.
                # Non-JSON payloads (e.g. CSV sources) skip validation silently.
                try:
                    _raw_data = json.loads(raw)
                    _cleaned, _issues = validate_payload(self.tool_id, _raw_data)
                    if _cleaned is None:
                        # General-1 fired — upstream returned empty payload
                        record_failure(self.source_id)
                        log.info(json.dumps({
                            "ts":         _iso_now(),
                            "event":      "validation_upstream_empty",
                            "tool":       self.tool_id,
                            "source":     self.source_id,
                            "action":     "skip_cache",
                        }))
                        continue
                    if _issues:
                        log.info(json.dumps({
                            "ts":               _iso_now(),
                            "event":            "validation_issues",
                            "tool":             self.tool_id,
                            "source":           self.source_id,
                            "validation_issues": _issues,
                        }))
                except (json.JSONDecodeError, ValueError):
                    pass  # non-JSON payload — validation skipped, proceed normally

                # Store raw bytes under a source-keyed cache entry
                # Subclasses call set_cached with their own fine-grained keys;
                # this base stores the raw fetch result for circuit-breaker health.
                set_cached(
                    tool_id=self.tool_id,
                    params_hash=f"ingest:{self.source_id}",
                    payload={"raw_hash": payload_hash, "fetched_at": _iso_now()},
                    ttl_seconds=self.ttl_seconds,
                )

                tripped = False
                record_success(self.source_id)

                log.info(json.dumps({
                    "ts":              _iso_now(),
                    "tool":            self.tool_id,
                    "source":          self.source_id,
                    "status":          "ok",
                    "payload_bytes":   len(raw),
                    "hash":            payload_hash,
                    "breaker_tripped": tripped,
                }))

            except Exception as exc:
                just_tripped = record_failure(self.source_id)
                log.error(json.dumps({
                    "ts":              _iso_now(),
                    "tool":            self.tool_id,
                    "source":          self.source_id,
                    "status":          "error",
                    "error":           str(exc),
                    "breaker_tripped": just_tripped,
                }))
                # NEVER re-raise — process must stay alive


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
