"""
feedback/agents/tool_worker.py — Per-tool feedback classification worker.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.8 / Section 11.6 Step 10

Rules (non-negotiable):
  - Loads ONLY its own TOOL_{tool_id}.md spec file — never another tool's spec.
  - With FEEDBACK_AGENTS_ACTIVE=false: writes empty JSON to output path, exits 0.
  - With FEEDBACK_AGENTS_ACTIVE=true: processes pending FeedbackRecords from Redis.
  - Zero Claude API calls in this module (pre-classification only).

Run as:
  python3 -m feedback.agents.tool_worker --tool-id T04
  python3 -m feedback.agents.tool_worker --tool-id T04 --output /tmp/out.json

Arguments:
  --tool-id   Tool ID to process (e.g. T04, T10). Required.
  --output    Path to write JSON output. Defaults to stdout.
  --once      Process one batch and exit (for cron / testing). Default: loop.

Environment variables:
  FEEDBACK_AGENTS_ACTIVE  — must be 'true' to do real work (default: false)
  DATANEXUS_REDIS_URL     — Redis URL
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis as redis_lib

from feedback.config import (
    FEEDBACK_AGENTS_ACTIVE,
    FEEDBACK_ENABLED_TOOLS,
    FEEDBACK_TTL,
    key_feedback,
    key_feedback_list,
    key_classifier_queue,
)
from feedback.models import FeedbackRecord
from feedback.pre_classifier import classify_record

log = logging.getLogger("feedback.agents.tool_worker")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

# Spec files live alongside the tools/ directory
_SPEC_DIR = Path(__file__).parents[3] / "datanexus" / "tools"


def _get_redis() -> Optional[redis_lib.Redis]:
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=5,
        )
        client.ping()
        return client
    except Exception as exc:
        log.warning("tool_worker: Redis unavailable — %s", exc)
        return None


def _load_own_spec(tool_id: str) -> str:
    """
    Load TOOL_{tool_id}.md from the tools spec directory.
    Returns empty string if not found.
    NEVER loads a spec for a different tool_id.
    """
    spec_path = _SPEC_DIR / f"TOOL_{tool_id}.md"
    if spec_path.exists():
        return spec_path.read_text(encoding="utf-8")
    # Fallback: look in project root
    root_path = Path(__file__).parents[3] / f"TOOL_{tool_id}.md"
    if root_path.exists():
        return root_path.read_text(encoding="utf-8")
    log.info("tool_worker: no spec file found for %s (non-fatal)", tool_id)
    return ""


def _write_output(data: dict, output_path: Optional[str]) -> None:
    """Write JSON data to output_path or stdout."""
    serialised = json.dumps(data, indent=2)
    if output_path:
        Path(output_path).write_text(serialised, encoding="utf-8")
        log.info("tool_worker: wrote output to %s", output_path)
    else:
        print(serialised, flush=True)


def _process_batch(tool_id: str, r: redis_lib.Redis, batch_size: int = 50) -> int:
    """
    Pull up to batch_size pending FeedbackRecords for tool_id from Redis,
    run pre_classifier, update classification field in place.
    Returns count of records processed.
    """
    processed = 0
    record_ids = r.zrange(key_feedback_list(tool_id), 0, batch_size - 1)

    for record_id in record_ids:
        raw = r.hget(key_feedback(tool_id, record_id), "data")
        if not raw:
            continue
        try:
            rec = FeedbackRecord.model_validate_json(raw)
        except Exception as exc:
            log.warning("tool_worker: invalid record %s — %s", record_id, exc)
            continue

        if rec.classification != "pending":
            continue   # already classified

        classification, score = classify_record(rec)
        rec.classification  = classification
        rec.score           = score
        rec.agent_version   = "pre_classifier/1.0"

        r.hset(
            key_feedback(tool_id, record_id),
            mapping={"data": rec.model_dump_json(), "vote_count": 1},
        )
        processed += 1

    return processed


def run(tool_id: str, output_path: Optional[str], once: bool) -> None:
    """Main worker entry point."""
    if tool_id not in FEEDBACK_ENABLED_TOOLS:
        log.error("tool_worker: unknown tool_id=%s — exiting", tool_id)
        sys.exit(1)

    # Load ONLY this tool's spec
    _spec_content = _load_own_spec(tool_id)

    # ── FEEDBACK_AGENTS_ACTIVE=false → write empty JSON and exit 0 ────────────
    if not FEEDBACK_AGENTS_ACTIVE:
        result = {
            "tool_id":    tool_id,
            "processed":  0,
            "status":     "inactive",
            "reason":     "FEEDBACK_AGENTS_ACTIVE is false",
            "ts":         datetime.now(timezone.utc).isoformat(),
        }
        _write_output(result, output_path)
        log.info("tool_worker: FEEDBACK_AGENTS_ACTIVE=false — wrote empty output, exit 0")
        sys.exit(0)

    # ── Active mode ────────────────────────────────────────────────────────────
    log.info("tool_worker: starting tool=%s active=true", tool_id)

    while True:
        r = _get_redis()
        if r is None:
            import time
            time.sleep(10)
            continue

        count = _process_batch(tool_id, r)
        log.info("tool_worker: processed %d records tool=%s", count, tool_id)

        result = {
            "tool_id":   tool_id,
            "processed": count,
            "status":    "ok",
            "ts":        datetime.now(timezone.utc).isoformat(),
        }
        if output_path:
            _write_output(result, output_path)

        if once:
            sys.exit(0)

        import time
        time.sleep(30)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DataNexus feedback tool_worker — classifies feedback for one tool.",
    )
    parser.add_argument("--tool-id",  required=True, help="Tool ID (e.g. T04, T10)")
    parser.add_argument("--output",   default=None,  help="Output JSON path (default: stdout)")
    parser.add_argument("--once",     action="store_true", help="Process one batch then exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    run(tool_id=args.tool_id, output_path=args.output, once=args.once)


if __name__ == "__main__":
    main()
