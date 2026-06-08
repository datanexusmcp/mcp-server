"""
datanexus/jobs/daily_digest.py — Daily health digest for the operator.

Sprint 5 Layer 2. Runs at 06:00 UTC daily (Docker cron service).
Reads from:
  datanexus:failures:{YYYY-MM-DD}    — Redis list written by failure_classifier
  datanexus:agent_gaps:{YYYY-MM-DD}  — Redis list written by report_feedback

Posts to DATANEXUS_SLACK_WEBHOOK if set; falls back to log output.
Zero-failure behavior: always sends, even when counts are zero.

Run as Docker service: python -m datanexus.jobs.daily_digest
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import redis as redis_lib

log = logging.getLogger("datanexus.jobs.daily_digest")

_REDIS_URL      = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_SLACK_WEBHOOK  = os.environ.get("DATANEXUS_SLACK_WEBHOOK", "")
_TARGET_HOUR_UTC = 6   # 06:00 UTC

# Human-readable notes per failure class
_CLASS_NOTES = {
    "format_error":    "user education, no action",
    "upstream_error":  "upstream health issue",
    "user_error":      "expected, no action",
    "rate_limit":      "rate limiting, no action",
    "code_bug":        "auto-PR candidate ↓",
    "infrastructure":  "infra issue, investigate",
}

_GAPS_TTL = 72 * 3600  # kept for reference


def _get_redis() -> Optional[redis_lib.Redis]:
    """Return a Redis client or None — never raises."""
    try:
        r = redis_lib.Redis.from_url(
            _REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=5,
        )
        r.ping()
        return r
    except Exception as exc:
        log.warning("daily_digest: Redis unavailable — %s", exc)
        return None


def _read_failures(r: redis_lib.Redis, date_str: str) -> list[dict]:
    """Read all failure entries for the given date. Returns empty list on error."""
    try:
        raw_list = r.lrange(f"datanexus:failures:{date_str}", 0, -1)
        result = []
        for raw in raw_list:
            try:
                result.append(json.loads(raw))
            except Exception:
                pass
        return result
    except Exception as exc:
        log.warning("daily_digest: error reading failures — %s", exc)
        return []


def _read_agent_gaps(r: redis_lib.Redis, date_str: str) -> list[dict]:
    """Read all agent gap entries for the given date. Returns empty list on error."""
    try:
        raw_list = r.lrange(f"datanexus:agent_gaps:{date_str}", 0, -1)
        result = []
        for raw in raw_list:
            try:
                result.append(json.loads(raw))
            except Exception:
                pass
        return result
    except Exception as exc:
        log.warning("daily_digest: error reading agent gaps — %s", exc)
        return []


def _read_total_calls(r: redis_lib.Redis, date_str: str) -> int:
    """Sum all dau:{tool_id}:{version}:{date} counters for the given date."""
    try:
        keys = r.keys(f"dau:*:{date_str}")
        if not keys:
            return 0
        pipe = r.pipeline()
        for k in keys:
            pipe.get(k)
        results = pipe.execute()
        total = 0
        for val in results:
            if val is not None:
                try:
                    total += int(val)
                except (ValueError, TypeError) as exc:
                    log.debug("daily_digest: skipping non-integer counter value: %s", exc)
        return total
    except Exception as exc:
        log.warning("daily_digest: error reading call counters — %s", exc)
        return 0


def _format_failures_section(failures: list[dict]) -> str:
    """Format the FAILURES section of the digest."""
    if not failures:
        return "── FAILURES by class ──────────────────────────────────────\n  (none)\n"

    class_counts: Counter = Counter()
    for f in failures:
        class_counts[f.get("error_class", "code_bug")] += 1

    total = len(failures)
    lines = ["── FAILURES by class ──────────────────────────────────────"]
    for cls, count in class_counts.most_common():
        pct = int(100 * count / total) if total else 0
        note = _CLASS_NOTES.get(cls, "")
        lines.append(f"  {cls:<16s} {count:>3d}  ({pct:>2d}%)  ← {note}")

    # Top failures grouped by error_code + tool_id
    lines.append("")
    lines.append("Top failures:")
    top_key: Counter = Counter()
    for f in failures:
        key = f"{f.get('error_code','?')} in {f.get('tool_id','?')}"
        top_key[key] += 1

    for i, (label, count) in enumerate(top_key.most_common(5), 1):
        suffix = " ← auto-PR" if any(
            f.get("error_class") == "code_bug"
            for f in failures
            if f"{f.get('error_code','?')} in {f.get('tool_id','?')}" == label
        ) else ""
        lines.append(f"  {i}. {label} ({count}×){suffix}")

    # Count code_bugs
    code_bug_count = class_counts.get("code_bug", 0)
    lines.append("")
    lines.append(f"code_bug PRs opened today: {code_bug_count}")
    if code_bug_count > 0:
        for f in failures:
            if f.get("error_class") == "code_bug":
                lines.append(
                    f"  → auto-PR candidate: {f.get('error_code','?')} "
                    f"in {f.get('tool_id','?')}"
                )
                break  # just show the first one; real auto-PR is Layer 3

    return "\n".join(lines)


def _format_gaps_section(gaps: list[dict]) -> str:
    """Format the AGENT GAPS section of the digest."""
    lines = ["── AGENT GAPS (roadmap signals) ───────────────────────────"]
    if not gaps:
        lines.append("  (none)")
    else:
        tool_gaps: dict[str, list[str]] = defaultdict(list)
        for g in gaps:
            tool_id = g.get("tool_id", "unknown")
            desc = g.get("gap_description", "")
            tool_gaps[tool_id].append(desc)

        sorted_tools = sorted(tool_gaps.items(), key=lambda x: -len(x[1]))
        for tool_id, descs in sorted_tools:
            count = len(descs)
            sample = descs[0][:80] if descs else ""
            lines.append(f"  {tool_id:<40s} {count}×  — {sample}")

    lines.append("")
    lines.append("→ Add top gap to TODOS.md as future enhancement candidate.")
    return "\n".join(lines)


def build_digest(date_str: str) -> str:
    """Build the full digest text for the given date. Never raises."""
    try:
        r = _get_redis()
        if r is None:
            failures = []
            gaps = []
            total_calls = 0
        else:
            failures    = _read_failures(r, date_str)
            gaps        = _read_agent_gaps(r, date_str)
            total_calls = _read_total_calls(r, date_str)

        failure_count = len(failures)
        gap_count     = len(gaps)
        failure_pct   = f"({100 * failure_count / total_calls:.1f}%)" if total_calls else "(N/A)"

        header = (
            f"DataNexus — Daily Health Report ({date_str})\n"
            "\n"
            f"Total tool calls (24h):  {total_calls:>6,d}\n"
            f"Failures:                {failure_count:>6d}  {failure_pct}\n"
            f"Agent Gaps:              {gap_count:>6d}  (intent not served)\n"
        )

        failures_section = _format_failures_section(failures)
        gaps_section     = _format_gaps_section(gaps)

        return f"{header}\n{failures_section}\n\n{gaps_section}"

    except Exception as exc:
        log.error("daily_digest.build_digest: unexpected error — %s", exc)
        return (
            f"DataNexus — Daily Health Report ({date_str})\n"
            f"ERROR: digest generation failed — {type(exc).__name__}\n"
            "Check server logs for details."
        )


def send_digest(digest_text: str) -> None:
    """Send digest to Slack webhook or log. Never raises."""
    log.info("daily_digest:\n%s", digest_text)

    if not _SLACK_WEBHOOK:
        log.info("daily_digest: DATANEXUS_SLACK_WEBHOOK not set — logged only")
        return

    try:
        payload = {"text": f"```\n{digest_text}\n```"}
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(_SLACK_WEBHOOK, json=payload)
            if resp.status_code == 200:
                log.info("daily_digest: Slack delivery OK")
            else:
                log.error(
                    "daily_digest: Slack webhook returned %d — %s",
                    resp.status_code, resp.text[:200],
                )
    except Exception as exc:
        log.error("daily_digest: Slack delivery failed — %s", exc)


def _seconds_until_next_run() -> float:
    """Seconds until next 06:00 UTC. Returns a value in [60, 86400]."""
    now = datetime.now(timezone.utc)
    target = now.replace(hour=_TARGET_HOUR_UTC, minute=0, second=0, microsecond=0)
    if now >= target:
        target += timedelta(days=1)
    secs = (target - now).total_seconds()
    return max(60.0, secs)


def main() -> None:
    """Entry point for the daily-digest Docker service."""
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    log.info("daily_digest: service started")

    while True:
        wait = _seconds_until_next_run()
        log.info("daily_digest: sleeping %.0fs until next 06:00 UTC run", wait)
        time.sleep(wait)

        # Report on yesterday (the 24h period that just completed)
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        log.info("daily_digest: building digest for %s", yesterday)

        digest = build_digest(yesterday)
        send_digest(digest)


if __name__ == "__main__":
    main()
