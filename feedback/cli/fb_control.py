"""
feedback/cli/fb_control.py — Management CLI for the DataNexus feedback system.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.10 / Section 11.6 Step 12

Commands:
  fb_control status   — Print queue depths and system state.
  fb_control pause    — Set Redis pause key (collector stops writing new records).
  fb_control resume   — Delete Redis pause key (collector resumes).
  fb_control flush    — Flush fb:queue (improvement signals).  Requires --confirm.
  fb_control digest   — Print today's digest for all enabled tools.

Run as:
  python3 -m feedback.cli.fb_control <command>

Environment variables:
  DATANEXUS_REDIS_URL — Redis URL (default: redis://localhost:6379)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import click
import redis as redis_lib

from feedback.config import (
    FEEDBACK_AGENTS_ACTIVE,
    FEEDBACK_ENABLED_TOOLS,
    BUG_SIGNALS,
    IMPROVEMENT_SIGNALS,
    key_alerts_immediate,
    key_feedback_list,
    key_feedback_queue,
    key_pause,
)

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_PAUSE_TTL = 24 * 3600   # auto-expire pause after 24h (safety)


def _get_redis() -> Optional[redis_lib.Redis]:
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        client.ping()
        return client
    except Exception as exc:
        click.echo(f"[ERROR] Redis unavailable: {exc}", err=True)
        return None


@click.group()
def cli() -> None:
    """DataNexus feedback system management CLI."""


@cli.command()
def status() -> None:
    """Print queue depths and system status summary."""
    r = _get_redis()

    if r is None:
        click.echo(json.dumps({
            "redis":   "unavailable",
            "ts":      datetime.now(timezone.utc).isoformat(),
        }))
        sys.exit(1)

    alerts_depth = r.llen(key_alerts_immediate())
    queue_depth  = r.llen(key_feedback_queue())
    is_paused    = bool(r.exists(key_pause()))

    tool_counts: dict[str, int] = {}
    for tool_id in sorted(FEEDBACK_ENABLED_TOOLS):
        tool_counts[tool_id] = r.zcard(key_feedback_list(tool_id))

    summary = {
        "status":           "ok",
        "redis":            "connected",
        "collector_paused": is_paused,
        "agents_active":    FEEDBACK_AGENTS_ACTIVE,
        "queues": {
            "alerts_immediate": alerts_depth,
            "feedback_queue":   queue_depth,
        },
        "feedback_counts":  tool_counts,
        "ts":               datetime.now(timezone.utc).isoformat(),
    }
    click.echo(json.dumps(summary, indent=2))


@cli.command()
def pause() -> None:
    """Pause the collector (no new feedback records written)."""
    r = _get_redis()
    if r is None:
        sys.exit(1)

    r.setex(key_pause(), _PAUSE_TTL, "1")
    click.echo(json.dumps({
        "action":    "pause",
        "status":    "ok",
        "pause_key": key_pause(),
        "ttl_secs":  _PAUSE_TTL,
        "ts":        datetime.now(timezone.utc).isoformat(),
    }))


@cli.command()
def resume() -> None:
    """Resume the collector (delete the pause key)."""
    r = _get_redis()
    if r is None:
        sys.exit(1)

    deleted = r.delete(key_pause())
    click.echo(json.dumps({
        "action":  "resume",
        "status":  "ok",
        "deleted": bool(deleted),
        "ts":      datetime.now(timezone.utc).isoformat(),
    }))


@cli.command()
@click.option("--confirm", is_flag=True, required=True,
              help="Must pass --confirm to flush the feedback queue.")
def flush(confirm: bool) -> None:
    """Flush the improvement-signal feedback queue (fb:queue)."""
    r = _get_redis()
    if r is None:
        sys.exit(1)

    depth = r.llen(key_feedback_queue())
    r.delete(key_feedback_queue())
    click.echo(json.dumps({
        "action":   "flush",
        "queue":    key_feedback_queue(),
        "flushed":  depth,
        "status":   "ok",
        "ts":       datetime.now(timezone.utc).isoformat(),
    }))


@cli.command()
def digest() -> None:
    """Print today's feedback digest for all enabled tools."""
    r   = _get_redis()
    ts  = datetime.now(timezone.utc).isoformat()

    result: dict = {"date": ts[:10], "tools": {}}

    for tool_id in sorted(FEEDBACK_ENABLED_TOOLS):
        total = bugs = improvements = 0
        if r:
            try:
                from feedback.config import key_feedback
                rids = r.zrange(key_feedback_list(tool_id), 0, -1)
                total = len(rids)
                for rid in rids[:500]:
                    raw = r.hget(key_feedback(tool_id, rid), "data")
                    if not raw:
                        continue
                    try:
                        rec = json.loads(raw)
                        sig = rec.get("signal", "")
                        if sig in BUG_SIGNALS:
                            bugs += 1
                        elif sig in IMPROVEMENT_SIGNALS:
                            improvements += 1
                    except Exception:
                        pass
            except Exception:
                pass

        result["tools"][tool_id] = {
            "total":       total,
            "bugs":        bugs,
            "improvements": improvements,
            "pending":     max(0, total - bugs - improvements),
        }

    click.echo(json.dumps(result, indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
