"""
feedback/agents/master.py — Agent supervisor for the feedback classification system.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.7 / Section 11.6 Step 9

Behaviour:
  FEEDBACK_AGENTS_ACTIVE=false (default):
    Logs a structured message and exits immediately with code 0.
    Must exit in under 1 second.

  FEEDBACK_AGENTS_ACTIVE=true:
    Spawns all worker agents and supervises them.
    Workers: tool_worker (one per FEEDBACK_ENABLED_TOOLS entry).

Run as:
  python3 -m feedback.agents.master

Environment variables:
  FEEDBACK_AGENTS_ACTIVE  — 'true' to activate (default: false)
  DATANEXUS_REDIS_URL     — Redis URL
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from feedback.config import FEEDBACK_AGENTS_ACTIVE, FEEDBACK_ENABLED_TOOLS

log = logging.getLogger("feedback.agents.master")


def _log_structured(event: str, **kwargs: object) -> None:
    """Print a structured JSON log line to stderr."""
    record = {
        "event":      event,
        "service":    "master",
        "ts":         datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }
    print(json.dumps(record), file=sys.stderr, flush=True)


def run() -> None:
    """
    Entry point.  Checks FEEDBACK_AGENTS_ACTIVE and either exits or spawns workers.
    """
    if not FEEDBACK_AGENTS_ACTIVE:
        _log_structured(
            "master_skip",
            reason="FEEDBACK_AGENTS_ACTIVE is false — agents disabled",
            action="exit_0",
        )
        log.info("feedback.agents.master: FEEDBACK_AGENTS_ACTIVE=false — exiting")
        sys.exit(0)

    # ── Active mode: spawn worker per enabled tool ────────────────────────────
    _log_structured(
        "master_start",
        tools=sorted(FEEDBACK_ENABLED_TOOLS),
        agent_count=len(FEEDBACK_ENABLED_TOOLS),
    )
    log.info(
        "feedback.agents.master: FEEDBACK_AGENTS_ACTIVE=true — spawning %d workers",
        len(FEEDBACK_ENABLED_TOOLS),
    )

    procs: list[subprocess.Popen] = []
    for tool_id in sorted(FEEDBACK_ENABLED_TOOLS):
        cmd = [sys.executable, "-m", "feedback.agents.tool_worker",
               "--tool-id", tool_id]
        proc = subprocess.Popen(cmd, env=os.environ.copy())
        procs.append(proc)
        log.info("feedback.agents.master: spawned worker tool=%s pid=%d", tool_id, proc.pid)

    # Simple supervisor loop — restart crashed workers
    try:
        while True:
            time.sleep(5)
            for i, proc in enumerate(procs):
                if proc.poll() is not None:
                    tool_id = sorted(FEEDBACK_ENABLED_TOOLS)[i]
                    log.warning(
                        "feedback.agents.master: worker tool=%s exited rc=%d — restarting",
                        tool_id, proc.returncode,
                    )
                    cmd = [sys.executable, "-m", "feedback.agents.tool_worker",
                           "--tool-id", tool_id]
                    procs[i] = subprocess.Popen(cmd, env=os.environ.copy())
    except KeyboardInterrupt:
        _log_structured("master_shutdown", reason="KeyboardInterrupt")
        for proc in procs:
            proc.terminate()
        sys.exit(0)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    run()
