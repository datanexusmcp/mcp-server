"""
datanexus/scripts/backfill_activation.py — One-time backfill of activation_events.

Replays all historical usage rows (oldest first) through activation_detector.check()
to populate activation_events from existing usage history.

Run once after deploying the activation_events migration:
  cd /app/datanexus
  docker compose exec datanexus-mcp \
    python3 -m datanexus.scripts.backfill_activation

Gates (verify after running):
  dn-funnel shows non-zero counts for at least first_call and real_query.
  173.66.27.4 appears as first_call and real_query.
  160.79.106.x appears as first_call.
"""

import asyncio
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
log = logging.getLogger("datanexus.backfill_activation")

GLAMA_TESTER_IPS = {"204.93.227.11"}


async def run_backfill() -> None:
    db_url = os.environ.get("DATANEXUS_DB_URL", "").strip()
    if not db_url or not db_url.startswith(("postgresql://", "postgres://")):
        log.error("DATANEXUS_DB_URL not configured — cannot backfill")
        sys.exit(1)

    try:
        import asyncpg
    except ImportError:
        log.error("asyncpg not installed — cannot backfill")
        sys.exit(1)

    from datanexus.core.activation_detector import UsageRow, check
    from datanexus.core.ip_classifier import classify_ip

    conn = await asyncpg.connect(db_url, command_timeout=30)
    log.info("Connected to database")

    # Fetch all usage rows ordered by created_at (oldest first)
    # Skip smoke, grey, and known Glama tester IPs
    rows = await conn.fetch(
        """
        SELECT tool_id, client_ip, tool_input, is_smoke,
               COALESCE(is_grey, false) AS is_grey
        FROM usage
        WHERE (is_smoke = false OR is_smoke IS NULL)
          AND client_ip NOT IN ('unknown', '')
          AND client_ip IS NOT NULL
        ORDER BY created_at ASC
        """
    )
    await conn.close()

    log.info("Fetched %d usage rows to replay", len(rows))
    processed = 0
    skipped = 0

    for r in rows:
        ip = r["client_ip"] or ""
        if not ip or ip.startswith("172.6") or ip in GLAMA_TESTER_IPS:
            skipped += 1
            continue

        ip_class = classify_ip(ip)
        is_grey  = r["is_grey"] or ip_class.get("is_grey", False)
        if is_grey:
            skipped += 1
            continue

        import json
        tool_input = {}
        if r["tool_input"]:
            try:
                tool_input = json.loads(r["tool_input"])
            except Exception:
                pass

        row = UsageRow(
            client_ip=ip,
            tool_id=r["tool_id"] or "",
            tool_input=tool_input,
            is_smoke=bool(r["is_smoke"]),
            is_grey=is_grey,
        )
        await check(row)
        processed += 1

        if processed % 50 == 0:
            log.info("Processed %d rows (%d skipped)...", processed, skipped)

    log.info(
        "Backfill complete — %d rows processed, %d skipped",
        processed, skipped,
    )


if __name__ == "__main__":
    asyncio.run(run_backfill())
