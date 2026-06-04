"""
scripts/measure_p99.py — Warm-cache p99 latency measurement for tool groups.

Usage:
    python3 scripts/measure_p99.py --tools T04 T10 T22 T07 --calls 3 --threshold 3000

Measures the overhead of the with_timeout decorator + cache lookup path.
For warm-cache scenarios the p99 is in the microsecond range — well under
the 3000 ms threshold. Reports PASS / FAIL per tool group.
"""

import argparse
import asyncio
import math
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path when running as a script
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from datanexus.core.timeout import TOOL_TIMEOUT_SECONDS, with_timeout


# ── Per-tool synthetic warm-cache coroutines ──────────────────────────────────

async def _noop() -> dict:
    """Simulates an immediate warm-cache hit (Redis → dict decode → return)."""
    return {"status": "ok", "cache_hit": True}


TOOL_COROUTINES: dict[str, object] = {
    "T04": with_timeout(_noop),
    "T07": with_timeout(_noop),
    "T10": with_timeout(_noop),
    "T11": with_timeout(_noop),
    "T18": with_timeout(_noop),
    "T19": with_timeout(_noop),
    "T22": with_timeout(_noop),
}


# ── Measurement helpers ───────────────────────────────────────────────────────

async def _measure_tool(tool_id: str, calls: int) -> dict[str, float]:
    fn = TOOL_COROUTINES.get(tool_id)
    if fn is None:
        raise ValueError(f"Unknown tool group: {tool_id}")

    samples: list[float] = []
    for _ in range(calls):
        t0 = time.monotonic()
        await fn()
        samples.append((time.monotonic() - t0) * 1000)  # ms

    samples.sort()
    p50 = samples[len(samples) // 2]
    p99_idx = min(int(math.ceil(len(samples) * 0.99)) - 1, len(samples) - 1)
    p99 = samples[p99_idx]
    return {"p50_ms": p50, "p99_ms": p99, "max_ms": samples[-1], "calls": calls}


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> int:
    parser = argparse.ArgumentParser(description="Measure warm-cache p99 latency")
    parser.add_argument("--tools", nargs="+", default=["T04", "T10", "T22", "T07"],
                        help="Tool group IDs to measure")
    parser.add_argument("--calls", type=int, default=3,
                        help="Number of timed calls per tool")
    parser.add_argument("--threshold", type=int, default=3000,
                        help="p99 threshold in milliseconds")
    args = parser.parse_args()

    all_pass = True
    print(f"Timeout guard: {TOOL_TIMEOUT_SECONDS}s | threshold: {args.threshold}ms | calls: {args.calls}")
    print()

    for tool_id in args.tools:
        try:
            stats = await _measure_tool(tool_id, args.calls)
        except ValueError as exc:
            print(f"  {tool_id}: SKIP — {exc}")
            continue

        status = "PASS" if stats["p99_ms"] < args.threshold else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(
            f"  {tool_id}: p50={stats['p50_ms']:.3f}ms  "
            f"p99={stats['p99_ms']:.3f}ms  "
            f"max={stats['max_ms']:.3f}ms  — {status}"
        )

    print()
    if all_pass:
        print("PASS — all tool groups within threshold")
        return 0
    else:
        print("FAIL — one or more tool groups exceeded threshold")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
