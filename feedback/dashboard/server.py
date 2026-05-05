"""
feedback/dashboard/server.py — Feedback intelligence and usage/adoption dashboard.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 8.9 / Section 12.8 / Phase 6

Two panels:
  1. Feedback Intelligence — signal breakdown, top bugs, vote counts,
     agent status banner showing FEEDBACK_AGENTS_ACTIVE and MCPIZE_ACTIVE.
  2. Usage / Adoption      — calls today, unique sessions, DAU 7-day trend,
     error rate, cache-hit ratio, p99 latency, top query patterns (privacy-safe).

Endpoints:
  GET /                 — 200 HTML with agent status banner
  GET /api/summary      — JSON with 'summary' and 'tools' keys
  GET /api/feedback     — Recent feedback records (last 50 per tool)
  GET /api/health       — Service health check

Redis key namespaces read:
  Feedback:  fb:feedback:{tool_id}:{record_id}  fb:feedback_list:{tool_id}
             fb:alerts:immediate  fb:queue  fb:pause
  Payment telemetry:  datanexus:calls:{tool_id}:{date}
                      datanexus:sessions:{tool_id}:{date}
  Audit:  dau:{tool_id}:{version}:{date}
          errors:{tool_id}:{date}
          cache_miss:{tool_id}:{date}
  Top-params (privacy-safe): datanexus:params_counts:{tool_id}

Run as:
  uvicorn feedback.dashboard.server:app --port 8101
  python3 -m feedback.dashboard.server  (dev mode)

Environment variables:
  DATANEXUS_REDIS_URL  — Redis URL (default: redis://localhost:6379)
  DASHBOARD_PORT       — Port (default: 8101)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

import redis as redis_lib
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

import payment.config as _payment_cfg
from payment.config import HAIKU_MAX_CALLS_PER_DAY
from feedback.config import (
    FEEDBACK_AGENTS_ACTIVE,
    FEEDBACK_ENABLED_TOOLS,
    BUG_SIGNALS,
    IMPROVEMENT_SIGNALS,
    key_feedback_list,
    key_feedback,
    key_alerts_immediate,
    key_feedback_queue,
    key_pause,
)

log = logging.getLogger("feedback.dashboard.server")

_REDIS_URL = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")
_PORT      = int(os.environ.get("DASHBOARD_PORT", "8101"))

# Tools actually registered in main.py.
# Update this set when a new tool-group is built AND registered in main.py.
# T22 and future tools must NOT appear here until they are registered.
_REGISTERED_TOOLS: frozenset = frozenset({"T04", "T10"})

# Tools shown in usage panel — only tools that are registered in main.py.
# Intersecting with _REGISTERED_TOOLS prevents future/placeholder tool IDs
# (e.g. T22 from MCPIZE_URLS) from appearing before they are built.
_ALL_TOOLS = sorted(
    (FEEDBACK_ENABLED_TOOLS | set(_payment_cfg.MCPIZE_URLS.keys()))
    & _REGISTERED_TOOLS
)

app = FastAPI(
    title="DataNexus Feedback Dashboard",
    version="2.0.0",
    description="Feedback intelligence and usage/adoption analytics for DataNexus MCP.",
)

# ── Redis ──────────────────────────────────────────────────────────────────────

_redis_client: Optional[redis_lib.Redis] = None


def _get_redis() -> Optional[redis_lib.Redis]:
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None
    try:
        client = redis_lib.Redis.from_url(
            _REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:
        log.warning("dashboard: Redis unavailable — %s", exc)
        return None


def _set_redis_client(client: Optional[redis_lib.Redis]) -> None:
    global _redis_client
    _redis_client = client


# ── Panel 1: Feedback Intelligence ────────────────────────────────────────────

def _get_feedback_stats() -> dict[str, Any]:
    """
    Per-tool feedback breakdown: total, bugs, improvements, pending.
    Reads from feedback sorted-sets and hsets.
    """
    r     = _get_redis()
    tools = {}

    for tool_id in sorted(FEEDBACK_ENABLED_TOOLS):
        total        = 0
        bugs         = 0
        improvements = 0

        if r:
            try:
                record_ids = r.zrange(key_feedback_list(tool_id), 0, -1)
                total      = len(record_ids)
                for rid in record_ids[:200]:
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
            except Exception as exc:
                log.warning("dashboard: feedback read error tool=%s — %s", tool_id, exc)

        tools[tool_id] = {
            "total_feedback":    total,
            "bug_count":         bugs,
            "improvement_count": improvements,
            "pending_count":     max(0, total - bugs - improvements),
        }

    return tools


def _get_queue_stats() -> dict[str, Any]:
    """Queue depths and pause state (always available regardless of MCPIZE_ACTIVE)."""
    r          = _get_redis()
    alerts_len = 0
    queue_len  = 0
    is_paused  = False

    if r:
        try:
            alerts_len = r.llen(key_alerts_immediate())
            queue_len  = r.llen(key_feedback_queue())
            is_paused  = bool(r.exists(key_pause()))
        except Exception as exc:
            log.warning("dashboard: queue stats error — %s", exc)

    return {
        "alerts_immediate_depth": alerts_len,
        "feedback_queue_depth":   queue_len,
        "collector_paused":       is_paused,
        "agents_active":          FEEDBACK_AGENTS_ACTIVE,
    }


# ── Panel 2: Usage & Adoption ──────────────────────────────────────────────────

def _date_range_7d() -> list[str]:
    """Return ISO date strings for today and the prior 6 days (newest first)."""
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=i)).isoformat() for i in range(7)]


def get_usage_summary() -> dict[str, Any]:
    """
    Return usage summary for all tracked tools.

    Per tool:
      calls_today       — datanexus:calls:{tool_id}:{date}  (payment telemetry INCR)
      sessions_today    — datanexus:sessions:{tool_id}:{date} (SCARD)
      dau_7d            — calls per day for last 7 days
      error_rate        — errors:{tool_id}:{date} / calls_today  (audit counters)
      cache_hit_ratio   — 1 - (cache_miss:{tool_id}:{date} / calls_today)
      p99_latency_ms    — datanexus:p99:{tool_id}:{date} if available, else null
      top_params        — top 5 params_hash from datanexus:params_counts:{tool_id}
    """
    r     = _get_redis()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dates = _date_range_7d()
    tools = {}

    for tool_id in _ALL_TOOLS:
        calls_today   = 0
        sessions_today = 0
        dau_7d: list[dict] = []
        error_count   = 0
        cache_misses  = 0
        p99_ms: Optional[float] = None
        top_params: list[dict] = []

        if r:
            try:
                # ── calls today (payment telemetry) ─────────────────────────
                raw_calls = r.get(f"datanexus:calls:{tool_id}:{today}")
                calls_today = int(raw_calls) if raw_calls else 0

                # ── unique sessions today ────────────────────────────────────
                sessions_today = r.scard(f"datanexus:sessions:{tool_id}:{today}")

                # ── DAU 7-day trend ──────────────────────────────────────────
                pipe = r.pipeline()
                for d in dates:
                    pipe.get(f"datanexus:calls:{tool_id}:{d}")
                raw_dau = pipe.execute()
                dau_7d = [
                    {"date": d, "calls": int(v) if v else 0}
                    for d, v in zip(dates, raw_dau)
                ]

                # ── error rate (audit counters) ──────────────────────────────
                raw_err = r.get(f"errors:{tool_id}:{today}")
                error_count = int(raw_err) if raw_err else 0

                # ── cache hit ratio (audit counters) ─────────────────────────
                raw_miss = r.get(f"cache_miss:{tool_id}:{today}")
                cache_misses = int(raw_miss) if raw_miss else 0

                # ── p99 latency (if written) ─────────────────────────────────
                raw_p99 = r.get(f"datanexus:p99:{tool_id}:{today}")
                if raw_p99 is not None:
                    try:
                        p99_ms = float(raw_p99)
                    except ValueError:
                        pass

                # ── top 5 params_hash (privacy-safe sorted set) ─────────────
                raw_top = r.zrevrange(
                    f"datanexus:params_counts:{tool_id}", 0, 4,
                    withscores=True,
                )
                top_params = [
                    {"params_hash": h, "count": int(score)}
                    for h, score in raw_top
                ]

            except Exception as exc:
                log.warning("dashboard: usage read error tool=%s — %s", tool_id, exc)

        # Compute derived stats
        error_rate     = round(error_count / calls_today, 4) if calls_today > 0 else 0.0
        cache_hit_count = max(0, calls_today - cache_misses)
        cache_hit_ratio = round(cache_hit_count / calls_today, 4) if calls_today > 0 else None

        tools[tool_id] = {
            "calls_today":      calls_today,
            "sessions_today":   sessions_today,
            "dau_7d":           dau_7d,
            "error_rate":       error_rate,
            "error_count":      error_count,
            "cache_hit_ratio":  cache_hit_ratio,
            "p99_latency_ms":   p99_ms,
            "top_params":       top_params,
        }

    return tools


def get_conversion_stats() -> dict[str, Any]:
    """
    Return MCPize conversion stats.

    If MCPIZE_ACTIVE=False (free window) → status='free_window'.
    If MCPIZE_ACTIVE=True  → return entitlement/subscription counts.

    Always reads _payment_cfg.MCPIZE_ACTIVE at call time (not import time).
    """
    # ── free window: no conversion stats yet ──────────────────────────────────
    if not _payment_cfg.MCPIZE_ACTIVE:
        return {
            "status":  "free_window",
            "message": "Conversion stats available after paid tier launch.",
        }

    # ── paid window: read entitlement key counts per tool ─────────────────────
    r       = _get_redis()
    by_tool: dict[str, Any] = {}

    for tool_id in _ALL_TOOLS:
        entitlement_count = 0
        grace_count       = 0
        if r:
            try:
                # Count entitlement keys via SCAN — no KEYS* in production
                ent_pattern   = f"datanexus:entitlement:{tool_id}:*"
                grace_pattern = f"datanexus:grace:{tool_id}:*"
                ent_cursor, ent_keys     = r.scan(0, match=ent_pattern,   count=500)
                grace_cursor, grace_keys = r.scan(0, match=grace_pattern, count=500)
                entitlement_count = len(ent_keys)
                grace_count       = len(grace_keys)
            except Exception as exc:
                log.warning("dashboard: conversion stats error tool=%s — %s", tool_id, exc)

        by_tool[tool_id] = {
            "active_entitlements": entitlement_count,
            "in_grace_period":     grace_count,
            "upgrade_url":         _payment_cfg.MCPIZE_URLS.get(tool_id, ""),
        }

    return {
        "status":     "active",
        "mcpize_url": "https://mcpize.io",
        "by_tool":    by_tool,
    }


# ── Section 13 data helpers ───────────────────────────────────────────────────

def _get_s13_stats() -> dict[str, Any]:
    """
    Fetch all four Section 13 dashboard elements from Redis in one pass.

    Returns:
      digests:              dict[tool_id → digest fields or None]
      haiku_calls_today:    int
      pending_github_issues: int
      digest_available:     bool
    """
    r        = _get_redis()
    today    = date.today().isoformat()
    week_str = date.today().strftime("%G-W%V")

    haiku_calls_today    = 0
    pending_github_issues = 0
    digest_available     = False
    digests: dict[str, Any] = {}

    if r:
        try:
            # Element 2: Haiku call counter
            raw_haiku = r.get(f"haiku:calls:{today}")
            haiku_calls_today = int(raw_haiku) if raw_haiku else 0

            # Element 3: Pending GitHub issues (SCAN — no KEYS in production)
            cursor = 0
            gh_count = 0
            while True:
                cursor, keys = r.scan(cursor, match="datanexus:github:pending:*", count=200)
                gh_count += len(keys)
                if cursor == 0:
                    break
            pending_github_issues = gh_count

            # Element 1: Weekly digest per registered tool
            for tool_id in sorted(_REGISTERED_TOOLS):
                key = f"datanexus:digest:{tool_id}:{week_str}"
                raw = r.hgetall(key)
                if raw:
                    try:
                        digests[tool_id] = {
                            "data_quality_score":    float(raw.get("data_quality_score", 1.0)),
                            "top_issues":            json.loads(raw.get("top_issues", "[]")),
                            "sprint_recommendations": json.loads(raw.get("sprint_recommendations", "[]")),
                            "generated_at":          raw.get("generated_at", ""),
                        }
                        digest_available = True
                    except Exception:
                        digests[tool_id] = None
                else:
                    digests[tool_id] = None

            # digest_available: check any datanexus:digest:* key exists
            if not digest_available:
                _, any_keys = r.scan(0, match="datanexus:digest:*", count=10)
                digest_available = len(any_keys) > 0

        except Exception as exc:
            log.warning("dashboard: s13 stats error — %s", exc)

    return {
        "digests":               digests,
        "haiku_calls_today":     haiku_calls_today,
        "pending_github_issues": pending_github_issues,
        "digest_available":      digest_available,
    }


# ── HTML builder ───────────────────────────────────────────────────────────────

def _fmt_pct(v: Optional[float]) -> str:
    if v is None:
        return "n/a"
    return f"{v * 100:.1f}%"


def _fmt_ms(v: Optional[float]) -> str:
    if v is None:
        return "n/a"
    return f"{v:.0f} ms"


def _build_dau_sparkline(dau_7d: list[dict]) -> str:
    """Render a tiny text sparkline for 7-day DAU (oldest → newest)."""
    vals = [d["calls"] for d in reversed(dau_7d)]
    if not any(vals):
        return "—"
    mx = max(vals) or 1
    bars = "▁▂▃▄▅▆▇█"
    return "".join(bars[min(7, int(v / mx * 7))] for v in vals)


def _build_html(
    feedback_tools: dict,
    queue_stats: dict,
    usage_tools: dict,
    conv_stats: dict,
    s13_stats: Optional[dict] = None,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── banners ────────────────────────────────────────────────────────────────
    def _badge(active: bool, on_label: str = "ACTIVE", off_label: str = "INACTIVE") -> str:
        if active:
            return f'<span style="color:#22c55e">● {on_label}</span>'
        return f'<span style="color:#f59e0b">● {off_label}</span>'

    agents_badge  = _badge(FEEDBACK_AGENTS_ACTIVE)
    mcpize_badge  = _badge(_payment_cfg.MCPIZE_ACTIVE, on_label="PAID ACTIVE", off_label="FREE WINDOW")
    pause_badge   = (
        '<span style="color:#ef4444">⏸ PAUSED</span>'
        if queue_stats["collector_paused"]
        else '<span style="color:#22c55e">▶ RUNNING</span>'
    )

    # ── Panel 1: feedback rows ─────────────────────────────────────────────────
    fb_rows = ""
    for tid, d in feedback_tools.items():
        fb_rows += (
            f"<tr><td>{tid}</td>"
            f"<td>{d['total_feedback']}</td>"
            f"<td>{d['bug_count']}</td>"
            f"<td>{d['improvement_count']}</td>"
            f"<td>{d['pending_count']}</td></tr>\n"
        )

    # ── Panel 2: usage rows ────────────────────────────────────────────────────
    usage_rows = ""
    for tid, d in usage_tools.items():
        spark = _build_dau_sparkline(d.get("dau_7d", []))
        usage_rows += (
            f"<tr>"
            f"<td>{tid}</td>"
            f"<td>{d['calls_today']}</td>"
            f"<td>{d['sessions_today']}</td>"
            f"<td style='font-family:monospace'>{spark}</td>"
            f"<td>{_fmt_pct(d['error_rate'] if d['error_count'] > 0 else None)}</td>"
            f"<td>{_fmt_pct(d['cache_hit_ratio'])}</td>"
            f"<td>{_fmt_ms(d['p99_latency_ms'])}</td>"
            f"</tr>\n"
        )

    # ── Top query patterns rows ────────────────────────────────────────────────
    params_rows = ""
    for tid, d in usage_tools.items():
        top = d.get("top_params", [])
        if top:
            for rank, p in enumerate(top, 1):
                params_rows += (
                    f"<tr><td>{tid}</td>"
                    f"<td>#{rank}</td>"
                    f"<td style='font-family:monospace'>{p['params_hash']}</td>"
                    f"<td>{p['count']}</td></tr>\n"
                )
        else:
            params_rows += f"<tr><td>{tid}</td><td colspan='3' style='color:#94a3b8'>no data yet</td></tr>\n"

    # ── Conversion panel ───────────────────────────────────────────────────────
    if conv_stats.get("status") == "free_window":
        conv_html = (
            f'<p style="color:#f59e0b">⏳ {conv_stats["message"]}</p>'
        )
    else:
        conv_rows = ""
        for tid, c in conv_stats.get("by_tool", {}).items():
            url_cell = (
                f'<a href="{c["upgrade_url"]}" target="_blank">{c["upgrade_url"]}</a>'
                if c["upgrade_url"] else "—"
            )
            conv_rows += (
                f"<tr><td>{tid}</td>"
                f"<td>{c['active_entitlements']}</td>"
                f"<td>{c['in_grace_period']}</td>"
                f"<td>{url_cell}</td></tr>\n"
            )
        conv_html = f"""
        <table>
          <thead><tr><th>Tool</th><th>Active entitlements</th>
          <th>In grace period</th><th>Upgrade URL</th></tr></thead>
          <tbody>{conv_rows}</tbody>
        </table>"""

    # ── Section 13 panels ─────────────────────────────────────────────────────
    s13 = s13_stats or {}
    haiku_today   = s13.get("haiku_calls_today", 0)
    gh_pending    = s13.get("pending_github_issues", 0)
    dig_available = s13.get("digest_available", False)
    digests       = s13.get("digests", {})

    # Panel S13-A: Weekly digest per tool
    digest_rows = ""
    for tool_id, dig in digests.items():
        if dig:
            score_pct = f"{dig['data_quality_score'] * 100:.0f}%"
            top_str   = "; ".join(dig["top_issues"][:3]) or "—"
            sprint_str = "; ".join(dig["sprint_recommendations"][:2]) or "—"
            gen_at    = dig.get("generated_at", "")[:16]
            digest_rows += (
                f"<tr><td>{tool_id}</td><td>{score_pct}</td>"
                f"<td style='max-width:280px'>{top_str}</td>"
                f"<td style='max-width:280px'>{sprint_str}</td>"
                f"<td>{gen_at}</td></tr>\n"
            )
        else:
            digest_rows += (
                f"<tr><td>{tool_id}</td>"
                f"<td colspan='4' style='color:#94a3b8'>no digest this week</td></tr>\n"
            )

    if not digest_rows:
        digest_rows = "<tr><td colspan='5' style='color:#94a3b8'>no digest data</td></tr>\n"

    # Haiku budget colour
    haiku_pct = haiku_today / HAIKU_MAX_CALLS_PER_DAY if HAIKU_MAX_CALLS_PER_DAY else 0
    haiku_color = "#ef4444" if haiku_pct >= 0.9 else ("#f59e0b" if haiku_pct >= 0.7 else "#22c55e")

    s13_section = f"""
  <h2>Section 13 — Haiku Validation Architecture</h2>

  <!-- S13 Panel A: Weekly Quality Digest -->
  <h3 style="font-size:0.95rem;margin:1rem 0 0.4rem">Weekly Quality Digest
    <span style="color:#94a3b8;font-weight:400;font-size:0.85rem">
      ({'available' if dig_available else 'not yet generated this week'})
    </span>
  </h3>
  <table>
    <thead><tr>
      <th>Tool</th><th>Quality score</th><th>Top issues (up to 3)</th>
      <th>Sprint recommendations</th><th>Generated at</th>
    </tr></thead>
    <tbody>{digest_rows}</tbody>
  </table>

  <!-- S13 Panel B: Haiku call budget -->
  <h3 style="font-size:0.95rem;margin:1rem 0 0.4rem">Haiku Call Budget</h3>
  <table>
    <thead><tr><th>Calls today</th><th>Daily limit</th><th>Utilisation</th></tr></thead>
    <tbody>
      <tr>
        <td>{haiku_today}</td>
        <td>{HAIKU_MAX_CALLS_PER_DAY}</td>
        <td style="color:{haiku_color}">{haiku_pct * 100:.1f}%</td>
      </tr>
    </tbody>
  </table>

  <!-- S13 Panel C: Pending GitHub issues -->
  <h3 style="font-size:0.95rem;margin:1rem 0 0.4rem">Pending GitHub Issues</h3>
  <table>
    <thead><tr><th>Queued (datanexus:github:pending:*)</th></tr></thead>
    <tbody>
      <tr><td style="color:{'#ef4444' if gh_pending > 0 else '#22c55e'}">{gh_pending}</td></tr>
    </tbody>
  </table>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DataNexus Dashboard</title>
  <style>
    body  {{ font-family: system-ui, sans-serif; max-width: 1100px;
             margin: 2rem auto; padding: 0 1rem; background: #f8fafc; color: #1e293b; }}
    h1    {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
    h2    {{ font-size: 1.1rem; margin: 1.75rem 0 0.5rem; border-bottom: 2px solid #e2e8f0;
             padding-bottom: 0.25rem; }}
    .banner {{ background: #1e293b; color: #f8fafc; padding: 0.75rem 1.2rem;
               border-radius: 8px; margin-bottom: 1.5rem;
               display: flex; flex-wrap: wrap; gap: 1.5rem; align-items: center; }}
    .banner .ts {{ margin-left: auto; opacity: 0.55; font-size: 0.85rem; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff;
             border-radius: 6px; overflow: hidden;
             box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
    th, td {{ border: 1px solid #e2e8f0; padding: 0.45rem 0.75rem; }}
    th    {{ background: #f1f5f9; font-weight: 600; }}
    tr:hover td {{ background: #f8fafc; }}
    .note {{ color: #64748b; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <h1>DataNexus Feedback &amp; Usage Dashboard</h1>
  <p class="note">DataNexus MCP · Sprint 1 · <a href="/api/summary">/api/summary</a></p>

  <!-- ── Agent status banner (gate requirement: shows FEEDBACK_AGENTS_ACTIVE + MCPIZE_ACTIVE) ── -->
  <div class="banner" id="agent-status-banner">
    <span>Agents: {agents_badge}</span>
    <span>MCPize: {mcpize_badge}</span>
    <span>Collector: {pause_badge}</span>
    <span>Alerts: {queue_stats['alerts_immediate_depth']}</span>
    <span>Queue: {queue_stats['feedback_queue_depth']}</span>
    <span class="ts">{ts}</span>
  </div>

  <!-- ══════════════════════════════════════════════════════════════
       Panel 1 — Feedback Intelligence
  ══════════════════════════════════════════════════════════════ -->
  <h2>Panel 1 — Feedback Intelligence</h2>
  <table>
    <thead><tr>
      <th>Tool</th><th>Total feedback</th><th>Bugs</th>
      <th>Improvements</th><th>Pending</th>
    </tr></thead>
    <tbody>{fb_rows}</tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════════
       Panel 2 — Usage & Adoption  (Section 12.8)
  ══════════════════════════════════════════════════════════════ -->
  <h2>Panel 2 — Usage &amp; Adoption</h2>
  <table>
    <thead><tr>
      <th>Tool</th><th>Calls today</th><th>Sessions today</th>
      <th>DAU 7d ▸</th><th>Error rate</th><th>Cache hit</th><th>p99 latency</th>
    </tr></thead>
    <tbody>{usage_rows}</tbody>
  </table>

  <!-- Top query patterns (privacy-safe: params_hash only) -->
  <h2>Top Query Patterns — params_hash (privacy-safe)</h2>
  <p class="note">Raw parameters are never stored. Aggregated by params_hash only.</p>
  <table>
    <thead><tr><th>Tool</th><th>Rank</th><th>params_hash</th><th>Calls</th></tr></thead>
    <tbody>{params_rows}</tbody>
  </table>

  <!-- Conversion panel -->
  <h2>MCPize Conversion Stats</h2>
  {conv_html}

  <!-- ══════════════════════════════════════════════════════════════
       Section 13 — Haiku Validation Architecture
  ══════════════════════════════════════════════════════════════ -->
  {s13_section}

</body>
</html>"""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Main dashboard — HTML with agent status banner (FEEDBACK_AGENTS_ACTIVE + MCPIZE_ACTIVE)."""
    feedback_tools = _get_feedback_stats()
    queue_stats    = _get_queue_stats()
    usage_tools    = get_usage_summary()
    conv_stats     = get_conversion_stats()
    s13_stats      = _get_s13_stats()
    html           = _build_html(feedback_tools, queue_stats, usage_tools, conv_stats, s13_stats=s13_stats)
    return HTMLResponse(content=html, status_code=200)


@app.get("/api/summary")
async def api_summary() -> JSONResponse:
    """
    JSON summary with 'summary' and 'tools' keys.

    summary  — totals, agent state, MCPIZE_ACTIVE, queue depths
    tools    — per-tool feedback + usage stats merged
    """
    feedback_tools = _get_feedback_stats()
    queue_stats    = _get_queue_stats()
    usage_tools    = get_usage_summary()
    conv_stats     = get_conversion_stats()
    s13_stats      = _get_s13_stats()

    # Merge feedback + usage per tool
    all_tool_ids = sorted(set(feedback_tools) | set(usage_tools))
    merged: dict[str, Any] = {}
    for tid in all_tool_ids:
        merged[tid] = {
            **(feedback_tools.get(tid) or {}),
            **(usage_tools.get(tid)    or {}),
        }

    return JSONResponse({
        "summary": {
            "total_tools":              len(all_tool_ids),
            "feedback_agents_active":   FEEDBACK_AGENTS_ACTIVE,
            "mcpize_active":            _payment_cfg.MCPIZE_ACTIVE,
            "alerts_immediate_depth":   queue_stats["alerts_immediate_depth"],
            "feedback_queue_depth":     queue_stats["feedback_queue_depth"],
            "collector_paused":         queue_stats["collector_paused"],
            "conversion":               conv_stats,
            # ── Section 13 keys ───────────────────────────────────────────────
            "haiku_calls_today":        s13_stats["haiku_calls_today"],
            "haiku_daily_limit":        HAIKU_MAX_CALLS_PER_DAY,
            "pending_github_issues":    s13_stats["pending_github_issues"],
            "digest_available":         s13_stats["digest_available"],
            # ─────────────────────────────────────────────────────────────────
            "generated_at":             datetime.now(timezone.utc).isoformat(),
        },
        "tools": merged,
    })


@app.get("/api/feedback")
async def api_feedback() -> JSONResponse:
    """Recent feedback records — last 50 per tool."""
    r       = _get_redis()
    results = {}

    for tool_id in sorted(FEEDBACK_ENABLED_TOOLS):
        records = []
        if r:
            try:
                rids = r.zrevrange(key_feedback_list(tool_id), 0, 49)
                for rid in rids:
                    raw = r.hget(key_feedback(tool_id, rid), "data")
                    if raw:
                        try:
                            records.append(json.loads(raw))
                        except Exception:
                            pass
            except Exception:
                pass
        results[tool_id] = records

    return JSONResponse({"feedback": results})


@app.get("/api/health")
async def api_health() -> JSONResponse:
    """Service health check."""
    r        = _get_redis()
    redis_ok = False
    if r:
        try:
            r.ping()
            redis_ok = True
        except Exception:
            pass

    return JSONResponse({
        "status":                  "ok",
        "redis":                   "connected" if redis_ok else "unavailable",
        "feedback_agents_active":  FEEDBACK_AGENTS_ACTIVE,
        "mcpize_active":           _payment_cfg.MCPIZE_ACTIVE,
        "ts":                      datetime.now(timezone.utc).isoformat(),
    })


# ── Dev entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run("feedback.dashboard.server:app", host="0.0.0.0", port=_PORT, reload=False)
