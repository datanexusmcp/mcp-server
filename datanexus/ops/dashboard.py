"""
DataNexus operator dashboard — FastAPI app.

Serves on http://127.0.0.1:8101/ops/dashboard (localhost only).
Reads metrics from Redis and PostgreSQL; never mutates data.

Endpoints:
  GET /ops/dashboard          — full HTML dashboard
  GET /ops/api/metrics        — JSON metrics snapshot (same data, for fetch())
  GET /ops/health             — {"ok": true}

The dashboard auto-refreshes every 15 seconds via JavaScript fetch().
"""

import logging

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from datanexus.ops.metrics import get_all_metrics

logger = logging.getLogger("datanexus.ops.dashboard")

# ---------------------------------------------------------------------------
# Redis client — separate pool from the MCP billing path so the dashboard
# never shares state with the billing event loop (important in threaded mode).
# ---------------------------------------------------------------------------

_dashboard_redis = None


async def _get_redis():
    global _dashboard_redis
    if _dashboard_redis is not None:
        return _dashboard_redis
    try:
        import redis.asyncio as aioredis
        from datanexus.config import REDIS_URL
        _dashboard_redis = aioredis.from_url(
            REDIS_URL, decode_responses=True, socket_connect_timeout=2
        )
        await _dashboard_redis.ping()
        logger.info("Dashboard Redis connected at %s", REDIS_URL)
    except Exception as exc:
        logger.warning("Dashboard Redis unavailable: %s", exc)
        _dashboard_redis = None
    return _dashboard_redis


# ---------------------------------------------------------------------------
# HTML — self-contained, no external CDN dependencies
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DataNexus Ops</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:      #0f1117;
    --surface: #1a1d27;
    --border:  #2a2d3a;
    --text:    #e2e8f0;
    --muted:   #8892a4;
    --accent:  #6366f1;
    --green:   #22c55e;
    --amber:   #f59e0b;
    --red:     #ef4444;
    --mono:    'JetBrains Mono', 'Fira Code', monospace;
  }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif;
         font-size: 14px; line-height: 1.5; }

  /* ── header ── */
  header { display: flex; align-items: center; justify-content: space-between;
           padding: 16px 24px; border-bottom: 1px solid var(--border);
           background: var(--surface); }
  header h1 { font-size: 18px; font-weight: 600; letter-spacing: -.3px; }
  header h1 span { color: var(--accent); }
  .meta { font-size: 12px; color: var(--muted); display: flex; gap: 16px; align-items: center; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green);
         animation: pulse 2s infinite; display: inline-block; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  /* ── layout ── */
  main { max-width: 1280px; margin: 0 auto; padding: 24px; }

  /* ── cards ── */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 16px; margin-bottom: 28px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
          padding: 18px 20px; }
  .card .label { font-size: 11px; font-weight: 500; color: var(--muted);
                 text-transform: uppercase; letter-spacing: .8px; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: 700; font-family: var(--mono);
                 line-height: 1; }
  .card .sub   { font-size: 11px; color: var(--muted); margin-top: 4px; }

  /* ── section ── */
  section { background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 20px; margin-bottom: 24px; }
  section h2 { font-size: 13px; font-weight: 600; text-transform: uppercase;
               letter-spacing: .6px; color: var(--muted); margin-bottom: 16px; }

  /* ── table ── */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { text-align: left; padding: 8px 12px; font-weight: 500; color: var(--muted);
             border-bottom: 1px solid var(--border); font-size: 11px;
             text-transform: uppercase; letter-spacing: .5px; white-space: nowrap; }
  tbody tr { border-bottom: 1px solid var(--border); }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(99,102,241,.06); }
  tbody td { padding: 10px 12px; font-family: var(--mono); }
  .tool-badge { display: inline-block; background: rgba(99,102,241,.15);
                color: var(--accent); border-radius: 4px; padding: 2px 7px;
                font-size: 12px; font-weight: 600; }
  .bar-wrap { display: flex; align-items: center; gap: 8px; }
  .bar { height: 6px; border-radius: 3px; background: var(--border); flex: 1; max-width: 80px; }
  .bar-fill { height: 6px; border-radius: 3px; background: var(--green); transition: width .4s; }
  .bar-fill.warn { background: var(--amber); }
  .bar-fill.bad  { background: var(--red); }
  .num { text-align: right; }
  .pct { min-width: 42px; text-align: right; font-size: 12px; color: var(--muted); }
  .zero { color: var(--border); }

  /* ── feed ── */
  .feed-list { max-height: 360px; overflow-y: auto; display: flex;
               flex-direction: column; gap: 4px; }
  .feed-item { display: flex; align-items: center; gap: 10px; padding: 7px 10px;
               background: var(--bg); border-radius: 5px; font-family: var(--mono);
               font-size: 12px; }
  .feed-tool { flex-shrink: 0; min-width: 36px; text-align: center; }
  .feed-session { color: var(--muted); flex-shrink: 0; min-width: 76px; }
  .feed-ts { color: var(--muted); font-size: 11px; margin-left: auto; flex-shrink: 0; }
  .feed-empty { color: var(--muted); font-size: 13px; padding: 12px 0; text-align: center; }

  /* ── upstream health ── */
  .upstream-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                   gap: 10px; }
  .upstream-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
                   background: var(--bg); border-radius: 6px; border: 1px solid var(--border); }
  .upstream-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .upstream-dot.pass     { background: var(--green); }
  .upstream-dot.fail     { background: var(--red); }
  .upstream-dot.degraded { background: var(--amber); }
  .upstream-dot.skip     { background: var(--muted); }
  .upstream-dot.unknown  { background: var(--border); }
  .upstream-info { flex: 1; min-width: 0; }
  .upstream-name { font-size: 12px; font-weight: 600; font-family: var(--mono);
                   white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .upstream-meta { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .upstream-badge { font-size: 10px; font-weight: 600; letter-spacing: .5px;
                    padding: 1px 5px; border-radius: 3px; flex-shrink: 0; }
  .upstream-badge.pass     { background: rgba(34,197,94,.15); color: var(--green); }
  .upstream-badge.fail     { background: rgba(239,68,68,.15);  color: var(--red); }
  .upstream-badge.degraded { background: rgba(245,158,11,.15); color: var(--amber); }
  .upstream-badge.skip     { background: rgba(136,146,164,.12); color: var(--muted); }
  .upstream-badge.unknown  { background: var(--border); color: var(--muted); }
  .upstream-empty { color: var(--muted); font-size: 13px; padding: 12px 0; text-align: center; }

  /* ── misc ── */
  .spinner { display: inline-block; width: 14px; height: 14px;
             border: 2px solid var(--border); border-top-color: var(--accent);
             border-radius: 50%; animation: spin .7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .error-notice { color: var(--amber); font-size: 12px; padding: 12px 0; }
</style>
</head>
<body>
<header>
  <h1>Data<span>Nexus</span> Ops</h1>
  <div class="meta">
    <span><span class="dot"></span> live</span>
    <span id="refresh-label">refreshing&hellip;</span>
    <span id="last-updated"></span>
  </div>
</header>
<main>

  <!-- Summary cards -->
  <div class="cards">
    <div class="card">
      <div class="label">Calls Today</div>
      <div class="value" id="c-calls">—</div>
      <div class="sub">all tools</div>
    </div>
    <div class="card">
      <div class="label">Sessions Today</div>
      <div class="value" id="c-sessions">—</div>
      <div class="sub">unique IDs</div>
    </div>
    <div class="card">
      <div class="label">Repeat Sessions</div>
      <div class="value" id="c-repeat">—</div>
      <div class="sub">2+ days in last 7d</div>
    </div>
    <div class="card">
      <div class="label">Cache Hit Rate</div>
      <div class="value" id="c-hitrate">—</div>
      <div class="sub" id="c-hitrate-sub">all tools combined</div>
    </div>
    <div class="card">
      <div class="label">Grandfathered</div>
      <div class="value" id="c-grandfathered">—</div>
      <div class="sub">free-tier sessions</div>
    </div>
  </div>

  <!-- Per-tool metrics table -->
  <section>
    <h2>Tool Metrics — <span id="date-label" style="font-style:normal;color:var(--text)"></span></h2>
    <table>
      <thead>
        <tr>
          <th>Tool</th>
          <th class="num">Calls</th>
          <th class="num">Sessions</th>
          <th class="num">Hits</th>
          <th class="num">Misses</th>
          <th>Hit Rate</th>
        </tr>
      </thead>
      <tbody id="tool-tbody">
        <tr><td colspan="6" style="padding:20px;color:var(--muted);text-align:center">
          <span class="spinner"></span></td></tr>
      </tbody>
    </table>
  </section>

  <!-- Live feed -->
  <section>
    <h2>Live Feed <span style="font-weight:400;color:var(--muted)">(last 50 calls)</span></h2>
    <div class="feed-list" id="feed-list">
      <div class="feed-empty"><span class="spinner"></span></div>
    </div>
  </section>

  <!-- Upstream Health -->
  <section>
    <h2>Upstream Health <span style="font-weight:400;color:var(--muted)" id="canary-checked-at"></span></h2>
    <div class="upstream-grid" id="upstream-grid">
      <div class="upstream-empty"><span class="spinner"></span></div>
    </div>
  </section>

</main>
<script>
const REFRESH_MS = 15_000;
let timer = null;

function fmt(n) { return n == null ? '—' : Number(n).toLocaleString(); }
function pct(r) { return r == null ? '—' : (r * 100).toFixed(1) + '%'; }

function barClass(rate) {
  if (rate == null) return '';
  if (rate >= 0.7) return '';
  if (rate >= 0.4) return 'warn';
  return 'bad';
}

function hitRateCell(hits, misses, rate) {
  if (rate == null) return '<td>—</td>';
  const w = Math.round(rate * 80);
  const cls = barClass(rate);
  return `<td>
    <div class="bar-wrap">
      <div class="bar"><div class="bar-fill ${cls}" style="width:${w}px"></div></div>
      <span class="pct">${pct(rate)}</span>
    </div>
  </td>`;
}

function renderTools(tools) {
  const tbody = document.getElementById('tool-tbody');
  if (!tools || !tools.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="error-notice" style="text-align:center;padding:16px">No data yet — make some tool calls to populate metrics.</td></tr>';
    return;
  }
  tbody.innerHTML = tools.map(t => {
    const noActivity = t.calls_today === 0 && t.cache_hits === 0 && t.cache_misses === 0;
    return `<tr>
      <td><span class="tool-badge">${t.tool_id}</span></td>
      <td class="num ${t.calls_today === 0 ? 'zero' : ''}">${fmt(t.calls_today)}</td>
      <td class="num ${t.sessions_today === 0 ? 'zero' : ''}">${fmt(t.sessions_today)}</td>
      <td class="num ${t.cache_hits === 0 ? 'zero' : ''}">${fmt(t.cache_hits)}</td>
      <td class="num ${t.cache_misses === 0 ? 'zero' : ''}">${fmt(t.cache_misses)}</td>
      ${hitRateCell(t.cache_hits, t.cache_misses, t.hit_rate)}
    </tr>`;
  }).join('');
}

function renderUpstreamHealth(items) {
  const el = document.getElementById('upstream-grid');
  if (!items || !items.length) {
    el.innerHTML = '<div class="upstream-empty">No canary data yet — canary runs hourly.</div>';
    return;
  }
  // Show most-recent checked_at across all items
  const latest = items.reduce((a, b) => (a.checked_at > b.checked_at ? a : b), items[0]);
  const ts = latest.checked_at ? latest.checked_at.replace('T', ' ').slice(0, 19) + 'Z' : '';
  document.getElementById('canary-checked-at').textContent = ts ? '— last run ' + ts : '';

  el.innerHTML = items.map(item => {
    const cls  = (item.status || 'unknown').toLowerCase();
    const lat  = item.latency_ms > 0 ? item.latency_ms + 'ms' : '';
    const err  = item.error ? ' · ' + item.error.slice(0, 60) : '';
    return `<div class="upstream-item">
      <div class="upstream-dot ${cls}"></div>
      <div class="upstream-info">
        <div class="upstream-name">${item.source}</div>
        <div class="upstream-meta">${item.tool_id}${lat ? ' · ' + lat : ''}${err}</div>
      </div>
      <span class="upstream-badge ${cls}">${item.status}</span>
    </div>`;
  }).join('');
}

function renderFeed(entries) {
  const el = document.getElementById('feed-list');
  if (!entries || !entries.length) {
    el.innerHTML = '<div class="feed-empty">No activity yet.</div>';
    return;
  }
  el.innerHTML = entries.map(e => {
    const ts = e.ts ? e.ts.replace('T', ' ').slice(0, 19) + 'Z' : '';
    return `<div class="feed-item">
      <span class="feed-tool"><span class="tool-badge">${e.tool || '?'}</span></span>
      <span class="feed-session">sid:${e.session || '?'}</span>
      <span style="color:var(--muted);font-size:11px">${e.params_hash || ''}</span>
      <span class="feed-ts">${ts}</span>
    </div>`;
  }).join('');
}

async function refresh() {
  document.getElementById('refresh-label').textContent = 'fetching…';
  try {
    const res = await fetch('/ops/api/metrics');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const d = await res.json();
    const t = d.totals || {};

    // Cards
    document.getElementById('c-calls').textContent     = fmt(t.calls_today);
    document.getElementById('c-sessions').textContent  = fmt(t.sessions_today);
    document.getElementById('c-repeat').textContent    = fmt(t.repeat_sessions_7d);
    document.getElementById('c-hitrate').textContent   =
      t.avg_hit_rate != null ? pct(t.avg_hit_rate) : '—';
    const gf = t.grandfathered_sessions;
    document.getElementById('c-grandfathered').textContent =
      gf === -1 ? 'all' : fmt(gf);

    // Date label
    document.getElementById('date-label').textContent = d.date || '';

    // Table + feed + upstream health
    renderTools(d.tools || []);
    renderFeed(d.feed || []);
    renderUpstreamHealth(d.upstream_health || []);

    const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z';
    document.getElementById('last-updated').textContent = 'updated ' + now;
    document.getElementById('refresh-label').textContent = 'auto-refresh 15s';
  } catch (err) {
    document.getElementById('refresh-label').textContent = 'error — retrying';
    console.error('Dashboard refresh failed:', err);
  }
  timer = setTimeout(refresh, REFRESH_MS);
}

refresh();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------

def create_dashboard_app() -> FastAPI:
    app = FastAPI(title="DataNexus Ops", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/ops/health")
    async def health():
        return {"ok": True}

    @app.get("/ops/api/metrics")
    async def metrics_api():
        r = await _get_redis()
        if r is None:
            return JSONResponse(
                status_code=503,
                content={"error": "Redis unavailable — metrics not accessible"},
            )
        data = await get_all_metrics(r)
        return JSONResponse(content=data)

    @app.get("/ops/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return HTMLResponse(content=_DASHBOARD_HTML)

    return app
