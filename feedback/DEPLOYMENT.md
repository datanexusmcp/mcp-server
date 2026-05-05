# DataNexus Feedback System — Deployment Guide

**Spec:** DataNexus_MCP_Spec_v7_3.docx Section 8 / Section 11.6 Step 14  
**Server:** Hetzner CAX11 — `datanexusmcp.com` / `178.104.251.70`  
**Last updated:** 2026-05-01

---

## 1. Environment Variables

All variables go in `/app/.env` on the Hetzner server. Never commit secrets.

```bash
# ── Infrastructure ────────────────────────────────────────────────────────────
DATANEXUS_REDIS_URL=redis://localhost:6379
DATANEXUS_DB_URL=postgresql://datanexus:PASSWORD@localhost:5432/datanexus

# ── Feedback system ───────────────────────────────────────────────────────────

# Master switch — set to 'true' to activate AI classification agents.
# Leave unset (or 'false') during free tier; activate when agents are ready.
FEEDBACK_AGENTS_ACTIVE=false

# ntfy.sh push notifications for bug alerts
NTFY_TOPIC=datanexus-bugs
NTFY_BASE_URL=https://ntfy.sh
# NTFY_TOKEN=your_ntfy_token_here   # optional — for private ntfy.sh channels

# Dashboard port (default: 8101)
# DASHBOARD_PORT=8101

# NVD API key (optional — higher rate limit for T10 CVE lookups)
# DATANEXUS_NVD_API_KEY=your_nvd_key_here
```

---

## 2. Activation Procedure

### 2.1 Initial deploy (agents inactive)

```bash
# On Hetzner server
cd /app
git pull
pip install -r requirements.txt

# Start the MCP server (already running via systemd)
sudo systemctl restart datanexus-mcp

# Verify 12 tools registered
curl -s http://localhost:8000/ | python3 -m json.tool | grep -c '"name"'
# Expected: 12

# Start the feedback dashboard
sudo systemctl enable datanexus-feedback-dashboard
sudo systemctl start  datanexus-feedback-dashboard
curl -s http://localhost:8101/api/health | python3 -m json.tool
```

### 2.2 Activating AI agents (Phase 4 Step 9+)

```bash
# 1. Set the flag in .env
echo "FEEDBACK_AGENTS_ACTIVE=true" >> /app/.env

# 2. Restart the master agent
sudo systemctl restart datanexus-feedback-master

# 3. Verify workers started
sudo journalctl -u datanexus-feedback-master -n 20

# 4. Verify bug_listener is running
sudo systemctl status datanexus-feedback-bug-listener
```

---

## 3. systemd Service Files

### 3.1 MCP Server (`/etc/systemd/system/datanexus-mcp.service`)

```ini
[Unit]
Description=DataNexus MCP Server
After=network.target redis.service

[Service]
Type=simple
User=datanexus
WorkingDirectory=/app
EnvironmentFile=/app/.env
ExecStart=/app/venv/bin/python3 -m uvicorn datanexus.main:app \
    --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 3.2 Feedback Dashboard (`/etc/systemd/system/datanexus-feedback-dashboard.service`)

```ini
[Unit]
Description=DataNexus Feedback Dashboard
After=network.target redis.service datanexus-mcp.service

[Service]
Type=simple
User=datanexus
WorkingDirectory=/app
EnvironmentFile=/app/.env
ExecStart=/app/venv/bin/python3 -m uvicorn feedback.dashboard.server:app \
    --host 0.0.0.0 --port 8101 --workers 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 3.3 Bug Listener (`/etc/systemd/system/datanexus-feedback-bug-listener.service`)

```ini
[Unit]
Description=DataNexus Feedback Bug Listener (BLPOP daemon)
After=network.target redis.service

[Service]
Type=simple
User=datanexus
WorkingDirectory=/app
EnvironmentFile=/app/.env
ExecStart=/app/venv/bin/python3 -m feedback.agents.bug_listener
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 3.4 Feedback Master (`/etc/systemd/system/datanexus-feedback-master.service`)

```ini
[Unit]
Description=DataNexus Feedback Agent Master (spawns tool workers when active)
After=network.target redis.service

[Service]
Type=simple
User=datanexus
WorkingDirectory=/app
EnvironmentFile=/app/.env
ExecStart=/app/venv/bin/python3 -m feedback.agents.master
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Load all services

```bash
sudo systemctl daemon-reload
sudo systemctl enable datanexus-mcp
sudo systemctl enable datanexus-feedback-dashboard
sudo systemctl enable datanexus-feedback-bug-listener
sudo systemctl enable datanexus-feedback-master
```

---

## 4. Cron Entries

Add to `/etc/cron.d/datanexus`:

```cron
# Daily feedback digest — 06:00 UTC
0 6 * * * datanexus cd /app && /app/venv/bin/python3 -m feedback.cli.fb_control digest \
    >> /var/log/datanexus/digest.log 2>&1

# Weekly: purge dedup keys older than FEEDBACK_TTL (Redis handles via TTL, this is a sanity check)
0 3 * * 0 datanexus cd /app && /app/venv/bin/python3 -c \
    "from feedback.cli.fb_control import cli; cli(['status'])" \
    >> /var/log/datanexus/weekly_status.log 2>&1

# Upstream schema fingerprint check — every 6 hours
0 */6 * * * datanexus cd /app && /app/venv/bin/python3 -c \
    "from feedback.upstream_monitor import check_and_update_fingerprint; print('ok')" \
    >> /var/log/datanexus/schema_check.log 2>&1
```

---

## 5. ntfy.sh Setup

### 5.1 Create a topic

```bash
# Public topic (no auth required)
export NTFY_TOPIC=datanexus-bugs-YOURNAME   # make it hard to guess

# Subscribe on your phone:
#   iOS/Android: install ntfy app → subscribe to "datanexus-bugs-YOURNAME"

# Test the alert manually
curl -d "Test alert from DataNexus" https://ntfy.sh/datanexus-bugs-YOURNAME
```

### 5.2 Private channel (recommended for production)

```bash
# Create account at ntfy.sh, generate token
export NTFY_TOKEN=tk_yourtokenhere
export NTFY_BASE_URL=https://ntfy.sh

# Add to /app/.env
echo "NTFY_TOKEN=tk_yourtokenhere" >> /app/.env
echo "NTFY_TOPIC=datanexus-bugs" >> /app/.env
```

---

## 6. CLI Reference

All commands run from `/app` directory:

```bash
# Status summary
python3 -m feedback.cli.fb_control status

# Pause new feedback ingestion (maintenance)
python3 -m feedback.cli.fb_control pause

# Resume after pause
python3 -m feedback.cli.fb_control resume

# Today's digest
python3 -m feedback.cli.fb_control digest

# Flush the improvement-signal queue (irreversible — requires --confirm)
python3 -m feedback.cli.fb_control flush --confirm
```

---

## 7. Health Checks

```bash
# MCP server
curl -s http://localhost:8000/

# Feedback dashboard
curl -s http://localhost:8101/api/health

# Redis
redis-cli ping

# Bug listener status
sudo systemctl status datanexus-feedback-bug-listener

# Queue depths
python3 -m feedback.cli.fb_control status
```

---

## 8. Rollback Procedure

```bash
# 1. Pause the collector
python3 -m feedback.cli.fb_control pause

# 2. Stop services
sudo systemctl stop datanexus-feedback-master
sudo systemctl stop datanexus-feedback-bug-listener

# 3. Roll back code
cd /app && git checkout <previous-tag>
pip install -r requirements.txt

# 4. Restart
sudo systemctl start datanexus-mcp
sudo systemctl start datanexus-feedback-bug-listener

# 5. Resume collector
python3 -m feedback.cli.fb_control resume
```

---

## 9. Secret Rotation Schedule

| Secret | Rotation interval | Next due |
|--------|------------------|----------|
| `NTFY_TOKEN` | 90 days | 2026-08-01 |
| `DATANEXUS_NVD_API_KEY` | 90 days | 2026-08-01 |
| `POSTGRES_PASSWORD` | 90 days | 2026-08-01 |

---

*This file is the single deployment reference for the feedback system.  
Update it on every infrastructure change.*
