# Task: Add Persistent Caddy Access Logging

## Context
Read /Users/sangeetajagadeesh/OmSaiRam/DATANEXUS_CONTEXT_MAY22.md for full
project context before starting.

## Problem
Caddy only logs warn-level entries. Successful requests are invisible —
real client IPs are lost. 66.132.x.x hit the server on May 22 but left
no trace in Caddy logs because all their POSTs succeeded.

## Goal
Add a structured JSON access log to Caddy so every request (success or
failure) is logged with the real client IP to a persistent file.

## Changes Required

### 1. Caddyfile
File: /app/datanexus/Caddyfile (local repo copy)

Add inside the `datanexusmcp.com { }` block, before the @blocked matcher:

    log {
      output file /var/log/caddy/access.log {
        roll_size 50mb
        roll_keep 5
      }
      format json
    }

### 2. docker-compose.yml
Under the `caddy:` service, add /var/log/caddy as a volume mount so the
log file persists outside the container:

    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - /var/log/caddy:/var/log/caddy   ← ADD THIS LINE

(Keep all existing volume entries — only add the new line.)

### 3. Create log directory on Hetzner
Before restarting, ensure the directory exists on the host:

    ssh datanexus "mkdir -p /var/log/caddy"

## Deploy Steps
1. Edit Caddyfile and docker-compose.yml locally
2. git add Caddyfile docker-compose.yml
3. git commit -m "Add Caddy access log — persistent JSON per-request logging"
4. git push
5. ssh datanexus
6. cd /app/datanexus
7. mkdir -p /var/log/caddy
8. git pull
9. docker compose up -d caddy   # restart caddy only, no full rebuild needed

## Verify
After restart, make one test request from your Mac:
    curl -s https://datanexusmcp.com/mcp -X POST \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"initialize","id":1}'

Then on Hetzner:
    tail -5 /var/log/caddy/access.log

Must show a JSON line with your Mac's real IP in the `request.remote_ip`
field.

Also verify Caddy still works:
    curl -s https://datanexusmcp.com/mcp | head -1
    docker compose ps   # all containers Up

## Success Criteria
- /var/log/caddy/access.log exists and is being written to
- Every request appears as a JSON line with real client IP
- docker compose logs caddy still works normally
- No disruption to live traffic (caddy restart is < 1 second)

## Do NOT
- Do not change any other Caddyfile directives
- Do not touch datanexus-mcp or redis services
- Do not remove existing caddy volumes
- Do not deploy mid-session without confirming containers are Up after restart
