#!/bin/bash
# start.sh — DataNexus MCP startup script
# Runs both the MCP server (port 8000) and feedback dashboard (port 8101)
set -e

echo "[start.sh] Starting DataNexus MCP services..."

# Start feedback dashboard in background (port 8101)
uvicorn feedback.dashboard.server:app \
  --host 0.0.0.0 \
  --port 8101 \
  --log-level info &
DASHBOARD_PID=$!
echo "[start.sh] Dashboard started (PID $DASHBOARD_PID) on :8101"

# Start MCP server in foreground (port 8000)
echo "[start.sh] Starting MCP server on :8000"
exec python -m datanexus.main
