#!/bin/bash
set -e

echo "Deploying DataNexus MCP to Hetzner..."

# Sync code to server
rsync -avz --exclude='.git' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.env' \
  . root@178.104.251.70:/app/datanexus/

# Deploy on server
ssh root@178.104.251.70 << 'ENDSSH'
  cd /app/datanexus
  docker compose pull
  docker compose build --no-cache
  docker compose up -d
  echo "Waiting for services..."
  sleep 10
  docker compose ps
ENDSSH

echo "Deploy complete."
echo "MCP endpoint: https://datanexusmcp.com/mcp"
echo "Dashboard: https://datanexusmcp.com/ops/dashboard"
