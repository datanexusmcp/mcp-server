-- datanexus/core/db_migrations/add_activation_events.sql
-- Additive only — no existing tables modified.
-- Run on Hetzner:
--   cd /app/datanexus && docker compose exec postgres \
--     psql -U dn datanexus -f /migrations/add_activation_events.sql

CREATE TABLE IF NOT EXISTS activation_events (
  id              SERIAL PRIMARY KEY,
  client_ip       TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  -- Values:
  -- 'first_call'    Level 1  — first ever tool call from this IP
  -- 'real_query'    Level 1b — non-example, non-test input
  -- 'multi_tool'    Level 2  — 3+ distinct tools in one 30-min session
  -- 'return_visit'  Level 3  — called tools on 2nd calendar day
  -- 'power_user'    Level 4  — 10+ calls in a rolling 7-day window
  tool_id         TEXT,
  session_id      TEXT,
  metadata        JSONB,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activation_client_ip   ON activation_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_activation_event_type  ON activation_events(event_type);
CREATE INDEX IF NOT EXISTS idx_activation_created_at  ON activation_events(created_at);
