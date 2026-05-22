-- datanexus/db/migrations/004_usage_instrumentation.sql
-- Applied manually on Hetzner 2026-05-22 before container restart.
-- Adds 6 columns + 3 indexes to the usage table so every tool call can be
-- recorded with real client IP, input params, outcome, latency, and smoke flag.

ALTER TABLE usage ADD COLUMN IF NOT EXISTS client_ip  text;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS tool_input jsonb;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS success    boolean DEFAULT true;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS error_msg  text;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS latency_ms integer;
ALTER TABLE usage ADD COLUMN IF NOT EXISTS is_smoke   boolean DEFAULT false;

CREATE INDEX IF NOT EXISTS usage_created_at_idx ON usage(created_at DESC);
CREATE INDEX IF NOT EXISTS usage_tool_id_idx    ON usage(tool_id);
CREATE INDEX IF NOT EXISTS usage_client_ip_idx  ON usage(client_ip);
