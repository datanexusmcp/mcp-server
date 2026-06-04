-- migrate_call_type.sql
-- Adds call_type / is_organic columns to the usage table and backfills history.
--
-- Run on Hetzner:
--   docker compose exec postgres psql -U dn -d datanexus -f /app/datanexus/scripts/migrate_call_type.sql
--
-- Safe to re-run (all statements are idempotent via IF NOT EXISTS / DO NOTHING).

-- 1. Add columns ---------------------------------------------------------------
ALTER TABLE usage ADD COLUMN IF NOT EXISTS call_type  VARCHAR(20) DEFAULT 'unknown';
ALTER TABLE usage ADD COLUMN IF NOT EXISTS is_organic BOOLEAN     DEFAULT FALSE;

-- 2. Backfill: Glama (172.64.0.0/13 = 172.64.x – 172.71.x) -------------------
UPDATE usage
SET    call_type  = 'glama',
       is_organic = FALSE
WHERE  call_type = 'unknown'
  AND  client_ip IS NOT NULL
  AND  client_ip != 'unknown'
  AND  client_ip::inet <<= '172.64.0.0/13'::inet;

-- 3. Backfill: Claude.ai connector IPs (Anthropic 160.79.104.0/21) -------------
UPDATE usage
SET    call_type  = 'claude_ai',
       is_organic = TRUE
WHERE  call_type = 'unknown'
  AND  client_ip IS NOT NULL
  AND  client_ip != 'unknown'
  AND  client_ip::inet <<= '160.79.104.0/21'::inet;

-- 4. Backfill: smoke (is_smoke=true already set by DATANEXUS_SMOKE_RUN flag) ---
UPDATE usage
SET    call_type  = 'smoke',
       is_organic = FALSE
WHERE  call_type = 'unknown'
  AND  is_smoke  = TRUE;

-- 5. Backfill: unknown IP (not already classified) -----------------------------
UPDATE usage
SET    call_type  = 'unknown',
       is_organic = FALSE
WHERE  call_type = 'unknown'
  AND  (client_ip IS NULL OR client_ip = 'unknown');

-- 6. Backfill: everything remaining = organic ----------------------------------
UPDATE usage
SET    call_type  = 'organic',
       is_organic = TRUE
WHERE  call_type = 'unknown';

-- 7. Verify -------------------------------------------------------------------
SELECT call_type, count(*) AS n
FROM   usage
GROUP  BY call_type
ORDER  BY n DESC;
