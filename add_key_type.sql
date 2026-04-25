-- =============================================================================
-- WrapSec — Add key_type to api_keys
-- Run after wrapsec_db_fix_final.sql and add_severity.sql
-- =============================================================================

-- STEP 1 — Add key_type column
-- Default 'live' so ALL existing keys remain unaffected
ALTER TABLE api_keys
ADD COLUMN key_type VARCHAR(20) NOT NULL DEFAULT 'live';

-- STEP 2 — Add check constraint — only valid types allowed
ALTER TABLE api_keys
ADD CONSTRAINT ck_api_keys_key_type
CHECK (key_type IN ('live', 'trial', 'admin'));

-- STEP 3 — Index for fast lookup by type
CREATE INDEX ix_api_keys_key_type ON api_keys (key_type);

-- STEP 4 — Verify
SELECT key_type, COUNT(*) AS count
FROM api_keys
GROUP BY key_type;

SELECT conname, pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE conname = 'ck_api_keys_key_type';
