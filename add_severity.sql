-- =============================================================================
-- WrapSec — Add severity column to audit_logs
-- Run after wrapsec_db_fix_final.sql
-- =============================================================================

-- STEP 1 — Add severity column
ALTER TABLE audit_logs
ADD COLUMN severity VARCHAR(10) NULL;

-- STEP 2 — Backfill existing rows
-- Mirrors compute_severity() in domain/value_objects/severity.py
UPDATE audit_logs SET severity =
    CASE
        -- BLOCK decisions
        WHEN decision = 'BLOCK' AND (
            primary_reason LIKE '%_GUARDRAIL_BLOCK'
            OR risk_score >= 0.9
        ) THEN 'CRITICAL'
        WHEN decision = 'BLOCK' THEN 'HIGH'
        -- SYSTEM_ERROR (any decision)
        WHEN primary_reason = 'SYSTEM_ERROR' THEN 'HIGH'
        -- SANITIZE
        WHEN decision = 'SANITIZE' THEN 'MEDIUM'
        -- ALLOW
        ELSE 'LOW'
    END
WHERE severity IS NULL;

-- STEP 3 — Add index for SIEM/security tool queries
CREATE INDEX ix_audit_logs_severity
ON audit_logs (severity, created_at DESC);

-- STEP 4 — Verify
SELECT severity, COUNT(*) AS count
FROM audit_logs
GROUP BY severity
ORDER BY count DESC;
