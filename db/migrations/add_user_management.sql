-- ═══════════════════════════════════════════════════════════════════════════
-- WrapSec User Management Migration v1
-- Creates:   admin_events, auth_events
-- Modifies:  users (ck_users_dept_required constraint — both directions)
--
-- Idempotent — safe to run multiple times.
-- Run AFTER add_users.sql.
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Fix ck_users_dept_required (both directions) ──────────────────────────────
--
-- Old constraint: CHECK (role = 'ADMIN' OR dept_id IS NOT NULL)
--   Only enforces non-ADMIN must have dept_id.
--   Does NOT enforce ADMIN must have dept_id = NULL.
--
-- New constraint: CHECK ((role = 'ADMIN' AND dept_id IS NULL) OR (role != 'ADMIN' AND dept_id IS NOT NULL))
--   Enforces both directions:
--     role = ADMIN     → dept_id MUST be NULL
--     role != ADMIN    → dept_id MUST NOT be NULL

DO $$
BEGIN
    -- Drop old single-direction constraint
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_users_dept_required' AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users DROP CONSTRAINT ck_users_dept_required;
    END IF;

    -- Add new bidirectional constraint
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_users_dept_required_v2' AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT ck_users_dept_required_v2
            CHECK (
                (role = 'ADMIN'  AND dept_id IS NULL)
                OR
                (role != 'ADMIN' AND dept_id IS NOT NULL)
            );
    END IF;
END $$;

-- ── admin_events ──────────────────────────────────────────────────────────────
--
-- Tracks all administrative actions: user create/update/deactivate,
-- role changes, password resets, dept changes.
--
-- dept_id rules:
--   Tenant-scoped actions (dept creation, settings) → dept_id = NULL
--   Dept-scoped actions (user management)           → dept_id = target user's dept_id AFTER update
--
-- action values are enum-controlled in application code:
--   user_created, user_deactivated, user_reactivated,
--   password_reset, role_changed, dept_changed
--
-- metadata rules:
--   role_changed  → {"old_role": "...", "new_role": "..."}
--   dept_changed  → {"old_dept_id": "...", "new_dept_id": "..."}
--   user_created  → {"role": "...", "dept_id": "..."}
--   Never store passwords, tokens, or secrets in metadata.

CREATE TABLE IF NOT EXISTS admin_events (
    id             UUID      PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID      NOT NULL REFERENCES tenants(id),
    dept_id        UUID      NULL,
    actor_user_id  UUID      NOT NULL REFERENCES users(id),
    target_user_id UUID      NULL     REFERENCES users(id),
    action         VARCHAR(50) NOT NULL,
    metadata       JSONB     NULL,
    ip_address     VARCHAR(45) NULL,
    user_agent     VARCHAR(500) NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_events_tenant_time
    ON admin_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_events_actor
    ON admin_events (actor_user_id);

CREATE INDEX IF NOT EXISTS idx_admin_events_target
    ON admin_events (target_user_id);

CREATE INDEX IF NOT EXISTS idx_admin_events_dept
    ON admin_events (dept_id);

-- ── auth_events ───────────────────────────────────────────────────────────────
--
-- Tracks all authentication attempts: login success and failure.
-- Designed for future: brute-force detection, security analytics, alerting.
--
-- tenant_id is NULLABLE:
--   Known user   → set to user's tenant_id
--   Unknown user → NULL (user not found, cannot resolve tenant)
--   Never use fake or sentinel values for unknown tenant.
--
-- action values: login_success, login_failed
--
-- failure_reason values (enum-controlled in application code):
--   invalid_password, user_not_found, account_disabled,
--   account_inactive, token_expired
--
-- Logging model: non-blocking, best-effort.
--   Must use BackgroundTasks or separate DB session.
--   Must NOT use the same session as the login request.
--   Must NOT delay login response.

CREATE TABLE IF NOT EXISTS auth_events (
    id             UUID      PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID      NULL,
    user_id        UUID      NULL,
    action         VARCHAR(50) NOT NULL,
    success        BOOLEAN   NOT NULL,
    failure_reason VARCHAR(50) NULL,
    ip_address     VARCHAR(45) NULL,
    user_agent     VARCHAR(500) NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_events_tenant_time
    ON auth_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_user
    ON auth_events (user_id);

CREATE INDEX IF NOT EXISTS idx_auth_events_success
    ON auth_events (success);

CREATE INDEX IF NOT EXISTS idx_auth_events_ip
    ON auth_events (ip_address);
