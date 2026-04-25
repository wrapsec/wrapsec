-- ═══════════════════════════════════════════════════════════════════════════
-- WrapSec JWT Migration v1
-- Creates:   users, refresh_tokens
-- Modifies:  audit_logs (principal_type), api_keys (tenant_id NOT NULL)
--
-- Idempotent — safe to run multiple times.
-- Run BEFORE first startup with JWT enabled.
--
-- Isolation level assumption: PostgreSQL default READ COMMITTED.
-- SELECT FOR UPDATE in RefreshTokenRepository.get_by_hash() relies on this.
-- Do NOT change isolation level without reviewing refresh token rotation flow.
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Users ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id                    UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id             UUID    NOT NULL REFERENCES tenants(id),
    dept_id               UUID    REFERENCES departments(id),
    email                 VARCHAR(255) NOT NULL,
    password_hash         VARCHAR(255) NOT NULL,
    role                  VARCHAR(50)  NOT NULL DEFAULT 'DEVELOPER',
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    token_version         INT     NOT NULL DEFAULT 1,
    created_at            TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at         TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_tenant      ON users(tenant_id);
CREATE INDEX IF NOT EXISTS ix_users_dept        ON users(dept_id);
CREATE INDEX IF NOT EXISTS ix_users_role        ON users(role);
CREATE INDEX IF NOT EXISTS ix_users_role_active ON users(role, is_active);

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower
    ON users (LOWER(email));

-- ck_users_role
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_users_role' AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT ck_users_role
            CHECK (role IN ('ADMIN', 'DEVELOPER', 'VIEWER'));
    END IF;
END $$;

-- ck_users_dept_required
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_users_dept_required' AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT ck_users_dept_required
            CHECK (role = 'ADMIN' OR dept_id IS NOT NULL);
    END IF;
END $$;

-- ── dept_id ↔ tenant composite integrity (R6 fix) ────────────────────────────

-- uq_departments_id_tenant
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_departments_id_tenant' AND conrelid = 'departments'::regclass
    ) THEN
        ALTER TABLE departments
            ADD CONSTRAINT uq_departments_id_tenant
            UNIQUE (id, tenant_id);
    END IF;
END $$;

-- fk_users_dept_tenant
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_users_dept_tenant' AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT fk_users_dept_tenant
            FOREIGN KEY (dept_id, tenant_id)
            REFERENCES departments(id, tenant_id);
    END IF;
END $$;

-- ── Refresh tokens ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    VARCHAR(64) NOT NULL UNIQUE,
    token_version INT  NOT NULL DEFAULT 1,
    expires_at    TIMESTAMP NOT NULL,
    revoked_at    TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_hash    ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_expires ON refresh_tokens(expires_at);

CREATE INDEX IF NOT EXISTS ix_refresh_active
    ON refresh_tokens(user_id)
    WHERE revoked_at IS NULL;

-- ── Audit logs: principal attribution ────────────────────────────────────────

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS principal_type VARCHAR(20) DEFAULT 'api_key';

CREATE INDEX IF NOT EXISTS ix_audit_principal_type
    ON audit_logs(principal_type);

-- ── API keys: enforce tenant_id NOT NULL ──────────────────────────────────────

UPDATE api_keys
    SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default' LIMIT 1)
    WHERE tenant_id IS NULL;

ALTER TABLE api_keys ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS ck_api_keys_non_admin_tenant;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS ck_api_keys_tenant_required;
