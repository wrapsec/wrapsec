-- WrapSec — Complete Database Schema
-- Generated from live database introspection on 2026-05-03
--
-- NOTE: As of v1.1.0 the schema is managed by Alembic. The authoritative
-- source is db/models.py + db/migrations/versions/. This file is kept as
-- a human-readable reference snapshot and is not used at runtime.
--
-- To bootstrap a fresh database use `alembic upgrade head` (also run
-- automatically on API startup via db.session.run_migrations).

-- ── Extension ────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── tenants ──────────────────────────────────────────────────────────────────

CREATE TABLE tenants (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug          VARCHAR(50)  NOT NULL,
    name          VARCHAR(100) NOT NULL,
    description   TEXT,
    global_policy JSONB        NOT NULL DEFAULT '{}',
    is_active     BOOLEAN      DEFAULT TRUE,
    contact_email VARCHAR(100),
    created_by    VARCHAR(100),
    created_at    TIMESTAMP    DEFAULT NOW(),
    CONSTRAINT tenants_slug_key UNIQUE (slug)
);

-- ── departments ───────────────────────────────────────────────────────────────

CREATE TABLE departments (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         NOT NULL REFERENCES tenants(id),
    slug            VARCHAR(50)  NOT NULL,
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    policy_override JSONB,
    is_active       BOOLEAN      DEFAULT TRUE,
    contact_email   VARCHAR(100),
    created_by      VARCHAR(100),
    created_at      TIMESTAMP    DEFAULT NOW(),
    CONSTRAINT departments_tenant_id_slug_key UNIQUE (tenant_id, slug),
    CONSTRAINT uq_departments_id_tenant       UNIQUE (id, tenant_id)
);

CREATE INDEX ix_dept_tenant ON departments (tenant_id);

-- ── applications ──────────────────────────────────────────────────────────────

CREATE TABLE applications (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID         NOT NULL REFERENCES tenants(id),
    dept_id             UUID         NOT NULL REFERENCES departments(id),
    slug                VARCHAR(50)  NOT NULL,
    name                VARCHAR(100) NOT NULL,
    description         TEXT,
    owner_name          VARCHAR(100),
    owner_email         VARCHAR(100),
    environment         VARCHAR(20)  DEFAULT 'production',
    metadata            JSONB,
    policy_override     JSONB,
    rate_limit_override JSONB,
    is_active           BOOLEAN      DEFAULT TRUE,
    created_at          TIMESTAMP    DEFAULT NOW(),
    CONSTRAINT applications_dept_id_slug_key UNIQUE (dept_id, slug)
);

CREATE INDEX ix_app_dept ON applications (dept_id);

-- ── api_keys ──────────────────────────────────────────────────────────────────

CREATE TABLE api_keys (
    id           UUID         PRIMARY KEY,
    key_id       VARCHAR(50)  NOT NULL,
    name         VARCHAR(100) NOT NULL,
    key_hash     VARCHAR(100) NOT NULL,
    is_admin     BOOLEAN      NOT NULL,
    revoked      BOOLEAN      NOT NULL,
    expires_at   TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at   TIMESTAMP    NOT NULL,
    tenant_id    UUID         NOT NULL REFERENCES tenants(id),
    dept_id      UUID         REFERENCES departments(id),
    app_id       UUID         REFERENCES applications(id),
    key_type     VARCHAR(20)  NOT NULL DEFAULT 'live',
    CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash),
    CONSTRAINT ck_api_keys_key_type  CHECK (key_type IN ('live', 'trial', 'admin'))
);

CREATE UNIQUE INDEX ix_api_keys_key_id  ON api_keys (key_id);
CREATE INDEX        ix_api_keys_key_type ON api_keys (key_type);
CREATE INDEX        ix_key_app           ON api_keys (app_id);

-- ── users ─────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id                    UUID         PRIMARY KEY,
    tenant_id             UUID         NOT NULL REFERENCES tenants(id),
    dept_id               UUID         REFERENCES departments(id),
    email                 VARCHAR(255) NOT NULL,
    password_hash         VARCHAR(255) NOT NULL,
    role                  VARCHAR(50)  NOT NULL,
    is_active             BOOLEAN      NOT NULL,
    force_password_change BOOLEAN      NOT NULL,
    token_version         INTEGER      NOT NULL,
    created_at            TIMESTAMP    NOT NULL,
    last_login_at         TIMESTAMP,
    CONSTRAINT ck_users_role CHECK (role IN ('ADMIN', 'DEVELOPER', 'VIEWER')),
    CONSTRAINT ck_users_dept_required_v2 CHECK (
        (role = 'ADMIN'  AND dept_id IS NULL) OR
        (role <> 'ADMIN' AND dept_id IS NOT NULL)
    ),
    CONSTRAINT fk_users_dept_tenant FOREIGN KEY (dept_id, tenant_id)
        REFERENCES departments(id, tenant_id),
    CONSTRAINT users_dept_id_fkey   FOREIGN KEY (dept_id)    REFERENCES departments(id),
    CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id)  REFERENCES tenants(id)
);

CREATE INDEX        ix_users_tenant    ON users (tenant_id);
CREATE INDEX        ix_users_dept      ON users (dept_id);
CREATE INDEX        ix_users_role      ON users (role);
CREATE INDEX        ix_users_role_active ON users (role, is_active);
CREATE UNIQUE INDEX ux_users_email_lower ON users (LOWER(email));

-- ── refresh_tokens ────────────────────────────────────────────────────────────

CREATE TABLE refresh_tokens (
    id            UUID        PRIMARY KEY,
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    VARCHAR(64) NOT NULL,
    token_version INTEGER     NOT NULL,
    expires_at    TIMESTAMP   NOT NULL,
    revoked_at    TIMESTAMP,
    created_at    TIMESTAMP   NOT NULL,
    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX ix_refresh_tokens_user    ON refresh_tokens (user_id);
CREATE INDEX ix_refresh_tokens_hash    ON refresh_tokens (token_hash);
CREATE INDEX ix_refresh_tokens_expires ON refresh_tokens (expires_at);
CREATE INDEX ix_refresh_active         ON refresh_tokens (user_id)
    WHERE revoked_at IS NULL;

-- ── settings ──────────────────────────────────────────────────────────────────

CREATE TABLE settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT         NOT NULL,
    updated_at TIMESTAMP    NOT NULL
);

-- ── audit_logs ────────────────────────────────────────────────────────────────

CREATE TABLE audit_logs (
    id                   UUID           PRIMARY KEY,
    trace_id             VARCHAR(50)    NOT NULL,
    decision             VARCHAR(20)    NOT NULL,
    risk_score           DOUBLE PRECISION NOT NULL,
    threats              JSONB          NOT NULL,
    input_hash           VARCHAR(100)   NOT NULL,
    detection_mode       VARCHAR(20)    NOT NULL,
    execution_mode       VARCHAR(20)    NOT NULL,
    llm_invoked          BOOLEAN        NOT NULL,
    latency_ms           DOUBLE PRECISION NOT NULL,
    tenant_id            VARCHAR(100),
    source               VARCHAR(100),
    user_id              VARCHAR(100),
    created_at           TIMESTAMP      NOT NULL,
    detection_scores     JSONB          DEFAULT '{}',
    guardrail_scores     JSONB          DEFAULT '{}',
    key_id               VARCHAR(50)    DEFAULT NULL,
    ip_address           VARCHAR(50)    DEFAULT NULL,
    user_agent           VARCHAR(255)   DEFAULT NULL,
    attribution_verified BOOLEAN        DEFAULT FALSE,
    app_id               VARCHAR(50)    DEFAULT NULL,
    dept_id              VARCHAR(50)    DEFAULT NULL,
    policy_source        VARCHAR(50)    DEFAULT NULL,
    primary_reason       VARCHAR(50)    DEFAULT NULL,
    confidence           DOUBLE PRECISION,
    confidence_band      VARCHAR(10)    DEFAULT NULL,
    input_length         INTEGER        DEFAULT 0,
    proxy_interaction_id UUID,
    severity             VARCHAR(10),
    principal_type       VARCHAR(20)    DEFAULT 'api_key'
);

CREATE UNIQUE INDEX ix_audit_logs_trace_id         ON audit_logs (trace_id);
CREATE INDEX        ix_audit_logs_tenant_id         ON audit_logs (tenant_id);
CREATE INDEX        ix_audit_logs_created_desc      ON audit_logs (created_at DESC);
CREATE INDEX        ix_audit_logs_decision          ON audit_logs (decision);
CREATE INDEX        ix_audit_logs_decision_created  ON audit_logs (decision, created_at);
CREATE INDEX        ix_audit_logs_exec_mode         ON audit_logs (execution_mode);
CREATE INDEX        ix_audit_logs_severity          ON audit_logs (severity, created_at DESC);
CREATE INDEX        ix_audit_logs_tenant_created    ON audit_logs (tenant_id, created_at);
CREATE INDEX        ix_audit_tenant_created         ON audit_logs (tenant_id, created_at);
CREATE INDEX        ix_audit_tenant_dept_time       ON audit_logs (tenant_id, dept_id, created_at DESC);
CREATE INDEX        ix_audit_key_created            ON audit_logs (key_id, created_at);
CREATE INDEX        ix_audit_dept_created           ON audit_logs (dept_id, created_at);
CREATE INDEX        ix_audit_app_created            ON audit_logs (app_id, created_at);
CREATE INDEX        ix_audit_principal_type         ON audit_logs (principal_type);

-- ── proxy_interactions ────────────────────────────────────────────────────────

CREATE TABLE proxy_interactions (
    id                    UUID            PRIMARY KEY,
    trace_id              VARCHAR(64)     NOT NULL,
    key_id                VARCHAR(50),
    user_id               VARCHAR(256),
    input_raw             TEXT,
    input_sanitized       TEXT,
    input_decision        VARCHAR(16)     NOT NULL,
    input_primary_reason  VARCHAR(64)     NOT NULL,
    input_confidence      DOUBLE PRECISION NOT NULL,
    input_threats         JSON,
    input_attack_type     VARCHAR(64),
    provider              VARCHAR(32),
    model                 VARCHAR(128),
    provider_latency_ms   INTEGER,
    execution_status      VARCHAR(32)     NOT NULL,
    output_raw            TEXT,
    output_sanitized      TEXT,
    output_decision       VARCHAR(16),
    output_primary_reason VARCHAR(64),
    output_confidence     DOUBLE PRECISION,
    output_threats        JSON,
    behavior_flag         VARCHAR(32),
    output_flags          JSON,
    total_latency_ms      INTEGER         NOT NULL,
    created_at            TIMESTAMP       NOT NULL
);

CREATE UNIQUE INDEX ix_proxy_interactions_trace_id ON proxy_interactions (trace_id);
CREATE INDEX        ix_proxy_int_key_id             ON proxy_interactions (key_id);
CREATE INDEX        ix_proxy_int_created            ON proxy_interactions (created_at);
CREATE INDEX        ix_proxy_int_exec_status        ON proxy_interactions (execution_status);
CREATE INDEX        ix_proxy_int_attack_type        ON proxy_interactions (input_attack_type);
CREATE INDEX        ix_proxy_key_time               ON proxy_interactions (key_id, created_at DESC);

-- ── proxy_provider_configs ────────────────────────────────────────────────────

CREATE TABLE proxy_provider_configs (
    id                   UUID        PRIMARY KEY,
    key_id               VARCHAR(50) NOT NULL,
    provider             VARCHAR(32) NOT NULL,
    base_url             TEXT        NOT NULL,
    provider_api_key_enc TEXT,
    default_model        VARCHAR(128) NOT NULL,
    timeout_seconds      INTEGER     NOT NULL,
    created_at           TIMESTAMP   NOT NULL,
    updated_at           TIMESTAMP   NOT NULL
);

CREATE UNIQUE INDEX ix_proxy_provider_configs_key_id ON proxy_provider_configs (key_id);

-- ── admin_events ──────────────────────────────────────────────────────────────

CREATE TABLE admin_events (
    id             UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID         NOT NULL REFERENCES tenants(id),
    dept_id        UUID,
    actor_user_id  UUID         NOT NULL REFERENCES users(id),
    target_user_id UUID         REFERENCES users(id),
    action         VARCHAR(50)  NOT NULL,
    metadata       JSONB,
    ip_address     VARCHAR(45),
    user_agent     VARCHAR(500),
    created_at     TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admin_events_tenant_time ON admin_events (tenant_id, created_at DESC);
CREATE INDEX idx_admin_events_actor       ON admin_events (actor_user_id);
CREATE INDEX idx_admin_events_target      ON admin_events (target_user_id);
CREATE INDEX idx_admin_events_dept        ON admin_events (dept_id);

-- ── auth_events ───────────────────────────────────────────────────────────────

CREATE TABLE auth_events (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID,
    user_id        UUID,
    action         VARCHAR(50) NOT NULL,
    success        BOOLEAN     NOT NULL,
    failure_reason VARCHAR(50),
    ip_address     VARCHAR(45),
    user_agent     VARCHAR(500),
    created_at     TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_events_tenant_time ON auth_events (tenant_id, created_at DESC);
CREATE INDEX idx_auth_events_user        ON auth_events (user_id);
CREATE INDEX idx_auth_events_success     ON auth_events (success);
CREATE INDEX idx_auth_events_ip          ON auth_events (ip_address);

-- ── account_lockouts ──────────────────────────────────────────────────────────

CREATE TABLE account_lockouts (
    id              UUID        PRIMARY KEY,
    email           VARCHAR(255) NOT NULL,
    failed_attempts INTEGER     NOT NULL,
    locked_until    TIMESTAMP,
    last_failed_at  TIMESTAMP,
    created_at      TIMESTAMP   NOT NULL,
    updated_at      TIMESTAMP   NOT NULL,
    CONSTRAINT account_lockouts_email_key UNIQUE (email)
);

CREATE INDEX idx_account_lockouts_email        ON account_lockouts (email);
CREATE INDEX idx_account_lockouts_locked_until ON account_lockouts (locked_until);

-- ── Seed: default tenant ──────────────────────────────────────────────────────
-- Application bootstrap creates the admin user on first startup.
-- This seed creates the required default tenant so bootstrap can find it.

INSERT INTO tenants (slug, name, description, global_policy, is_active)
VALUES ('default', 'Default', 'Default tenant', '{}', TRUE)
ON CONFLICT (slug) DO NOTHING;
