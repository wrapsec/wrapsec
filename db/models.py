# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
from sqlalchemy import (
    Column, String, Float, Boolean,
    DateTime, Text, JSON, Integer, Index, ForeignKey,
    CheckConstraint, UniqueConstraint
)
from services.time import utc_now
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB


# JSONB on PostgreSQL (indexed, containment ops, jsonb_* functions), plain
# JSON on SQLite (no jsonb type). Every JSON-holding column uses this alias
# so the SQL layer matches the way we query these columns
# (jsonb_array_elements_text, cast(.., JSONB).contains(..), @>, ?, etc.).
# v1.2.3: introduced after testcontainers exposed drift between the model
# (was `JSON`) and the actual PG column (`jsonb` from a pre-baseline
# hand-alter) that had silently kept production working. Migration
# 0006_json_to_jsonb aligns any existing `json` columns to `jsonb`.
JSONVariant = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class TenantModel(Base):
    __tablename__ = "tenants"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug          = Column(String(50),  nullable=False, unique=True)
    name          = Column(String(100), nullable=False)
    description   = Column(Text,        nullable=True)
    global_policy = Column(JSONVariant,        nullable=False, default=dict)
    is_active     = Column(Boolean,     nullable=False, default=True)
    contact_email = Column(String(100), nullable=True)
    created_by    = Column(String(100), nullable=True)
    created_at    = Column(DateTime(timezone=True),    nullable=False, default=utc_now)
    # BCP-47 tag; NULL = inherit the system default. Validated against the
    # supported-locales allowlist before use (never trusted blindly).
    locale        = Column(String(35),  nullable=True)


class DepartmentModel(Base):
    __tablename__ = "departments"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id       = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    slug            = Column(String(50),  nullable=False)
    name            = Column(String(100), nullable=False)
    description     = Column(Text,        nullable=True)
    policy_override = Column(JSONVariant,        nullable=True,  default=None)
    is_active       = Column(Boolean,     nullable=False, default=True)
    contact_email   = Column(String(100), nullable=True)
    created_by      = Column(String(100), nullable=True)
    created_at      = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_dept_tenant", "tenant_id"),
        # A department slug is a stable per-tenant identifier (used in policy
        # resolution). Unique among ACTIVE departments only, so a slug frees up
        # when a department is deactivated (soft-deleted).
        Index("uq_dept_tenant_slug_active", "tenant_id", "slug",
              unique=True, postgresql_where="is_active"),
    )


class ApplicationModel(Base):
    __tablename__ = "applications"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id           = Column(UUID(as_uuid=True), ForeignKey("tenants.id"),    nullable=False)
    dept_id             = Column(UUID(as_uuid=True), ForeignKey("departments.id"), nullable=False)
    slug                = Column(String(50),  nullable=False)
    name                = Column(String(100), nullable=False)
    description         = Column(Text,        nullable=True)
    owner_name          = Column(String(100), nullable=True)
    owner_email         = Column(String(100), nullable=True)
    environment         = Column(String(20),  nullable=False, default="production")
    metadata_           = Column("metadata",  JSONVariant, nullable=True, default=None)
    policy_override     = Column(JSONVariant,        nullable=True,  default=None)
    rate_limit_override = Column(JSONVariant,        nullable=True,  default=None)
    is_active           = Column(Boolean,     nullable=False, default=True)
    created_at          = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_app_dept", "dept_id"),
        # Application slug is unique per tenant among ACTIVE applications.
        Index("uq_app_tenant_slug_active", "tenant_id", "slug",
              unique=True, postgresql_where="is_active"),
    )


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id       = Column(String(50),  nullable=False, unique=True, index=True)
    decision       = Column(String(20),  nullable=False, index=True)
    risk_score     = Column(Float,       nullable=False)
    threats        = Column(JSONVariant,        nullable=False, default=list)
    input_hash     = Column(String(100), nullable=False)
    detection_mode = Column(String(20),  nullable=False)
    execution_mode = Column(String(20),  nullable=False)
    llm_invoked    = Column(Boolean,     nullable=False, default=False)
    latency_ms     = Column(Float,       nullable=False)
    detection_scores   = Column(JSONVariant,    nullable=True)
    guardrail_scores   = Column(JSONVariant,    nullable=True)
    key_id             = Column(String(50),  nullable=True)
    ip_address         = Column(String(50),  nullable=True)
    user_agent         = Column(String(255), nullable=True)
    attribution_verified = Column(Boolean,   nullable=False, default=False)
    # String columns intentionally - no ForeignKey to preserve audit history after
    # entity deletion (tenant/dept/app can be deactivated or removed without losing logs).
    app_id         = Column(String(50),  nullable=True)
    dept_id        = Column(String(50),  nullable=True)
    tenant_id      = Column(String(50),  nullable=True)
    policy_source  = Column(String(50),  nullable=True)
    primary_reason = Column(String(50),  nullable=True)
    confidence      = Column(Float,      nullable=True)
    confidence_band = Column(String(10), nullable=True)
    source         = Column(String(100), nullable=True)
    user_id        = Column(String(100), nullable=True)
    input_length   = Column(Integer,     nullable=True,  default=0)
    proxy_interaction_id = Column(UUID(as_uuid=True), ForeignKey("proxy_interactions.id", ondelete="SET NULL"), nullable=True)
    severity       = Column(String(10),  nullable=True)
    principal_type = Column(String(20),  nullable=True,  default="api_key")
    model_version  = Column(String(50),  nullable=True)
    # v1.2.0 session tracking - caller-supplied opaque identifiers.
    # Validated in api/v1/schemas/request.py (max 200, [A-Za-z0-9_.:-]).
    session_id     = Column(String(200), nullable=True)
    turn_index     = Column(Integer,     nullable=True)
    run_id         = Column(String(200), nullable=True)
    # v1.7.0 input provenance (trust boundary): where the scanned text came from.
    # NOT NULL with a server default so every row carries an explicit source and
    # the engine/audit never see NULL. Values are the InputSource enum.
    input_source   = Column(String(32),  nullable=False, server_default="user_prompt")
    # v1.2.0 tamper-evident hash chain. SHA-256 hex = 64 chars.
    # Populated by the hash-chained audit writer; UPDATE blocked by trigger.
    record_hash    = Column(String(64),  nullable=True)
    prev_hash      = Column(String(64),  nullable=True)
    created_at     = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_audit_logs_decision_created", "decision",   "created_at"),
        Index("ix_audit_logs_tenant_created",   "tenant_id",  "created_at"),
        Index("ix_audit_tenant_dept_time",      "tenant_id",  "dept_id", "created_at"),
        Index("ix_audit_key_created",           "key_id",     "created_at"),
        Index("ix_audit_app_created",           "app_id",     "created_at"),
        Index("ix_audit_dept_created",          "dept_id",    "created_at"),
        Index("ix_audit_user_created",          "user_id",    "created_at"),
        Index("ix_audit_logs_exec_mode",        "execution_mode"),
        Index("ix_audit_logs_created_desc",     "created_at"),
        Index("ix_audit_principal_type",        "principal_type"),
        Index("ix_audit_session_created",       "session_id", "created_at"),
        Index("ix_audit_run_created",           "run_id",     "created_at"),
    )


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id       = Column(String(50),  nullable=False, unique=True, index=True)
    tenant_id    = Column(UUID(as_uuid=True), ForeignKey("tenants.id"),    nullable=False)
    dept_id      = Column(UUID(as_uuid=True), ForeignKey("departments.id"), nullable=True)
    app_id       = Column(UUID(as_uuid=True), ForeignKey("applications.id"), nullable=True)
    name         = Column(String(100), nullable=False)
    key_hash     = Column(String(100), nullable=False, unique=True)
    key_type     = Column(String(20),  nullable=False, default="live")
    is_admin     = Column(Boolean,     nullable=False, default=False)
    revoked      = Column(Boolean,     nullable=False, default=False)
    expires_at   = Column(DateTime(timezone=True),    nullable=True)
    last_used_at = Column(DateTime(timezone=True),    nullable=True)
    created_at   = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        # Only enforced in PostgreSQL (production). SQLite (used in tests) silently
        # skips this constraint - test scenarios that create invalid API key rows
        # will not be caught until the production schema is exercised.
        CheckConstraint(
            "is_admin = true OR (tenant_id IS NOT NULL AND dept_id IS NOT NULL)",
            name="ck_api_keys_non_admin_tenant",
            _create_rule=lambda ctx: ctx.dialect.name == "postgresql",
        ),
    )


class SettingsModel(Base):
    __tablename__ = "settings"

    key        = Column(String(100), primary_key=True)
    value      = Column(Text,        nullable=False)
    updated_at = Column(DateTime(timezone=True),    nullable=False, default=utc_now, onupdate=utc_now)


class ProxyProviderConfigModel(Base):
    __tablename__ = "proxy_provider_configs"

    id                   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id            = Column(String(50),  nullable=False, unique=True, index=True)
    provider             = Column(String(32),  nullable=False)
    base_url             = Column(Text,        nullable=False)
    provider_api_key_enc = Column(Text,        nullable=True)
    default_model        = Column(String(128), nullable=False)
    timeout_seconds      = Column(Integer,     nullable=False, default=60)
    created_at           = Column(DateTime(timezone=True),    nullable=False, default=utc_now)
    updated_at           = Column(DateTime(timezone=True),    nullable=False, default=utc_now,
                                  onupdate=utc_now)


class ProxyInteractionModel(Base):
    __tablename__ = "proxy_interactions"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id              = Column(String(64),  nullable=False, unique=True, index=True)
    key_id                = Column(String(50),  nullable=True)
    user_id               = Column(String(256), nullable=True)
    input_raw             = Column(Text,        nullable=True)
    input_sanitized       = Column(Text,        nullable=True)
    input_decision        = Column(String(16),  nullable=False)
    input_primary_reason  = Column(String(64),  nullable=False)
    input_confidence      = Column(Float,       nullable=False)
    input_threats         = Column(JSONVariant,        nullable=True,  default=list)
    input_attack_type     = Column(String(64),  nullable=True)
    provider              = Column(String(32),  nullable=True)
    model                 = Column(String(128), nullable=True)
    provider_latency_ms   = Column(Integer,     nullable=True)
    execution_status      = Column(String(32),  nullable=False)
    output_raw            = Column(Text,        nullable=True)
    output_sanitized      = Column(Text,        nullable=True)
    output_decision       = Column(String(16),  nullable=True)
    output_primary_reason = Column(String(64),  nullable=True)
    output_confidence     = Column(Float,       nullable=True)
    output_threats        = Column(JSONVariant,        nullable=True,  default=list)
    behavior_flag         = Column(String(32),  nullable=True)
    output_flags          = Column(JSONVariant,        nullable=True)
    total_latency_ms      = Column(Integer,     nullable=False)
    created_at            = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_proxy_int_key_id",      "key_id"),
        Index("ix_proxy_key_time",        "key_id",  "created_at"),
        Index("ix_proxy_int_created",     "created_at"),
        Index("ix_proxy_int_exec_status", "execution_status"),
        Index("ix_proxy_int_attack_type", "input_attack_type"),
    )


class UserModel(Base):
    """
    Dashboard users - human operators authenticating via JWT.
    API key users (applications/services) are in APIKeyModel and do not have rows here.

    Tenant boundary: tenant_id NOT NULL - enforced at DB level (Layer 1).
    dept_id NULL valid ONLY for ADMIN - enforced by ck_users_dept_required_v2 (both directions):
        role = ADMIN     -> dept_id MUST be NULL
        role != ADMIN    -> dept_id MUST NOT be NULL
    dept_id must belong to same tenant - validated in UserRepository.create/update().

    Email uniqueness: case-insensitive via ux_users_email_lower (LOWER(email)) index.
    Always stored lowercase - normalize_email() must be called before every write.

    token_version: incremented by logout_all_sessions() to immediately invalidate all JWTs.
    Triggered by: password change, role change, dept change, deactivation, admin reset.
    """
    __tablename__ = "users"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id             = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    dept_id               = Column(UUID(as_uuid=True), ForeignKey("departments.id"), nullable=True)
    email                 = Column(String(255), nullable=False)
    password_hash         = Column(String(255), nullable=False)
    role                  = Column(String(50),  nullable=False, default="DEVELOPER")
    is_active             = Column(Boolean,     nullable=False, default=True)
    force_password_change = Column(Boolean,     nullable=False, default=False)
    token_version         = Column(Integer,     nullable=False, default=1)
    created_at            = Column(DateTime(timezone=True),    nullable=False, default=utc_now)
    last_login_at         = Column(DateTime(timezone=True),    nullable=True)
    # BCP-47 tag; NULL = inherit tenant/system default. Validated against the
    # supported-locales allowlist before use (never trusted blindly).
    locale                = Column(String(35),  nullable=True)

    __table_args__ = (
        Index("ix_users_tenant",      "tenant_id"),
        Index("ix_users_dept",        "dept_id"),
        Index("ix_users_role",        "role"),
        Index("ix_users_role_active", "role", "is_active"),
        CheckConstraint(
            "role IN ('ADMIN', 'DEVELOPER', 'VIEWER', 'AUDITOR')",
            name="ck_users_role",
        ),
        # Updated by migration 0005_add_auditor_role:
        #   role = ADMIN                       -> dept_id MUST be NULL
        #   role = AUDITOR                     -> dept_id may be NULL (tenant-wide)
        #                                         or set (department-scoped)
        #   role IN (DEVELOPER, VIEWER)        -> dept_id MUST NOT be NULL
        # AUDITOR scoping is flexible: attach at tenant-wide (NULL dept_id)
        # or narrower (single department).
        CheckConstraint(
            "(role = 'ADMIN' AND dept_id IS NULL) OR "
            "(role = 'AUDITOR') OR "
            "(role IN ('DEVELOPER', 'VIEWER') AND dept_id IS NOT NULL)",
            name="ck_users_dept_required_v2",
        ),
    )


class RefreshTokenModel(Base):
    """
    Opaque refresh tokens for JWT session management.
    Raw token NEVER stored - only SHA-256(raw) persisted.
    Rotation: every use revokes old token and creates new one.
    Race condition prevention: get_by_hash() uses SELECT FOR UPDATE.
    token_version: stores user.token_version at issuance - mismatch means session invalidated.
    Cleanup: two clauses run daily (expires+revoked, and 90-day absolute cutoff).
    """
    __tablename__ = "refresh_tokens"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False)
    token_hash    = Column(String(64),  nullable=False, unique=True)
    token_version = Column(Integer,     nullable=False, default=1)
    expires_at    = Column(DateTime(timezone=True),    nullable=False)
    revoked_at    = Column(DateTime(timezone=True),    nullable=True)
    created_at    = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_refresh_tokens_user",    "user_id"),
        Index("ix_refresh_tokens_hash",    "token_hash"),
        Index("ix_refresh_tokens_expires", "expires_at"),
        Index("ix_refresh_active", "user_id", postgresql_where="revoked_at IS NULL"),
    )


class AdminEventModel(Base):
    """
    Administrative action log - one row per admin action.
    Separate from audit_logs (AI security events) and auth_events (login tracking).

    Logging: synchronous, post-commit, same request lifecycle. Best-effort.
    If logging fails -> log internally, do not fail request.

    action must be a value from AdminEventAction enum (domain/enums.py).
    dept_id = NULL for tenant-scoped actions, target user's dept_id (post-update) for user actions.
    For dept_changed: dept_id = new_dept_id; metadata contains old_dept_id and new_dept_id.

    metadata keys must be consistent per action type:
        role_changed  -> {"old_role": "...", "new_role": "..."}
        dept_changed  -> {"old_dept_id": "...", "new_dept_id": "..."}
        user_created  -> {"role": "...", "dept_id": "..."}
    Never store passwords, tokens, or secrets in metadata.
    """
    __tablename__ = "admin_events"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id      = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    dept_id        = Column(UUID(as_uuid=True), nullable=True)
    actor_user_id  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    target_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action         = Column(String(50),  nullable=False)
    metadata_      = Column("metadata", JSONVariant, nullable=True)
    ip_address     = Column(String(45),  nullable=True)
    user_agent     = Column(String(500), nullable=True)
    created_at     = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("idx_admin_events_tenant_time", "tenant_id", "created_at"),
        Index("idx_admin_events_actor",       "actor_user_id"),
        Index("idx_admin_events_target",      "target_user_id"),
        Index("idx_admin_events_dept",        "dept_id"),
    )


class AuthEventModel(Base):
    """
    Authentication event log - one row per login attempt.
    Separate from audit_logs (AI security events) and admin_events (admin actions).

    Logging: non-blocking, best-effort. Must use BackgroundTasks or separate DB session.
    Must NOT use the request session. Must NOT delay login response.

    tenant_id NULLABLE - NULL when user not found (cannot resolve tenant).
    user_id   NULLABLE - NULL when user not found.
    Prefer NULL over incorrect attribution. Never use sentinel values.

    action must be a value from AuthEventAction enum.
    failure_reason must be a value from AuthFailureReason enum when success=False.

    ip_address index supports future brute-force detection and security analytics
    without schema changes.
    """
    __tablename__ = "auth_events"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id      = Column(UUID(as_uuid=True), nullable=True)
    user_id        = Column(UUID(as_uuid=True), nullable=True)
    action         = Column(String(50),  nullable=False)
    success        = Column(Boolean,     nullable=False)
    failure_reason = Column(String(50),  nullable=True)
    ip_address     = Column(String(45),  nullable=True)
    user_agent     = Column(String(500), nullable=True)
    created_at     = Column(DateTime(timezone=True),    nullable=False, default=utc_now)

    __table_args__ = (
        Index("idx_auth_events_tenant_time", "tenant_id", "created_at"),
        Index("idx_auth_events_user",        "user_id"),
        Index("idx_auth_events_success",     "success"),
        Index("idx_auth_events_ip",          "ip_address"),
    )


class WebhookEndpointModel(Base):
    """
    Outbound webhook destination (v1.3.0). One row per (tenant, url).

    Signing secret is stored per-endpoint, not per-tenant, so a single
    tenant can route BLOCK events to multiple destinations with
    independent verification material and rotate each one in isolation.

    Secret rotation uses an expiring-keys array. `old_secrets` is a
    JSON array of {ciphertext, expires_at} entries that remain valid
    for signature verification until their expiry, giving receivers a
    grace window to update verifier code before the old secret stops
    being accepted. All secret material is envelope-encrypted via
    security.encryption (v2 wire format, per-record DEK, HYOK-ready).
    Distinct HMAC secret per feature per the conflict-prevention rule:
    this material MUST NOT be reused for the audit hash chain, JWT
    signing, or inbound SDK request signing.

    Circuit-breaker fields: `first_failure_at` is set on the first
    delivery failure and cleared on the next success; a background
    sweep flips `disabled` once the failure timer exceeds the
    configured grace window. See v1.3.0 delivery-pipeline commits.
    """
    __tablename__ = "webhook_endpoints"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id        = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    url              = Column(Text,        nullable=False)
    description      = Column(Text,        nullable=True)
    # NULL = generic HMAC-signed webhook (secret_enc is a signing secret).
    # A connector slug (e.g. "splunk_hec", "datadog_logs",
    # "sentinel_logs_ingestion", "elastic_ecs") selects a SIEM connector,
    # in which case secret_enc holds that connector's ingest token/key and
    # `config` holds its per-endpoint options. See services/webhooks/connectors.
    connector_type   = Column(Text,        nullable=True,  default=None)
    secret_enc       = Column(Text,        nullable=False)
    old_secrets      = Column(JSONVariant, nullable=True,  default=list)
    event_types      = Column(JSONVariant, nullable=True,  default=None)
    headers          = Column(JSONVariant, nullable=True,  default=None)
    # Per-connector configuration (e.g. Sentinel dcr_immutable_id/stream_name,
    # Elastic index, Splunk sourcetype). NULL for generic webhooks.
    config           = Column(JSONVariant, nullable=True,  default=None)
    disabled         = Column(Boolean,     nullable=False, default=False)
    first_failure_at = Column(DateTime(timezone=True),    nullable=True)
    rate_limit       = Column(Integer,     nullable=True)
    created_at       = Column(DateTime(timezone=True),    nullable=False, default=utc_now)
    updated_at       = Column(DateTime(timezone=True),    nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "url", name="uq_webhook_endpoints_tenant_url"),
        Index("ix_webhook_endpoints_tenant_disabled", "tenant_id", "disabled"),
    )


class WebhookDeliveryAttemptModel(Base):
    """
    Per-attempt log for outbound webhook deliveries (v1.3.0).

    Append-only. A single logical webhook (identified by `msg_id` and
    the `webhook-id` header) produces one row per delivery attempt,
    including the first attempt and every retry. Retention is
    partition-based: the postgres migration creates monthly RANGE
    partitions on `created_at`, and a maintenance job (added in a
    later v1.3.0 commit) drops partitions older than the configured
    retention window.

    Composite primary key `(id, created_at)` is required by postgres
    partitioning: the PK must include every partitioning column. The
    column ordering (id first) matches the intuitive read of "the row
    with this id" while keeping the DDL valid.

    Denormalized `url` snapshots the endpoint URL at delivery time.
    Endpoint URLs may change after an attempt is logged, and this row
    must remain a truthful record of what was actually attempted.
    Same reasoning as denormalizing `tenant_id` -- routing decisions
    outside of hot-path queries stay correct even if the endpoint or
    its parent moves.

    `response_body_truncated` is a bounded slice of the receiver's
    response body. The emitter is responsible for truncating to a
    small ceiling before writing (see later v1.3.0 delivery-worker
    commit); an unbounded response column would let a single misbehaved
    receiver returning multi-megabyte HTML error pages fill disk.

    `next_attempt_at` gates the retry scheduler: workers scan for rows
    with `status = 'pending' AND next_attempt_at <= now()`. NULL means
    "no further attempt scheduled" (either terminal or currently in
    flight). Indexed as leading column so the scheduler scan is a
    range scan, not a table scan.
    """
    __tablename__ = "webhook_delivery_attempts"

    id                      = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at              = Column(DateTime(timezone=True),           primary_key=True, nullable=False, default=utc_now)
    endpoint_id             = Column(UUID(as_uuid=True), ForeignKey("webhook_endpoints.id"), nullable=False)
    tenant_id               = Column(UUID(as_uuid=True), ForeignKey("tenants.id"),           nullable=False)
    msg_id                  = Column(String(64), nullable=False)
    url                     = Column(Text,       nullable=False)
    event_type              = Column(String(100), nullable=False)
    attempt_number          = Column(Integer,    nullable=False)
    status                  = Column(String(20), nullable=False)
    http_status_code        = Column(Integer,    nullable=True)
    response_body_truncated = Column(Text,       nullable=True)
    response_duration_ms    = Column(Integer,    nullable=True)
    error_message           = Column(Text,       nullable=True)
    next_attempt_at         = Column(DateTime(timezone=True),   nullable=True)
    ended_at                = Column(DateTime(timezone=True),   nullable=True)

    __table_args__ = (
        Index("ix_webhook_delivery_attempts_msg_id",           "msg_id"),
        Index("ix_webhook_delivery_attempts_endpoint_status",  "endpoint_id", "status"),
        Index("ix_webhook_delivery_attempts_next_attempt",     "next_attempt_at"),
    )


class EmailOutboxModel(Base):
    """
    Transactional email outbox (v1.8.3).

    One row per notification to send. The row is created inside the business
    transaction that triggers the notification (password change, admin reset,
    lockout), so the intent to send an email is committed atomically with the
    business change: if the business transaction rolls back, so does the email.

    Subject and bodies are rendered at enqueue time and stored here, so the
    delivery worker is template- and locale-agnostic and the exact content is
    captured for audit. V1 notifications are informational and carry no secrets,
    so persisting the rendered content is safe.

    `tenant_id` is a foreign key (tenants are never hard-deleted). `user_id` is a
    denormalized audit reference with no foreign key: the outbox is operational
    history whose content (recipient address) is self-contained, and it must not
    couple to the user lifecycle. `recipient` is likewise a snapshot of the
    address at enqueue time.

    Worker claim scan: `status = 'queued' AND available_at <= now()` ordered by
    `available_at`, so the composite index leads with those columns for a range
    scan. `available_at` is the retry gate -- a transient failure reschedules the
    row by pushing `available_at` into the future per the shared retry schedule.

    Status values are domain.enums.EmailStatus. `provider_accepted` means the
    SMTP server accepted the message for relay; it is NOT proof of recipient
    delivery. `delivered`/`bounced` are reserved for a future provider-webhook
    capability and are never set by the SMTP-only V1.
    """
    __tablename__ = "email_outbox"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id           = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=True)
    # Denormalized audit reference (no FK), snapshotted from the recipient user
    # at enqueue. NULL for tenant-level notifications (e.g. an admin recipient
    # has no department). Belongs to tenant_id by construction: both are copied
    # from the same user, whose dept-in-tenant is a DB invariant.
    department_id       = Column(UUID(as_uuid=True), nullable=True)
    user_id             = Column(UUID(as_uuid=True), nullable=True)
    notification_type   = Column(String(64),  nullable=False)
    recipient           = Column(String(255), nullable=False)
    locale              = Column(String(35),  nullable=True)
    subject             = Column(Text,        nullable=False)
    body_text           = Column(Text,        nullable=False)
    body_html           = Column(Text,        nullable=True)
    status              = Column(String(20),  nullable=False, default="queued")
    attempt_count       = Column(Integer,     nullable=False, default=0)
    available_at        = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at          = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at          = Column(DateTime(timezone=True), nullable=True)
    sending_at          = Column(DateTime(timezone=True), nullable=True)
    sent_at             = Column(DateTime(timezone=True), nullable=True)
    provider_message_id = Column(String(255), nullable=True)
    last_error          = Column(Text,        nullable=True)
    trace_id            = Column(String(64),  nullable=True)

    __table_args__ = (
        Index("ix_email_outbox_status_available", "status", "available_at"),
        Index("ix_email_outbox_tenant_created",   "tenant_id", "created_at"),
    )
