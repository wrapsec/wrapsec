import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Boolean,
    DateTime, Text, JSON, Integer, Index, ForeignKey,
    CheckConstraint
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.dialects.postgresql import UUID


class Base(DeclarativeBase):
    pass


class TenantModel(Base):
    __tablename__ = "tenants"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug          = Column(String(50),  nullable=False, unique=True)
    name          = Column(String(100), nullable=False)
    description   = Column(Text,        nullable=True)
    global_policy = Column(JSON,        nullable=False, default=dict)
    is_active     = Column(Boolean,     nullable=False, default=True)
    contact_email = Column(String(100), nullable=True)
    created_by    = Column(String(100), nullable=True)
    created_at    = Column(DateTime,    nullable=False, default=datetime.utcnow)


class DepartmentModel(Base):
    __tablename__ = "departments"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id       = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    slug            = Column(String(50),  nullable=False)
    name            = Column(String(100), nullable=False)
    description     = Column(Text,        nullable=True)
    policy_override = Column(JSON,        nullable=True,  default=None)
    is_active       = Column(Boolean,     nullable=False, default=True)
    contact_email   = Column(String(100), nullable=True)
    created_by      = Column(String(100), nullable=True)
    created_at      = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_dept_tenant", "tenant_id"),
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
    metadata_           = Column("metadata",  JSON, nullable=True, default=None)
    policy_override     = Column(JSON,        nullable=True,  default=None)
    rate_limit_override = Column(Integer,     nullable=True,  default=None)
    is_active           = Column(Boolean,     nullable=False, default=True)
    created_at          = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_app_dept", "dept_id"),
    )


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id       = Column(String(50),  nullable=False, unique=True, index=True)
    decision       = Column(String(20),  nullable=False, index=True)
    risk_score     = Column(Float,       nullable=False)
    threats        = Column(JSON,        nullable=False, default=list)
    input_hash     = Column(String(100), nullable=False)
    detection_mode = Column(String(20),  nullable=False)
    execution_mode = Column(String(20),  nullable=False)
    llm_invoked    = Column(Boolean,     nullable=False, default=False)
    latency_ms     = Column(Float,       nullable=False)
    detection_scores   = Column(JSON,    nullable=True)
    guardrail_scores   = Column(JSON,    nullable=True)
    key_id             = Column(String(50),  nullable=True)
    ip_address         = Column(String(50),  nullable=True)
    user_agent         = Column(String(255), nullable=True)
    attribution_verified = Column(Boolean,   nullable=False, default=False)
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
    proxy_interaction_id = Column(UUID(as_uuid=True), nullable=True)
    severity       = Column(String(10),  nullable=True)
    principal_type = Column(String(20),  nullable=True,  default="api_key")
    created_at     = Column(DateTime,    nullable=False, default=datetime.utcnow)

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
    )


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id       = Column(String(50),  nullable=False, unique=True, index=True)
    tenant_id    = Column(UUID(as_uuid=True), ForeignKey("tenants.id"),    nullable=True)
    dept_id      = Column(UUID(as_uuid=True), ForeignKey("departments.id"), nullable=True)
    app_id       = Column(UUID(as_uuid=True), ForeignKey("applications.id"), nullable=True)
    name         = Column(String(100), nullable=False)
    key_hash     = Column(String(100), nullable=False, unique=True)
    key_type     = Column(String(20),  nullable=False, default="live")
    is_admin     = Column(Boolean,     nullable=False, default=False)
    revoked      = Column(Boolean,     nullable=False, default=False)
    expires_at   = Column(DateTime,    nullable=True)
    last_used_at = Column(DateTime,    nullable=True)
    created_at   = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
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
    updated_at = Column(DateTime,    nullable=False, default=datetime.utcnow)


class ProxyProviderConfigModel(Base):
    __tablename__ = "proxy_provider_configs"

    id                   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id               = Column(String(50),  nullable=False, unique=True, index=True)
    provider             = Column(String(32),  nullable=False)
    base_url             = Column(Text,        nullable=False)
    provider_api_key_enc = Column(Text,        nullable=True)
    default_model        = Column(String(128), nullable=False)
    timeout_seconds      = Column(Integer,     nullable=False, default=60)
    created_at           = Column(DateTime,    nullable=False, default=datetime.utcnow)
    updated_at           = Column(DateTime,    nullable=False, default=datetime.utcnow,
                                  onupdate=datetime.utcnow)


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
    input_threats         = Column(JSON,        nullable=True,  default=list)
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
    output_threats        = Column(JSON,        nullable=True,  default=list)
    behavior_flag         = Column(String(32),  nullable=True)
    output_flags          = Column(JSON,        nullable=True)
    total_latency_ms      = Column(Integer,     nullable=False)
    created_at            = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_proxy_int_key_id",      "key_id"),
        Index("ix_proxy_key_time",        "key_id",  "created_at"),
        Index("ix_proxy_int_created",     "created_at"),
        Index("ix_proxy_int_exec_status", "execution_status"),
        Index("ix_proxy_int_attack_type", "input_attack_type"),
    )


class UserModel(Base):
    """
    Dashboard users — human operators authenticating via JWT.
    API key users (applications/services) are in APIKeyModel and do not have rows here.

    Tenant boundary: tenant_id NOT NULL — enforced at DB level (Layer 1).
    dept_id NULL valid ONLY for ADMIN — enforced by ck_users_dept_required_v2 (both directions):
        role = ADMIN     → dept_id MUST be NULL
        role != ADMIN    → dept_id MUST NOT be NULL
    dept_id must belong to same tenant — validated in UserRepository.create/update().

    Email uniqueness: case-insensitive via ux_users_email_lower (LOWER(email)) index.
    Always stored lowercase — normalize_email() must be called before every write.

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
    created_at            = Column(DateTime,    nullable=False, default=datetime.utcnow)
    last_login_at         = Column(DateTime,    nullable=True)

    __table_args__ = (
        Index("ix_users_tenant",      "tenant_id"),
        Index("ix_users_dept",        "dept_id"),
        Index("ix_users_role",        "role"),
        Index("ix_users_role_active", "role", "is_active"),
        CheckConstraint(
            "role IN ('ADMIN', 'DEVELOPER', 'VIEWER')",
            name="ck_users_role",
        ),
        # Updated in add_user_management.sql — enforces BOTH directions:
        #   role = ADMIN     → dept_id MUST be NULL
        #   role != ADMIN    → dept_id MUST NOT be NULL
        CheckConstraint(
            "(role = 'ADMIN' AND dept_id IS NULL) OR (role != 'ADMIN' AND dept_id IS NOT NULL)",
            name="ck_users_dept_required_v2",
        ),
    )


class RefreshTokenModel(Base):
    """
    Opaque refresh tokens for JWT session management.
    Raw token NEVER stored — only SHA-256(raw) persisted.
    Rotation: every use revokes old token and creates new one.
    Race condition prevention: get_by_hash() uses SELECT FOR UPDATE.
    token_version: stores user.token_version at issuance — mismatch means session invalidated.
    Cleanup: two clauses run daily (expires+revoked, and 90-day absolute cutoff).
    """
    __tablename__ = "refresh_tokens"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False)
    token_hash    = Column(String(64),  nullable=False, unique=True)
    token_version = Column(Integer,     nullable=False, default=1)
    expires_at    = Column(DateTime,    nullable=False)
    revoked_at    = Column(DateTime,    nullable=True)
    created_at    = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_refresh_tokens_user",    "user_id"),
        Index("ix_refresh_tokens_hash",    "token_hash"),
        Index("ix_refresh_tokens_expires", "expires_at"),
        Index("ix_refresh_active", "user_id", postgresql_where="revoked_at IS NULL"),
    )


class AdminEventModel(Base):
    """
    Administrative action log — one row per admin action.
    Separate from audit_logs (AI security events) and auth_events (login tracking).

    Logging: synchronous, post-commit, same request lifecycle. Best-effort.
    If logging fails → log internally, do not fail request.

    action must be a value from AdminEventAction enum (domain/enums.py).
    dept_id = NULL for tenant-scoped actions, target user's dept_id (post-update) for user actions.
    For dept_changed: dept_id = new_dept_id; metadata contains old_dept_id and new_dept_id.

    metadata keys must be consistent per action type:
        role_changed  → {"old_role": "...", "new_role": "..."}
        dept_changed  → {"old_dept_id": "...", "new_dept_id": "..."}
        user_created  → {"role": "...", "dept_id": "..."}
    Never store passwords, tokens, or secrets in metadata.
    """
    __tablename__ = "admin_events"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id      = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    dept_id        = Column(UUID(as_uuid=True), nullable=True)
    actor_user_id  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    target_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action         = Column(String(50),  nullable=False)
    metadata_      = Column("metadata", JSON, nullable=True)
    ip_address     = Column(String(45),  nullable=True)
    user_agent     = Column(String(500), nullable=True)
    created_at     = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_admin_events_tenant_time", "tenant_id", "created_at"),
        Index("idx_admin_events_actor",       "actor_user_id"),
        Index("idx_admin_events_target",      "target_user_id"),
        Index("idx_admin_events_dept",        "dept_id"),
    )


class AuthEventModel(Base):
    """
    Authentication event log — one row per login attempt.
    Separate from audit_logs (AI security events) and admin_events (admin actions).

    Logging: non-blocking, best-effort. Must use BackgroundTasks or separate DB session.
    Must NOT use the request session. Must NOT delay login response.

    tenant_id NULLABLE — NULL when user not found (cannot resolve tenant).
    user_id   NULLABLE — NULL when user not found.
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
    created_at     = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_auth_events_tenant_time", "tenant_id", "created_at"),
        Index("idx_auth_events_user",        "user_id"),
        Index("idx_auth_events_success",     "success"),
        Index("idx_auth_events_ip",          "ip_address"),
    )
