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
    # Severity is computed at write time from decision + risk_score + primary_reason.
    # See domain/value_objects/severity.py for the full model.
    # Values: CRITICAL / HIGH / MEDIUM / LOW
    # Never returned in scan responses — audit and SIEM use only.
    severity       = Column(String(10),  nullable=True)
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
    is_admin     = Column(Boolean,     nullable=False, default=False)
    revoked      = Column(Boolean,     nullable=False, default=False)
    expires_at   = Column(DateTime,    nullable=True)
    last_used_at = Column(DateTime,    nullable=True)
    created_at   = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        # PostgreSQL only — constraint already applied in the live DB via migration.
        # SQLite (integration tests) does not support this constraint syntax,
        # so we gate it by dialect at DDL time.
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
    """
    Stores the LLM provider configuration per API key (tenant).
    One row per key_id. Replaced entirely on PUT /v1/settings/proxy.
    provider_api_key_enc is AES-256-GCM encrypted and never returned in responses.
    """
    __tablename__ = "proxy_provider_configs"

    id                   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id               = Column(String(50),  nullable=False, unique=True, index=True)
    # key_id matches APIKeyModel.key_id -- used for lookup by the authenticated key

    provider             = Column(String(32),  nullable=False)
    # provider values: openai | ollama | custom
    # openai covers: OpenAI, Azure OpenAI, Groq, Together AI, Anyscale,
    #                and any OpenAI-compatible endpoint via base_url

    base_url             = Column(Text,        nullable=False)
    provider_api_key_enc = Column(Text,        nullable=True)
    # AES-256-GCM encrypted plaintext API key.
    # Null is valid for ollama (no auth required).

    default_model        = Column(String(128), nullable=False)
    timeout_seconds      = Column(Integer,     nullable=False, default=60)

    created_at           = Column(DateTime,    nullable=False, default=datetime.utcnow)
    updated_at           = Column(DateTime,    nullable=False, default=datetime.utcnow,
                                  onupdate=datetime.utcnow)


class ProxyInteractionModel(Base):
    """
    One row per proxy request. Captures the full interaction lifecycle.
    Separate from audit_logs which covers scan-only mode.

    Lifecycle:
        input scan -> input decision -> provider call -> output scan -> output decision -> logged
    """
    __tablename__ = "proxy_interactions"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id              = Column(String(64),  nullable=False, unique=True, index=True)
    key_id                = Column(String(50),  nullable=True)
    user_id               = Column(String(256), nullable=True)

    # -- Input --
    input_raw             = Column(Text,        nullable=True)
    input_sanitized       = Column(Text,        nullable=True)
    # null if input_decision = ALLOW or BLOCK (no sanitization applied)

    input_decision        = Column(String(16),  nullable=False)  # ALLOW / BLOCK / SANITIZE
    input_primary_reason  = Column(String(64),  nullable=False)
    input_confidence      = Column(Float,       nullable=False)
    input_threats         = Column(JSON,        nullable=True,  default=list)
    input_attack_type     = Column(String(64),  nullable=True)
    # input_attack_type: set to input_threats[0] when input_decision != ALLOW
    # null when input_decision = ALLOW (no attack detected)
    # examples: PROMPT_INJECTION, JAILBREAK, MALICIOUS_INTENT, PII, TOXICITY

    # -- Provider --
    provider              = Column(String(32),  nullable=True)
    # null when execution_status = BLOCKED (provider was never called)

    model                 = Column(String(128), nullable=True)
    provider_latency_ms   = Column(Integer,     nullable=True)
    execution_status      = Column(String(32),  nullable=False)
    # execution_status values:
    #   SUCCESS        input clean, provider responded, output clean or sanitized
    #   BLOCKED        input decision was BLOCK, provider never called
    #   OUTPUT_BLOCKED input clean, provider responded, output decision was BLOCK
    #   FAILED         provider call failed (network error, auth error)
    #   TIMEOUT        provider call timed out

    # -- Output --
    output_raw            = Column(Text,        nullable=True)
    # null when execution_status in (BLOCKED, FAILED, TIMEOUT)

    output_sanitized      = Column(Text,        nullable=True)
    # null when output_decision = ALLOW or BLOCK, or when no output exists

    output_decision       = Column(String(16),  nullable=True)   # ALLOW / BLOCK / SANITIZE
    output_primary_reason = Column(String(64),  nullable=True)
    output_confidence     = Column(Float,       nullable=True)
    output_threats        = Column(JSON,        nullable=True,  default=list)
    # output_confidence and output_threats are null when no output exists

    # -- Future evaluation hooks (always null in V1, populated in V2) --
    behavior_flag         = Column(String(32),  nullable=True)
    # V2 values: NORMAL / OVER_REFUSAL / UNDER_REFUSAL
    # Populated by WildGuard response_refusal classification in V2

    output_flags          = Column(JSON,        nullable=True)
    # V2 values: e.g. ["LOW_CONFIDENCE", "SUSPICIOUS_OUTPUT"]
    # Populated by output evaluation engine in V2

    # -- Timing --
    total_latency_ms      = Column(Integer,     nullable=False)
    created_at            = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_proxy_int_key_id",      "key_id"),
        Index("ix_proxy_key_time",        "key_id",  "created_at"),
        Index("ix_proxy_int_created",     "created_at"),
        Index("ix_proxy_int_exec_status", "execution_status"),
        Index("ix_proxy_int_attack_type", "input_attack_type"),
    )