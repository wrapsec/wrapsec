import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Boolean,
    DateTime, Text, JSON, Integer, Index, ForeignKey
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
    source         = Column(String(100), nullable=True)
    user_id        = Column(String(100), nullable=True)
    created_at     = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_audit_logs_decision_created", "decision",   "created_at"),
        Index("ix_audit_logs_tenant_created",   "tenant_id",  "created_at"),
        Index("ix_audit_key_created",           "key_id",     "created_at"),
        Index("ix_audit_app_created",           "app_id",     "created_at"),
        Index("ix_audit_dept_created",          "dept_id",    "created_at"),
        Index("ix_audit_user_created",          "user_id",    "created_at"),
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


class SettingsModel(Base):
    __tablename__ = "settings"

    key        = Column(String(100), primary_key=True)
    value      = Column(Text,        nullable=False)
    updated_at = Column(DateTime,    nullable=False, default=datetime.utcnow)