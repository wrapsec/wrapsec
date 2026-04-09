import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Boolean,
    DateTime, Text, JSON, Index
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.dialects.postgresql import UUID


class Base(DeclarativeBase):
    pass


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
    llm_invoked        = Column(Boolean, nullable=False, default=False)
    key_id               = Column(String(50),  nullable=True)
    ip_address           = Column(String(50),  nullable=True)
    user_agent           = Column(String(255), nullable=True)
    attribution_verified = Column(Boolean,     nullable=False, default=False)
    detection_scores   = Column(JSON,    nullable=True,  default=dict)
    guardrail_scores   = Column(JSON,    nullable=True,  default=dict)
    latency_ms     = Column(Float,       nullable=False)
    tenant_id      = Column(String(100), nullable=True,  index=True)
    source         = Column(String(100), nullable=True)
    user_id        = Column(String(100), nullable=True)
    created_at     = Column(DateTime,    nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_audit_logs_decision_created", "decision", "created_at"),
        Index("ix_audit_logs_tenant_created",   "tenant_id", "created_at"),
    )


class SettingsModel(Base):
    __tablename__ = "settings"

    key        = Column(String(100), primary_key=True)
    value      = Column(Text,        nullable=False)
    updated_at = Column(DateTime,    nullable=False, default=datetime.utcnow)


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id       = Column(String(50),  nullable=False, unique=True, index=True)
    name         = Column(String(100), nullable=False)
    key_hash     = Column(String(100), nullable=False, unique=True)
    is_admin     = Column(Boolean,     nullable=False, default=False)
    revoked      = Column(Boolean,     nullable=False, default=False)
    expires_at   = Column(DateTime,    nullable=True)
    last_used_at = Column(DateTime,    nullable=True)
    created_at   = Column(DateTime,    nullable=False, default=datetime.utcnow)