# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, SecretStr, field_validator
from sqlalchemy import func, select as sa_select
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from config.settings import get_settings
from db.models import AuditLogModel
from db.repositories.department import DepartmentRepository
from domain.entities.principal import Principal
from errors.exceptions import NotFoundError
from security.encryption import encrypt, decrypt, mask

router = APIRouter()

_ENCRYPTED_SECTIONS = ("llm", "proxy_provider")


def _mask_policy_override(override: dict | None) -> dict | None:
    """Strip api_key_enc from sensitive sections, replace with api_key_masked."""
    if not override:
        return override
    result = {}
    _s     = get_settings()
    for k, v in override.items():
        if k in _ENCRYPTED_SECTIONS and isinstance(v, dict):
            section = dict(v)
            enc     = section.pop("api_key_enc", None)
            if enc:
                try:
                    section["api_key_masked"] = mask(decrypt(enc, _s.secret_key))
                except ValueError:
                    section["api_key_masked"] = "****"
            result[k] = section
        else:
            result[k] = v
    return result


def _format(dept) -> dict:
    return {
        "id":              str(dept.id),
        "tenant_id":       str(dept.tenant_id),
        "slug":            dept.slug,
        "name":            dept.name,
        "description":     dept.description,
        "policy_override": _mask_policy_override(dept.policy_override),
        "contact_email":   dept.contact_email,
        "is_active":       dept.is_active,
        "created_at":      dept.created_at.isoformat(),
    }


class DepartmentCreateSchema(BaseModel):
    slug:            str
    name:            str
    description:     str | None = None
    policy_override: dict | None = None
    contact_email:   str | None = None


class DepartmentUpdateSchema(BaseModel):
    name:            str | None = None
    description:     str | None = None
    policy_override: dict | None = None
    contact_email:   str | None = None
    is_active:       bool | None = None


_VALID_PROVIDERS = {"openai", "ollama", "custom"}

_BLOCKED_HOSTS   = frozenset({"localhost", "metadata.google.internal", "metadata.goog"})
import ipaddress as _ip
_PRIVATE_NETS    = [
    _ip.ip_network("127.0.0.0/8"),  _ip.ip_network("10.0.0.0/8"),
    _ip.ip_network("172.16.0.0/12"), _ip.ip_network("192.168.0.0/16"),
    _ip.ip_network("169.254.0.0/16"), _ip.ip_network("0.0.0.0/8"),
    _ip.ip_network("::1/128"),       _ip.ip_network("fc00::/7"),
    _ip.ip_network("fe80::/10"),
]


def _validate_provider_url(v: str) -> str:
    from urllib.parse import urlparse
    v = v.rstrip("/")
    if not v.startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")
    host = (urlparse(v).hostname or "").lower()
    if host in _BLOCKED_HOSTS:
        raise ValueError("base_url must not target private or internal addresses")
    try:
        addr = _ip.ip_address(host)
        if any(addr in net for net in _PRIVATE_NETS):
            raise ValueError("base_url must not target private or internal addresses")
    except ValueError:
        pass
    return v


class DeptLLMOverrideSchema(BaseModel):
    provider: str       | None = None
    model:    str       | None = None
    base_url: str       | None = None
    timeout:  int       | None = None
    api_key:  SecretStr | None = None
    clear:    bool = False

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_PROVIDERS:
            raise ValueError(f"provider must be one of: {', '.join(sorted(_VALID_PROVIDERS))}")
        return v

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_provider_url(v)

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int | None) -> int | None:
        if v is not None and not (5 <= v <= 120):
            raise ValueError("timeout must be between 5 and 120 seconds")
        return v


class DeptProxyOverrideSchema(BaseModel):
    provider:        str       | None = None
    base_url:        str       | None = None
    default_model:   str       | None = None
    timeout_seconds: int       | None = None
    api_key:         SecretStr | None = None
    clear:           bool = False

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_PROVIDERS:
            raise ValueError(f"provider must be one of: {', '.join(sorted(_VALID_PROVIDERS))}")
        return v

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_provider_url(v)

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 300):
            raise ValueError("timeout_seconds must be between 1 and 300")
        return v


@router.post("")
async def create_department(
    body:      DepartmentCreateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Creates a new department under the authenticated principal's tenant.
    Auth: JWT + ADMIN role required.
    """
    tenant_id = uuid.UUID(request.state.tenant_id)

    repo   = DepartmentRepository(db)
    record = await repo.create({
        "tenant_id":       tenant_id,
        "slug":            body.slug,
        "name":            body.name,
        "description":     body.description,
        "policy_override": body.policy_override,
        "contact_email":   body.contact_email,
    })
    await db.commit()
    return JSONResponse(content=_format(record), status_code=201)


@router.get("")
async def list_departments(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """
    Lists departments scoped to the authenticated principal's tenant.
    ADMIN principals see all departments. Non-admin principals see only their own department.
    """
    tenant_id = uuid.UUID(request.state.tenant_id)

    repo  = DepartmentRepository(db)
    # ADMIN sees all departments; DEVELOPER sees only their own
    if request.state.is_admin or not request.state.dept_id:
        items = await repo.list_by_tenant(tenant_id)
    else:
        dept = await repo.get_by_id(uuid.UUID(request.state.dept_id))
        items = [dept] if dept else []
    return JSONResponse(content={"departments": [_format(d) for d in items]})


@router.get("/{dept_id}/stats")
async def get_department_stats(
    dept_id:   str,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """
    Aggregates audit_logs for this department.
    Returns total request count, decision breakdown, block rate, average latency,
    and the top 5 threat categories by frequency.
    """
    dept_check = await DepartmentRepository(db).get_by_id(uuid.UUID(dept_id))
    if not dept_check or str(dept_check.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)

    # Total requests
    total = await db.scalar(
        sa_select(func.count()).where(AuditLogModel.dept_id == dept_id)
    ) or 0

    # Decision breakdown
    decisions = await db.execute(
        sa_select(
            AuditLogModel.decision,
            func.count().label("count"),
        )
        .where(AuditLogModel.dept_id == dept_id)
        .group_by(AuditLogModel.decision)
    )
    decision_counts = {row.decision: row.count for row in decisions}

    # Average latency
    avg_latency = await db.scalar(
        sa_select(func.avg(AuditLogModel.latency_ms))
        .where(AuditLogModel.dept_id == dept_id)
    ) or 0.0

    # Top threats — aggregate in Python to avoid JSON/JSONB type issues
    threats_result = await db.execute(
        sa_select(AuditLogModel.threats)
        .where(AuditLogModel.dept_id == dept_id)
    )
    threat_counts: dict[str, int] = {}
    for row in threats_result:
        threats = row.threats or []
        if isinstance(threats, list):
            for t in threats:
                if t:
                    threat_counts[t] = threat_counts.get(t, 0) + 1

    top_threats = [
        {"category": k, "count": v}
        for k, v in sorted(
            threat_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
    ]

    block_rate = round(
        decision_counts.get("BLOCK", 0) / total, 3
    ) if total > 0 else 0.0

    return JSONResponse(content={
        "dept_id":        dept_id,
        "total":          total,
        "decisions":      decision_counts,
        "block_rate":     block_rate,
        "avg_latency_ms": round(avg_latency, 2),
        "top_threats":    top_threats,
    })

@router.get("/{dept_id}/policy")
async def get_department_policy(
    dept_id:   str,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """
    Returns the fully resolved effective policy for this department.
    Merges: system defaults → tenant global → department override.
    Useful for compliance verification.
    """
    from services.policy_resolver import resolve_policy

    repo   = DepartmentRepository(db)
    dept   = await repo.get_by_id(uuid.UUID(dept_id))
    if not dept or str(dept.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)

    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = str(dept.tenant_id),
        dept_id   = dept_id,
        app_id    = None,
    )

    return JSONResponse(content={
        "dept_id":         dept_id,
        "dept_name":       dept.name,
        "policy_source":   policy_source,
        "override_set":    dept.policy_override is not None,
        "policy_override": _mask_policy_override(dept.policy_override),
        "resolved_policy": policy,
    })

@router.get("/{dept_id}")
async def get_department(
    dept_id:   str,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """Returns a single department by ID. 404 if not found."""
    repo   = DepartmentRepository(db)
    record = await repo.get_by_id(uuid.UUID(dept_id))
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)
    return JSONResponse(content=_format(record))


@router.put("/{dept_id}")
async def update_department(
    dept_id:   str,
    body:      DepartmentUpdateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Partially updates a department. Only fields present in the request body are applied.
    Explicitly set null values (e.g. policy_override=null) are also applied — use this
    to clear a department's policy override back to tenant-level defaults.
    Auth: JWT + ADMIN role required.
    """
    repo     = DepartmentRepository(db)
    existing = await repo.get_by_id(uuid.UUID(dept_id))
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)
    # Use exclude_unset=True so explicitly set null values (e.g. policy_override=null)
    # are included — filtering "if v is not None" would silently drop them
    data = body.model_dump(exclude_unset=True)
    record = await repo.update(uuid.UUID(dept_id), data)
    if not record:
        raise NotFoundError("department", dept_id)
    await db.commit()
    return JSONResponse(content=_format(record))


@router.patch("/{dept_id}/policy/llm")
async def update_dept_llm_override(
    dept_id:   str,
    body:      DeptLLMOverrideSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Set or clear the LLM detection override for a department.
    When set, this dept's requests use the specified LLM provider/model/key for threat detection.
    api_key is encrypted before storage — never stored or returned in plaintext.
    Set clear=true to remove the override and inherit the global LLM configuration.
    Auth: JWT + ADMIN role required.
    """
    repo     = DepartmentRepository(db)
    existing = await repo.get_by_id(uuid.UUID(dept_id))
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)

    override = dict(existing.policy_override or {})

    if body.clear:
        override.pop("llm", None)
    else:
        current = dict(override.get("llm") or {})
        if body.provider    is not None: current["provider"] = body.provider
        if body.model       is not None: current["model"]    = body.model
        if body.base_url    is not None: current["base_url"] = body.base_url
        if body.timeout     is not None: current["timeout"]  = body.timeout
        if body.api_key is not None:
            raw = body.api_key.get_secret_value().strip()
            if raw:
                current["api_key_enc"] = encrypt(raw, get_settings().secret_key)
            else:
                current.pop("api_key_enc", None)
        if current:
            override["llm"] = current

    record = await repo.update(uuid.UUID(dept_id), {
        "policy_override": override or None
    })
    if not record:
        raise NotFoundError("department", dept_id)
    await db.commit()
    return JSONResponse(content=_format(record))


@router.patch("/{dept_id}/policy/proxy")
async def update_dept_proxy_override(
    dept_id:   str,
    body:      DeptProxyOverrideSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Set or clear the proxy provider override for a department.
    When set, proxy mode requests from this dept fall back to this provider if no
    per-key proxy config exists. api_key encrypted before storage.
    Set clear=true to remove the override and require per-key proxy configuration.
    Auth: JWT + ADMIN role required.
    """
    repo     = DepartmentRepository(db)
    existing = await repo.get_by_id(uuid.UUID(dept_id))
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)

    override = dict(existing.policy_override or {})

    if body.clear:
        override.pop("proxy_provider", None)
    else:
        current = dict(override.get("proxy_provider") or {})
        if body.provider        is not None: current["provider"]        = body.provider
        if body.base_url        is not None: current["base_url"]        = body.base_url
        if body.default_model   is not None: current["default_model"]   = body.default_model
        if body.timeout_seconds is not None: current["timeout_seconds"] = body.timeout_seconds
        if body.api_key is not None:
            raw = body.api_key.get_secret_value().strip()
            if raw:
                current["api_key_enc"] = encrypt(raw, get_settings().secret_key)
            else:
                current.pop("api_key_enc", None)
        if current:
            override["proxy_provider"] = current

    record = await repo.update(uuid.UUID(dept_id), {
        "policy_override": override or None
    })
    if not record:
        raise NotFoundError("department", dept_id)
    await db.commit()
    return JSONResponse(content=_format(record))


@router.delete("/{dept_id}")
async def delete_department(
    dept_id:   str,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Soft-deletes a department by setting is_active=False.
    The department record is retained for audit history.
    Auth: JWT + ADMIN role required.
    """
    repo     = DepartmentRepository(db)
    existing = await repo.get_by_id(uuid.UUID(dept_id))
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)
    record = await repo.update(uuid.UUID(dept_id), {"is_active": False})
    if not record:
        raise NotFoundError("department", dept_id)
    await db.commit()
    return JSONResponse(content={"dept_id": dept_id, "deactivated": True})
