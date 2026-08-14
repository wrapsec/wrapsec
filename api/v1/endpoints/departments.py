# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator
from sqlalchemy import func
from sqlalchemy import select as sa_select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from config.settings import get_settings
from db.models import AuditLogModel
from db.repositories.admin_event import AdminEventRepository
from db.repositories.application import ApplicationRepository
from db.repositories.department import DepartmentRepository
from domain.entities.principal import Principal
from domain.enums import AdminEventAction
from errors.exceptions import ConflictError, NotFoundError, ValidationError
from security.encryption import decrypt, encrypt, mask
from security.url_validator import validate_llm_base_url, validate_policy_override_urls
from services.slug import is_reserved_slug, slugify
from services.time import to_iso_z

logger = logging.getLogger("wrapsec.departments")

router = APIRouter()

_ENCRYPTED_SECTIONS = ("llm", "proxy_provider")


def _require_dept_scope(request: Request, dept_id: str) -> None:
    """
    For non-admin principals, restrict department read endpoints to the caller's
    own dept_id. Raises NotFoundError (not ForbiddenError) so a scoped caller
    cannot enumerate sibling departments by probing responses.

    Admin principals bypass this check and can read any department in the tenant
    (the tenant-scope check on each endpoint still applies).
    """
    if getattr(request.state, "is_admin", False):
        return
    own_dept_id = getattr(request.state, "dept_id", None)
    if not own_dept_id or str(own_dept_id) != dept_id:
        raise NotFoundError("department", dept_id)


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


def _format(dept, application_count: int = 0) -> dict:
    return {
        "id":                str(dept.id),
        "tenant_id":         str(dept.tenant_id),
        "slug":              dept.slug,
        "name":              dept.name,
        "description":       dept.description,
        "policy_override":   _mask_policy_override(dept.policy_override),
        "contact_email":     dept.contact_email,
        "is_active":         dept.is_active,
        "application_count": application_count,
        "created_at":        to_iso_z(dept.created_at),
    }


class DepartmentCreateSchema(BaseModel):
    slug:            str
    name:            str = Field(min_length=1, max_length=100)
    description:     str | None = Field(None, max_length=2000)
    policy_override: dict | None = None
    contact_email:   EmailStr | None = None

    @field_validator("slug")
    @classmethod
    def _canonical_slug(cls, v: str) -> str:
        # Canonicalize server-side so the stored slug is identical whatever the
        # caller sent (dashboard, SDK, raw API) -- never trust the client's form.
        s = slugify(v)
        if not s:
            raise ValueError("slug must contain at least one letter or digit")
        return s


class DepartmentUpdateSchema(BaseModel):
    name:            str | None = Field(None, min_length=1, max_length=100)
    description:     str | None = Field(None, max_length=2000)
    policy_override: dict | None = None
    contact_email:   EmailStr | None = None
    is_active:       bool | None = None


_VALID_PROVIDERS = {"openai", "ollama", "custom"}


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
        return validate_llm_base_url(v)

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
        return validate_llm_base_url(v)

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

    if is_reserved_slug(body.slug):
        raise ValidationError(f"slug '{body.slug}' is reserved")

    # C2: SSRF-validate any base_url in the generic policy_override, matching the
    # dedicated /policy/llm and /policy/proxy PATCH endpoints.
    try:
        validate_policy_override_urls(body.policy_override)
    except ValueError as e:
        raise ValidationError(str(e)) from None

    repo = DepartmentRepository(db)
    if await repo.get_by_slug(tenant_id, body.slug):
        raise ConflictError(f"A department with slug '{body.slug}' already exists")

    record = await repo.create({
        "tenant_id":       tenant_id,
        "slug":            body.slug,
        "name":            body.name,
        "description":     body.description,
        "policy_override": body.policy_override,
        "contact_email":   body.contact_email,
    })
    try:
        await db.commit()
    except IntegrityError:
        # The (tenant_id, slug) unique index is the race-safe backstop for the
        # pre-check above (two concurrent creates of the same slug).
        await db.rollback()
        raise ConflictError(
            f"A department with slug '{body.slug}' already exists"
        ) from None
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

    counts = await ApplicationRepository(db).count_active_by_dept(tenant_id)
    return JSONResponse(content={
        "departments": [_format(d, counts.get(str(d.id), 0)) for d in items],
    })


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
    _require_dept_scope(request, dept_id)

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
    decision_counts = {row.decision: row._mapping["count"] for row in decisions}

    # Average latency
    avg_latency = await db.scalar(
        sa_select(func.avg(AuditLogModel.latency_ms))
        .where(AuditLogModel.dept_id == dept_id)
    ) or 0.0

    # Top threats - aggregate in Python to avoid JSON/JSONB type issues
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
    Merges: system defaults -> tenant global -> department override.
    Useful for compliance verification.
    """
    _require_dept_scope(request, dept_id)

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
    _require_dept_scope(request, dept_id)

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
    Explicitly set null values (e.g. policy_override=null) are also applied - use this
    to clear a department's policy override back to tenant-level defaults.
    Auth: JWT + ADMIN role required.
    """
    repo     = DepartmentRepository(db)
    existing = await repo.get_by_id(uuid.UUID(dept_id))
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("department", dept_id)
    # Use exclude_unset=True so explicitly set null values (e.g. policy_override=null)
    # are included - filtering "if v is not None" would silently drop them
    data = body.model_dump(exclude_unset=True)
    if "policy_override" in data:
        try:
            validate_policy_override_urls(data["policy_override"])
        except ValueError as e:
            raise ValidationError(str(e)) from None
    record = await repo.update(uuid.UUID(dept_id), data)
    if not record:
        raise NotFoundError("department", dept_id)
    await db.commit()

    if "policy_override" in data:
        try:
            event_repo = AdminEventRepository(db)
            await event_repo.insert(
                tenant_id     = uuid.UUID(request.state.tenant_id),
                actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
                action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
                dept_id       = uuid.UUID(dept_id),
                metadata      = {"scope": "department", "dept_id": dept_id, "section": "policy_override"},
                ip_address    = get_client_ip(request),
                user_agent    = request.headers.get("user-agent"),
            )
            await db.commit()
        except Exception as e:
            # Audit-event write is best-effort; the change was committed above and
            # must not fail the request on an audit-log error.
            logger.error(
                "admin_event write failed action=policy_override_changed dept_id=%s error=%s",
                dept_id, e,
            )

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
    api_key is encrypted before storage - never stored or returned in plaintext.
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

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
            dept_id       = uuid.UUID(dept_id),
            metadata      = {"scope": "department", "dept_id": dept_id, "section": "llm", "cleared": body.clear},
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception as e:
        # Audit-event write is best-effort; the change was committed above and
        # must not fail the request on an audit-log error.
        logger.error(
            "admin_event write failed action=policy_override_changed dept_id=%s error=%s",
            dept_id, e,
        )

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

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
            dept_id       = uuid.UUID(dept_id),
            metadata      = {"scope": "department", "dept_id": dept_id, "section": "proxy_provider", "cleared": body.clear},
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception as e:
        # Audit-event write is best-effort; the change was committed above and
        # must not fail the request on an audit-log error.
        logger.error(
            "admin_event write failed action=policy_override_changed dept_id=%s error=%s",
            dept_id, e,
        )

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
