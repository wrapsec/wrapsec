# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, SecretStr, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from api.v1.middleware.auth import get_client_ip
from config.settings import get_settings
from db.repositories.admin_event import AdminEventRepository
from db.repositories.application import ApplicationRepository
from db.repositories.department import DepartmentRepository
from domain.entities.principal import Principal
from domain.enums import AdminEventAction
from errors.exceptions import NotFoundError
from security.encryption import encrypt, decrypt, mask
from services.policy_resolver import resolve_policy

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


def _format(app) -> dict:
    return {
        "id":                   str(app.id),
        "tenant_id":            str(app.tenant_id),
        "dept_id":              str(app.dept_id),
        "slug":                 app.slug,
        "name":                 app.name,
        "description":          app.description,
        "owner_name":           app.owner_name,
        "owner_email":          app.owner_email,
        "environment":          app.environment,
        "metadata":             app.metadata_,
        "policy_override":      _mask_policy_override(app.policy_override),
        "rate_limit_override":  app.rate_limit_override,
        "is_active":            app.is_active,
        "created_at":           app.created_at.isoformat(),
    }


class ApplicationCreateSchema(BaseModel):
    dept_id:            str
    slug:               str
    name:               str
    description:        str  | None = None
    owner_name:         str  | None = None
    owner_email:        str  | None = None
    environment:        str  | None = "production"
    metadata:           dict | None = None
    policy_override:    dict | None = None
    rate_limit_override: int | None = None


class ApplicationUpdateSchema(BaseModel):
    name:               str  | None = None
    description:        str  | None = None
    owner_name:         str  | None = None
    owner_email:        str  | None = None
    environment:        str  | None = None
    metadata:           dict | None = None
    policy_override:    dict | None = None
    rate_limit_override: int | None = None
    is_active:          bool | None = None


@router.post("")
async def create_application(
    body:      ApplicationCreateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    tenant_id = uuid.UUID(request.state.tenant_id)

    # Validate department belongs to authenticated tenant
    dept_repo = DepartmentRepository(db)
    dept      = await dept_repo.get_by_id(uuid.UUID(body.dept_id))
    if not dept or str(dept.tenant_id) != str(tenant_id):
        raise NotFoundError("department", body.dept_id)

    repo   = ApplicationRepository(db)
    record = await repo.create({
        "tenant_id":           tenant_id,
        "dept_id":             uuid.UUID(body.dept_id),
        "slug":                body.slug,
        "name":                body.name,
        "description":         body.description,
        "owner_name":          body.owner_name,
        "owner_email":         body.owner_email,
        "environment":         body.environment or "production",
        "metadata_":           body.metadata,
        "policy_override":     body.policy_override,
        "rate_limit_override": body.rate_limit_override,
    })
    await db.commit()
    return JSONResponse(content=_format(record), status_code=201)


@router.get("")
async def list_applications(
    request:   Request,
    dept_id:   str | None = None,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    tenant_id = uuid.UUID(request.state.tenant_id)
    repo      = ApplicationRepository(db)

    # ADMIN: filter by requested dept_id or show all
    # DEVELOPER: always scoped to own dept from state
    effective_dept = dept_id
    if not request.state.is_admin and request.state.dept_id:
        effective_dept = request.state.dept_id

    if effective_dept:
        items = await repo.list_by_dept(uuid.UUID(effective_dept))
    else:
        items = await repo.list_by_tenant(tenant_id)

    return JSONResponse(content={"applications": [_format(a) for a in items]})


@router.get("/{app_id}")
async def get_application(
    app_id:    uuid.UUID,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    repo   = ApplicationRepository(db)
    record = await repo.get_by_id(app_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))
    return JSONResponse(content=_format(record))


@router.put("/{app_id}")
async def update_application(
    app_id:    uuid.UUID,
    body:      ApplicationUpdateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    repo    = ApplicationRepository(db)
    existing = await repo.get_by_id(app_id)
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    if "metadata" in data:
        data["metadata_"] = data.pop("metadata")
    record = await repo.update(app_id, data)
    if not record:
        raise NotFoundError("application", str(app_id))
    await db.commit()

    if "policy_override" in data:
        try:
            event_repo = AdminEventRepository(db)
            await event_repo.insert(
                tenant_id     = uuid.UUID(request.state.tenant_id),
                actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
                action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
                dept_id       = record.dept_id,
                metadata      = {"scope": "application", "app_id": str(app_id), "dept_id": str(record.dept_id), "section": "policy_override"},
                ip_address    = get_client_ip(request),
                user_agent    = request.headers.get("user-agent"),
            )
            await db.commit()
        except Exception:
            pass

    return JSONResponse(content=_format(record))


@router.delete("/{app_id}")
async def delete_application(
    app_id:    uuid.UUID,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    repo     = ApplicationRepository(db)
    existing = await repo.get_by_id(app_id)
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))
    record = await repo.update(app_id, {"is_active": False})
    if not record:
        raise NotFoundError("application", str(app_id))
    await db.commit()
    return JSONResponse(content={"app_id": str(app_id), "deactivated": True})

@router.get("/{app_id}/policy")
async def get_application_policy(
    app_id:    uuid.UUID,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),
):
    """
    Returns the fully resolved effective policy for this application.
    Merges: system defaults → tenant global → department → application.
    Application overrides are currently null for most keys — set via policy_override field.
    """
    repo = ApplicationRepository(db)
    app  = await repo.get_by_id(app_id)
    if not app or str(app.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))

    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = str(app.tenant_id),
        dept_id   = str(app.dept_id),
        app_id    = str(app_id),
    )

    return JSONResponse(content={
        "app_id":          str(app_id),
        "app_name":        app.name,
        "dept_id":         str(app.dept_id),
        "policy_source":   policy_source,
        "override_set":    app.policy_override is not None,
        "policy_override": _mask_policy_override(app.policy_override),
        "resolved_policy": policy,
    })

class ApplicationPolicySchema(BaseModel):
    policy_override: dict | None = None


@router.put("/{app_id}/policy")
async def set_application_policy(
    app_id:    uuid.UUID,
    body:      ApplicationPolicySchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Set or update application-level policy override.
    Merged on top of department policy during request processing.
    Pass policy_override: null to remove all overrides.
    """
    repo   = ApplicationRepository(db)
    record = await repo.get_by_id(app_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))

    record = await repo.update(app_id, {
        "policy_override": body.policy_override
    })
    await db.commit()

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
            dept_id       = record.dept_id,
            metadata      = {"scope": "application", "app_id": str(app_id), "dept_id": str(record.dept_id), "section": "full", "cleared": body.policy_override is None},
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception:
        pass

    policy, policy_source = await resolve_policy(
        db        = db,
        tenant_id = str(record.tenant_id),
        dept_id   = str(record.dept_id),
        app_id    = str(app_id),
    )

    return JSONResponse(content={
        "app_id":          str(app_id),
        "app_name":        record.name,
        "dept_id":         str(record.dept_id),
        "policy_override": _mask_policy_override(record.policy_override),
        "policy_source":   policy_source,
        "resolved_policy": policy,
        "updated":         True,
    })


@router.delete("/{app_id}/policy")
async def reset_application_policy(
    app_id:    uuid.UUID,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Reset application policy override to null.
    Application will inherit from department policy.
    """
    repo   = ApplicationRepository(db)
    record = await repo.get_by_id(app_id)
    if not record or str(record.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))

    await repo.update(app_id, {"policy_override": None})
    await db.commit()

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
            dept_id       = record.dept_id,
            metadata      = {"scope": "application", "app_id": str(app_id), "dept_id": str(record.dept_id), "section": "full", "cleared": True},
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception:
        pass

    return JSONResponse(content={
        "app_id":          str(app_id),
        "app_name":        record.name,
        "policy_override": None,
        "reset":           True,
        "message":         "Application policy override removed. Inheriting from department.",
    })


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


class AppLLMOverrideSchema(BaseModel):
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


class AppProxyOverrideSchema(BaseModel):
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


@router.patch("/{app_id}/policy/llm")
async def update_app_llm_override(
    app_id:    uuid.UUID,
    body:      AppLLMOverrideSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Set or clear the LLM detection override for an application.
    Takes precedence over department-level LLM override.
    api_key is encrypted before storage — never stored or returned in plaintext.
    Set clear=true to remove and inherit from the department.
    Auth: JWT + ADMIN role required.
    """
    repo     = ApplicationRepository(db)
    existing = await repo.get_by_id(app_id)
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))

    override = dict(existing.policy_override or {})

    if body.clear:
        override.pop("llm", None)
    else:
        current = dict(override.get("llm") or {})
        if body.provider is not None: current["provider"] = body.provider
        if body.model    is not None: current["model"]    = body.model
        if body.base_url is not None: current["base_url"] = body.base_url
        if body.timeout  is not None: current["timeout"]  = body.timeout
        if body.api_key is not None:
            raw = body.api_key.get_secret_value().strip()
            if raw:
                current["api_key_enc"] = encrypt(raw, get_settings().secret_key)
            else:
                current.pop("api_key_enc", None)
        if current:
            override["llm"] = current

    record = await repo.update(app_id, {"policy_override": override or None})
    if not record:
        raise NotFoundError("application", str(app_id))
    await db.commit()

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
            dept_id       = record.dept_id,
            metadata      = {"scope": "application", "app_id": str(app_id), "dept_id": str(record.dept_id), "section": "llm", "cleared": body.clear},
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception:
        pass

    return JSONResponse(content=_format(record))


@router.patch("/{app_id}/policy/proxy")
async def update_app_proxy_override(
    app_id:    uuid.UUID,
    body:      AppProxyOverrideSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),
):
    """
    Set or clear the proxy provider override for an application.
    Takes precedence over department-level proxy override for proxy mode requests.
    api_key is encrypted before storage — never stored or returned in plaintext.
    Set clear=true to fall back to the department-level proxy override.
    Auth: JWT + ADMIN role required.
    """
    repo     = ApplicationRepository(db)
    existing = await repo.get_by_id(app_id)
    if not existing or str(existing.tenant_id) != request.state.tenant_id:
        raise NotFoundError("application", str(app_id))

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

    record = await repo.update(app_id, {"policy_override": override or None})
    if not record:
        raise NotFoundError("application", str(app_id))
    await db.commit()

    try:
        event_repo = AdminEventRepository(db)
        await event_repo.insert(
            tenant_id     = uuid.UUID(request.state.tenant_id),
            actor_user_id = uuid.UUID(str(principal.id).replace("user:", "")),
            action        = AdminEventAction.POLICY_OVERRIDE_CHANGED,
            dept_id       = record.dept_id,
            metadata      = {"scope": "application", "app_id": str(app_id), "dept_id": str(record.dept_id), "section": "proxy_provider", "cleared": body.clear},
            ip_address    = get_client_ip(request),
            user_agent    = request.headers.get("user-agent"),
        )
        await db.commit()
    except Exception:
        pass

    return JSONResponse(content=_format(record))