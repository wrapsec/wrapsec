# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.dependencies.auth import get_current_principal, require_admin
from api.v1.dependencies.db import get_db
from db.repositories.tenant import TenantRepository
from domain.entities.principal import Principal
from services.localization import validate_locale_input
from services.time import to_iso_z

router = APIRouter()


async def _resolve_caller_tenant(repo: TenantRepository, request: Request):
    """Resolve the caller's OWN tenant from the authenticated identity.

    Every tenant-profile read/write is scoped to request.state.tenant_id -- never
    a fixed 'default' tenant -- so a tenant admin can only ever view or modify
    their own tenant, not a shared/other one.
    """
    tid = getattr(request.state, "tenant_id", None)
    if not tid:
        return None
    try:
        return await repo.get_by_id(uuid.UUID(str(tid)))
    except (ValueError, TypeError):
        return None


def _format(tenant, is_admin: bool = False) -> dict:
    result = {
        "id":            str(tenant.id),
        "slug":          tenant.slug,
        "name":          tenant.name,
        "description":   tenant.description,
        "contact_email": tenant.contact_email,
        "is_active":     tenant.is_active,
        "created_at":    to_iso_z(tenant.created_at),
        "locale":        tenant.locale,
    }
    if is_admin:
        result["global_policy"] = tenant.global_policy
    return result


# ── Policy schema - mirrors system_defaults() in policy_resolver.py ──────────
# All fields optional - only provided keys are merged into the active policy.
# extra="forbid" rejects unknown keys, preventing injection of arbitrary fields.

class _ThresholdsPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    block:    float | None = Field(None, gt=0.0, le=1.0)
    sanitize: float | None = Field(None, ge=0.0, lt=1.0)

    @model_validator(mode="after")
    def block_gt_sanitize(self) -> "_ThresholdsPolicy":
        if self.block is not None and self.sanitize is not None and self.block <= self.sanitize:
            raise ValueError("block must be greater than sanitize")
        return self


class _DetectionPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    rule_enabled: bool | None = None
    ml_enabled:   bool | None = None
    llm_enabled:  bool | None = None


class _PiiPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    enabled:            bool  | None = None
    block_threshold:    float | None = Field(None, gt=0.0, le=1.0)
    sanitize_threshold: float | None = Field(None, ge=0.0, lt=1.0)


class _ToxicityPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    enabled:            bool  | None = None
    block_threshold:    float | None = Field(None, gt=0.0, le=1.0)
    sanitize_threshold: float | None = Field(None, ge=0.0, lt=1.0)


class _GuardrailsPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    pii:      _PiiPolicy      | None = None
    toxicity: _ToxicityPolicy | None = None


class _RateLimitPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    per_minute: int | None = Field(None, ge=1, le=10000)


class GlobalPolicySchema(BaseModel):
    model_config = {"extra": "forbid"}
    thresholds: _ThresholdsPolicy  | None = None
    detection:  _DetectionPolicy   | None = None
    guardrails: _GuardrailsPolicy  | None = None
    rate_limit: _RateLimitPolicy   | None = None


class TenantUpdateSchema(BaseModel):
    name:          str                | None = None
    description:   str                | None = None
    contact_email: str                | None = None
    global_policy: GlobalPolicySchema | None = None
    # Tenant default locale (BCP-47). Validated against the supported-locales
    # allowlist; an unsupported value is rejected 422 INVALID_ENUM. max_length
    # mirrors the tenants.locale VARCHAR(35) column and caps an oversized string
    # before the allowlist validator runs (same boundary as MePatchSchema).
    locale:        str                | None = Field(default=None, max_length=35)

    @field_validator("locale")
    @classmethod
    def _valid_locale(cls, v: str | None) -> str | None:
        return validate_locale_input(v)


@router.get("")
async def get_tenant(
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    _principal: Principal    = Depends(get_current_principal),
):
    """
    Returns tenant profile. global_policy is only returned to admin principals -
    non-admins see metadata without the security policy configuration.
    Scoped to the caller's own tenant. Auth: any valid principal.
    """
    repo   = TenantRepository(db)
    tenant = await _resolve_caller_tenant(repo, request)
    if not tenant:
        return JSONResponse(content={"error": "No tenant found"}, status_code=404)
    return JSONResponse(content=_format(tenant, is_admin=getattr(_principal, "is_admin", False)))


@router.put("")
async def update_tenant(
    body:      TenantUpdateSchema,
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    _principal: Principal   = Depends(require_admin()),
):
    """
    Partially updates tenant metadata: name, description, contact_email, global_policy.
    Only fields present in the request body are updated. Scoped to the caller's
    own tenant. Auth: JWT + ADMIN role required.
    """
    repo   = TenantRepository(db)
    tenant = await _resolve_caller_tenant(repo, request)
    if not tenant:
        return JSONResponse(content={"error": "No tenant found"}, status_code=404)

    if body.name          is not None: tenant.name          = body.name
    if body.description   is not None: tenant.description   = body.description
    if body.contact_email is not None: tenant.contact_email = body.contact_email
    if body.locale        is not None: tenant.locale        = body.locale
    if body.global_policy is not None:
        tenant.global_policy = body.global_policy.model_dump(exclude_none=True)

    await db.commit()
    await db.refresh(tenant)
    return JSONResponse(content=_format(tenant, is_admin=True))