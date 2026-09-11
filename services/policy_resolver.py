# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import logging
import uuid

from config.settings import get_settings
from db.repositories.application import ApplicationRepository
from db.repositories.department import DepartmentRepository
from errors.exceptions import PolicyResolutionDegraded
from security.encryption import decrypt

logger = logging.getLogger("wrapsec.policy")


# ── System defaults ────────────────────────────────────────────
def system_defaults() -> dict:
    # F-6: get_settings() per-call to honor the documented invariant that
    # settings are reloaded on each call (supports key rotation and test
    # isolation). Called once per request via resolve_policy(), so the
    # overhead is negligible compared to the DB reads that follow.
    settings = get_settings()
    return {
        "detection": {
            "rule_weight":   0.4,
            "ml_weight":     0.3,
            "llm_weight":    0.3,
            "rule_enabled":  True,
            "ml_enabled":    True,
            "llm_enabled":   True,
            "llm_trigger":   settings.llm_trigger_threshold,
        },
        "thresholds": {
            "block":    settings.block_threshold,
            "sanitize": settings.sanitize_threshold,
        },
        "guardrails": {
            "pii": {
                "enabled":            True,
                "block_threshold":    settings.block_threshold,
                "sanitize_threshold": settings.sanitize_threshold,
            }
        },
        "llm": {
            "provider":  settings.llm_provider,
            "model":     settings.llm_model,
            "base_url":  settings.llm_base_url,
            "timeout":   settings.llm_timeout,
        },
        "rate_limit": {
            "per_minute": 60,
        },
    }


# ── Deep merge ─────────────────────────────────────────────────
def deep_merge(parent: dict, child: dict | None) -> dict:
    """
    Recursively merge child into parent.
    Only non-null fields in child override parent.
    Missing or null fields in child preserve parent values.
    """
    if child is None:
        return parent

    result = parent.copy()

    for key, value in child.items():
        if value is None:
            # Null field - inherit from parent
            continue
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            # Nested dict - recurse
            result[key] = deep_merge(result[key], value)
        else:
            # Scalar - override
            result[key] = value

    return result


# ── Policy source ──────────────────────────────────────────────
def determine_policy_source(
    dept_override: dict | None,
    app_override:  dict | None,
) -> str:
    """
    Returns the highest priority level that changed any field.
    tenant global_policy is no longer used - DB settings table is authoritative.
    """
    if app_override:
        return "application_override"
    if dept_override:
        return "department_override"
    return "system_default"


# ── Resolve policy ─────────────────────────────────────────────
async def resolve_policy(
    db,
    tenant_id: str | None = None,
    dept_id:   str | None = None,
    app_id:    str | None = None,
) -> tuple[dict, str]:
    """
    Resolve the effective policy for a request.
    Returns (resolved_policy, policy_source).

    Resolution order:
      system defaults
        -> DB settings (policy_thresholds, detection_layers, llm_settings, rate_limit)
          -> department policy_override
            -> application policy_override
    """
    # F-6: get_settings() per-call so key rotation and test overrides land
    # inside a single request scope (secret_key for decryption, threshold
    # fallback values). system_defaults() also fetches its own snapshot.
    settings = get_settings()

    # The fallback, and never mutated. Everything below builds a SEPARATE
    # working copy and commits it only when the whole load completes, so the
    # failure result is always exactly the defaults.
    #
    # This is defence in depth, not a live bug fix, and the distinction is
    # worth keeping accurate. The four stored reads are hoisted above the
    # assignments that consume them, so today a read failure lands before any
    # layer has been written and the old in-place code also returned clean
    # defaults. The invariant held by ACCIDENT OF STATEMENT ORDER: move one
    # read below one assignment -- or add a fifth setting and read it where it
    # is used -- and a failure starts returning a mixture of this tenant's
    # settings and the system's, with the split depending on which read failed.
    # Building into a working copy makes the invariant structural instead.
    policy   = system_defaults()
    resolved = system_defaults()

    dept_override   = None
    app_override    = None

    # Every layer that failed to load. A non-empty list means the effective
    # policy is UNKNOWN, not "the defaults": the tenant may have tightened,
    # loosened or changed nothing, and a failed read cannot tell those apart.
    failed_layers: list[str] = []

    try:
        # Load DB settings layered env-default -> platform_settings -> tenant_settings
        # (D5 two-table split). Tenant values override platform defaults per key;
        # both override the system defaults applied below.
        from db.repositories.settings import (
            PlatformSettingsRepository,
            TenantSettingsRepository,
        )
        platform_repo = PlatformSettingsRepository(db)
        tenant_repo   = TenantSettingsRepository(db)
        tid           = uuid.UUID(str(tenant_id)) if tenant_id else None

        async def _layered(key: str) -> dict:
            base = await platform_repo.get(key) or {}
            if tid is not None:
                override = await tenant_repo.get(tid, key) or {}
                return {**base, **override}
            return base

        stored_thresholds = await _layered("policy_thresholds")
        stored_layers     = await _layered("detection_layers")
        stored_llm        = await _layered("llm_settings")
        stored_rate_limit = await _layered("rate_limit")

        # Apply global DB settings as tenant-level defaults
        if stored_thresholds:
            resolved["thresholds"]["block"]    = stored_thresholds.get("block_threshold",    resolved["thresholds"]["block"])
            resolved["thresholds"]["sanitize"] = stored_thresholds.get("sanitize_threshold", resolved["thresholds"]["sanitize"])
            resolved["guardrails"]["pii"]["block_threshold"]    = resolved["thresholds"]["block"]
            resolved["guardrails"]["pii"]["sanitize_threshold"] = resolved["thresholds"]["sanitize"]

        if stored_layers:
            resolved["detection"]["rule_enabled"] = stored_layers.get("rule_enabled", True)
            resolved["detection"]["ml_enabled"]   = stored_layers.get("ml_enabled",   True)
            resolved["detection"]["llm_enabled"]  = stored_layers.get("llm_enabled",  True)

        if stored_llm:
            resolved["llm"]["provider"] = stored_llm.get("provider", resolved["llm"]["provider"])
            resolved["llm"]["model"]    = stored_llm.get("model",    resolved["llm"]["model"])
            resolved["llm"]["base_url"] = stored_llm.get("base_url", resolved["llm"]["base_url"])
            resolved["llm"]["timeout"]  = stored_llm.get("timeout",  resolved["llm"]["timeout"])
            resolved["detection"]["llm_trigger"] = stored_llm.get("llm_trigger", resolved["detection"]["llm_trigger"])

        if stored_rate_limit:
            resolved["rate_limit"]["per_minute"] = stored_rate_limit.get("per_minute", resolved["rate_limit"]["per_minute"])

        # Tenant global_policy - intentionally skipped.
        # global_policy on the tenant is kept in the DB for future use
        # but is NOT applied in policy resolution. DB settings table
        # (policy_thresholds, detection_layers, llm_settings, rate_limit)
        # is the authoritative source for global settings.
        # Per-dept and per-app overrides use dept/app policy_override instead.

        # Department policy_override
        if dept_id:
            try:
                dept_repo = DepartmentRepository(db)
                dept      = await dept_repo.get_by_id(uuid.UUID(str(dept_id)))
                # Same ownership check the application branch applies below. A
                # department id is not a tenant boundary on its own: nothing in
                # the schema ties api_keys.dept_id to api_keys.tenant_id, so a
                # department carrying a foreign tenant would otherwise have its
                # thresholds applied to this tenant's traffic.
                if dept and tenant_id and str(dept.tenant_id) != str(tenant_id):
                    logger.error(
                        "policy dept_tenant_mismatch dept_id=%s dept.tenant=%s "
                        "request.tenant=%s - skipping dept policy",
                        dept_id, dept.tenant_id, tenant_id,
                    )
                    dept = None
                if dept and dept.policy_override:
                    dept_override = dept.policy_override
                    resolved      = deep_merge(resolved, dept_override)
            except Exception as e:
                # NOT a warning-and-continue. A department override that failed
                # to load may have TIGHTENED this tenant's policy; continuing
                # would serve the un-tightened base as though it were the
                # resolved answer, which is the same defect one layer down.
                logger.error(f"Failed to load department policy: {e}")
                failed_layers.append("department")

        # Application policy_override - applied if set; null inherits from department
        if app_id:
            try:
                app_repo = ApplicationRepository(db)
                app      = await app_repo.get_by_id(uuid.UUID(str(app_id)))
                if app and tenant_id and str(app.tenant_id) != str(tenant_id):
                    logger.error(
                        "policy app_tenant_mismatch app_id=%s app.tenant=%s "
                        "request.tenant=%s - skipping app policy",
                        app_id, app.tenant_id, tenant_id,
                    )
                    app = None
                if app and app.policy_override:
                    app_override = app.policy_override
                    resolved     = deep_merge(resolved, app_override)
                # rate_limit_override is a dedicated integer column - enforced separately
                # from policy_override so it doesn't require JSONB knowledge to set.
                if app and app.rate_limit_override is not None:
                    resolved["rate_limit"]["per_minute"] = app.rate_limit_override
            except Exception as e:
                logger.error(f"Failed to load application policy: {e}")
                failed_layers.append("application")

        # Reached only when every layer above loaded. `policy` keeps the pure
        # defaults until this point, so the except below needs no cleanup.
        policy = resolved

    except Exception as e:
        logger.error(f"Policy resolution failed: {e} - effective policy is UNKNOWN")
        failed_layers.append("tenant")
        try:
            from observability.metrics import SYSTEM_ERRORS
            SYSTEM_ERRORS.labels(execution_mode="unknown").inc()
        except Exception:
            pass  # Metrics increment is best-effort inside the fallback handler.

    # Plugin policy layers (2.9): a final ceiling applied after core resolution,
    # so a plan/entitlement layer can clamp even an app override. OSS registers
    # none, so this is skipped entirely and the resolved policy is byte-identical
    # to before the hook existed. Fail-open lives inside apply_policy_layers.
    from services.policy_layers import registered_policy_layers
    if registered_policy_layers():
        from services.policy_layers import PolicyContext, apply_policy_layers
        policy = await apply_policy_layers(
            policy,
            PolicyContext(db=db, tenant_id=tenant_id, dept_id=dept_id, app_id=app_id),
        )

    # Decrypt any api_key_enc fields that were merged in from dept/app overrides.
    # api_key_enc is stored encrypted in policy_override; callers need plaintext api_key.
    for section in ("llm", "proxy_provider"):
        sec = policy.get(section)
        if isinstance(sec, dict) and "api_key_enc" in sec:
            enc = sec.pop("api_key_enc")
            try:
                sec["api_key"] = decrypt(enc, settings.secret_key)
            except ValueError:
                logger.error(
                    "policy api_key_enc decryption failed section=%r - "
                    "provider credentials are invalid (SECRET_KEY mismatch or corrupted value). "
                    "Re-enter the provider API key via the dashboard.",
                    section,
                )
                raise ValueError(
                    f"Provider API key for section '{section}' could not be decrypted. "
                    "The stored credential is invalid. Re-enter it via Settings."
                ) from None

    # Validate final thresholds - DB or override values could be inconsistent
    block    = policy["thresholds"]["block"]
    sanitize = policy["thresholds"]["sanitize"]
    if not (0.0 < sanitize < block <= 1.0):
        logger.error(
            "Resolved thresholds invalid (block=%.2f sanitize=%.2f) - "
            "reverting to system defaults",
            block, sanitize,
        )
        policy["thresholds"]["block"]    = settings.block_threshold
        policy["thresholds"]["sanitize"] = settings.sanitize_threshold

    policy_source = determine_policy_source(
        dept_override, app_override
    )

    if failed_layers:
        # Fail closed. The caller asked for the effective policy and there is
        # no honest answer: serving the defaults here is precisely the silent
        # relaxation this refuses to perform.
        #
        # Raising rather than returning a flag is deliberate. A returned flag
        # can be ignored by a caller that never reads it, and the failure mode
        # of ignoring it is to enforce under an unverified policy. An exception
        # cannot be ignored by accident, and an enforcement path that does
        # nothing about it fails SAFE.
        raise PolicyResolutionDegraded(failed_layers)

    return policy, policy_source


async def resolve_policy_for_preview(
    db,
    tenant_id: str | None = None,
    dept_id:   str | None = None,
    app_id:    str | None = None,
) -> tuple[dict, str, bool]:
    """Resolve for DISPLAY, tolerating a degraded result.

    For callers that render a policy without applying it. They are not deciding
    anything, so refusing them helps nobody -- but they must not present system
    defaults as though they were the tenant's resolved policy.

    Returns (policy, policy_source, degraded). The three-element return is the
    point: a caller cannot receive a degraded policy from this function without
    also receiving the fact that it is degraded, and cannot unpack it into the
    two-element form the enforcement path uses.

    NEVER call this from an enforcement path. `resolve_policy` is the one that
    decides, and it refuses.
    """
    try:
        policy, source = await resolve_policy(
            db, tenant_id=tenant_id, dept_id=dept_id, app_id=app_id,
        )
        return policy, source, False
    except PolicyResolutionDegraded as degraded:
        logger.warning(
            "policy preview degraded tenant=%s failed_layers=%s - "
            "rendering system defaults, marked degraded",
            tenant_id, degraded.failed_layers,
        )
        return system_defaults(), "degraded", True