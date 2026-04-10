import logging
from db.repositories.tenant import TenantRepository
from db.repositories.department import DepartmentRepository
from db.repositories.application import ApplicationRepository
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.policy")
settings = get_settings()


# ── System defaults ────────────────────────────────────────────
def system_defaults() -> dict:
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
            # Null field — inherit from parent
            continue
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            # Nested dict — recurse
            result[key] = deep_merge(result[key], value)
        else:
            # Scalar — override
            result[key] = value

    return result


# ── Policy source ──────────────────────────────────────────────
def determine_policy_source(
    tenant_override: dict | None,
    dept_override:   dict | None,
    app_override:    dict | None,
) -> str:
    """
    Returns the highest priority level that changed any field.
    """
    if app_override:
        return "application_override"
    if dept_override:
        return "department_override"
    if tenant_override and tenant_override != {}:
        return "tenant_global"
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
        → tenant global_policy
          → department policy_override
            → application policy_override (v1.1)
    """
    import uuid

    policy = system_defaults()

    tenant_override = None
    dept_override   = None
    app_override    = None

    try:
        # Load DB settings (global thresholds + layers override system defaults)
        from db.repositories.settings import SettingsRepository
        settings_repo     = SettingsRepository(db)
        stored_thresholds = await settings_repo.get("policy_thresholds") or {}
        stored_layers     = await settings_repo.get("detection_layers")  or {}
        stored_llm        = await settings_repo.get("llm_settings")      or {}

        # Apply global DB settings as tenant-level defaults
        if stored_thresholds:
            policy["thresholds"]["block"]    = stored_thresholds.get("block_threshold",    policy["thresholds"]["block"])
            policy["thresholds"]["sanitize"] = stored_thresholds.get("sanitize_threshold", policy["thresholds"]["sanitize"])
            policy["guardrails"]["pii"]["block_threshold"]    = policy["thresholds"]["block"]
            policy["guardrails"]["pii"]["sanitize_threshold"] = policy["thresholds"]["sanitize"]

        if stored_layers:
            policy["detection"]["rule_enabled"] = stored_layers.get("rule_enabled", True)
            policy["detection"]["ml_enabled"]   = stored_layers.get("ml_enabled",   True)
            policy["detection"]["llm_enabled"]  = stored_layers.get("llm_enabled",  True)

        if stored_llm:
            policy["llm"]["provider"] = stored_llm.get("provider", policy["llm"]["provider"])
            policy["llm"]["model"]    = stored_llm.get("model",    policy["llm"]["model"])
            policy["llm"]["base_url"] = stored_llm.get("base_url", policy["llm"]["base_url"])
            policy["llm"]["timeout"]  = stored_llm.get("timeout",  policy["llm"]["timeout"])
            policy["detection"]["llm_trigger"] = stored_llm.get("llm_trigger", policy["detection"]["llm_trigger"])

        # Tenant global_policy
        if tenant_id:
            try:
                tenant_repo = TenantRepository(db)
                tenant      = await tenant_repo.get_by_id(uuid.UUID(str(tenant_id)))
                if tenant and tenant.global_policy:
                    tenant_override = tenant.global_policy
                    policy          = deep_merge(policy, tenant_override)
            except Exception as e:
                logger.warning(f"Failed to load tenant policy: {e}")

        # Department policy_override
        if dept_id:
            try:
                dept_repo = DepartmentRepository(db)
                dept      = await dept_repo.get_by_id(uuid.UUID(str(dept_id)))
                if dept and dept.policy_override:
                    dept_override = dept.policy_override
                    policy        = deep_merge(policy, dept_override)
            except Exception as e:
                logger.warning(f"Failed to load department policy: {e}")

        # Application policy_override (null in v1 — placeholder)
        if app_id:
            try:
                app_repo = ApplicationRepository(db)
                app      = await app_repo.get_by_id(uuid.UUID(str(app_id)))
                if app and app.policy_override:
                    app_override = app.policy_override
                    policy       = deep_merge(policy, app_override)
            except Exception as e:
                logger.warning(f"Failed to load application policy: {e}")

    except Exception as e:
        logger.error(f"Policy resolution failed: {e} — using system defaults")

    policy_source = determine_policy_source(
        tenant_override, dept_override, app_override
    )

    return policy, policy_source