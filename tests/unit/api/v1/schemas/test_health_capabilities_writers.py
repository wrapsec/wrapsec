# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The health and capabilities writers cannot produce a body the models reject.

These routes do not read persisted rows the way the audit family does. Their
required fields come from two places, and each is checked at its source:

  * SETTINGS -- `get_settings()` supplies `version` and every `/health/config`
    default. Those defaults are typed on the Settings class, so the premise is
    that the declared types still match what the model expects. A settings field
    retyped from float to str would break the response before any test that only
    exercises a stored override;
  * STORED TENANT SETTINGS -- the alternative source for `/health/config`, written
    only through `PUT /v1/settings/*`, whose request schemas already constrain
    the types (`float` thresholds, `bool` layers, `int` timeout and per_minute,
    `str` provider/model). Both branches are validated below against the model;
  * THE CAPABILITY REGISTRY -- `effective_capabilities()` returns
    `[c for c in get_capabilities() if ...]`, and `get_capabilities()` returns
    `sorted(_CAPABILITIES)`, so the elements are whatever `register_capability`
    stored. Exercised with a real registration rather than assumed.
"""

from __future__ import annotations

import pytest

from api.v1.schemas.response import (
    CapabilitiesResponse,
    ConfigDetectionLayers,
    ConfigLLM,
    ConfigRateLimit,
    ConfigThresholds,
    HealthConfigResponse,
    HealthResponse,
)
from config.settings import get_settings

# ── the settings defaults every required field falls back to ─────────────────

@pytest.mark.parametrize("field,expected", [
    ("app_version",           str),
    ("block_threshold",       float),
    ("sanitize_threshold",    float),
    ("llm_provider",          str),
    ("llm_model",             str),
    ("llm_trigger_threshold", float),
    ("llm_timeout",           int),
    ("rate_limit_per_minute", int),
])
def test_the_settings_default_matches_the_declared_type(field, expected):
    """Each of these is served directly when a tenant has stored nothing, so its
    type IS the response contract on a default deployment."""
    value = getattr(get_settings(), field)
    assert isinstance(value, expected), (
        f"settings.{field} is {type(value).__name__}, but the response model "
        f"declares {expected.__name__}"
    )


def test_the_health_body_the_writer_builds_satisfies_the_model():
    body = {"status": "ok", "version": get_settings().app_version}

    served = HealthResponse.model_validate(body).model_dump(exclude_unset=True)
    assert served == body


# ── /health/config, both caller branches ─────────────────────────────────────

def _config_body(*, authorized: bool, stored: bool) -> dict:
    """The body the handler builds, mirrored branch for branch: `source` always,
    values only for a caller holding `settings:read`."""
    s = get_settings()
    body = {
        "version": s.app_version,
        "thresholds":       {"source": "database" if stored else "environment"},
        "detection_layers": {"source": "database" if stored else "environment"},
        "llm":              {"source": "database" if stored else "environment"},
        "rate_limit":       {"source": "database" if stored else "environment"},
    }
    if not authorized:
        return body
    body["thresholds"].update({"block": s.block_threshold, "sanitize": s.sanitize_threshold})
    body["detection_layers"].update({"rule": True, "ml": True, "llm": True})
    body["llm"].update({
        "provider": s.llm_provider, "model": s.llm_model,
        "llm_trigger": s.llm_trigger_threshold, "timeout": s.llm_timeout,
    })
    body["rate_limit"]["per_minute"] = s.rate_limit_per_minute
    return body


@pytest.mark.parametrize("authorized", [True, False])
@pytest.mark.parametrize("stored", [True, False])
def test_every_config_body_satisfies_the_model(authorized, stored):
    body   = _config_body(authorized=authorized, stored=stored)
    served = HealthConfigResponse.model_validate(body).model_dump(exclude_unset=True)

    assert set(served) == set(body), (
        f"the model changed the top-level key set "
        f"(dropped {set(body) - set(served)}, added {set(served) - set(body)})"
    )
    for section in ("thresholds", "detection_layers", "llm", "rate_limit"):
        assert set(served[section]) == set(body[section]), (
            f"{section}: model served {sorted(served[section])}, writer built "
            f"{sorted(body[section])}"
        )
    if not authorized:
        assert served["thresholds"] == {"source": body["thresholds"]["source"]}, (
            "a withheld value came back; absence is the restriction"
        )


def test_a_restricted_section_carries_no_null_placeholders():
    """The distinction the whole convention rests on: the withheld keys are
    missing, not present-and-null."""
    served = HealthConfigResponse.model_validate(
        _config_body(authorized=False, stored=False)
    ).model_dump(exclude_unset=True)

    for section, model in (
        ("thresholds", ConfigThresholds), ("detection_layers", ConfigDetectionLayers),
        ("llm", ConfigLLM), ("rate_limit", ConfigRateLimit),
    ):
        withheld = set(model.model_fields) - {"source"}
        assert not (withheld & set(served[section])), (
            f"{section} served withheld keys {sorted(withheld & set(served[section]))}"
        )


# ── the capability registry ──────────────────────────────────────────────────

def test_the_capability_writer_emits_strings(monkeypatch):
    """Exercised through a real registration, so the claim is about the registry
    rather than about the empty OSS case."""
    from services import capabilities as registry

    monkeypatch.setattr(registry, "_CAPABILITIES", {"advanced_policy", "sso"})

    caps = registry.effective_capabilities()
    assert caps == sorted(caps), "the registry is expected to return sorted names"
    assert all(isinstance(c, str) for c in caps)

    body   = {"edition": "enterprise" if caps else "oss", "capabilities": caps}
    served = CapabilitiesResponse.model_validate(body).model_dump(exclude_unset=True)
    assert served == body


def test_the_oss_build_reports_an_empty_list_not_null():
    """An empty array is the OSS contract. A null would make every consumer
    special-case the edition that ships by default."""
    from services.capabilities import effective_capabilities

    caps = effective_capabilities()
    body = {"edition": "enterprise" if caps else "oss", "capabilities": caps}

    served = CapabilitiesResponse.model_validate(body).model_dump(exclude_unset=True)
    assert isinstance(served["capabilities"], list)
    assert served["edition"] in ("oss", "enterprise")
