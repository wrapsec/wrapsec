# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The public settings writers cannot produce a body the models reject.

Every one of these responses is `stored or default`, so each family has two
writer branches and both are exercised here from the smallest valid state.

WHY EVERY FIELD CAN BE REQUIRED. A stored dict is written only by that family's
own PUT handler -- four `repo.set` call sites, all in `settings.py`, and nothing
else in the repository writes those keys. Each handler starts from the family's
default and overwrites named keys, so a stored dict always carries the full key
set.

AND THE LEGACY QUESTION, checked rather than assumed: the key sets have never
changed. `_default_llm()` looks new because v1.5.2 converted a module-level
`DEFAULT_LLM` dict into a function -- the no-module-level-settings fix -- but the
five keys were identical before and after, and the same is true of thresholds,
layers and rate_limit. So no stored dict written by an earlier build can lack a
field these models require.

NO CREDENTIAL FIELD EXISTS ON ANY OF THESE MODELS. The request side accepts an
`api_key`; the response side carries `api_key_masked` and nothing else. That is
asserted directly at the bottom.
"""

from __future__ import annotations

import pytest

from api.v1.schemas.response import (
    DetectionLayersResponse,
    DetectionLayersUpdatedResponse,
    LLMSettingsResponse,
    LLMSettingsUpdatedResponse,
    ProxyProviderConfigResponse,
    RateLimitResponse,
    RateLimitUpdatedResponse,
    ThresholdsResponse,
    ThresholdsUpdatedResponse,
)
from config.settings import get_settings
from services.time import to_iso_z, utc_now

_NOW = to_iso_z(utc_now())


# ── each family, environment branch and database branch ──────────────────────

def _thresholds_default() -> dict:
    s = get_settings()
    return {"block_threshold": s.block_threshold, "sanitize_threshold": s.sanitize_threshold}


def _llm_default() -> dict:
    s = get_settings()
    return {"provider": s.llm_provider, "model": s.llm_model, "base_url": s.llm_base_url,
            "timeout": s.llm_timeout, "llm_trigger": s.llm_trigger_threshold}


_CASES = [
    # (label, GET body, GET model, PUT model)
    ("thresholds/environment", _thresholds_default(), ThresholdsResponse, ThresholdsUpdatedResponse),
    ("thresholds/stored",      {"block_threshold": 0.9, "sanitize_threshold": 0.2},
                               ThresholdsResponse, ThresholdsUpdatedResponse),
    ("thresholds/boundary",    {"block_threshold": 1.0, "sanitize_threshold": 0.000001},
                               ThresholdsResponse, ThresholdsUpdatedResponse),
    ("layers/environment",     {"rule_enabled": True, "ml_enabled": True, "llm_enabled": True},
                               DetectionLayersResponse, DetectionLayersUpdatedResponse),
    ("layers/all_disabled",    {"rule_enabled": False, "ml_enabled": False, "llm_enabled": False},
                               DetectionLayersResponse, DetectionLayersUpdatedResponse),
    ("rate_limit/environment", {"per_minute": get_settings().rate_limit_per_minute, "source": "environment"},
                               RateLimitResponse, RateLimitUpdatedResponse),
    ("rate_limit/stored",      {"per_minute": 1, "source": "database"},
                               RateLimitResponse, RateLimitUpdatedResponse),
]


@pytest.mark.parametrize("label,body,get_model,_put_model", _CASES)
def test_every_read_body_the_writer_produces_satisfies_the_model(label, body, get_model, _put_model):
    served = get_model.model_validate(body).model_dump(exclude_unset=True)

    assert set(served) == set(body), (
        f"{label}: the model changed the key set "
        f"(dropped {set(body) - set(served)}, added {set(served) - set(body)})"
    )
    assert served == body, f"{label}: the model altered a value"


@pytest.mark.parametrize("label,body,_get_model,put_model", _CASES)
def test_every_write_body_the_writer_produces_satisfies_the_model(label, body, _get_model, put_model):
    written = {**body, "updated_at": _NOW}
    served  = put_model.model_validate(written).model_dump(exclude_unset=True)

    assert set(served) == set(written), f"{label}: the write model changed the key set"
    assert served["updated_at"] == _NOW


@pytest.mark.parametrize("masked", [None, "sk-...cdef", "****"])
def test_the_llm_family_accepts_every_masked_state(masked):
    """`api_key_masked` is null with no key stored, a mask when one is, and
    `****` when a stored key cannot be decrypted with the current secret."""
    body   = {**_llm_default(), "api_key_masked": masked}
    served = LLMSettingsResponse.model_validate(body).model_dump(exclude_unset=True)

    assert served == body
    written = {**body, "updated_at": _NOW}
    assert LLMSettingsUpdatedResponse.model_validate(written).model_dump(exclude_unset=True) == written


@pytest.mark.parametrize("masked", [None, "sk-...cdef", "****"])
@pytest.mark.parametrize("timestamps", [(None, None), (_NOW, _NOW)])
def test_the_proxy_config_body_satisfies_the_model(masked, timestamps):
    """`created_at` / `updated_at` are non-null columns, but the builder guards
    both with `if config.x else None`, so the model follows the writer."""
    created, updated = timestamps
    body = {
        "provider": "openai", "base_url": "https://api.openai.com/v1",
        "api_key_masked": masked, "default_model": "gpt-4o",
        "timeout_seconds": 30, "created_at": created, "updated_at": updated,
    }

    served = ProxyProviderConfigResponse.model_validate(body).model_dump(exclude_unset=True)
    assert served == body


# ── no response model on this surface can carry a credential ─────────────────

_ALL_MODELS = [
    ThresholdsResponse, ThresholdsUpdatedResponse,
    DetectionLayersResponse, DetectionLayersUpdatedResponse,
    LLMSettingsResponse, LLMSettingsUpdatedResponse,
    RateLimitResponse, RateLimitUpdatedResponse,
    ProxyProviderConfigResponse,
]


@pytest.mark.parametrize("model", _ALL_MODELS)
def test_no_settings_response_model_declares_a_credential(model):
    for field in ("api_key", "api_key_enc", "provider_api_key_enc", "secret_key", "enc"):
        assert field not in model.model_fields, (
            f"{model.__name__} declares {field}: the schema would advertise a "
            "provider credential on a response"
        )


@pytest.mark.parametrize("model", [LLMSettingsResponse, ProxyProviderConfigResponse])
def test_a_plaintext_key_added_to_a_settings_body_is_filtered_out(model):
    """If a writer ever started emitting the raw key, the model has no field to
    hold it."""
    body = (
        {**_llm_default(), "api_key_masked": "sk-...cdef"}
        if model is LLMSettingsResponse else
        {"provider": "openai", "base_url": "https://api.openai.com/v1",
         "api_key_masked": "sk-...cdef", "default_model": "gpt-4o",
         "timeout_seconds": 30, "created_at": _NOW, "updated_at": _NOW}
    )
    poisoned = {**body, "api_key": "sk-plaintext-leak", "provider_api_key_enc": "enc-blob"}

    served = model.model_validate(poisoned).model_dump(exclude_unset=True)

    assert "api_key" not in served and "provider_api_key_enc" not in served
    assert "sk-plaintext-leak" not in str(served)
    assert served == body


def test_only_the_rate_limit_family_declares_a_source():
    """`source` is a rate-limit field, not a settings-wide one. A model that
    grew it would advertise a field its handler never sets."""
    for model in (ThresholdsResponse, DetectionLayersResponse, LLMSettingsResponse,
                  ProxyProviderConfigResponse):
        assert "source" not in model.model_fields, f"{model.__name__} grew a source field"
    assert "source" in RateLimitResponse.model_fields
