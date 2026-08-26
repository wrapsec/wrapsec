# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The public settings response models are applied by the runtime.

Eleven operations, ten of them modelled: four families with a GET and a PUT, plus
the proxy provider read and upsert. The eleventh, `DELETE /v1/settings/proxy`,
answers 204 with no body and is a recorded non-model route.

DETECTOR. Every one of these bodies is built inline from stored values or
environment defaults, so there is no shared formatter to wrap and no way to
inject an undeclared KEY -- the same limitation as the health and key families.
The equivalent proof is a TYPE violation at the value's source: `get_settings()`
supplies the defaults, and a threshold forced to a string must not be served. A
`JSONResponse` hands it to the caller untouched, so each detector fails if its
own success return is reverted.

WHAT IS ACTUALLY AT RISK HERE, and is tested directly:

  * BOTH BRANCHES. Each GET answers from stored tenant values or from the
    environment default, and they are different code paths. Both are exercised;
  * SOURCE. Only `rate_limit` reports `source`, and it must flip from
    `environment` to `database` once a value is stored. The other three families
    return no such field, and a model must not invent one;
  * CREDENTIALS. The LLM and proxy families accept an `api_key` on the request
    and return only `api_key_masked`. That asymmetry is asserted, including that
    the raw key never comes back after being written.

Authorization is NOT re-tested here: `test_settings_rbac.py` and
`test_api_settings.py` already cover `settings:read` on the reads, ADMIN on the
writes, and the trial-key refusal; all of it passes unchanged.
"""

from types import SimpleNamespace

import pytest
from fastapi.exceptions import ResponseValidationError

_PUBLIC_GETS = [
    ("/v1/settings/thresholds", {"block_threshold", "sanitize_threshold"}),
    ("/v1/settings/layers",     {"rule_enabled", "ml_enabled", "llm_enabled"}),
    ("/v1/settings/llm",        {"provider", "model", "base_url", "timeout",
                                 "llm_trigger", "api_key_masked"}),
    ("/v1/settings/rate_limit", {"per_minute", "source"}),
]


# ── the environment branch ───────────────────────────────────────────────────

@pytest.mark.parametrize("path,fields", _PUBLIC_GETS)
@pytest.mark.asyncio
async def test_a_read_with_nothing_stored_serves_the_declared_fields(
    client, admin_jwt_headers, path, fields,
):
    """The default branch: no tenant override, so the body comes from the
    environment."""
    r = await client.get(path, headers=admin_jwt_headers)

    assert r.status_code == 200, r.text
    assert set(r.json()) == fields, (
        f"{path} served {sorted(r.json())}, expected {sorted(fields)}"
    )


@pytest.mark.asyncio
async def test_only_rate_limit_reports_a_source(client, admin_jwt_headers):
    """`source` is not a general settings field. Three families must not grow
    one just because a model could carry it."""
    for path, _ in _PUBLIC_GETS[:3]:
        body = (await client.get(path, headers=admin_jwt_headers)).json()
        assert "source" not in body, f"{path} grew a source field"

    rate = (await client.get("/v1/settings/rate_limit", headers=admin_jwt_headers)).json()
    assert rate["source"] == "environment", "nothing is stored, so the source is the environment"


# ── the database branch ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_stored_value_is_served_and_flips_the_source(client, admin_jwt_headers):
    """The other branch, end to end: write, then read back."""
    put = await client.put("/v1/settings/rate_limit", json={"per_minute": 123},
                           headers=admin_jwt_headers)
    assert put.status_code == 200, put.text
    assert set(put.json()) == {"per_minute", "source", "updated_at"}
    assert put.json()["per_minute"] == 123 and put.json()["source"] == "database"

    got = await client.get("/v1/settings/rate_limit", headers=admin_jwt_headers)
    assert got.status_code == 200, got.text
    assert got.json() == {"per_minute": 123, "source": "database"}, (
        "the stored branch must serve the stored value and no extra field"
    )


@pytest.mark.asyncio
async def test_a_write_adds_updated_at_and_a_read_does_not(client, admin_jwt_headers):
    """The one shape difference between GET and PUT, which is why they have
    separate models."""
    put = await client.put("/v1/settings/thresholds", json={"block_threshold": 0.8},
                           headers=admin_jwt_headers)
    assert put.status_code == 200, put.text
    assert "updated_at" in put.json()

    got = await client.get("/v1/settings/thresholds", headers=admin_jwt_headers)
    assert got.status_code == 200, got.text
    assert "updated_at" not in got.json(), (
        "a read grew updated_at; the GET and PUT models are supposed to differ"
    )
    assert got.json()["block_threshold"] == 0.8


# ── runtime enforcement, one detector per success return ─────────────────────

def _settings_with(**overrides):
    """A settings stand-in carrying one deliberately wrong type."""
    from config.settings import get_settings

    real = get_settings()
    base = {name: getattr(real, name) for name in (
        "block_threshold", "sanitize_threshold", "llm_provider", "llm_model",
        "llm_base_url", "llm_timeout", "llm_trigger_threshold",
        "rate_limit_per_minute", "secret_key", "app_version",
    )}
    base.update(overrides)
    return lambda: SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_the_thresholds_read_will_not_serve_a_wrong_type(client, admin_jwt_headers, monkeypatch):
    from api.v1.endpoints import settings as settings_module

    monkeypatch.setattr(settings_module, "get_settings",
                        _settings_with(block_threshold="not-a-number"))

    try:
        r = await client.get("/v1/settings/thresholds", headers=admin_jwt_headers)
    except ResponseValidationError as rejected:
        assert "block_threshold" in str(rejected)
        return

    assert r.status_code != 200 or "not-a-number" not in r.text, (
        "a threshold violating the declared type was served"
    )


@pytest.mark.asyncio
async def test_the_rate_limit_read_will_not_serve_a_wrong_type(client, admin_jwt_headers, monkeypatch):
    """Patched at `_default_rate_limit`, not at `get_settings`.

    A settings stand-in reaches every other reader in the handler too, and a
    missing attribute there produces a 500 -- which satisfies "not 200" while
    proving nothing about the model. Patching the one builder whose result lands
    in the body keeps the failure attributable.
    """
    from api.v1.endpoints import settings as settings_module

    monkeypatch.setattr(settings_module, "_default_rate_limit", lambda: {"per_minute": "lots"})

    try:
        r = await client.get("/v1/settings/rate_limit", headers=admin_jwt_headers)
    except ResponseValidationError as rejected:
        assert "per_minute" in str(rejected)
        return

    assert r.status_code == 200 and "lots" not in r.text, (
        f"the environment branch served a per_minute violating its type "
        f"(status={r.status_code})"
    )


@pytest.mark.asyncio
async def test_the_rate_limit_stored_branch_will_not_serve_a_wrong_type(
    client, admin_jwt_headers, monkeypatch,
):
    """The rate-limit read has TWO success returns -- stored and environment --
    and they are separate code paths, so each needs its own detector. This one
    forces the STORED branch by making the repository return a value."""
    from api.v1.endpoints import settings as settings_module

    async def _stored(self, key):
        return {"per_minute": "lots"} if key == settings_module.RATE_LIMIT_KEY else None

    monkeypatch.setattr(settings_module._BoundTenantSettings, "get", _stored)

    try:
        r = await client.get("/v1/settings/rate_limit", headers=admin_jwt_headers)
    except ResponseValidationError as rejected:
        assert "per_minute" in str(rejected)
        return

    assert r.status_code == 200 and "lots" not in r.text, (
        f"the stored branch served a per_minute violating its type (status={r.status_code})"
    )


@pytest.mark.asyncio
async def test_the_layers_read_will_not_serve_a_wrong_type(client, admin_jwt_headers, monkeypatch):
    """The layers default is a module-level literal, so it is the lever here."""
    from api.v1.endpoints import settings as settings_module

    monkeypatch.setattr(settings_module, "DEFAULT_LAYERS",
                        {"rule_enabled": "yes", "ml_enabled": True, "llm_enabled": True})

    try:
        r = await client.get("/v1/settings/layers", headers=admin_jwt_headers)
    except ResponseValidationError as rejected:
        assert "rule_enabled" in str(rejected)
        return

    assert r.status_code == 200 and '"yes"' not in r.text, (
        f"a layer flag violating the declared type was served (status={r.status_code})"
    )


@pytest.mark.asyncio
async def test_the_proxy_upsert_will_not_serve_a_wrong_type(client, admin_jwt_headers, monkeypatch):
    """The upsert's own detector. It shares `_build_config_response` with the
    read, but this is its own request and its own success return."""
    from api.v1.endpoints import proxy_settings as proxy_module

    real = proxy_module._build_config_response
    monkeypatch.setattr(proxy_module, "_build_config_response",
                        lambda config: {**real(config), "timeout_seconds": "quickly"})

    try:
        r = await client.put(
            "/v1/settings/proxy",
            # A PUBLIC base_url: the SSRF guard on this field rejects localhost
            # and private ranges, which would fail the request before the
            # response model is ever reached.
            json={"provider": "openai", "base_url": "https://api.openai.com/v1",
                  "api_key": "sk-detector-key-0123456789", "default_model": "gpt-4o",
                  "timeout": 30},
            headers=admin_jwt_headers,
        )
    except ResponseValidationError as rejected:
        assert "timeout_seconds" in str(rejected)
        return

    assert r.status_code == 200 and "quickly" not in r.text, (
        f"the upsert served a timeout violating its type (status={r.status_code})"
    )


@pytest.mark.asyncio
async def test_the_llm_read_will_not_serve_a_wrong_type(client, admin_jwt_headers, monkeypatch):
    from api.v1.endpoints import settings as settings_module

    monkeypatch.setattr(settings_module, "get_settings",
                        _settings_with(llm_timeout="soon"))

    try:
        r = await client.get("/v1/settings/llm", headers=admin_jwt_headers)
    except ResponseValidationError as rejected:
        assert "timeout" in str(rejected)
        return

    assert r.status_code != 200 or "soon" not in r.text


@pytest.mark.asyncio
async def test_the_writes_will_not_serve_a_wrong_typed_timestamp(client, admin_jwt_headers, monkeypatch):
    """All four PUT bodies take `updated_at` from the module's `to_iso_z`, so one
    detector covers each of them in turn -- each is its own request."""
    from api.v1.endpoints import settings as settings_module

    monkeypatch.setattr(settings_module, "to_iso_z", lambda *_a, **_k: 12345)

    for path, payload in (
        ("/v1/settings/thresholds", {"block_threshold": 0.75}),
        ("/v1/settings/layers",     {"rule_enabled": True}),
        ("/v1/settings/llm",        {"model": "llama3.2"}),
        ("/v1/settings/rate_limit", {"per_minute": 90}),
    ):
        try:
            r = await client.put(path, json=payload, headers=admin_jwt_headers)
        except ResponseValidationError as rejected:
            assert "updated_at" in str(rejected), f"{path}: {rejected}"
            continue

        assert r.status_code != 200 or "12345" not in r.text, (
            f"{path} served an updated_at violating the declared type"
        )


# ── the provider-credential surface ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_llm_read_never_returns_a_provider_key(client, admin_jwt_headers):
    """A key can be written and only its mask comes back -- on the write itself
    and on every later read."""
    from api.v1.schemas.response import LLMSettingsResponse, LLMSettingsUpdatedResponse

    secret = "sk-plaintext-must-never-come-back-0123456789"
    put = await client.put("/v1/settings/llm", json={"provider": "openai", "api_key": secret},
                           headers=admin_jwt_headers)
    assert put.status_code == 200, put.text
    assert secret not in put.text, "the write echoed the plaintext key"
    assert put.json()["api_key_masked"] and secret not in put.json()["api_key_masked"]

    got = await client.get("/v1/settings/llm", headers=admin_jwt_headers)
    assert got.status_code == 200, got.text
    assert secret not in got.text, "a later read returned the plaintext key"
    for field in ("api_key", "api_key_enc", "llm_api_key_enc"):
        assert field not in got.json(), f"{field} reached the caller"
        assert field not in LLMSettingsResponse.model_fields
        assert field not in LLMSettingsUpdatedResponse.model_fields


@pytest.mark.asyncio
async def test_the_proxy_config_read_is_admin_only_and_masks_its_key(client, admin_jwt_headers):
    """The proxy family shares the LLM family's credential rule. 404 until a
    provider is configured -- with the reduced error body this pass preserves."""
    from api.v1.schemas.response import ProxyProviderConfigResponse

    missing = await client.get("/v1/settings/proxy", headers=admin_jwt_headers)
    assert missing.status_code == 404, missing.text
    assert set(missing.json()["error"]) == {"code", "message"}, (
        "the reduced 404 body changed; that is an error-contract change"
    )

    secret = "sk-proxy-plaintext-must-not-return-0123456789"
    put = await client.put(
        "/v1/settings/proxy",
        json={"provider": "openai", "base_url": "https://api.openai.com/v1",
              "api_key": secret, "default_model": "gpt-4o", "timeout": 30},
        headers=admin_jwt_headers,
    )
    assert put.status_code == 200, put.text
    assert secret not in put.text
    assert set(put.json()) == set(ProxyProviderConfigResponse.model_fields)
    assert put.json()["api_key_masked"] and secret not in put.json()["api_key_masked"]

    got = await client.get("/v1/settings/proxy", headers=admin_jwt_headers)
    assert got.status_code == 200, got.text
    assert secret not in got.text
    assert set(got.json()) == set(ProxyProviderConfigResponse.model_fields)

    deleted = await client.delete("/v1/settings/proxy", headers=admin_jwt_headers)
    assert deleted.status_code == 204, deleted.text
    assert deleted.content == b"", "204 must carry no body"


@pytest.mark.asyncio
async def test_a_restricted_caller_is_still_refused(client, scored_key_pair):
    """Unchanged authorization, asserted here only so this file fails if the
    conversion accidentally opened a read."""
    _, trial = scored_key_pair

    for path in ("/v1/settings/thresholds", "/v1/settings/layers",
                 "/v1/settings/llm", "/v1/settings/rate_limit"):
        r = await client.get(path, headers=trial)
        assert r.status_code == 403, f"{path} admitted a trial key: {r.status_code}"
