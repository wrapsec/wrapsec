# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Runtime environment configuration (V1 runtime/capability work).

Production is the safe default: a missing/empty ENVIRONMENT resolves to
production, an explicit invalid value fails validation, and the COOKIE_SECURE
fail-closed guard remains correct under the new default. `_env_file=None` bypasses
the repo's local .env so these assert the true defaults.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from config.settings import Settings


def _settings(monkeypatch, env_value):
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    monkeypatch.setenv("ADMIN_API_KEY", "y" * 32)
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    if env_value is None:
        monkeypatch.delenv("ENVIRONMENT", raising=False)
    else:
        monkeypatch.setenv("ENVIRONMENT", env_value)
    return Settings(_env_file=None)


def test_missing_environment_is_production(monkeypatch):
    assert _settings(monkeypatch, None).environment == "production"


def test_model_default_is_production():
    # The field default itself (independent of env) is production-safe.
    assert Settings.model_fields["environment"].default == "production"


@pytest.mark.parametrize("value,expected", [
    ("development", "development"),
    ("staging",     "staging"),
    ("production",  "production"),
    ("PRODUCTION",  "production"),   # case-insensitive
    ("  Development ", "development"),  # trimmed
    ("",            "production"),   # empty -> production-safe
])
def test_environment_accepted_and_normalized(monkeypatch, value, expected):
    assert _settings(monkeypatch, value).environment == expected


@pytest.mark.parametrize("bad", ["proxi", "prod", "dev", "test", "evaluation"])
def test_invalid_environment_rejected(monkeypatch, bad):
    with pytest.raises(ValidationError):
        _settings(monkeypatch, bad)


def test_cookie_secure_guard_fails_closed_under_production(monkeypatch):
    monkeypatch.setenv("TESTING", "false")   # enable the guard
    s = _settings(monkeypatch, "production")
    s.cookie_secure = False
    with pytest.raises(ValueError):
        s.validate_cookie_security()


def test_cookie_secure_allowed_under_development(monkeypatch):
    monkeypatch.setenv("TESTING", "false")
    s = _settings(monkeypatch, "development")
    s.cookie_secure = False
    s.validate_cookie_security()  # no raise for local http dev
