# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
H3: startup guard forbids COOKIE_SECURE=false in staging or production.

Cookies flagged Secure are only sent by browsers over TLS. If an operator
accidentally deploys with COOKIE_SECURE=false behind a plain-HTTP listener,
session cookies leak in cleartext. The Settings guard fails the boot instead
of quietly issuing insecure cookies.
"""


import pytest

from config.settings import Settings


def _make(**overrides):
    defaults = dict(
        secret_key    = "x" * 32,
        admin_api_key = "wsk_admin_" + "y" * 32,
        database_url  = "postgresql+asyncpg://u:p@localhost/db",
    )
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture(autouse=True)
def _disable_testing_env(monkeypatch):
    # The guard short-circuits when TESTING=true. Tests below need it OFF
    # so that the real validation path runs.
    monkeypatch.delenv("TESTING", raising=False)


def test_production_with_cookie_secure_false_raises():
    s = _make(environment="production", cookie_secure=False)
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        s.validate_cookie_security()


def test_staging_with_cookie_secure_false_raises():
    s = _make(environment="staging", cookie_secure=False)
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        s.validate_cookie_security()


def test_production_with_cookie_secure_true_passes():
    s = _make(environment="production", cookie_secure=True)
    s.validate_cookie_security()


def test_development_with_cookie_secure_false_passes():
    s = _make(environment="development", cookie_secure=False)
    s.validate_cookie_security()


def test_case_insensitive_environment_value():
    s = _make(environment="PRODUCTION", cookie_secure=False)
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        s.validate_cookie_security()


def test_environment_with_surrounding_whitespace():
    s = _make(environment="  production  ", cookie_secure=False)
    with pytest.raises(ValueError, match="COOKIE_SECURE"):
        s.validate_cookie_security()


def test_testing_env_short_circuits(monkeypatch):
    monkeypatch.setenv("TESTING", "true")
    s = _make(environment="production", cookie_secure=False)
    # Should not raise even though config is unsafe - test suites need this.
    s.validate_cookie_security()
