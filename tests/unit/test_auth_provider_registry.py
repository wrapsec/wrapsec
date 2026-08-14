# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
AuthProvider registry (Phase 2, 2.8) -- pure-registry unit coverage. The full
login-routing / reference-plugin proof lives in
tests/integration/test_refplugin.py::test_auth_provider_registration_seam.
"""
import pytest

import services.auth.providers.registry as areg
from services.auth.providers import (
    PasswordAuthProvider,
    available_auth_providers,
    get_auth_provider,
    is_known,
    register_auth_provider,
)
from services.auth.providers.base import AuthProvider


def test_password_backend_registered_by_default():
    assert is_known("password") is True
    assert isinstance(get_auth_provider("password"), PasswordAuthProvider)
    assert "password" in available_auth_providers()


def test_unknown_method_resolves_to_none():
    assert get_auth_provider("no-such-method") is None
    assert is_known("no-such-method") is False


def test_registration_is_non_shadowing():
    class _Dummy(AuthProvider):
        @property
        def name(self):
            return "unit-dummy"

        async def authenticate(self, credentials, db):  # pragma: no cover
            raise AssertionError("not exercised in this test")

    assert is_known("unit-dummy") is False
    register_auth_provider(_Dummy())
    try:
        assert isinstance(get_auth_provider("unit-dummy"), _Dummy)
        assert "unit-dummy" in available_auth_providers()
        with pytest.raises(ValueError):        # same name twice
            register_auth_provider(_Dummy())
    finally:
        areg._PROVIDERS.pop("unit-dummy", None)


def test_cannot_overwrite_builtin_password():
    class _Fake(AuthProvider):
        @property
        def name(self):
            return "password"

        async def authenticate(self, credentials, db):  # pragma: no cover
            raise AssertionError("a shadowing provider must never run")

    with pytest.raises(ValueError):
        register_auth_provider(_Fake())
    # The genuine built-in is untouched.
    assert isinstance(get_auth_provider("password"), PasswordAuthProvider)
