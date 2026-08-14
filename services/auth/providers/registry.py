# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
AuthProvider registry -- the identity-backend seam (Phase 2, 2.8 / open-core P4).

login() no longer hardcodes the password backend; it resolves an AuthProvider by
method name from this registry. The OSS core registers exactly one provider,
"password". A plugin's register(app) adds OIDC/SAML/SCIM under new method names
via register_auth_provider(), and a future SSO login endpoint routes to them by
passing method=<name>. AuthService keeps ownership of lockout, account-active
checks, session issuance, and auth_event logging -- the provider only proves
identity (services/auth/providers/base.py).

Contract (deliberately identical to the connector registry so plugin authors
learn one shape):
  - register_auth_provider is NON-SHADOWING: registering a name that already
    exists raises ValueError. A plugin ADDS a method; it never silently replaces
    the built-in "password" backend (which would be an auth-bypass foot-gun).
  - get_auth_provider(name) returns the provider or None; the caller decides how
    an unknown method fails (login() treats it as an authentication failure and
    does not leak which methods exist).
  - This registry is informational routing, never authorization.
"""

from __future__ import annotations

from services.auth.providers.base import AuthProvider
from services.auth.providers.password import PasswordAuthProvider

# The default method name login() resolves when no explicit method is supplied.
PASSWORD_METHOD = "password"

_PROVIDERS: dict[str, AuthProvider] = {}


def register_auth_provider(provider: AuthProvider) -> None:
    """
    Register an AuthProvider under its .name so login() can route to it.
    Non-shadowing: a name already present raises ValueError (a plugin adds a new
    method; it must not overwrite a built-in backend).
    """
    name = provider.name
    if name in _PROVIDERS:
        raise ValueError(f"auth provider '{name}' is already registered")
    _PROVIDERS[name] = provider


def get_auth_provider(name: str) -> AuthProvider | None:
    """Return the provider registered under `name`, or None if unknown."""
    return _PROVIDERS.get(name)


def is_known(name: str) -> bool:
    return name in _PROVIDERS


def available_auth_providers() -> list[str]:
    """Sorted method names login() can currently route to. Informational."""
    return sorted(_PROVIDERS)


# The OSS core provides exactly one identity backend by default. Plugins extend
# the set at startup; they never remove or replace this one.
register_auth_provider(PasswordAuthProvider())
