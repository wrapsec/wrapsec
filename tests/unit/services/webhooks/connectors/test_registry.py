# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.registry.

The registry is the single dispatch point the delivery handler uses to
route an endpoint to its connector. The three outcomes -- generic
(None), known spec, unknown (raise) -- are each load-bearing: a wrong
None would mis-sign a connector payload, and a silent fallthrough on an
unknown slug would ship garbage. These tests pin all three.
"""

from __future__ import annotations

import pytest

from services.webhooks.connectors import datadog, elastic, sentinel, splunk
from services.webhooks.connectors.registry import (
    KNOWN_CONNECTOR_TYPES,
    AuthKind,
    UnknownConnectorError,
    get_spec,
    is_known,
)


# --- Generic (NULL) path ----------------------------------------------

def test_null_connector_type_is_generic_webhook():
    assert get_spec(None) is None


# --- Known slugs ------------------------------------------------------

@pytest.mark.parametrize(
    "module, expected_auth",
    [
        (splunk,   AuthKind.STATIC_TOKEN),
        (datadog,  AuthKind.STATIC_TOKEN),
        (elastic,  AuthKind.STATIC_TOKEN),
        (sentinel, AuthKind.ENTRA_BEARER),
    ],
)
def test_each_connector_resolves_to_its_build_request_and_auth_kind(module, expected_auth):
    spec = get_spec(module.CONNECTOR_TYPE)
    assert spec is not None
    assert spec.connector_type == module.CONNECTOR_TYPE
    assert spec.build_request is module.build_request
    assert spec.auth_kind is expected_auth


def test_only_sentinel_uses_entra_bearer():
    bearer = {
        ct for ct in KNOWN_CONNECTOR_TYPES
        if get_spec(ct).auth_kind is AuthKind.ENTRA_BEARER
    }
    assert bearer == {sentinel.CONNECTOR_TYPE}


# --- Unknown slug -----------------------------------------------------

def test_unknown_connector_type_raises():
    with pytest.raises(UnknownConnectorError) as exc:
        get_spec("nope_not_real")
    assert exc.value.connector_type == "nope_not_real"


# --- Coverage guard ---------------------------------------------------

def test_registry_covers_exactly_the_four_connector_modules():
    """Guards against adding a connector module but forgetting to
    register it (or vice versa)."""
    assert KNOWN_CONNECTOR_TYPES == {
        splunk.CONNECTOR_TYPE,
        datadog.CONNECTOR_TYPE,
        sentinel.CONNECTOR_TYPE,
        elastic.CONNECTOR_TYPE,
    }


# --- is_known (admin validation helper) -------------------------------

def test_is_known_accepts_null_and_registered_slugs():
    assert is_known(None) is True
    assert is_known(splunk.CONNECTOR_TYPE) is True


def test_is_known_rejects_unregistered_slug():
    assert is_known("bogus") is False
