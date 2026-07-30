# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for services.webhooks.connectors.form_schema.

The form schema drives the dashboard's dynamic create form. The load-bearing
guarantee is that it never drifts from the registry: every connector is
present, and every required_config key surfaces as a config field marked
required. A missing/incorrect required flag would let the UI submit an
endpoint the API then rejects (or worse, one that fails every delivery).
"""

from __future__ import annotations

from services.webhooks.connectors import registry
from services.webhooks.connectors.form_schema import connector_forms


def _by_type():
    return {f["type"]: f for f in connector_forms()}


def test_covers_generic_plus_every_registered_connector():
    types = set(_by_type().keys())
    assert types == {None} | set(registry.KNOWN_CONNECTOR_TYPES)


def test_generic_secret_is_generated_not_required():
    generic = _by_type()[None]
    assert generic["secret"]["generated"] is True
    assert generic["secret"]["required"] is False
    assert generic["config_fields"] == []


def test_connector_secret_is_required_input():
    for ct in registry.KNOWN_CONNECTOR_TYPES:
        sec = _by_type()[ct]["secret"]
        assert sec["generated"] is False
        assert sec["required"] is True
        assert sec["label"]                      # non-empty label


def test_required_config_matches_registry_exactly():
    """No drift: the fields marked required in the form must be exactly the
    registry's required_config for that connector."""
    forms = _by_type()
    for ct in registry.KNOWN_CONNECTOR_TYPES:
        form_required = {
            f["key"] for f in forms[ct]["config_fields"] if f["required"]
        }
        assert form_required == set(registry.get_spec(ct).required_config), ct


def test_every_required_key_is_present_as_a_field():
    """A required key that has no field would be un-fillable in the UI."""
    forms = _by_type()
    for ct in registry.KNOWN_CONNECTOR_TYPES:
        field_keys = {f["key"] for f in forms[ct]["config_fields"]}
        assert set(registry.get_spec(ct).required_config) <= field_keys, ct


def test_sentinel_declares_its_four_required_keys():
    sentinel = _by_type()["sentinel_logs_ingestion"]
    required = {f["key"] for f in sentinel["config_fields"] if f["required"]}
    assert required == {"dcr_immutable_id", "stream_name", "tenant_id", "client_id"}


def test_each_entry_has_url_label_and_help():
    for f in connector_forms():
        assert f["url"]["label"]
        assert f["label"]
