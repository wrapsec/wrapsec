# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Connector form schema for the dashboard's dynamic create form (v1.3.1).

The admin Integrations page renders one form per webhook destination type.
Rather than hardcode each connector's fields in the frontend, the API
serves this schema so adding a connector needs no dashboard redeploy --
the schema-driven-forms pattern used by Svix/Datadog integration UIs.

Each entry declares the display label, what the `secret` means for that
type (or that it is generated server-side, for the generic webhook), the
URL label/help, and the config fields. A field's `required` flag is
derived from registry.required_config at serialization time, so this
module and the runtime dispatch never drift on which keys are mandatory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.webhooks.connectors import (
    datadog,
    elastic,
    registry,
    sentinel,
    splunk,
)


@dataclass(frozen=True)
class FieldSpec:
    key:   str
    label: str
    help:  str = ""


@dataclass(frozen=True)
class ConnectorForm:
    # None => the generic HMAC webhook (no connector).
    connector_type:   str | None
    label:            str
    # Display label for the secret input; the client also honors `generated`.
    secret_label:     str
    # True => secret is generated server-side (generic webhook): no input.
    secret_generated: bool
    url_label:        str
    url_help:         str
    config_fields:    tuple[FieldSpec, ...] = field(default_factory=tuple)


_FORMS: tuple[ConnectorForm, ...] = (
    ConnectorForm(
        connector_type   = None,
        label            = "Generic webhook (HMAC-signed)",
        secret_label     = "Signing secret (HMAC-SHA256)",
        secret_generated = True,
        url_label        = "Destination URL",
        url_help         = "Public HTTPS URL that receives the signed event POST.",
    ),
    ConnectorForm(
        connector_type   = splunk.CONNECTOR_TYPE,
        label            = "Splunk HTTP Event Collector",
        secret_label     = "HEC token",
        secret_generated = False,
        url_label        = "HEC URL",
        url_help         = "HEC host or collector URL, e.g. https://http-inputs-host:8088",
        config_fields    = (
            FieldSpec("index",      "Index",      "Target index; omit to use the token default."),
            FieldSpec("sourcetype", "Sourcetype", "Defaults to wrapsec:security."),
        ),
    ),
    ConnectorForm(
        connector_type   = datadog.CONNECTOR_TYPE,
        label            = "Datadog Logs",
        secret_label     = "API key",
        secret_generated = False,
        url_label        = "Intake URL",
        url_help         = "Site intake host, e.g. https://http-intake.logs.datadoghq.com",
        config_fields    = (
            FieldSpec("service",  "Service",  "Defaults to wrapsec."),
            FieldSpec("ddsource", "Source",   "Defaults to wrapsec."),
            FieldSpec("hostname", "Hostname", "Optional host tag."),
        ),
    ),
    ConnectorForm(
        connector_type   = sentinel.CONNECTOR_TYPE,
        label            = "Microsoft Sentinel (Logs Ingestion)",
        secret_label     = "App registration client secret",
        secret_generated = False,
        url_label        = "Data collection endpoint URL",
        url_help         = "DCR logs-ingestion endpoint, e.g. https://<dce>.ingest.monitor.azure.com",
        config_fields    = (
            FieldSpec("dcr_immutable_id", "DCR immutable ID", "From the data collection rule overview."),
            FieldSpec("stream_name",      "Stream name",      "e.g. Custom-WrapSec_CL"),
            FieldSpec("tenant_id",        "Directory (tenant) ID", "Entra tenant GUID."),
            FieldSpec("client_id",        "Application (client) ID", "App registration GUID."),
            FieldSpec("cloud",            "Cloud",            "public (default), usgov, or china."),
        ),
    ),
    ConnectorForm(
        connector_type   = elastic.CONNECTOR_TYPE,
        label            = "Elastic (ECS)",
        secret_label     = "API key (base64)",
        secret_generated = False,
        url_label        = "Elasticsearch URL",
        url_help         = "Cluster base URL, e.g. https://host:9243",
        config_fields    = (
            FieldSpec("index",       "Index or data stream", "e.g. logs-wrapsec.security-default"),
            FieldSpec("ecs_version", "ECS version",          "Defaults to 8.11.0."),
        ),
    ),
)


def connector_forms() -> list[dict]:
    """Serialize the form schema for GET /v1/admin/webhooks/connector-types.
    A config field's `required` is read from registry.required_config so the
    form and the runtime validator agree on mandatory keys."""
    out: list[dict] = []
    for form in _FORMS:
        spec = (
            registry.get_spec(form.connector_type)
            if form.connector_type is not None
            else None
        )
        required = spec.required_config if spec is not None else frozenset()
        out.append({
            "type":  form.connector_type,
            "label": form.label,
            "secret": {
                "label":     form.secret_label,
                "generated": form.secret_generated,
                "required":  not form.secret_generated,
            },
            "url": {"label": form.url_label, "help": form.url_help},
            "config_fields": [
                {
                    "key":      f.key,
                    "label":    f.label,
                    "help":     f.help,
                    "required": f.key in required,
                }
                for f in form.config_fields
            ],
        })
    return out
