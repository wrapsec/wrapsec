# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Connector registry and dispatch (v1.3.0, 12b.2).

Maps a webhook_endpoints.connector_type slug to the connector that
builds its outbound request, plus the auth kind the delivery handler
needs to resolve the endpoint's credential. Pure lookup, no I/O.

Three delivery shapes exist:

  * connector_type IS NULL      -> generic HMAC-signed webhook. There is
                                   no connector; the handler signs the
                                   raw body with security.webhook_signing
                                   and POSTs it. get_spec returns None to
                                   signal this path.

  * connector_type is a known   -> a ConnectorSpec: its build_request
    slug                           produces the request, and auth_kind
                                   tells the handler how to turn
                                   secret_enc into the auth header.

  * connector_type is set but    -> UnknownConnectorError. This is a
    unrecognized                   data-integrity problem, never a
                                   transient one: retrying will never
                                   fix it, and silently falling back to
                                   the generic HMAC path would sign with
                                   a value that is not a signing secret
                                   and ship garbage. The handler catches
                                   this and dead-letters the message.

auth_kind is a label only -- the actual token acquisition lives in the
handler (12b.4) and, for Entra, the token provider (12b.3). Keeping the
label here means the handler has no magic connector-type strings.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from services.webhooks.connectors import datadog, elastic, sentinel, splunk
from services.webhooks.connectors.base import ConnectorRequest

# A connector's build_request. All four share this signature:
#   (url, token, event_type, body, config=None) -> ConnectorRequest
BuildRequest = Callable[..., ConnectorRequest]


class AuthKind(str, Enum):
    """How the handler turns webhook_endpoints.secret_enc into an auth
    header for this connector."""
    # secret_enc decrypts to the token placed directly in the auth header
    # (Splunk HEC token, Datadog API key, Elastic API key).
    STATIC_TOKEN = "static_token"
    # secret_enc is an app-registration client secret; the handler runs
    # the Entra client-credentials flow and passes the resulting bearer
    # access token as the connector's `token` (Sentinel Logs Ingestion).
    ENTRA_BEARER = "entra_bearer"


@dataclass(frozen=True)
class ConnectorSpec:
    connector_type: str
    build_request:  BuildRequest
    auth_kind:      AuthKind
    # Config keys the endpoint MUST carry for this connector to deliver.
    # Validated by the admin API at create time so a misconfigured endpoint
    # is rejected up front rather than failing every delivery into the DLQ.
    # Spans build_request AND auth needs (e.g. Sentinel needs the DCR keys
    # for the URL plus the app-registration keys for the bearer token).
    required_config: frozenset[str] = frozenset()


class UnknownConnectorError(Exception):
    """Raised when an endpoint carries a connector_type slug that is not
    registered. Permanent (non-retryable) by nature."""

    def __init__(self, connector_type: str):
        self.connector_type = connector_type
        super().__init__(f"unknown connector_type: {connector_type!r}")


# One spec per connector module. Sourcing connector_type from each module's
# own CONNECTOR_TYPE constant keeps the slug defined in exactly one place.
_SPECS: tuple[ConnectorSpec, ...] = (
    # Splunk/Datadog carry the destination in the url and authenticate with a
    # single token, so no config is strictly required.
    ConnectorSpec(splunk.CONNECTOR_TYPE,   splunk.build_request,   AuthKind.STATIC_TOKEN),
    ConnectorSpec(datadog.CONNECTOR_TYPE,  datadog.build_request,  AuthKind.STATIC_TOKEN),
    # Sentinel needs the DCR immutable id + stream (for the URL) and the app
    # registration tenant/client (for the Entra bearer).
    ConnectorSpec(
        sentinel.CONNECTOR_TYPE, sentinel.build_request, AuthKind.ENTRA_BEARER,
        required_config=frozenset({"dcr_immutable_id", "stream_name", "tenant_id", "client_id"}),
    ),
    # Elastic needs the target index / data stream.
    ConnectorSpec(
        elastic.CONNECTOR_TYPE, elastic.build_request, AuthKind.STATIC_TOKEN,
        required_config=frozenset({"index"}),
    ),
)

_REGISTRY: dict[str, ConnectorSpec] = {spec.connector_type: spec for spec in _SPECS}

# Public set of registered slugs, for admin-API validation (12b.6).
KNOWN_CONNECTOR_TYPES: frozenset[str] = frozenset(_REGISTRY)


def get_spec(connector_type: str | None) -> ConnectorSpec | None:
    """
    Resolve a connector_type to its spec.

    Returns None for a NULL connector_type (generic HMAC webhook path).
    Raises UnknownConnectorError for a non-null slug that is not
    registered.
    """
    if connector_type is None:
        return None
    try:
        return _REGISTRY[connector_type]
    except KeyError:
        raise UnknownConnectorError(connector_type) from None


def is_known(connector_type: str | None) -> bool:
    """True if connector_type is NULL (generic) or a registered slug.
    Used by the admin API to reject unknown slugs at create time."""
    return connector_type is None or connector_type in _REGISTRY


def missing_config(connector_type: str, config: dict | None) -> list[str]:
    """Return the required config keys absent (or empty) for `connector_type`,
    sorted for stable error messages. Empty list means the config is complete.
    Raises UnknownConnectorError if the slug is not registered."""
    spec = get_spec(connector_type)
    if spec is None:                      # generic webhook: no connector config
        return []
    cfg = config or {}
    return sorted(k for k in spec.required_config if not cfg.get(k))
