# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Capability registry and plugin loader (OSS core).

WrapSec is open-core: the OSS core is complete and self-hostable, and paid
features ship in a separate PRIVATE package installed only in the enterprise
image. The core stays edition-agnostic -- it discovers plugins through Python
entry points (the same mechanism pytest, Airflow, and Superset use) rather than
hardcoding any package name.

  * `load_plugins(app)` discovers every entry point registered under the
    `wrapsec.plugins` group and calls it with the app. In the OSS edition no
    such package is installed, so this is a no-op and no paid code exists in the
    process. A plugin registers by declaring, in its own packaging metadata:

        [project.entry-points."wrapsec.plugins"]
        <name> = "<module>:register"

    where `register(app)` plugs features into the OSS extension points (the
    AuthProvider registry, the connector registry, additional routers) and calls
    `register_capability` for each feature it activates.

  * The capability registry lets the app and the dashboard discover which
    optional features are active (GET /v1/capabilities) so paid UI can be shown
    or hidden. OSS returns an empty set.

The OSS core holds NO license code -- license verification lives entirely in the
plugin, keeping the OSS edition clean.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

logger = logging.getLogger("wrapsec.capabilities")

# Entry-point group plugins register under. Stable public contract -- renaming
# it would break installed plugins, so treat it as versioned API.
PLUGIN_GROUP = "wrapsec.plugins"

_CAPABILITIES: set[str] = set()


def register_capability(name: str) -> None:
    """Mark an optional capability as active. Called by a plugin once a paid
    feature is licensed and wired in."""
    _CAPABILITIES.add(name)


def is_enabled(name: str) -> bool:
    return name in _CAPABILITIES


def get_capabilities() -> list[str]:
    return sorted(_CAPABILITIES)


# ── Settings-aware resolver ───────────────────────────────────────────────────
# The registry functions above stay PURE and settings-agnostic. The resolver
# below composes the registry with the WRAPSEC_FEATURES ceiling. It answers "is
# this plugin capability available?" -- it is never an authorization control, and
# it never touches per-principal (proxy) or per-build (transformer) gating.

def capability_available(name: str) -> bool:
    """
    True if `name` is a registered plugin capability AND permitted by the
    configured ceiling. Unset ceiling (WRAPSEC_FEATURES) means no restriction:

        capability_available(name) =
            is_enabled(name) AND (features unset OR name in features)

    Authorization (per-key / per-tenant / per-build) stays entirely separate.
    """
    from config.settings import get_settings
    features = get_settings().configured_features()
    return is_enabled(name) and (features is None or name in features)


def effective_capabilities() -> list[str]:
    """Registered plugin capabilities that survive the configured ceiling -- the
    informational set surfaced by GET /v1/capabilities. Non-authoritative."""
    return [c for c in get_capabilities() if capability_available(c)]


def load_plugins(app) -> None:
    """
    Discover and load every plugin registered under the `wrapsec.plugins`
    entry-point group, calling each `register(app)`. No-op in the OSS edition
    (nothing installed under the group). Never crashes the app: a plugin that
    fails to load degrades to the remaining feature set and is logged, rather
    than taking the process down.
    """
    discovered = entry_points(group=PLUGIN_GROUP)
    if not discovered:
        logger.info("no wrapsec.plugins found -- running OSS edition")
        return

    for ep in discovered:
        try:
            register = ep.load()
            register(app)
            logger.info("loaded plugin %s", ep.name)
        except Exception as exc:                          # noqa: BLE001
            logger.error("plugin %s failed to load, continuing without it: %s", ep.name, exc)

    logger.info("plugins loaded: capabilities=%s", get_capabilities())
