# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Plugin DB migration convention + helper (Phase 2, 2.10 / open-core P4).

Core startup runs `alembic upgrade head` against the CORE migration chain only
(db/session.run_migrations). A plugin that owns tables ships its OWN Alembic
chain and runs it through run_plugin_migrations() from its register() or a CLI.

The two chains never touch because each uses its own Alembic version table:
core keeps the default `alembic_version`; a plugin gets
`alembic_version_<name>`. So `alembic upgrade head` on the core chain never sees
a plugin revision (and cannot mark it applied/pending), and a plugin upgrade
never rewrites the core history. This is decided BEFORE any plugin ships tables
because retrofitting migration ownership onto a shared version table is painful.

Plugin table rules (I8): a plugin table holding tenant data carries tenant_id
NOT NULL and every read is tenant-filtered -- the same isolation contract as core
tables, enforced structurally by the route-isolation guard for any route the
plugin mounts.

A plugin's env.py MUST read the version table from
config.attributes["version_table"] and pass it to context.configure(); the
reference env.py in plugins/refplugin/wrapsec_refplugin/migrations/env.py shows
the whole pattern. See docs/plugin_migrations.md.
"""

from __future__ import annotations

import re
from pathlib import Path

# A plugin name becomes part of a SQL identifier (the version table), so restrict
# it to a safe character class rather than trusting the caller.
_SAFE_NAME = re.compile(r"^[a-z0-9_]+$")


def plugin_version_table(plugin_name: str) -> str:
    """The isolated Alembic version table for a plugin: `alembic_version_<name>`."""
    if not _SAFE_NAME.match(plugin_name or ""):
        raise ValueError(
            "plugin_name must match [a-z0-9_]+ (it names an Alembic version table)"
        )
    return f"alembic_version_{plugin_name}"


def run_plugin_migrations(
    plugin_name:     str,
    script_location: str | Path,
    database_url:    str | None = None,
) -> None:
    """
    Upgrade a plugin's own Alembic chain to head against its ISOLATED version
    table (alembic_version_<plugin_name>). Call this from the plugin's
    register(app) or a management CLI -- NOT from core startup, which migrates
    only the core chain.

    database_url is optional: when omitted, the plugin env.py resolves it from
    application settings (identical to core). command.upgrade is synchronous and
    the reference env.py calls asyncio.run internally, so invoke this from a
    worker thread (asyncio.to_thread) when calling from inside an event loop.
    """
    from alembic import command
    from alembic.config import Config

    version_table = plugin_version_table(plugin_name)   # validates the name

    cfg = Config()
    cfg.set_main_option("script_location", str(script_location))
    if database_url:
        cfg.set_main_option("sqlalchemy.url", database_url)
    # The plugin env.py reads this and passes it to context.configure(); it is the
    # single source of the version-table isolation.
    cfg.attributes["version_table"] = version_table

    command.upgrade(cfg, "head")
