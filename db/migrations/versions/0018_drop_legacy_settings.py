# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""drop the legacy global settings table (settings split, contract phase)

Revision ID: 0018_drop_legacy_settings
Revises: 0017_settings_split
Create Date: 2026-08-14

Settings model D5/D1 two-table split, contract phase (C2c). Every reader and
writer now uses tenant_settings (per-tenant) or platform_settings (control-plane),
and 0017 copied the legacy rows into tenant_settings under the default tenant, so
the old global `settings` table is dropped.

Guarded: a no-op when the table is already absent (a fresh model-driven baseline
never created it, since SettingsModel was removed from the ORM).
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_drop_legacy_settings"
down_revision: str | None = "0017_settings_split"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if "settings" in set(sa.inspect(bind).get_table_names()):
        op.drop_table("settings")


def downgrade() -> None:
    # One-way: the legacy global settings table is superseded by tenant_settings
    # + platform_settings; there is no meaningful reconstruction.
    pass
