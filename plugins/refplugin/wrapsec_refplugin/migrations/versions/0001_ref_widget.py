# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""ref plugin widget table (2.10 reference migration)

A trivial plugin-owned table used only to prove the plugin migration helper runs
a plugin chain against an isolated version table. It follows I8: tenant data
carries tenant_id NOT NULL so plugin tables inherit the same isolation contract
as core tables.

Revision ID: 0001_ref_widget
Revises:
Create Date: 2026-08-14
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_ref_widget"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ref_plugin_widget",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ref_plugin_widget")
