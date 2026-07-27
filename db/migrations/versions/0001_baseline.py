# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""baseline schema matching v1.0.11 ORM

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-27

Bootstraps Alembic against the schema shipped in v1.0.11. Delegates to
Base.metadata.create_all(checkfirst=True) so the same migration is safe on:

  - a fresh database (creates every table)
  - an existing v1.0.11 database (skips tables that already exist)

Downstream migrations (v1.2.0+) use idiomatic op.create_table / op.add_column
calls so schema diffs stay auditable in git history.
"""
from typing import Sequence, Union

from alembic import op

from db.models import Base


revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
