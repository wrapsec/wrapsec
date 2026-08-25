# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""align api_keys.ip_allowlist to JSONB on PostgreSQL

Revision ID: 0024_ip_allowlist_jsonb
Revises: 0023_auth_event_key_id
Create Date: 2026-08-25

The column's type depends on how a database reached head, which left two
deployments at the same revision with different schemas:

  * a FRESH install gets `jsonb`, because the baseline builds the table from the
    models and the model declares `JSONVariant`
    (`JSON().with_variant(JSONB(), "postgresql")`);
  * a database that UPGRADED through 0022 gets `json`, because that migration
    adds the column as a plain `sa.JSON()`.

0006 aligned every JSON column of its day to jsonb for the same reason -- the
code queries these columns with jsonb operators, and `json` fails them with
`function jsonb_array_elements_text(json) does not exist`. This column postdates
0006's target list, so nothing has ever aligned it. Today's readers go through
the ORM as a whole list rather than a jsonb operator, so this is closing a
divergence before it becomes a fault, not repairing a live one.

The conversion is value-preserving: `USING column::jsonb` re-parses the stored
document, and the contents are arrays of CIDR strings, so no row needs
transformation. NULL casts to NULL and an empty array stays an empty array.

Both directions are guarded by the column's CURRENT type, so re-running either
is a no-op and neither fails on a database that is already in the target state.
"""
from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0024_ip_allowlist_jsonb"
down_revision: str | None = "0023_auth_event_key_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE  = "api_keys"
_COLUMN = "ip_allowlist"


def _current_type(bind) -> str | None:
    """Data type of the column, or None when the table or column is absent."""
    row = bind.execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": _TABLE, "c": _COLUMN},
    ).first()
    return row[0] if row else None


def _convert(bind, target: str, source: str) -> None:
    if _current_type(bind) != source:
        return
    op.execute(
        f"ALTER TABLE {_TABLE} "
        f"ALTER COLUMN {_COLUMN} TYPE {target} USING {_COLUMN}::{target}"
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # Off PostgreSQL, JSONVariant falls back to JSON and there is no jsonb
        # type to convert to.
        return
    _convert(bind, "jsonb", "json")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _convert(bind, "json", "jsonb")
