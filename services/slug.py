# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Server-side slug canonicalization.

The dashboard slugifies as a convenience, but the server is the source of truth:
a slug must be canonical and validated no matter which caller (dashboard, SDK,
raw API) created the resource. This mirrors the dashboard's `slugify` so the same
name yields the same slug on both sides.
"""

import re

# Slugs reserved by the platform. `default` is the bootstrap tenant/department
# slug and must never be claimed by a user-created resource.
RESERVED_SLUGS = frozenset({"default"})

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    """Canonical slug: lowercase, non-alphanumeric runs collapse to a single
    hyphen, no leading/trailing hyphen, capped at 50 chars (the DB column width).
    Returns "" when the input has no alphanumeric characters."""
    collapsed = _NON_ALNUM.sub("-", (value or "").lower()).strip("-")
    return collapsed[:50].rstrip("-")


def is_reserved_slug(slug: str) -> bool:
    return slug in RESERVED_SLUGS
