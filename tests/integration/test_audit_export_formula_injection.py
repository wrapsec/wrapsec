# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""An exported cell must not become a formula in a spreadsheet.

The export writes caller-influenced fields -- `source` arrives verbatim from
scan metadata -- into CSV. A cell beginning `=`, `+`, `-`, `@`, tab or carriage
return is interpreted as a formula by common spreadsheet applications, so a
hostile caller can plant something that runs when a compliance administrator
opens the file.

The neutralization already exists and predates this test by a month. What did
not exist was anything holding it in place: it is one small helper and one call,
and nothing would have failed if either were removed. This covers the control,
not its absence.

ONE EXPORT, MANY PAYLOADS. The export carries its own rate limit of a handful
per minute, so a parametrised test that exported per payload spends the budget
and starts measuring the limiter instead of the escaping. Planting every payload
first and exporting once is also the more faithful shape: a real export contains
whatever a caller has accumulated.
"""

from __future__ import annotations

import uuid

import pytest

_EXPORT       = "/v1/audit/export"
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")

_PAYLOADS = {
    "equals": '=HYPERLINK("http://evil.test","click")',
    "plus":   "+1+1",
    "minus":  "-1+1",
    "at":     "@SUM(1,1)",
    "tab":    "\tcmd",
    "cr":     "\rcmd",
}


@pytest.mark.asyncio
async def test_no_exported_cell_begins_with_a_formula_lead(client, admin_headers):
    ordinary = f"ordinary-{uuid.uuid4().hex[:8]}"

    for value in (*_PAYLOADS.values(), ordinary):
        await client.post(
            "/v1/ai/request",
            json={"input": f"export injection check {uuid.uuid4().hex[:8]}",
                  "metadata": {"source": value}},
            headers=admin_headers,
        )

    resp = await client.get(_EXPORT, headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.text

    offenders = []
    for line in body.splitlines():
        for cell in line.split(","):
            bare = cell.strip().strip('"')
            if bare and bare[0] in _FORMULA_LEAD:
                offenders.append(cell)

    assert not offenders, (
        "cells begin with a formula lead and were not neutralised, so opening "
        f"this export in a spreadsheet executes them: {offenders[:5]}"
    )

    # The control lives here rather than in its own test, for the same
    # rate-limit reason: escaping everything would satisfy the assertion above
    # and corrupt every export.
    if ordinary in body:
        assert f"'{ordinary}" not in body, "an ordinary value was given a quote prefix"


@pytest.mark.asyncio
async def test_the_neutralisation_covers_the_documented_lead_characters():
    """Read directly, so the set cannot silently shrink.

    The end-to-end test above only proves the characters it happens to plant are
    handled; this states which characters the control claims to cover.
    """
    from api.v1.endpoints.audit import _csv_safe

    for lead in _FORMULA_LEAD:
        value = f"{lead}payload"
        assert _csv_safe(value).startswith("'"), (
            f"a cell beginning {lead!r} is not neutralised"
        )

    assert _csv_safe("ordinary") == "ordinary"
    assert _csv_safe(None) is None
    assert _csv_safe(42) == 42
