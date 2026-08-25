#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Write the published OpenAPI schema to docs/openapi.json.

The committed file is the API's advertised-contract baseline: schema changes show
up as a diff on it rather than being discovered by a consumer. Regenerate it in
the same commit as any change to a route, a request model, or a response model,
and read the diff before pushing.

CORE BUILD ONLY. The schema must describe the OSS edition, so this refuses to
write when a plugin has registered capabilities -- a plugin route or a paid
capability reaching the published schema would advertise an endpoint the OSS
build does not serve. Plugins are discovered through the `wrapsec.plugins`
entry-point group, so an editable install of one in the working environment is
enough to contaminate the output.

Deterministic: keys are sorted and the indent is fixed, so an unrelated
regeneration produces no diff.

    python scripts/gen_openapi.py            # write docs/openapi.json
    python scripts/gen_openapi.py --check    # exit 1 if the file is out of date
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TARGET    = _REPO_ROOT / "docs" / "openapi.json"

# Importing the app builds settings, which validate. These are placeholders for a
# schema dump only -- they never reach a request path, and TESTING keeps the
# import off any network or database.
_IMPORT_ENV = {
    "TESTING":       "true",
    "SECRET_KEY":    "openapi_schema_generation_placeholder_key",
    "ADMIN_API_KEY": "openapi_schema_generation_placeholder_admin",
}


def _render() -> str:
    for key, value in _IMPORT_ENV.items():
        os.environ.setdefault(key, value)
    sys.path.insert(0, str(_REPO_ROOT))

    from api.main import app
    from services.capabilities import get_capabilities

    registered = get_capabilities()
    if registered:
        raise SystemExit(
            "refusing to write the published schema: plugin capabilities are "
            f"registered in this environment ({sorted(registered)}). The schema "
            "must be generated from the core build."
        )

    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="do not write; exit 1 if docs/openapi.json differs from the app",
    )
    args = parser.parse_args()

    rendered = _render()

    if args.check:
        current = _TARGET.read_text(encoding="utf-8") if _TARGET.exists() else ""
        if current == rendered:
            print(f"{_TARGET.relative_to(_REPO_ROOT)} is up to date")
            return 0
        print(
            f"{_TARGET.relative_to(_REPO_ROOT)} is out of date. "
            "Run: python scripts/gen_openapi.py",
            file=sys.stderr,
        )
        return 1

    _TARGET.write_text(rendered, encoding="utf-8")
    print(f"wrote {_TARGET.relative_to(_REPO_ROOT)} ({len(rendered)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
