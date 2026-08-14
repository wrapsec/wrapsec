# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Fence for TenantRepository.get_bootstrap_default (plugin-strategy criterion 7).

get_bootstrap_default() resolves the deployment's default tenant. It is
legitimate ONLY for bootstrap, first-run setup, admin-key auth, and
deployment-level config that has no per-request tenant. EVERYWHERE else the
tenant must come from the authenticated identity (request.state.tenant_id /
principal). This test enumerates every production call site and fails when one
appears outside the allowlist -- so an innocuous get_bootstrap_default() can never
silently drift into a tenant-scoped request path and collapse isolation (exactly
what happened to the retention script before Phase 2). Tests and the manual
retention runner are exempt: they legitimately seed or delegate.
"""
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

# Production roots only.
_SCAN_DIRS = [
    "api", "services", "db", "clients", "workers",
    "engine", "config", "security", "cache", "domain",
]

# repo-relative file -> why it may resolve the default tenant.
_ALLOWLIST = {
    "api/main.py":               "startup seed_default_tenant + bootstrap_admin",
    "api/v1/endpoints/setup.py": "first-run /setup flow (pre-tenant)",
    "api/v1/middleware/auth.py": "admin-key sentinel -> default tenant (the one mapping)",
    "api/v1/endpoints/settings.py": "tenant-less admin-key principal falls back to default",
    "clients/__init__.py":       "deployment-level detector LLM config (no per-request tenant)",
}

_CALL = re.compile(r"\.get_bootstrap_default\s*\(")


def _callers() -> set[str]:
    found: set[str] = set()
    for d in _SCAN_DIRS:
        root = _REPO / d
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if _CALL.search(path.read_text(encoding="utf-8")):
                found.add(path.relative_to(_REPO).as_posix())
    return found


def test_no_caller_outside_the_allowlist():
    unexpected = _callers() - set(_ALLOWLIST)
    assert not unexpected, (
        "New get_bootstrap_default() call site(s) outside the fence allowlist:\n  "
        + "\n  ".join(sorted(unexpected))
        + "\nIf this is a tenant-scoped request path, use the authenticated "
          "identity's tenant instead. If it is a legitimate bootstrap/deployment "
          "use, add the file to _ALLOWLIST with a justification."
    )


def test_allowlist_has_no_stale_entries():
    stale = set(_ALLOWLIST) - _callers()
    assert not stale, (
        "Allowlist lists files that no longer call get_bootstrap_default -- "
        "remove them:\n  " + "\n  ".join(sorted(stale))
    )
