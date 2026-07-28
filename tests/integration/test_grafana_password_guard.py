"""Regression tests for the Grafana bootstrap-credential guard.

The guard rejects unset, empty, denylisted (e.g. `admin`, `changeme`), and
short (<12 char) values before Grafana can boot on default credentials.
This test sources the same shell helper `scripts/lib/grafana_password_guard.sh`
that setup.sh sources, so any regression to the denylist or length rule
fails CI, not just the manual shell test that predated this file.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
# Source the guard helper via a repo-relative path so this works uniformly
# under git-bash, WSL, and native Linux -- each of which represents the
# Windows drive differently (D:/..., /mnt/d/..., etc.). subprocess runs
# with cwd=REPO_ROOT so the relative path resolves in any bash flavor.
GUARD_LIB_RELATIVE = "scripts/lib/grafana_password_guard.sh"


def _run_guard(value: str) -> tuple[int, str]:
    """Source the guard helper and invoke check_grafana_password with value.

    Returns (exit_code, stderr). exit_code 0 means accepted, 1 means rejected.
    Any other code indicates a problem sourcing or invoking the helper.

    The value is passed via env var (not `$1`) because on Windows,
    subprocess.list2cmdline drops positional args when the resolved bash is
    the WSL launcher. WSLENV forwards WRAPSEC_PW into WSL's env; on Linux CI
    and git-bash WSLENV is ignored and the env passthrough is native.
    """
    script = f'. "{GUARD_LIB_RELATIVE}"\ncheck_grafana_password "$WRAPSEC_PW"\n'
    env = os.environ.copy()
    env["WRAPSEC_PW"] = value
    env["WSLENV"] = (env.get("WSLENV", "") + ":WRAPSEC_PW").lstrip(":")
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=REPO_ROOT,
        env=env,
    )
    return result.returncode, result.stderr


pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None,
    reason="bash not available; guard is a shell function",
)


WEAK_VALUES = [
    # Denylisted values, including case variants
    "admin", "Admin", "ADMIN",
    "password", "Password",
    "changeme", "changeme_before_deploy",
    "grafana", "wrapsec",
    "letmein", "123456", "qwerty", "default",
    # Empty / unset
    "",
    # Below the 12-char minimum
    "short12",       # 7 chars
    "elevenchars",   # 11 chars
]

STRONG_VALUES = [
    "twelve_char1",                # exactly 12 chars
    "MyStrongPass2026!",           # 17 chars, mixed case + digit + symbol
    "AdminButLongerAndUnique123",  # starts with 'admin' but full string is not on denylist
    "A" * 128,                     # long boundary
]


class TestGrafanaPasswordGuard:
    @pytest.mark.parametrize("value", WEAK_VALUES)
    def test_weak_values_rejected(self, value: str) -> None:
        code, stderr = _run_guard(value)
        # Guard returns exactly 1 on rejection; other nonzero codes (e.g. 127
        # for "command not found") indicate the helper failed to load, which
        # would be a false positive if we accepted any nonzero code.
        assert code == 1, (
            f"expected reject (exit 1) for {value!r}, got exit {code} "
            f"with stderr: {stderr.strip()!r}"
        )
        assert stderr.strip(), f"expected reason on stderr for {value!r}, got empty"

    @pytest.mark.parametrize("value", STRONG_VALUES)
    def test_strong_values_accepted(self, value: str) -> None:
        code, stderr = _run_guard(value)
        assert code == 0, (
            f"expected accept for {value!r}, but guard rejected with: {stderr.strip()!r}"
        )
        assert stderr == "", f"expected silent success for {value!r}, got: {stderr!r}"

    def test_denylist_is_case_insensitive(self) -> None:
        for variant in ("admin", "Admin", "ADMIN", "AdMiN"):
            code, _ = _run_guard(variant)
            assert code == 1, f"case variant {variant!r} slipped past denylist (exit {code})"

    def test_length_boundary_at_12(self) -> None:
        code_11, _ = _run_guard("a" * 11)
        code_12, _ = _run_guard("z" * 12)
        assert code_11 == 1, "11-char password should be rejected"
        assert code_12 == 0, "12-char password should be accepted"
