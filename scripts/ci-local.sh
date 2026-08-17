#!/usr/bin/env bash
# Reproduce the OS-divergent CI checks locally in Docker (Linux), so results
# that differ from a Windows dev box -- e.g. ruff EXE001 ("shebang present but
# file is not executable"), which never fires on Windows, or an npm ci that
# breaks only on the Linux lockfile -- surface BEFORE pushing.
#
# It streams `git archive HEAD` INTO the container and untars there, so every
# file keeps its git-stored mode (100644 non-exec / 100755 exec). A Windows
# bind-mount would instead mark everything executable and hide the exact class
# of issue this is meant to catch.
#
# Scope is deliberately the checks that DIFFER by OS: the ruff lint and the
# dashboard lint/type/build. The deterministic gates (pyright, semgrep, pytest,
# the eval gate, vitest) give the same result on the Windows box, so run those
# the fast local way (`make typecheck`, `make semgrep`, `make coverage`,
# `make eval`, `cd dashboard && npm run test:coverage`) -- no container needed.
#
# Usage: bash scripts/ci-local.sh   (or `make ci-local`). Requires Docker.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

RUFF_VERSION=0.16.2   # keep in lockstep with .github/workflows/ci.yml

echo "==> [1/2] backend lint on Linux (ruff ${RUFF_VERSION})"
git archive HEAD | docker run --rm -i "python:3.10-slim" bash -euc '
  mkdir -p /src && tar -x -C /src && cd /src
  pip install -q "ruff=='"${RUFF_VERSION}"'"
  ruff check .
'

echo "==> [2/2] dashboard static on Linux (eslint / tsc / build)"
# node:20-slim is glibc like the ubuntu CI runner but a fraction of the size.
# NEXT_PUBLIC_API_URL must be set or `next build` fails the M4 guard (matches the
# frontend-static job env).
git archive HEAD | docker run --rm -i -e NEXT_PUBLIC_API_URL=http://localhost "node:20-slim" bash -euc '
  mkdir -p /src && tar -x -C /src && cd /src/dashboard
  npm ci --no-audit --no-fund
  npm run lint
  npm run typecheck
  npm run build
'

echo "==> local CI reproduction PASSED (OS-divergent checks green)"
