# Contributing to WrapSec

Thank you for your interest in contributing. This document covers how to report issues and submit changes.

## Reporting Issues

Open a GitHub issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behaviour
- WrapSec version and environment details

For security vulnerabilities, see [SECURITY.md](SECURITY.md) - do not open a public issue.

## Development Setup

```bash
# Python API
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # fill in required values
uvicorn api.main:app --reload

# Dashboard
cd dashboard
npm install
npm run dev

# Python SDK
cd sdk/python
pip install -e ".[dev]"

# Node.js SDK
cd sdk/node
npm install
npm run build
```

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes with tests where applicable.
3. Ensure `pytest` passes and the dashboard builds cleanly.
4. Open a pull request with a clear description of what changed and why.

All contributions must pass CI checks before merging.

## Code Style

- Python: `ruff` for linting and formatting (`ruff check . && ruff format .`)
- TypeScript: `tsc --noEmit` must pass
- Keep changes focused - one concern per PR
