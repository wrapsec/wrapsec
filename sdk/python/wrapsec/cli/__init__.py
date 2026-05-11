# Re-export cli entry point from this package
# pyproject.toml points to: wrapsec.cli:cli
# Spec: Section 2.1 (thin re-export - stable top-level path)

from wrapsec.cli.main import cli  # noqa: F401

__all__ = ["cli"]