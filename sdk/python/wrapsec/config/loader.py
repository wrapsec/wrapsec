"""
Configuration loader — resolves config from env, file, and defaults.

Priority chain (highest to lowest):
  1. Environment variables (WRAPSEC_API_KEY, WRAPSEC_BASE_URL, WRAPSEC_TIMEOUT)
  2. Config file (~/.config/wrapsec/config.json on Linux/macOS,
                  %APPDATA%\\wrapsec\\config.json on Windows)
  3. Hardcoded defaults (base_url: http://localhost:8000, timeout: 30)

Returns a typed WrapSecConfig object — never raw strings.

Spec reference: Section 3 (config/loader.py), Section 13.2 (config command),
                Section 14.1 (config file location)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from wrapsec.config.schema import (
    ALLOWED_CONFIG_KEYS,
    DEFAULTS,
    TIMEOUT_MIN,
    WrapSecConfig,
    validate_config_value,
)

logger = logging.getLogger("wrapsec.config")


# ── Config file location ────────────────────────────────────────────────────

def get_config_dir() -> Path:
    """
    Returns the platform-appropriate config directory.

    Linux/macOS: $XDG_CONFIG_HOME/wrapsec (fallback: ~/.config/wrapsec)
    Windows:     %APPDATA%\\wrapsec

    Spec: Section 14.1 — finalised, breaking change to move after V1 release
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or Path.home()
        return Path(base) / "wrapsec"
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "wrapsec"


def get_config_path() -> Path:
    return get_config_dir() / "config.json"


# ── File operations ─────────────────────────────────────────────────────────

def _ensure_config_dir() -> None:
    get_config_dir().mkdir(parents=True, exist_ok=True)


def _read_config_file() -> dict[str, object]:
    """Read config file. Returns empty dict if file does not exist or is corrupt."""
    path = get_config_path()
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            logger.warning("Config file is not a JSON object — ignoring")
            return {}
        return raw
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Could not read config file {path}: {e}")
        return {}


def _write_config_file(data: dict[str, object]) -> None:
    """Write config file with chmod 600 on Unix."""
    _ensure_config_dir()
    path = get_config_path()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass  # chmod is a no-op on Windows


# ── Public API ──────────────────────────────────────────────────────────────

def load_config() -> WrapSecConfig:
    """
    Resolve and return the active configuration.

    Priority (highest to lowest):
      1. Environment variables
      2. Config file
      3. Defaults

    Returns WrapSecConfig — a typed object, never raw strings.

    Spec: Section 3 (config/loader.py returns typed config object)
    """
    file_config = _read_config_file()

    # api_key: env → file → None (no default)
    api_key = (
        os.environ.get("WRAPSEC_API_KEY")
        or file_config.get("api_key")
        or None
    )

    # base_url: env → file → default
    base_url = (
        os.environ.get("WRAPSEC_BASE_URL")
        or file_config.get("base_url")
        or str(DEFAULTS["base_url"])
    )

    # timeout: env → file → default
    raw_timeout = (
        os.environ.get("WRAPSEC_TIMEOUT")
        or file_config.get("timeout")
    )
    if raw_timeout is not None:
        try:
            timeout = int(raw_timeout)
            if timeout < TIMEOUT_MIN:
                logger.warning(
                    f"Configured timeout {timeout}s is below minimum {TIMEOUT_MIN}s — "
                    f"using {TIMEOUT_MIN}s"
                )
                timeout = TIMEOUT_MIN
        except (ValueError, TypeError):
            logger.warning(f"Invalid timeout value {raw_timeout!r} — using default 30s")
            timeout = int(DEFAULTS["timeout"])
    else:
        timeout = int(DEFAULTS["timeout"])

    return WrapSecConfig(
        api_key  = str(api_key) if api_key else None,
        base_url = str(base_url).rstrip("/"),
        timeout  = timeout,
    )


def get_config_value(key: str) -> object | None:
    """Return the raw value for a single key from the config file."""
    if key not in ALLOWED_CONFIG_KEYS:
        raise ValueError(f"Unknown config key: {key!r}")
    return _read_config_file().get(key)


def set_config_value(key: str, value: str) -> None:
    """
    Validate and write a single config value.
    Validation runs at write time — invalid values are rejected immediately.

    Spec: Section 13.2 — validation at CLI and SDK level
    """
    coerced = validate_config_value(key, value)
    data    = _read_config_file()
    data[key] = coerced
    _write_config_file(data)


def clear_config() -> None:
    """Remove all stored config values."""
    _write_config_file({})


def mask_api_key(key: str | None) -> str:
    """
    Mask an API key for display. Never print the raw key.
    Spec: Section 10.3 — always mask API key in output
    """
    if not key:
        return "(not set)"
    if len(key) < 12:
        return "****"
    return key[:6] + "****" + key[-4:]


def get_config_source(key: str) -> str:
    """Return a human-readable description of where a config value came from."""
    env_map = {
        "api_key":  "WRAPSEC_API_KEY",
        "base_url": "WRAPSEC_BASE_URL",
        "timeout":  "WRAPSEC_TIMEOUT",
    }
    if key in env_map and os.environ.get(env_map[key]):
        return "environment variable"
    if _read_config_file().get(key) is not None:
        return "config file"
    return "default"
