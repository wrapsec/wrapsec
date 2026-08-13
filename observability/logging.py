# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import logging
import re
import sys
from datetime import datetime, timezone

from config.settings import get_settings

settings = get_settings()


# Extra fields that must never appear in structured logs - accidental inclusion
# of secrets via logger.info(..., extra={...}) would write them to log streams.
_SENSITIVE_EXTRAS = frozenset({
    "api_key", "secret_key", "secret", "password", "passwd",
    "token", "access_token", "refresh_token",
    "provider_api_key", "provider_api_key_enc",
    "authorization", "credential", "credentials",
})


# H7 defense-in-depth: even when a developer accidentally logs a Set-Cookie
# header, a full response object, or an exception whose repr embeds a refresh
# token, these regexes rewrite the raw value before it hits the log stream.
# We only redact the value; the surrounding context (key name, header prefix)
# is preserved so the log entry remains useful.
_REDACTED = "[REDACTED]"

# refresh_token=<value>[; expires=...]  (in cookies, query strings, form bodies)
_REFRESH_COOKIE_RE = re.compile(
    r"(refresh_token\s*[=:]\s*)([^;\s\"',&]+)",
    re.IGNORECASE,
)

# Set-Cookie: <full header value up to CRLF>
_SET_COOKIE_HEADER_RE = re.compile(
    r"(set-cookie\s*:\s*)([^\r\n]+)",
    re.IGNORECASE,
)

# Authorization: Bearer <token>
_BEARER_RE = re.compile(
    r"(bearer\s+)([A-Za-z0-9\-_.]{8,})",
    re.IGNORECASE,
)


def scrub_sensitive(text: str) -> str:
    """
    Redact refresh tokens, Set-Cookie header values, and bearer tokens
    from a log-safe string.

    Callable from tests. Deterministic - repeated application is idempotent.
    """
    if not text:
        return text
    text = _REFRESH_COOKIE_RE.sub(r"\1" + _REDACTED, text)
    text = _SET_COOKIE_HEADER_RE.sub(r"\1" + _REDACTED, text)
    text = _BEARER_RE.sub(r"\1" + _REDACTED, text)
    return text


class SensitiveDataFilter(logging.Filter):
    """
    Scrubs refresh tokens and cookie headers from log records before they
    reach any handler. This runs unconditionally on the root logger so that
    both the JSON production formatter and the plain-text dev formatter
    inherit the protection.

    Runs during filter() (pre-format) so we rewrite record.msg and clear
    record.args - the alternative (rewrite in format()) would only protect
    one formatter and would still leak via handlers using a different one.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            # A broken record formatting is not our problem; let it through
            # and rely on the handler's error handling.
            return True

        cleaned = scrub_sensitive(rendered)
        if cleaned != rendered:
            record.msg  = cleaned
            record.args = ()

        # exc_text is memoized by Formatter after first format() call.
        # If it already has token content, scrub it too.
        if record.exc_text:
            record.exc_text = scrub_sensitive(record.exc_text)

        return True

_STANDARD_LOG_FIELDS = frozenset({
    "name", "msg", "args", "levelname", "levelno",
    "pathname", "filename", "module", "exc_info",
    "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread",
    "threadName", "processName", "process", "message",
    "taskName", "trace_id",
})


class JSONFormatter(logging.Formatter):
    """
    Structured JSON log formatter.
    Every log line is a valid JSON object.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
        }

        # Add trace_id if present
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.__dict__["trace_id"]

        # Add extra fields - skip standard logging internals and sensitive keys
        for key, value in record.__dict__.items():
            if key in _SENSITIVE_EXTRAS:
                continue
            if key not in _STANDARD_LOG_FIELDS:
                try:
                    json.dumps(value)
                    log_entry[key] = value
                except (TypeError, ValueError):
                    log_entry[key] = str(value)

        # Add exception info if present. Tracebacks can embed request/response
        # objects via chained frames or repr() - scrub them defensively.
        if record.exc_info:
            log_entry["exception"] = scrub_sensitive(self.formatException(record.exc_info))

        return json.dumps(log_entry)


def setup_logging() -> None:
    """
    Configure structured JSON logging for the entire application.
    Call once at startup.
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers.clear()
    # Also drop any previous scrubber so re-invocation (tests) doesn't stack them.
    for f in list(root_logger.filters):
        if isinstance(f, SensitiveDataFilter):
            root_logger.removeFilter(f)

    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    if settings.log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s - %(message)s"
        ))

    root_logger.addHandler(handler)
    # H7: root-logger-level scrubber for defense-in-depth against accidental
    # refresh-token, Set-Cookie, and Authorization: Bearer logging.
    root_logger.addFilter(SensitiveDataFilter())

    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)