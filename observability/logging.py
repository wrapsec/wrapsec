# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import logging
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
            log_entry["trace_id"] = record.trace_id

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

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

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

    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)