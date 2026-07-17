"""
Structured JSON logging for LogSentry.

Replaces the plain-text formatter with machine-parseable JSON output,
enabling log aggregation in tools like ELK, Splunk, and Datadog.

Design decisions:
  - StructuredFormatter emits one JSON object per line (JSON-Lines format).
  - Correlation ID is injected at the record level by CoreMiddleware.
  - Sensitive fields (api_key, password, token, secret) are scrubbed.
  - File handler uses RotatingFileHandler (not TimedRotating) for
    predictable disk-usage behaviour in containers.
  - Guards against double-handler registration on re-import.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

from app.config.settings import settings

# ---------------------------------------------------------------------------
# Sensitive field scrubbing
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = frozenset(
    {"api_key", "password", "token", "secret", "authorization", "key"}
)


def _scrub(value: Any) -> Any:
    """Recursively redact sensitive keys from dicts."""
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if k.lower() in _SENSITIVE_KEYS else _scrub(v)
            for k, v in value.items()
        }
    return value


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class StructuredFormatter(logging.Formatter):
    """
    Emit a single-line JSON object per log record.

    Fields emitted:
      timestamp, level, logger, message, correlation_id (when present),
      module, function, line, plus any extra= kwargs passed to the logger.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Inject correlation ID if set by CoreMiddleware
        correlation_id = getattr(record, "correlation_id", None)
        if correlation_id:
            log_entry["correlation_id"] = correlation_id

        # Attach any extra= fields (scrubbed)
        for key, val in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName", "correlation_id",
            } and not key.startswith("_"):
                # Scrub if the key itself is sensitive, otherwise scrub nested dicts
                if key.lower() in _SENSITIVE_KEYS:
                    log_entry[key] = "[REDACTED]"
                else:
                    log_entry[key] = _scrub(val)

        # Exception info
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def setup_logging() -> None:
    """
    Configure structured JSON logging for the entire application.

    Safe to call multiple times — handlers are only added once.
    """
    log_dir = os.path.dirname(settings.LOG_FILE_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(settings.LOG_LEVEL)

    # Skip if handlers already registered (prevents duplicates on hot-reload)
    if root_logger.handlers:
        return

    formatter = StructuredFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Rotating file handler — max 100 MB per file, keep 10 files
    try:
        file_handler = RotatingFileHandler(
            settings.LOG_FILE_PATH,
            maxBytes=100 * 1024 * 1024,  # 100 MB
            backupCount=10,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except OSError as exc:
        # Non-fatal: log to console only if file handler fails (e.g. read-only FS)
        root_logger.warning("Could not create file log handler: %s", exc)

    # Quiet noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    logging.info("Structured JSON logging configured", extra={"log_file": settings.LOG_FILE_PATH})
