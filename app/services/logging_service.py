"""Structured logging configuration."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from app.config import AppSettings


_BUILTIN_LOG_RECORD_FIELDS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


@dataclass(slots=True)
class ApplicationLoggers:
    """Named loggers used by the service."""

    app: logging.Logger
    raw_events: logging.Logger
    alerts: logging.Logger
    errors: logging.Logger


class JsonFormatter(logging.Formatter):
    """Render log records as JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _BUILTIN_LOG_RECORD_FIELDS and not key.startswith("_")
        }
        if extras:
            payload["context"] = extras
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=self._default_serializer)

    def _default_serializer(self, value: Any) -> Any:
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "to_log_dict"):
            return value.to_log_dict()
        return str(value)


def configure_logging(settings: AppSettings) -> ApplicationLoggers:
    """Configure console and rotating JSON loggers."""

    log_directory = settings.resolve_path(settings.logging.directory)
    log_directory.mkdir(parents=True, exist_ok=True)

    formatter = JsonFormatter()
    level = getattr(logging, settings.logging.level.upper(), logging.INFO)

    app_logger = _configure_named_logger(
        "rdp_monitor.app",
        level,
        _build_rotating_handler(log_directory / "service.log", level, settings, formatter),
    )
    raw_logger = _configure_named_logger(
        "rdp_monitor.raw_events",
        level,
        _build_rotating_handler(log_directory / "raw_events.log", level, settings, formatter),
    )
    alert_logger = _configure_named_logger(
        "rdp_monitor.alerts",
        level,
        _build_rotating_handler(log_directory / "alerts.log", level, settings, formatter),
    )
    error_logger = _configure_named_logger(
        "rdp_monitor.errors",
        logging.ERROR,
        _build_rotating_handler(log_directory / "errors.log", logging.ERROR, settings, formatter),
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    if not any(type(handler) is logging.StreamHandler for handler in app_logger.handlers):
        app_logger.addHandler(console_handler)

    return ApplicationLoggers(
        app=app_logger,
        raw_events=raw_logger,
        alerts=alert_logger,
        errors=error_logger,
    )


def _configure_named_logger(
    name: str,
    level: int,
    rotating_handler: RotatingFileHandler,
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False
    logger.addHandler(rotating_handler)
    return logger


def _build_rotating_handler(
    path: Path,
    level: int,
    settings: AppSettings,
    formatter: logging.Formatter,
) -> RotatingFileHandler:
    handler = RotatingFileHandler(
        filename=path,
        maxBytes=settings.logging.max_bytes,
        backupCount=settings.logging.backup_count,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(formatter)
    return handler
