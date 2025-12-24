"""
Logging configuration for VScanX.

Provides a simple JSON formatter with timestamps and levels to keep logs
structured and avoid leaking sensitive data. Call setup_logging() early in
application startup (e.g., CLI entrypoint) to configure the root logger.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional


class JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter to keep output structured."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "time": self.formatTime(record, self.datefmt),
        }

        # Attach optional context fields when present
        for key in ("scan_id", "module", "target"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger with JSON output to stdout."""

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers on repeated setup
    root.handlers = [handler]

    # Silence overly noisy third-party loggers by default
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def setup_logging_with_file(
    level: int = logging.INFO, log_path: Optional[str] = None
) -> None:
    """
    Configure root logger with JSON output to stdout and optional JSONL file sink.
    """
    handlers = []

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(JsonFormatter())
    handlers.append(stdout_handler)

    if log_path:
        path = Path(log_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        handlers.append(file_handler)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = handlers

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
