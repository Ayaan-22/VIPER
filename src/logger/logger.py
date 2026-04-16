"""
logger.py
---------
Structured JSON logging with console output, file rotation,
and optional coloured severity badges for interactive sessions.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# ANSI colour codes
_COLOURS = {
    "DEBUG":    "\033[36m",   # cyan
    "INFO":     "\033[32m",   # green
    "WARNING":  "\033[33m",   # yellow
    "ERROR":    "\033[31m",   # red
    "CRITICAL": "\033[35m",   # magenta
    "RESET":    "\033[0m",
}


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Emits each log record as a single-line JSON object."""

    SKIP_ATTRS = frozenset({
        "args", "created", "exc_info", "exc_text", "filename",
        "funcName", "id", "levelname", "levelno", "lineno",
        "module", "msecs", "message", "msg", "name", "pathname",
        "process", "processName", "relativeCreated", "stack_info",
        "thread", "threadName",
    })

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        payload: Dict[str, Any] = {
            "ts":      time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            ) + f".{int(record.msecs):03d}Z",
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.message,
        }
        # Attach any extra fields the caller passed in
        for key, val in record.__dict__.items():
            if key not in self.SKIP_ATTRS:
                payload[key] = val

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Coloured console formatter
# ---------------------------------------------------------------------------

class ColouredConsoleFormatter(logging.Formatter):
    FMT = "{colour}[{level}]{reset} {ts}  {message}"

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, "")
        reset  = _COLOURS["RESET"]
        ts     = time.strftime("%H:%M:%S", time.localtime(record.created))
        return self.FMT.format(
            colour=colour,
            reset=reset,
            level=record.levelname[0],  # single letter: D/I/W/E/C
            ts=ts,
            message=record.getMessage(),
        )


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def setup_logger(
    name: str = "nids",
    log_file: str = "logs/nids.log",
    level: str = "INFO",
    log_format: str = "json",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    console: bool = True,
    colorize: bool = True,
) -> logging.Logger:
    """
    Create (or return existing) a fully-configured logger.

    Parameters
    ----------
    name         : logger name (hierarchical, e.g. "nids.detector")
    log_file     : path to rotating file log
    level        : minimum log level string
    log_format   : "json" or "text"
    max_bytes    : file rotation threshold
    backup_count : number of rotated files to retain
    console      : whether to also write to stderr
    colorize     : use ANSI colours on the console handler
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # --- file handler ---
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(
        JsonFormatter() if log_format == "json" else logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        )
    )
    logger.addHandler(file_handler)

    # --- console handler ---
    if console:
        con = logging.StreamHandler(sys.stderr)
        con.setFormatter(
            ColouredConsoleFormatter() if colorize else logging.Formatter(
                "[%(levelname)s] %(message)s"
            )
        )
        logger.addHandler(con)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the root 'nids' logger."""
    return logging.getLogger(f"nids.{name}")
