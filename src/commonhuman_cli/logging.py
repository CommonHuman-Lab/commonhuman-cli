# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import logging
import traceback

from commonhuman_cli.colour import GREEN, YELLOW, CYAN, DIM

__all__ = [
    "FINDING",
    "StingLogger",
    "get_logger",
    "setup_logging",
    "ScanResultHandler",
]

# Custom level for confirmed findings — sits between INFO (20) and WARNING (30).
FINDING = 25
logging.addLevelName(FINDING, "FINDING")


class StingLogger(logging.Logger):
    """Logger subclass that adds a .finding() convenience method."""

    def finding(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(FINDING):
            self._log(FINDING, msg, args, **kwargs)


# Called once at import so all tool logger hierarchies use StingLogger.
logging.setLoggerClass(StingLogger)


def get_logger(name: str) -> StingLogger:
    """Return (or create) a StingLogger for *name*."""
    return logging.getLogger(name)  # type: ignore[return-value]


class _ColorHandler(logging.StreamHandler):
    """Writes log records to stdout with ANSI colour based on level."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.levelno >= logging.WARNING:
                print(YELLOW(f"[!] {msg}"))
            elif record.levelno == FINDING:
                print(GREEN(f"[+] {msg}"))
            elif record.levelno == logging.DEBUG:
                print(CYAN(f"[~] {msg}"))
            else:
                print(DIM(f"[*] {msg}"))
            if record.exc_info:
                traceback.print_exception(*record.exc_info)
            self.flush()
        except Exception:
            self.handleError(record)


def setup_logging(verbose: bool, quiet: bool, logger_name: str) -> None:
    """Configure the *logger_name* hierarchy with colour output.

    Each tool passes its own logger_name (e.g. "breachsql", "stingxss") so
    namespaces remain isolated even when both are imported in the same process.
    """
    root = get_logger(logger_name)
    for h in root.handlers[:]:
        h.close()
        root.handlers.remove(h)
    root.propagate = False
    if quiet:
        root.setLevel(logging.ERROR)
        return
    handler = _ColorHandler()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(handler)


class ScanResultHandler(logging.Handler):
    """Appends formatted log messages to a ScanResult.log list."""

    def __init__(self, result) -> None:
        super().__init__()
        self._result = result

    def emit(self, record: logging.LogRecord) -> None:
        self._result.append_log(self.format(record))
