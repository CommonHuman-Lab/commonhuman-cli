# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ScanResultBase"]


@dataclass
class ScanResultBase:
    """Common scan metadata and thread-safe append helpers.

    Tool-specific ScanResult classes inherit from this and add their own
    finding lists and to_dict() implementation. Call _base_dict() inside
    to_dict() to get the pre-populated common fields.

    Field ordering ensures dataclass inheritance works: the only required
    field (target) has no default; every subsequent field has a default,
    so child classes can freely append defaulted fields.
    """

    target:          str
    started_at:      float = field(default_factory=time.time)
    finished_at:     float = 0.0
    duration_s:      float = 0.0
    waf_detected:    str | None = None
    evasion_applied: str | None = None
    crawled_urls:    int = 0
    params_tested:   int = 0
    requests_sent:   int = 0
    log:             list[str] = field(default_factory=list)
    errors:          list[str] = field(default_factory=list)
    _lock:           threading.Lock = field(
                         default_factory=threading.Lock,
                         repr=False,
                         compare=False,
                     )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def finish(self) -> "ScanResultBase":
        self.finished_at = time.time()
        self.duration_s  = round(self.finished_at - self.started_at, 2)
        return self

    # ------------------------------------------------------------------
    # Thread-safe appends
    # ------------------------------------------------------------------

    def _append(self, attr: str, item: Any) -> None:
        with self._lock:
            getattr(self, attr).append(item)

    def append_error(self, msg: str) -> None:
        self._append("errors", msg)

    def append_log(self, msg: str) -> None:
        self._append("log", msg)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def success(self) -> bool:
        """False only when there are errors and zero findings."""
        return not bool(self.errors) or bool(getattr(self, "total_findings", 0))

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def _base_dict(self) -> dict[str, Any]:
        """Return common fields for use in a tool's own to_dict()."""
        return {
            "success":         self.success,
            "target":          self.target,
            "duration_s":      self.duration_s,
            "waf_detected":    self.waf_detected,
            "evasion_applied": self.evasion_applied,
            "crawled_urls":    self.crawled_urls,
            "params_tested":   self.params_tested,
            "requests_sent":   self.requests_sent,
            "errors":          self.errors,
            "log":             self.log,
        }
