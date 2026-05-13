# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.reporter.ScanResultBase."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import pytest

from commonhuman_cli.reporter import ScanResultBase

# ---------------------------------------------------------------------------
# Minimal concrete subclass — keeps tests self-contained
# ---------------------------------------------------------------------------

@dataclass
class _Result(ScanResultBase):
    items: list = field(default_factory=list)

    def append_item(self, item) -> None:
        self._append("items", item)

    @property
    def total_findings(self) -> int:
        return len(self.items)


def _r() -> _Result:
    return _Result(target="https://example.com")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInitialState:
    def test_target_set(self):
        assert _r().target == "https://example.com"

    def test_findings_empty(self):
        assert _r().total_findings == 0

    def test_errors_empty(self):
        assert _r().errors == []

    def test_log_empty(self):
        assert _r().log == []

    def test_waf_detected_none(self):
        assert _r().waf_detected is None

    def test_evasion_applied_none(self):
        assert _r().evasion_applied is None

    def test_stats_zero(self):
        r = _r()
        assert r.crawled_urls == 0
        assert r.params_tested == 0
        assert r.requests_sent == 0


class TestFinish:
    def test_sets_duration(self):
        r = _r()
        time.sleep(0.01)
        r.finish()
        assert r.duration_s > 0.0

    def test_finished_at_after_started_at(self):
        r = _r()
        time.sleep(0.01)
        r.finish()
        assert r.finished_at > r.started_at

    def test_returns_self(self):
        r = _r()
        assert r.finish() is r

    def test_duration_rounded_to_2dp(self):
        r = _r()
        r.finish()
        assert r.duration_s == round(r.duration_s, 2)


class TestSuccessProperty:
    def test_true_with_no_errors(self):
        assert _r().success is True

    def test_false_with_errors_and_no_findings(self):
        r = _r()
        r.append_error("fatal")
        assert r.success is False

    def test_true_with_errors_when_findings_exist(self):
        r = _r()
        r.append_error("non-fatal")
        r.append_item("finding")
        assert r.success is True


class TestAppendHelpers:
    def test_append_error(self):
        r = _r()
        r.append_error("connection failed")
        assert "connection failed" in r.errors

    def test_append_log(self):
        r = _r()
        r.append_log("[*] scanning param id")
        assert "[*] scanning param id" in r.log

    def test_append_item_increments_findings(self):
        r = _r()
        r.append_item("x")
        r.append_item("y")
        assert r.total_findings == 2


class TestThreadSafety:
    def test_concurrent_appends_are_safe(self):
        r = _r()
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(500):
                    r.append_item("finding")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert r.total_findings == 5000

    def test_concurrent_error_appends_are_safe(self):
        r = _r()

        def worker():
            for _ in range(100):
                r.append_error("err")

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(r.errors) == 500


class TestBaseDict:
    def test_contains_all_common_keys(self):
        r = _r()
        r.finish()
        d = r._base_dict()
        expected = {
            "success", "target", "duration_s", "waf_detected",
            "evasion_applied", "crawled_urls", "params_tested",
            "requests_sent", "errors", "log",
        }
        assert expected <= set(d.keys())

    def test_target_value(self):
        r = _r()
        assert r._base_dict()["target"] == "https://example.com"

    def test_success_reflected(self):
        r = _r()
        r.append_error("oops")
        assert r._base_dict()["success"] is False

    def test_waf_none_by_default(self):
        assert _r()._base_dict()["waf_detected"] is None

    def test_waf_value_propagated(self):
        r = _r()
        r.waf_detected = "Cloudflare"
        assert r._base_dict()["waf_detected"] == "Cloudflare"
