# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Reusable ScanResultBase subclass for tests that need a concrete result."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from commonhuman_cli.reporter import ScanResultBase


@dataclass
class _DummyResult(ScanResultBase):
    """Minimal concrete subclass used in tests."""

    findings: list = field(default_factory=list)

    def append_finding(self, item) -> None:
        self._append("findings", item)

    @property
    def total_findings(self) -> int:
        return len(self.findings)


@pytest.fixture()
def dummy_result() -> _DummyResult:
    return _DummyResult(target="https://example.com/search?q=1")


@pytest.fixture()
def dummy_result_with_findings(dummy_result) -> _DummyResult:
    dummy_result.append_finding("sqli-finding")
    dummy_result.append_finding("xss-finding")
    return dummy_result
