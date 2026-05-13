# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Regression tests for the TTY-at-import-time bug fixed in stingxss colour.py.

These tests ensure _use_colour() is always evaluated lazily so stdout
redirections that occur after import are correctly respected.
"""

from __future__ import annotations

import sys

import pytest

from commonhuman_cli.colour import (
    _use_colour, _c,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM,
)


class TestLazyTtyEvaluation:
    def test_colour_disabled_after_redirect(self, monkeypatch):
        """Simulates: process starts with a TTY, then redirects stdout to a file."""
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert _use_colour() is True

        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert _use_colour() is False  # must update — not cached at import

    def test_colour_enabled_after_redirect(self, monkeypatch):
        """Simulates: process starts without a TTY, then re-enables it."""
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert _use_colour() is False

        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert _use_colour() is True

    def test_each_call_checks_fresh(self, monkeypatch):
        """_use_colour must not cache — calling it twice with different isatty
        states must return different results each time."""
        results = []
        call_count = 0

        def alternating_isatty():
            nonlocal call_count
            call_count += 1
            return call_count % 2 == 1   # True, False, True, False ...

        monkeypatch.setattr(sys.stdout, "isatty", alternating_isatty)
        results.append(_use_colour())  # call 1 → True
        results.append(_use_colour())  # call 2 → False
        assert results == [True, False]


class TestColourFunctionsRespectTty:
    @pytest.mark.parametrize("fn", [RED, GREEN, YELLOW, CYAN, BOLD, DIM])
    def test_no_ansi_when_not_tty(self, fn, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert "\033[" not in fn("text")

    @pytest.mark.parametrize("fn", [RED, GREEN, YELLOW, CYAN, BOLD, DIM])
    def test_ansi_present_when_tty(self, fn, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert "\033[" in fn("text")

    def test_no_escape_codes_bleed_into_captured_output(self, capsys, no_colour):
        """Simulates capsys capturing — colour must be off when not a tty."""
        from commonhuman_cli.output import success, warning, error, info, debug
        success("a")
        warning("b")
        info("c")
        debug("d")
        out = capsys.readouterr().out
        assert "\033[" not in out
