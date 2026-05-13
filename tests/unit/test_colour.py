# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.colour."""

import sys

import pytest

from commonhuman_cli.colour import (
    _c, _use_colour,
    BOLD, CYAN, DIM, GREEN, RED, YELLOW,
    render_banner,
)


class TestUsColour:
    def test_returns_true_when_tty(self, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert _use_colour() is True

    def test_returns_false_when_not_tty(self, monkeypatch):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert _use_colour() is False

    def test_lazy_evaluation(self, monkeypatch):
        """_use_colour must re-evaluate on every call, not cache at import."""
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert _use_colour() is True
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert _use_colour() is False


class TestAnsiWrapper:
    def test_wraps_when_tty(self, force_colour):
        result = _c("31;1", "hello")
        assert result == "\033[31;1mhello\033[0m"

    def test_strips_when_no_tty(self, no_colour):
        result = _c("31;1", "hello")
        assert result == "hello"

    def test_empty_string(self, force_colour):
        result = _c("1", "")
        assert result == "\033[1m\033[0m"


class TestColourFunctions:
    @pytest.mark.parametrize("fn,code", [
        (RED,    "31;1"),
        (GREEN,  "38;5;46"),
        (YELLOW, "33;1"),
        (CYAN,   "36"),
        (BOLD,   "1"),
        (DIM,    "2"),
    ])
    def test_applies_correct_code(self, fn, code, force_colour):
        result = fn("text")
        assert f"\033[{code}m" in result
        assert "text" in result

    @pytest.mark.parametrize("fn", [RED, GREEN, YELLOW, CYAN, BOLD, DIM])
    def test_strips_when_no_tty(self, fn, no_colour):
        assert fn("text") == "text"


class TestRenderBanner:
    def test_returns_cyan_wrapped_text(self, force_colour):
        result = render_banner("MY TOOL")
        assert "MY TOOL" in result
        assert "\033[36m" in result

    def test_strips_colour_when_no_tty(self, no_colour):
        result = render_banner("MY TOOL")
        assert result == "MY TOOL"
