# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Integration tests: full setup_logging → emit → capsys cycle."""

from __future__ import annotations

import logging

import pytest

from commonhuman_cli.logging import FINDING, get_logger, setup_logging


class TestFullLoggingCycle:
    def test_info_appears_in_output(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="integ.info")
        get_logger("integ.info").info("hello world")
        assert "hello world" in capsys.readouterr().out

    def test_finding_appears_in_output(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="integ.finding")
        get_logger("integ.finding").finding("sqli confirmed")
        assert "sqli confirmed" in capsys.readouterr().out

    def test_warning_appears_in_output(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="integ.warn")
        get_logger("integ.warn").warning("rate limit hit")
        assert "rate limit hit" in capsys.readouterr().out

    def test_debug_hidden_in_normal_mode(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="integ.debug_hidden")
        get_logger("integ.debug_hidden").debug("should not appear")
        assert "should not appear" not in capsys.readouterr().out

    def test_debug_visible_in_verbose_mode(self, capsys, no_colour):
        setup_logging(verbose=True, quiet=False, logger_name="integ.debug_visible")
        get_logger("integ.debug_visible").debug("verbose line")
        assert "verbose line" in capsys.readouterr().out

    def test_quiet_suppresses_everything_below_error(self, capsys):
        setup_logging(verbose=True, quiet=True, logger_name="integ.quiet")
        log = get_logger("integ.quiet")
        log.debug("d")
        log.info("i")
        log.finding("f")
        log.warning("w")
        assert capsys.readouterr().out == ""

    def test_child_logger_inherits_config(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="integ.parent")
        child = get_logger("integ.parent.child")
        child.info("child message")
        assert "child message" in capsys.readouterr().out


class TestToolIsolation:
    def test_tool_a_silent_does_not_affect_tool_b(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=True,  logger_name="tool_a")
        setup_logging(verbose=False, quiet=False, logger_name="tool_b")
        get_logger("tool_a").info("a message")
        get_logger("tool_b").info("b message")
        out = capsys.readouterr().out
        assert "a message" not in out
        assert "b message" in out

    def test_finding_level_same_across_tools(self):
        log_a = get_logger("toolA.engine")
        log_b = get_logger("toolB.engine")
        assert log_a.finding.__func__ is log_b.finding.__func__  # type: ignore[attr-defined]
