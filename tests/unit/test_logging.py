# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.logging."""

import logging

import pytest

from commonhuman_cli.logging import (
    FINDING,
    ScanResultHandler,
    StingLogger,
    get_logger,
    setup_logging,
)


class TestFindingLevel:
    def test_value_is_25(self):
        assert FINDING == 25

    def test_level_name_registered(self):
        assert logging.getLevelName(FINDING) == "FINDING"

    def test_sits_between_info_and_warning(self):
        assert logging.INFO < FINDING < logging.WARNING


class TestStingLogger:
    def test_get_logger_returns_sting_logger(self):
        log = get_logger("test.sting")
        assert isinstance(log, StingLogger)

    def test_finding_method_exists(self):
        log = get_logger("test.finding_method")
        assert callable(log.finding)

    def test_finding_method_emits_at_level_25(self, capsys, force_colour):
        setup_logging(verbose=True, quiet=False, logger_name="test.emit")
        log = get_logger("test.emit")
        log.finding("vuln found")
        captured = capsys.readouterr()
        assert "vuln found" in captured.out

    def test_finding_suppressed_when_below_level(self, capsys):
        setup_logging(verbose=False, quiet=False, logger_name="test.suppress")
        log = get_logger("test.suppress")
        # DEBUG is below INFO — should not appear
        log.debug("this is debug")
        captured = capsys.readouterr()
        assert "debug" not in captured.out


class TestSetupLogging:
    def test_quiet_suppresses_info(self, capsys):
        setup_logging(verbose=False, quiet=True, logger_name="test.quiet")
        log = get_logger("test.quiet")
        log.info("should not appear")
        assert "should not appear" not in capsys.readouterr().out

    def test_quiet_suppresses_finding(self, capsys):
        setup_logging(verbose=False, quiet=True, logger_name="test.quiet2")
        log = get_logger("test.quiet2")
        log.finding("should not appear")
        assert "should not appear" not in capsys.readouterr().out

    def test_verbose_shows_debug(self, capsys, force_colour):
        setup_logging(verbose=True, quiet=False, logger_name="test.verbose")
        log = get_logger("test.verbose")
        log.debug("debug line")
        assert "debug line" in capsys.readouterr().out

    def test_normal_hides_debug(self, capsys, force_colour):
        setup_logging(verbose=False, quiet=False, logger_name="test.normal")
        log = get_logger("test.normal")
        log.debug("should be hidden")
        assert "should be hidden" not in capsys.readouterr().out

    def test_namespaces_are_isolated(self, capsys, force_colour):
        """Messages on 'tool_a' must not appear when 'tool_b' logger is used."""
        setup_logging(verbose=True, quiet=False, logger_name="tool_a")
        setup_logging(verbose=False, quiet=True,  logger_name="tool_b")
        get_logger("tool_b").info("tool_b message")
        assert "tool_b message" not in capsys.readouterr().out

    def test_repeated_setup_does_not_duplicate_handlers(self, capsys, force_colour):
        setup_logging(verbose=False, quiet=False, logger_name="test.dup")
        setup_logging(verbose=False, quiet=False, logger_name="test.dup")
        log = get_logger("test.dup")
        assert len(log.handlers) == 1

    def test_warning_prefix(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="test.warn")
        log = get_logger("test.warn")
        log.warning("bad thing")
        assert "[!]" in capsys.readouterr().out

    def test_info_prefix(self, capsys, no_colour):
        setup_logging(verbose=False, quiet=False, logger_name="test.info")
        log = get_logger("test.info")
        log.info("info thing")
        assert "[*]" in capsys.readouterr().out


class TestScanResultHandler:
    def test_appends_to_result_log(self):
        class _FakeResult:
            log = []
            def append_log(self, msg): self.log.append(msg)

        result = _FakeResult()
        handler = ScanResultHandler(result)
        handler.setFormatter(logging.Formatter("%(message)s"))

        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="hello world",
            args=(), exc_info=None,
        )
        handler.emit(record)
        assert "hello world" in result.log[0]


class TestColorHandlerEdgeCases:
    def test_exc_info_prints_traceback(self, capsys, no_colour):
        """Line 55: traceback.print_exception is called when exc_info is set."""
        setup_logging(verbose=False, quiet=False, logger_name="test.excinfo")
        log = get_logger("test.excinfo")
        try:
            raise ValueError("deliberate test error")
        except ValueError:
            log.exception("something failed")
        captured = capsys.readouterr()
        assert "something failed" in captured.out
        assert "ValueError: deliberate test error" in captured.err

    def test_broken_record_calls_handle_error(self, no_colour):
        """Lines 57-58: outer except catches errors from getMessage() itself."""
        from commonhuman_cli.logging import _ColorHandler

        class _BrokenRecord:
            levelno  = logging.INFO
            exc_info = None
            name     = "broken"
            msg      = ""
            args     = ()
            def getMessage(self):
                raise RuntimeError("record is corrupt")

        handler = _ColorHandler()
        errors_handled = []
        handler.handleError = lambda r: errors_handled.append(r)
        handler.emit(_BrokenRecord())
        assert len(errors_handled) == 1
