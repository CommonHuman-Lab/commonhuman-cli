# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.prompts."""

import sys

import pytest

from commonhuman_cli.prompts import prompt, prompt_bool, safe_int, section


class TestSafeInt:
    def test_valid_value_within_range(self):
        assert safe_int("5", 1, 1, 10) == 5

    def test_clamps_to_low(self):
        assert safe_int("0", 5, 1, 10) == 1

    def test_clamps_to_high(self):
        assert safe_int("99", 5, 1, 10) == 10

    def test_exactly_lo(self):
        assert safe_int("1", 5, 1, 10) == 1

    def test_exactly_hi(self):
        assert safe_int("10", 5, 1, 10) == 10

    def test_non_numeric_returns_default(self):
        assert safe_int("abc", 7, 1, 10) == 7

    def test_empty_string_returns_default(self):
        assert safe_int("", 3, 1, 10) == 3

    def test_float_string_returns_default(self):
        assert safe_int("3.5", 2, 1, 10) == 2


class TestPrompt:
    def test_returns_user_input(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "hello")
        assert prompt("Label") == "hello"

    def test_returns_default_on_empty_input(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert prompt("Label", default="default_val") == "default_val"

    def test_strips_whitespace(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "  trimmed  ")
        assert prompt("Label") == "trimmed"

    def test_eof_exits(self, monkeypatch):
        def raise_eof(_):
            raise EOFError
        monkeypatch.setattr("builtins.input", raise_eof)
        with pytest.raises(SystemExit) as exc:
            prompt("Label")
        assert exc.value.code == 0

    def test_keyboard_interrupt_exits(self, monkeypatch):
        def raise_ctrl_c(_):
            raise KeyboardInterrupt
        monkeypatch.setattr("builtins.input", raise_ctrl_c)
        with pytest.raises(SystemExit) as exc:
            prompt("Label")
        assert exc.value.code == 0


class TestPromptBool:
    @pytest.mark.parametrize("inp,expected", [
        ("y",    True),
        ("Y",    True),
        ("yes",  True),
        ("YES",  True),
        ("1",    True),
        ("true", True),
        ("n",    False),
        ("N",    False),
        ("no",   False),
        ("0",    False),
    ])
    def test_parses_truthy_falsy(self, monkeypatch, inp, expected):
        monkeypatch.setattr("builtins.input", lambda _: inp)
        assert prompt_bool("Label") is expected

    def test_empty_returns_default_false(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert prompt_bool("Label", default=False) is False

    def test_empty_returns_default_true(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert prompt_bool("Label", default=True) is True

    def test_eof_exits(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))
        with pytest.raises(SystemExit):
            prompt_bool("Label")


class TestSection:
    def test_prints_title(self, capsys, no_colour):
        section("Authentication")
        assert "Authentication" in capsys.readouterr().out

    def test_prints_separator_chars(self, capsys, no_colour):
        section("Target")
        assert "─" in capsys.readouterr().out

    def test_long_title_does_not_error(self, capsys, no_colour):
        section("A" * 45)   # longer than the 40-char fill width
        out = capsys.readouterr().out
        assert "A" * 45 in out
