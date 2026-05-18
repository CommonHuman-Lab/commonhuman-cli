# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.entrypoint."""

from __future__ import annotations

import re
import sys

import pytest

from commonhuman_cli.entrypoint import (
    compile_exclude_patterns,
    load_url_list,
    parse_auth_cred,
    parse_headers,
    validate_timeout,
)


class TestLoadUrlList:
    def test_reads_urls(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("https://a.com\nhttps://b.com\n")
        assert load_url_list(str(f)) == ["https://a.com", "https://b.com"]

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("https://a.com\n\nhttps://b.com\n")
        assert load_url_list(str(f)) == ["https://a.com", "https://b.com"]

    def test_skips_hash_comments(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("# comment\nhttps://a.com\n# another comment\nhttps://b.com\n")
        assert load_url_list(str(f)) == ["https://a.com", "https://b.com"]

    def test_strips_whitespace(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("  https://a.com  \n  https://b.com  \n")
        assert load_url_list(str(f)) == ["https://a.com", "https://b.com"]

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            load_url_list(str(tmp_path / "missing.txt"))
        assert exc.value.code == 2

    def test_empty_file_returns_empty_list(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert load_url_list(str(f)) == []

    def test_only_comments_returns_empty_list(self, tmp_path):
        f = tmp_path / "comments.txt"
        f.write_text("# comment 1\n# comment 2\n")
        assert load_url_list(str(f)) == []


class TestCompileExcludePatterns:
    def test_compiles_valid_patterns(self):
        pats = compile_exclude_patterns([r"\.jpg$", r"/admin/"])
        assert len(pats) == 2
        assert all(isinstance(p, re.Pattern) for p in pats)

    def test_compiled_patterns_match(self):
        pats = compile_exclude_patterns([r"\.jpg$"])
        assert pats[0].search("image.jpg")
        assert not pats[0].search("image.png")

    def test_empty_list_returns_empty(self):
        assert compile_exclude_patterns([]) == []

    def test_invalid_regex_exits_by_default(self):
        with pytest.raises(SystemExit) as exc:
            compile_exclude_patterns(["[invalid"])
        assert exc.value.code == 2

    def test_invalid_regex_raises_value_error_when_flag_off(self):
        with pytest.raises(ValueError, match="Invalid --exclude pattern"):
            compile_exclude_patterns(["[bad"], exit_on_error=False)

    def test_partial_valid_then_invalid_exits(self):
        with pytest.raises(SystemExit):
            compile_exclude_patterns([r"\.jpg$", "[bad"])


class TestParseHeaders:
    def test_basic_key_value(self):
        result = parse_headers(["Authorization: Bearer token"])
        assert result == {"Authorization": "Bearer token"}

    def test_splits_on_first_colon_only(self):
        result = parse_headers(["X-Custom: val:with:colons"])
        assert result["X-Custom"] == "val:with:colons"

    def test_multiple_headers(self):
        result = parse_headers(["Host: example.com", "Accept: text/html"])
        assert result["Host"] == "example.com"
        assert result["Accept"] == "text/html"

    def test_strips_whitespace(self):
        result = parse_headers(["  Key  :  Value  "])
        assert result["Key"] == "Value"

    def test_no_colon_skipped(self):
        result = parse_headers(["NotAHeader"])
        assert result == {}

    def test_empty_list(self):
        assert parse_headers([]) == {}

    def test_empty_value(self):
        result = parse_headers(["X-Empty:"])
        assert result["X-Empty"] == ""


class TestParseAuthCred:
    def test_splits_on_first_colon(self):
        assert parse_auth_cred("alice:secret") == ("alice", "secret")

    def test_password_with_colons_preserved(self):
        assert parse_auth_cred("alice:pa:ss:word") == ("alice", "pa:ss:word")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="username:password"):
            parse_auth_cred("")

    def test_no_colon_raises(self):
        with pytest.raises(ValueError, match="username:password"):
            parse_auth_cred("justusername")


class TestValidateTimeout:
    def test_warns_below_min(self, capsys):
        validate_timeout(3, min_val=5)
        assert "below minimum" in capsys.readouterr().err

    def test_no_output_at_min(self, capsys):
        validate_timeout(5, min_val=5)
        assert capsys.readouterr().err == ""

    def test_no_output_above_min(self, capsys):
        validate_timeout(30, min_val=5)
        assert capsys.readouterr().err == ""

    def test_warning_mentions_values(self, capsys):
        validate_timeout(2, min_val=5)
        err = capsys.readouterr().err
        assert "2" in err and "5" in err
