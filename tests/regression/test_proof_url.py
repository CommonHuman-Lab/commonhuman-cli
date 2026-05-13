# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Regression tests for proof_url — contracts from both breachsql and stingxss.

breachsql behaviour: append=True  (payload appended to original value)
stingxss  behaviour: append=False (payload replaces value entirely)

Both behaviours must be preserved exactly.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from commonhuman_cli.output import proof_url


class TestBreachsqlContract:
    """append=True: matches breachsql _proof_url semantics."""

    def test_original_value_preserved(self):
        url = "https://target.com/search?id=1"
        result = proof_url(url, "id", "' AND 1=1--", append=True)
        qs = parse_qs(urlparse(result).query)
        assert qs["id"][0].startswith("1")

    def test_payload_appended_after_original(self):
        url = "https://target.com/search?id=1"
        result = proof_url(url, "id", "INJECT", append=True)
        qs = parse_qs(urlparse(result).query, keep_blank_values=True)
        assert qs["id"][0] == "1INJECT"

    def test_missing_param_uses_fallback_original(self):
        url = "https://target.com/search?other=x"
        result = proof_url(url, "id", "INJECT", append=True)
        qs = parse_qs(urlparse(result).query)
        assert "id" in qs
        assert qs["id"][0] == "1INJECT"   # fallback "1" + payload

    def test_multiple_params_only_target_modified(self):
        url = "https://target.com/search?id=5&page=2"
        result = proof_url(url, "id", "INJECT", append=True)
        qs = parse_qs(urlparse(result).query)
        assert qs["page"][0] == "2"
        assert "INJECT" in qs["id"][0]

    def test_result_preserves_scheme_and_host(self):
        url = "https://target.com/path?id=1"
        result = proof_url(url, "id", "X", append=True)
        parsed = urlparse(result)
        assert parsed.scheme == "https"
        assert parsed.netloc == "target.com"
        assert parsed.path == "/path"


class TestStingxssContract:
    """append=False: matches stingxss _proof_url semantics."""

    def test_original_value_replaced(self):
        url = "https://target.com/search?q=safe"
        result = proof_url(url, "q", "<script>alert(1)</script>", append=False)
        qs = parse_qs(urlparse(result).query, keep_blank_values=True)
        assert qs["q"][0] == "<script>alert(1)</script>"

    def test_original_not_in_result(self):
        url = "https://target.com/search?q=original_value"
        result = proof_url(url, "q", "PAYLOAD", append=False)
        qs = parse_qs(urlparse(result).query)
        assert "original_value" not in qs["q"][0]

    def test_result_is_valid_url(self):
        url = "https://example.com/page?q=x"
        result = proof_url(url, "q", "XSS", append=False)
        parsed = urlparse(result)
        assert parsed.scheme == "https"
        assert parsed.netloc == "example.com"


class TestErrorHandling:
    """Both breachsql and stingxss return "" on failure — this must hold."""

    def test_malformed_url_returns_empty_append(self):
        assert proof_url("not-a-url", "q", "payload", append=True) == ""

    def test_malformed_url_returns_empty_replace(self):
        assert proof_url("not-a-url", "q", "payload", append=False) == ""

    def test_empty_url_returns_empty(self):
        assert proof_url("", "q", "payload") == ""


class TestDefaultBehaviour:
    def test_default_is_append_mode(self):
        url = "https://t.com/s?id=1"
        default = proof_url(url, "id", "X")
        explicit = proof_url(url, "id", "X", append=True)
        assert default == explicit
