# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.output."""

import sys

import pytest

from commonhuman_cli.output import (
    debug, error, info, print_errors, print_finding,
    print_finding_severity, print_footer, print_header, print_scan_meta,
    print_severity_summary, proof_url, success, warning,
)
from commonhuman_cli.colour import RED, GREEN, YELLOW, CYAN
from commonhuman_cli.severity import Severity


class TestStatusPrinters:
    def test_success_prefix(self, capsys, no_colour):
        success("all good")
        assert "[+] all good" in capsys.readouterr().out

    def test_warning_prefix(self, capsys, no_colour):
        warning("be careful")
        assert "[!] be careful" in capsys.readouterr().out

    def test_error_goes_to_stderr(self, capsys, no_colour):
        error("something broke")
        captured = capsys.readouterr()
        assert "[!] something broke" in captured.err
        assert captured.out == ""

    def test_info_prefix(self, capsys, no_colour):
        info("scanning")
        assert "[*] scanning" in capsys.readouterr().out

    def test_debug_prefix(self, capsys, no_colour):
        debug("raw payload")
        assert "[~] raw payload" in capsys.readouterr().out

    def test_success_uses_green(self, capsys, force_colour):
        success("found")
        out = capsys.readouterr().out
        assert "\033[38;5;46m" in out

    def test_warning_uses_yellow(self, capsys, force_colour):
        warning("caution")
        out = capsys.readouterr().out
        assert "\033[33;1m" in out

    def test_error_uses_red(self, capsys, force_colour):
        error("fail")
        err = capsys.readouterr().err
        assert "\033[31;1m" in err


class TestPrintHeader:
    def test_contains_title(self, capsys, no_colour):
        print_header("MyTool — Scan Summary")
        assert "MyTool — Scan Summary" in capsys.readouterr().out

    def test_default_width_60(self, capsys, no_colour):
        print_header("Title")
        out = capsys.readouterr().out
        assert "=" * 60 in out

    def test_custom_width(self, capsys, no_colour):
        print_header("Title", width=40)
        out = capsys.readouterr().out
        assert "=" * 40 in out


class TestPrintFooter:
    def test_outputs_separator(self, capsys, no_colour):
        print_footer()
        assert "=" * 60 in capsys.readouterr().out


class TestPrintScanMeta:
    def _meta(self, **kw):
        defaults = dict(
            target="https://example.com",
            duration_s=1.23,
            requests_sent=42,
            crawled_urls=10,
            params_tested=5,
        )
        defaults.update(kw)
        return defaults

    def test_target_printed(self, capsys, no_colour):
        print_scan_meta(**self._meta())
        assert "https://example.com" in capsys.readouterr().out

    def test_waf_none_string(self, capsys, no_colour):
        print_scan_meta(**self._meta(waf_detected=None))
        assert "None" in capsys.readouterr().out

    def test_waf_value_printed(self, capsys, no_colour):
        print_scan_meta(**self._meta(waf_detected="Cloudflare"))
        assert "Cloudflare" in capsys.readouterr().out

    def test_extra_kwargs_printed(self, capsys, no_colour):
        print_scan_meta(**self._meta(), **{"DBMS detected": "mysql"})
        assert "mysql" in capsys.readouterr().out


class TestPrintFinding:
    def test_index_and_tag_printed(self, capsys, no_colour):
        print_finding(1, "ERROR-BASED SQLi", RED, [("Param", "id"), ("URL", "https://x.com")])
        out = capsys.readouterr().out
        assert "1." in out
        assert "[ERROR-BASED SQLi]" in out

    def test_fields_printed(self, capsys, no_colour):
        print_finding(2, "DOM XSS", YELLOW, [("Source", "location.hash"), ("Sink", "innerHTML")])
        out = capsys.readouterr().out
        assert "location.hash" in out
        assert "innerHTML" in out

    def test_proof_url_printed_when_provided(self, capsys, no_colour):
        print_finding(3, "REFLECTED XSS", GREEN, [], proof="https://x.com?q=payload")
        assert "https://x.com?q=payload" in capsys.readouterr().out

    def test_proof_url_omitted_when_empty(self, capsys, no_colour):
        print_finding(4, "TAG", CYAN, [("A", "B")], proof="")
        assert "Proof" not in capsys.readouterr().out


class TestPrintErrors:
    def test_empty_list_prints_nothing(self, capsys):
        print_errors([])
        assert capsys.readouterr().out == ""

    def test_non_empty_prints_each_error(self, capsys, no_colour):
        print_errors(["timeout", "connection refused"])
        out = capsys.readouterr().out
        assert "timeout" in out
        assert "connection refused" in out


class TestProofUrl:
    def test_append_mode_preserves_original(self):
        url = "https://target.com/page?id=1"
        result = proof_url(url, "id", "' AND 1=1--", append=True)
        assert "id=" in result
        # original value should be present in some form
        assert "1" in result

    def test_append_mode_contains_payload(self):
        url = "https://target.com/page?id=1"
        result = proof_url(url, "id", "INJECT", append=True)
        assert "INJECT" in result

    def test_replace_mode_replaces_value(self):
        url = "https://target.com/page?q=safe"
        result = proof_url(url, "q", "<script>", append=False)
        # "safe" should not appear in the encoded param
        qs_part = result.split("?", 1)[1] if "?" in result else result
        assert "safe" not in qs_part

    def test_replace_mode_contains_payload(self):
        url = "https://target.com/page?q=x"
        result = proof_url(url, "q", "XSSPAYLOAD", append=False)
        assert "XSSPAYLOAD" in result

    def test_missing_param_append_uses_fallback(self):
        url = "https://target.com/page?other=val"
        result = proof_url(url, "id", "INJECT", append=True)
        assert "id=" in result
        assert "INJECT" in result

    def test_malformed_url_returns_empty(self):
        assert proof_url("not-a-url", "q", "payload") == ""

    def test_empty_url_returns_empty(self):
        assert proof_url("", "q", "payload") == ""

    def test_result_is_valid_url(self):
        from urllib.parse import urlparse
        result = proof_url("https://example.com/search?q=1", "q", "' OR 1=1--", append=True)
        parsed = urlparse(result)
        assert parsed.scheme == "https"
        assert parsed.netloc == "example.com"

    def test_encode_error_returns_empty(self, monkeypatch):
        """Lines 154-155: ValueError from urlencode is caught and returns ""."""
        import urllib.parse
        monkeypatch.setattr(urllib.parse, "urlencode", lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad")))
        result = proof_url("https://example.com/page?q=x", "q", "payload")
        assert result == ""


class TestPrintFindingSeverity:
    def test_index_and_tag_in_output(self, capsys, no_colour):
        print_finding_severity(1, "REFLECTED XSS", Severity.HIGH, [])
        out = capsys.readouterr().out
        assert "1." in out
        assert "REFLECTED XSS" in out

    def test_severity_label_in_tag(self, capsys, no_colour):
        print_finding_severity(2, "DOM XSS", Severity.MEDIUM, [])
        assert "MEDIUM" in capsys.readouterr().out

    def test_fields_printed(self, capsys, no_colour):
        print_finding_severity(3, "VULN", Severity.LOW, [("Param", "q"), ("URL", "https://x.com")])
        out = capsys.readouterr().out
        assert "Param" in out
        assert "q" in out
        assert "https://x.com" in out

    def test_proof_url_printed_when_provided(self, capsys, no_colour):
        print_finding_severity(4, "XSS", Severity.HIGH, [], proof="https://x.com?q=poc")
        assert "https://x.com?q=poc" in capsys.readouterr().out

    def test_proof_url_omitted_when_empty(self, capsys, no_colour):
        print_finding_severity(5, "XSS", Severity.HIGH, [("A", "B")], proof="")
        assert "Proof" not in capsys.readouterr().out

    def test_critical_uses_colour(self, capsys, force_colour):
        print_finding_severity(1, "STORED XSS", Severity.CRITICAL, [])
        out = capsys.readouterr().out
        assert "\033[" in out  # some ANSI escape present

    def test_info_uses_dim(self, capsys, force_colour):
        print_finding_severity(1, "NOTE", Severity.INFO, [])
        out = capsys.readouterr().out
        # DIM escape code present
        assert "\033[" in out


class TestPrintSeveritySummary:
    def test_all_severity_levels_shown(self, capsys, no_colour):
        counts = {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}
        print_severity_summary(counts)
        out = capsys.readouterr().out
        assert "CRITICAL" in out
        assert "HIGH" in out
        assert "MEDIUM" in out

    def test_counts_shown(self, capsys, no_colour):
        counts = {"critical": 3, "high": 7, "medium": 2, "low": 0, "info": 1}
        print_severity_summary(counts)
        out = capsys.readouterr().out
        assert "3" in out
        assert "7" in out

    def test_severity_label_present(self, capsys, no_colour):
        print_severity_summary({})
        assert "Severity" in capsys.readouterr().out

    def test_empty_counts_shows_zeros(self, capsys, no_colour):
        print_severity_summary({})
        out = capsys.readouterr().out
        assert "0" in out

    def test_output_is_single_line(self, capsys, no_colour):
        print_severity_summary({"high": 1})
        lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
        assert len(lines) == 1
