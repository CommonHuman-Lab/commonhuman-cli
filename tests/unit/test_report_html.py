# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.report_html."""

from __future__ import annotations

import pytest

from commonhuman_cli.report_html import render_html, _sev_bar


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(
    target: str = "https://target.com/",
    findings: list | None = None,
    **kwargs,
) -> dict:
    return {
        "target":          target,
        "duration_s":      1.5,
        "requests_sent":   42,
        "crawled_urls":    5,
        "params_tested":   10,
        "waf_detected":    None,
        "evasion_applied": None,
        "total_findings":  len(findings or []),
        "findings":        findings or [],
        **kwargs,
    }


def _finding(ftype: str = "reflected_xss", severity: str = "high", **kwargs) -> dict:
    return {"type": ftype, "severity": severity, "url": "https://target.com/?q=x", **kwargs}


# ---------------------------------------------------------------------------
# render_html — structure
# ---------------------------------------------------------------------------

class TestRenderHtmlStructure:
    def test_returns_string(self):
        assert isinstance(render_html([]), str)

    def test_doctype_present(self):
        assert "<!DOCTYPE html>" in render_html([])

    def test_html_tag_present(self):
        assert "<html" in render_html([])

    def test_body_closes(self):
        assert "</body>" in render_html([])

    def test_title_uses_tool_name(self):
        out = render_html([], tool_name="StingXSS", tool_version="1.0")
        assert "StingXSS" in out

    def test_title_without_tool_name(self):
        out = render_html([])
        assert "Scan Report" in out

    def test_tool_name_without_version(self):
        out = render_html([], tool_name="MyTool")
        assert "MyTool" in out
        assert "v" not in out.split("<title>")[1].split("</title>")[0]

    def test_footer_present(self):
        assert "<footer>" in render_html([])


# ---------------------------------------------------------------------------
# render_html — empty / no-findings paths
# ---------------------------------------------------------------------------

class TestRenderHtmlEmpty:
    def test_empty_results_shows_no_targets(self):
        assert "No targets scanned" in render_html([])

    def test_result_with_no_findings_shows_no_findings(self):
        out = render_html([_result(findings=[])])
        assert "No findings" in out

    def test_target_url_shown_in_result(self):
        out = render_html([_result(target="https://example.com/search?q=1")])
        assert "example.com" in out

    def test_sev_bar_empty_findings_returns_empty_string(self):
        assert _sev_bar([]) == ""


# ---------------------------------------------------------------------------
# render_html — findings table
# ---------------------------------------------------------------------------

class TestRenderHtmlFindings:
    def test_finding_type_shown(self):
        out = render_html([_result(findings=[_finding("reflected_xss")])])
        assert "reflected_xss" in out

    def test_severity_badge_shown(self):
        out = render_html([_result(findings=[_finding(severity="high")])])
        assert "HIGH" in out

    def test_known_severity_uses_color(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            out = render_html([_result(findings=[_finding(severity=sev)])])
            assert sev.upper() in out

    def test_unknown_severity_uses_fallback_color(self):
        out = render_html([_result(findings=[_finding(severity="weird")])])
        assert "#6b7280" in out

    def test_finding_url_shown_as_location(self):
        out = render_html([_result(findings=[_finding(url="https://target.com/?q=xss")])])
        assert "target.com" in out

    def test_inject_url_used_as_location_fallback(self):
        f = {"type": "stored_xss", "severity": "critical",
             "inject_url": "https://target.com/post", "url": ""}
        out = render_html([_result(findings=[f])])
        assert "target.com/post" in out

    def test_endpoint_used_as_location_fallback(self):
        f = {"type": "graphql_xss", "severity": "high",
             "endpoint": "https://target.com/graphql"}
        out = render_html([_result(findings=[f])])
        assert "target.com/graphql" in out

    def test_empty_location_omits_span(self):
        f = {"type": "hsts", "severity": "low"}
        out = render_html([_result(findings=[f])])
        assert "hsts" in out

    def test_multiple_findings_all_shown(self):
        findings = [_finding("reflected_xss", "high"), _finding("dom_xss", "medium")]
        out = render_html([_result(findings=findings)])
        assert "reflected_xss" in out
        assert "dom_xss" in out

    def test_finding_details_long_value_truncated(self):
        f = _finding(extra_field="A" * 200)
        out = render_html([_result(findings=[f])])
        assert "..." in out

    def test_finding_details_skips_none_value(self):
        f = _finding(nullable_field=None)
        out = render_html([_result(findings=[f])])
        assert "nullable_field" not in out

    def test_finding_details_skips_empty_string(self):
        f = _finding(empty_field="")
        out = render_html([_result(findings=[f])])
        assert "empty_field" not in out

    def test_finding_details_skips_false_value(self):
        f = _finding(bool_field=False)
        out = render_html([_result(findings=[f])])
        assert "bool_field" not in out

    def test_html_special_chars_escaped(self):
        f = _finding(payload='<script>alert(1)</script>')
        out = render_html([_result(findings=[f])])
        assert "<script>" not in out
        assert "&lt;script&gt;" in out


# ---------------------------------------------------------------------------
# render_html — multiple results
# ---------------------------------------------------------------------------

class TestRenderHtmlMultipleResults:
    def test_all_targets_present(self):
        out = render_html([
            _result(target="https://a.com/"),
            _result(target="https://b.com/"),
        ])
        assert "a.com" in out
        assert "b.com" in out

    def test_waf_and_evasion_shown(self):
        r = _result(waf_detected="Cloudflare", evasion_applied="unicode")
        out = render_html([r])
        assert "Cloudflare" in out
        assert "unicode" in out
