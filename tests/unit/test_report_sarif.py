# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.report_sarif."""

from __future__ import annotations

import pytest

from commonhuman_cli.report_sarif import render_sarif


_RULES: dict[str, tuple[str, str]] = {
    "reflected_xss": ("Reflected XSS", "XSS payload reflected in response"),
    "dom_xss":       ("DOM XSS", "Tainted data flows from source to sink"),
    "hsts":          ("HSTS Weak", "HSTS header absent or misconfigured"),
}


def _result(findings: list | None = None) -> dict:
    return {
        "target":   "https://target.com/",
        "findings": findings or [],
    }


def _finding(ftype: str = "reflected_xss", severity: str = "high", **kwargs) -> dict:
    return {"type": ftype, "severity": severity, "url": "https://target.com/?q=x", **kwargs}


# ---------------------------------------------------------------------------
# Document structure
# ---------------------------------------------------------------------------

class TestRenderSarifStructure:
    def test_returns_dict(self):
        assert isinstance(render_sarif([], "T", "1.0", {}), dict)

    def test_sarif_version(self):
        out = render_sarif([], "T", "1.0", {})
        assert out["version"] == "2.1.0"

    def test_schema_key_present(self):
        out = render_sarif([], "T", "1.0", {})
        assert "$schema" in out
        assert "sarif" in out["$schema"]

    def test_single_run(self):
        out = render_sarif([], "T", "1.0", {})
        assert len(out["runs"]) == 1

    def test_tool_name_in_driver(self):
        out = render_sarif([], "StingXSS", "0.1.6", {})
        assert out["runs"][0]["tool"]["driver"]["name"] == "StingXSS"

    def test_tool_version_in_driver(self):
        out = render_sarif([], "T", "9.9.9", {})
        assert out["runs"][0]["tool"]["driver"]["version"] == "9.9.9"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class TestRenderSarifRules:
    def test_rules_present_in_driver(self):
        out = render_sarif([], "T", "1.0", _RULES)
        driver_rules = out["runs"][0]["tool"]["driver"]["rules"]
        assert len(driver_rules) == len(_RULES)

    def test_rule_id_matches_key(self):
        out = render_sarif([], "T", "1.0", _RULES)
        ids = {r["id"] for r in out["runs"][0]["tool"]["driver"]["rules"]}
        assert "reflected_xss" in ids
        assert "dom_xss" in ids

    def test_rule_name_and_description(self):
        out = render_sarif([], "T", "1.0", _RULES)
        rule = next(r for r in out["runs"][0]["tool"]["driver"]["rules"]
                    if r["id"] == "reflected_xss")
        assert rule["name"] == "ReflectedXss"
        assert rule["shortDescription"]["text"] == "Reflected XSS"
        assert rule["fullDescription"]["text"] == "XSS payload reflected in response"

    def test_empty_rules_dict(self):
        out = render_sarif([], "T", "1.0", {})
        assert out["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

class TestRenderSarifResults:
    def test_empty_results_produces_no_sarif_results(self):
        out = render_sarif([], "T", "1.0", _RULES)
        assert out["runs"][0]["results"] == []

    def test_finding_becomes_sarif_result(self):
        out = render_sarif([_result([_finding()])], "T", "1.0", _RULES)
        assert len(out["runs"][0]["results"]) == 1

    def test_rule_id_matches_finding_type(self):
        out = render_sarif([_result([_finding("dom_xss")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["ruleId"] == "dom_xss"

    def test_high_severity_maps_to_error(self):
        out = render_sarif([_result([_finding(severity="high")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["level"] == "error"

    def test_critical_severity_maps_to_error(self):
        out = render_sarif([_result([_finding(severity="critical")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["level"] == "error"

    def test_medium_severity_maps_to_warning(self):
        out = render_sarif([_result([_finding(severity="medium")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["level"] == "warning"

    def test_low_severity_maps_to_note(self):
        out = render_sarif([_result([_finding(severity="low")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["level"] == "note"

    def test_info_severity_maps_to_none(self):
        out = render_sarif([_result([_finding(severity="info")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["level"] == "none"

    def test_unknown_severity_defaults_to_warning(self):
        out = render_sarif([_result([_finding(severity="weird")])], "T", "1.0", _RULES)
        assert out["runs"][0]["results"][0]["level"] == "warning"

    def test_finding_url_in_location(self):
        out = render_sarif([_result([_finding(url="https://t.com/?q=x")])], "T", "1.0", {})
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://t.com/?q=x"

    def test_inject_url_fallback(self):
        f = {"type": "stored_xss", "severity": "critical",
             "inject_url": "https://t.com/post", "url": ""}
        out = render_sarif([_result([f])], "T", "1.0", {})
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://t.com/post"

    def test_endpoint_fallback(self):
        f = {"type": "graphql_xss", "severity": "high",
             "endpoint": "https://t.com/graphql"}
        out = render_sarif([_result([f])], "T", "1.0", {})
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://t.com/graphql"

    def test_no_url_fields_gives_empty_uri(self):
        f = {"type": "hsts", "severity": "low"}
        out = render_sarif([_result([f])], "T", "1.0", {})
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == ""

    def test_message_contains_type(self):
        out = render_sarif([_result([_finding("reflected_xss")])], "T", "1.0", {})
        msg = out["runs"][0]["results"][0]["message"]["text"]
        assert "reflected_xss" in msg

    def test_message_contains_parameter_when_present(self):
        f = _finding(parameter="q")
        out = render_sarif([_result([f])], "T", "1.0", {})
        msg = out["runs"][0]["results"][0]["message"]["text"]
        assert "q" in msg

    def test_findings_from_multiple_results_aggregated(self):
        out = render_sarif(
            [_result([_finding("reflected_xss")]), _result([_finding("dom_xss")])],
            "T", "1.0", _RULES,
        )
        assert len(out["runs"][0]["results"]) == 2

    def test_no_uri_base_id_for_absolute_uri(self):
        out = render_sarif([_result([_finding()])], "T", "1.0", {})
        loc = out["runs"][0]["results"][0]["locations"][0]
        assert "uriBaseId" not in loc["physicalLocation"]["artifactLocation"]
