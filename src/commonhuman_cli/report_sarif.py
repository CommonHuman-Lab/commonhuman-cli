# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""SARIF 2.1.0 report generator for CommonHuman-Lab scanners.

Stdlib only — no external dependencies.

Usage::

    from commonhuman_cli.report_sarif import render_sarif
    import json

    RULES = {
        "reflected_xss": ("Reflected XSS", "XSS payload reflected in HTTP response"),
        # ... one entry per finding type the tool emits
    }

    sarif = render_sarif(
        results=[result.to_dict()],
        tool_name="StingXSS",
        tool_version="0.1.6",
        rules=RULES,
    )
    with open("report.sarif", "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
"""
from __future__ import annotations

__all__ = ["render_sarif"]

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/master/Schemata/sarif-schema-2.1.0.json"
)

_LEVEL: dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}


def _sarif_level(severity: str) -> str:
    return _LEVEL.get(severity.lower(), "warning")


def _finding_uri(f: dict) -> str:
    return f.get("url") or f.get("inject_url") or f.get("endpoint") or ""


def _finding_message(f: dict) -> str:
    ftype = f.get("type", "finding")
    loc   = _finding_uri(f)
    param = f.get("parameter") or f.get("field") or ""
    parts = [ftype]
    if param:
        parts.append(f"parameter={param}")
    if loc:
        parts.append(loc)
    return " — ".join(parts)


def render_sarif(
    results: list[dict],
    tool_name: str,
    tool_version: str,
    rules: dict[str, tuple[str, str]],
) -> dict:
    """Generate a SARIF 2.1.0 document from a list of scan results.

    Args:
        results:      List of ``ScanResult.to_dict()`` dicts.
        tool_name:    Tool name written into ``runs[].tool.driver.name``.
        tool_version: Semver string written into ``runs[].tool.driver.version``.
        rules:        Mapping of ``rule_id → (name, description)`` — one entry
                      per finding type the tool can emit.  Rule IDs should match
                      the ``"type"`` field on each finding.

    Returns:
        A ``dict`` representing a valid SARIF 2.1.0 document.  Serialise with
        ``json.dump(sarif, fh, indent=2)``.
    """
    sarif_rules = [
        {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": description},
        }
        for rule_id, (name, description) in rules.items()
    ]

    sarif_results: list[dict] = []
    for result in results:
        for f in result.get("findings", []):
            uri = _finding_uri(f)
            sarif_results.append(
                {
                    "ruleId": f.get("type", "unknown"),
                    "level": _sarif_level(f.get("severity", "medium")),
                    "message": {"text": _finding_message(f)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": uri,
                                    "uriBaseId": "%SRCROOT%",
                                }
                            }
                        }
                    ],
                }
            )

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
