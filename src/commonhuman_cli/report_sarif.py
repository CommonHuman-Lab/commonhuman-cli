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

import hashlib

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

# OWASP help URIs per rule id — used as helpUri and in help.text
_HELP_URIS: dict[str, str] = {
    "reflected_xss":  "https://owasp.org/www-community/attacks/xss/",
    "stored_xss":     "https://owasp.org/www-community/attacks/xss/",
    "dom_xss":        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
    "blind_xss":      "https://owasp.org/www-community/attacks/xss/",
    "browser_xss":    "https://owasp.org/www-community/attacks/xss/",
    "graphql_xss":    "https://owasp.org/www-community/attacks/xss/",
    "websocket_xss":  "https://owasp.org/www-community/attacks/xss/",
    "clickjacking":   "https://owasp.org/www-community/attacks/Clickjacking",
    "cors":           "https://owasp.org/www-community/vulnerabilities/CORS_OriginHeaderScrutiny",
    "jsonp_some":     "https://owasp.org/www-community/attacks/JSONP",
    "mixed_content":  "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
    "leaked_cookie":  "https://owasp.org/www-community/controls/SecureCookieAttribute",
    "open_redirect":  "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    "hsts":           "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    "vuln_lib":       "https://owasp.org/www-project-dependency-check/",
    "sri_missing":    "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    "crlf":           "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
    "xst":            "https://owasp.org/www-community/vulnerabilities/Cross_Site_Tracing",
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


def _pascal(name: str) -> str:
    """Convert 'Reflected XSS' → 'ReflectedXss' for SARIF rule name field."""
    return "".join(w.capitalize() for w in name.replace("-", " ").split())


def _fingerprint(f: dict) -> str:
    """Stable SHA-256 fingerprint for deduplication (first 16 hex chars)."""
    uri   = _finding_uri(f)
    ftype = f.get("type", "")
    param = f.get("parameter") or f.get("field") or ""
    key   = f"{ftype}:{uri}:{param}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def render_sarif(
    results: list[dict],
    tool_name: str,
    tool_version: str,
    rules: dict[str, tuple[str, str]],
    information_uri: str = "",
) -> dict:
    """Generate a SARIF 2.1.0 document from a list of scan results.

    Args:
        results:         List of ``ScanResult.to_dict()`` dicts.
        tool_name:       Tool name written into ``runs[].tool.driver.name``.
        tool_version:    Semver string written into ``runs[].tool.driver.version``.
        rules:           Mapping of ``rule_id → (name, description)`` — one entry
                         per finding type the tool can emit.  Rule IDs should match
                         the ``"type"`` field on each finding.
        information_uri: Optional URI for the tool's homepage / docs.

    Returns:
        A ``dict`` representing a valid SARIF 2.1.0 document.  Serialise with
        ``json.dump(sarif, fh, indent=2)``.
    """
    # Build rule list and an O(1) lookup from rule_id → array index
    rule_index: dict[str, int] = {}
    sarif_rules: list[dict] = []
    for idx, (rule_id, (name, description)) in enumerate(rules.items()):
        rule_index[rule_id] = idx
        help_uri = _HELP_URIS.get(rule_id, "")
        rule: dict = {
            "id":               rule_id,
            "name":             _pascal(name),
            "shortDescription": {"text": name},
            "fullDescription":  {"text": description},
            "help": {
                "text":     f"{description}. See: {help_uri}" if help_uri else description,
                "markdown": (
                    f"{description}.\n\nSee [{help_uri}]({help_uri})"
                    if help_uri else description
                ),
            },
        }
        if help_uri:
            rule["helpUri"] = help_uri
        sarif_rules.append(rule)

    sarif_results: list[dict] = []
    for result in results:
        for f in result.get("findings", []):
            uri      = _finding_uri(f)
            rule_id  = f.get("type", "unknown")
            ridx     = rule_index.get(rule_id, 0)

            sarif_result: dict = {
                "ruleId":    rule_id,
                "ruleIndex": ridx,
                "level":     _sarif_level(f.get("severity", "medium")),
                "message":   {"text": _finding_message(f)},
                "locations": [
                    {
                        "physicalLocation": {
                            # No uriBaseId: absolute http:// URIs must stand alone
                            "artifactLocation": {"uri": uri},
                            # GitHub Code Scanning requires a region; use line 1
                            # as a placeholder — web findings have no source line
                            "region": {"startLine": 1},
                        }
                    }
                ],
                # GitHub Advanced Security uses partialFingerprints for dedup
                "partialFingerprints": {
                    "primaryLocationLineHash/v1": _fingerprint(f),
                },
            }
            sarif_results.append(sarif_result)

    driver: dict = {
        "name":    tool_name,
        "version": tool_version,
        "rules":   sarif_rules,
    }
    if information_uri:
        driver["informationUri"] = information_uri

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool":    {"driver": driver},
                "results": sarif_results,
            }
        ],
    }
