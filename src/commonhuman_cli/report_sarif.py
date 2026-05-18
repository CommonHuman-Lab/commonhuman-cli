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
import re
import urllib.parse

__all__ = ["render_sarif"]

# Use the SchemaStore URL — SARIF2006 flags the raw GitHub URL
_SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json"

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
    "open_redirect":  "https://cheatsheetseries.owasp.org/cheatsheets/"
                      "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    "hsts":           "https://cheatsheetseries.owasp.org/cheatsheets/"
                      "HTTP_Strict_Transport_Security_Cheat_Sheet.html",
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
    """Convert 'Reflected XSS' / 'JSONP / SOME' → 'ReflectedXss' / 'JsonpSome'."""
    return "".join(w.capitalize() for w in re.split(r"[^a-zA-Z0-9]+", name) if w)


def _safe_uri(uri: str) -> str:
    """Percent-encode characters that violate RFC 3986 (e.g. payload in query)."""
    try:
        p = urllib.parse.urlparse(uri)
        return urllib.parse.urlunparse(p._replace(
            path=urllib.parse.quote(p.path, safe="/-._~"),
            query=urllib.parse.quote(p.query, safe="=&+%"),
        ))
    except Exception:
        return urllib.parse.quote(uri, safe=":/?#[]@!$&*+,;=-._~%")


def _fingerprint(f: dict) -> str:
    """Stable SHA-256 fingerprint for deduplication (first 16 hex chars)."""
    key = f"{f.get('type', '')}:{_finding_uri(f)}:{f.get('parameter') or f.get('field') or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _make_rule(rule_id: str, name: str, description: str) -> dict:
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
    return rule


def _make_location(uri: str) -> dict:
    safe = _safe_uri(uri)
    snippet = {"text": uri}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": safe},
            "region":        {"startLine": 1, "snippet": snippet},
            "contextRegion": {"startLine": 1, "snippet": snippet},
        },
        "logicalLocations": [{"name": uri, "kind": "url", "fullyQualifiedName": uri}],
    }


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
    rule_index: dict[str, int] = {}
    sarif_rules = [
        (rule_index.setdefault(rid, i) or None,  # side-effect: populate index
         _make_rule(rid, name, desc))
        for i, (rid, (name, desc)) in enumerate(rules.items())
    ]
    sarif_rules_list = [r for _, r in sarif_rules]

    sarif_results = [
        {
            "ruleId":    f.get("type", "unknown"),
            "ruleIndex": rule_index.get(f.get("type", "unknown"), 0),
            "level":     _sarif_level(f.get("severity", "medium")),
            "message":   {"text": _finding_message(f)},
            "locations": [_make_location(_finding_uri(f))],
            "partialFingerprints": {"primaryLocationLineHash/v1": _fingerprint(f)},
        }
        for result in results
        for f in result.get("findings", [])
    ]

    driver: dict = {
        "name":     tool_name,
        "fullName": f"{tool_name} Security Scanner",
        "version":  tool_version,
        "rules":    sarif_rules_list,
    }
    if information_uri:
        driver["informationUri"] = information_uri

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": f"{tool_name}/"},
                "tool":    {"driver": driver},
                "results": sarif_results,
            }
        ],
    }
