# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Self-contained HTML report generator for CommonHuman-Lab scanners.

Stdlib only — no external dependencies.

Usage::

    from commonhuman_cli.report_html import render_html

    html = render_html(
        results=[result.to_dict()],
        tool_name="StingXSS",
        tool_version="0.1.6",
    )
    with open("report.html", "w", encoding="utf-8") as fh:
        fh.write(html)
"""
from __future__ import annotations

import html as _html
from datetime import datetime, timezone

__all__ = ["render_html"]

_SEV_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#16a34a",
    "info":     "#2563eb",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
       background: #f1f5f9; color: #0f172a; line-height: 1.5; }
header { background: #0f172a; color: #f8fafc; padding: 1.5rem 2rem; }
header h1 { font-size: 1.4rem; font-weight: 700; }
header p  { font-size: 0.85rem; opacity: 0.6; margin-top: 0.25rem; }
.run { background: #fff; margin: 1.5rem 2rem; border-radius: 8px;
       box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden; }
.run-header { padding: 1rem 1.5rem; border-bottom: 1px solid #e2e8f0; }
.run-header h2 { font-size: 1rem; font-weight: 600; word-break: break-all; }
.meta { display: grid; grid-template-columns: repeat(auto-fill,minmax(160px,1fr));
        gap: .75rem; padding: 1rem 1.5rem; background: #f8fafc;
        border-bottom: 1px solid #e2e8f0; }
.meta-item .label { color: #64748b; font-size: .7rem; text-transform: uppercase;
                    letter-spacing: .05em; }
.meta-item .value { font-weight: 600; font-size: .85rem; }
table  { width: 100%; border-collapse: collapse; font-size: .85rem; }
th     { background: #f8fafc; text-align: left; padding: .6rem 1rem;
         border-bottom: 2px solid #e2e8f0; font-size: .75rem;
         text-transform: uppercase; letter-spacing: .05em; color: #64748b; }
td     { padding: .6rem 1rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: .7rem; font-weight: 600; color: #fff; }
.no-findings { padding: 1.5rem; color: #64748b; text-align: center; font-size: .9rem; }
.loc  { color: #2563eb; word-break: break-all; font-family: monospace; font-size: .78rem; }
.kv   { font-size: .78rem; margin: 1px 0; }
.k    { color: #64748b; }
footer { text-align: center; padding: 1rem; font-size: .75rem; color: #94a3b8; }
"""

_SKIP_FIELDS = frozenset({"type", "severity", "url", "inject_url", "endpoint"})


def _esc(text: object) -> str:
    return _html.escape(str(text))


def _sev_badge(sev: str) -> str:
    colour = _SEV_COLORS.get(sev.lower(), "#6b7280")
    return f'<span class="badge" style="background:{colour}">{_esc(sev.upper())}</span>'


def _finding_url(f: dict) -> str:
    return f.get("url") or f.get("inject_url") or f.get("endpoint") or ""


def _finding_details(f: dict) -> str:
    parts: list[str] = []
    for k, v in f.items():
        if k in _SKIP_FIELDS or v is None or v == "" or v is False:
            continue
        val = str(v)
        if len(val) > 120:
            val = val[:117] + "..."
        parts.append(f'<div class="kv"><span class="k">{_esc(k)}</span>: {_esc(val)}</div>')
    return f'<div>{"".join(parts)}</div>'


def _render_result(result: dict, idx: int) -> str:
    target   = result.get("target", "")
    findings = result.get("findings", [])
    total    = result.get("total_findings", len(findings))

    meta_items = [
        ("Duration",      f'{result.get("duration_s", 0)}s'),
        ("Requests",      str(result.get("requests_sent", 0))),
        ("Crawled URLs",  str(result.get("crawled_urls", 0))),
        ("Params tested", str(result.get("params_tested", 0))),
        ("WAF",           result.get("waf_detected") or "None"),
        ("Evasion",       result.get("evasion_applied") or "None"),
        ("Findings",      str(total)),
    ]
    meta_html = "".join(
        f'<div class="meta-item">'
        f'<div class="label">{_esc(lbl)}</div>'
        f'<div class="value">{_esc(val)}</div>'
        f'</div>'
        for lbl, val in meta_items
    )

    if not findings:
        body = '<div class="no-findings">No findings.</div>'
    else:
        rows = []
        for i, f in enumerate(findings, 1):
            loc = _finding_url(f)
            loc_html = f'<span class="loc">{_esc(loc)}</span>' if loc else ""
            rows.append(
                f"<tr><td>{i}</td>"
                f"<td>{_esc(f.get('type', ''))}</td>"
                f"<td>{_sev_badge(f.get('severity', 'info'))}</td>"
                f"<td>{loc_html}</td>"
                f"<td>{_finding_details(f)}</td></tr>"
            )
        body = (
            "<table>"
            "<thead><tr>"
            "<th>#</th><th>Type</th><th>Severity</th>"
            "<th>Location</th><th>Details</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )

    return (
        f'<div class="run">'
        f'<div class="run-header"><h2>{idx}. {_esc(target)}</h2></div>'
        f'<div class="meta">{meta_html}</div>'
        f"{body}"
        f"</div>"
    )


def render_html(
    results: list[dict],
    tool_name: str = "",
    tool_version: str = "",
) -> str:
    """Generate a self-contained HTML scan report.

    Args:
        results:      List of ``ScanResult.to_dict()`` dicts.
        tool_name:    Tool name shown in the header (e.g. ``"StingXSS"``).
        tool_version: Version string (e.g. ``"0.1.6"``).

    Returns:
        A complete, self-contained HTML document as a string.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if tool_name and tool_version:
        ver_label = f"{tool_name} v{tool_version}"
    elif tool_name:
        ver_label = tool_name
    else:
        ver_label = ""

    title   = _esc(f"{ver_label} Scan Report" if ver_label else "Scan Report")
    subline = f"Generated {_esc(now)}"
    if ver_label:
        subline += f" &middot; {_esc(ver_label)}"

    if results:
        runs_html = "".join(_render_result(r, i) for i, r in enumerate(results, 1))
    else:
        runs_html = '<div class="run"><div class="no-findings">No targets scanned.</div></div>'

    footer_name = _esc(ver_label or "CommonHuman-Lab")

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{title}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        f"<header><h1>{title}</h1><p>{subline}</p></header>\n"
        f"{runs_html}\n"
        f"<footer>Generated by {footer_name}</footer>\n"
        "</body>\n"
        "</html>"
    )
