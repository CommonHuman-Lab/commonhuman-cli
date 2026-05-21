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
.sev-bar { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
           padding: .75rem 1.5rem; border-bottom: 1px solid #e2e8f0;
           background: #fff; }
.sev-chip { display: inline-flex; align-items: center; gap: .35rem;
            padding: .3rem .75rem; border-radius: 20px; font-size: .75rem;
            font-weight: 700; color: #fff; letter-spacing: .03em; }
.sev-chip .chip-count { font-size: .9rem; }
.sev-label { font-size: .7rem; text-transform: uppercase; color: #94a3b8;
             letter-spacing: .05em; margin-right: .25rem; }
.no-findings { padding: 1.5rem; color: #64748b; text-align: center; font-size: .9rem; }
.loc  { color: #2563eb; word-break: break-all; font-family: monospace; font-size: .78rem; }
.kv   { font-size: .78rem; margin: 1px 0; }
.k    { color: #64748b; }
footer { text-align: center; padding: 1rem; font-size: .75rem; color: #94a3b8; }

/* Tabs */
.tab-bar { display: flex; gap: 0; border-bottom: 2px solid #e2e8f0; background: #f8fafc; }
.tab-btn { padding: .6rem 1.25rem; font-size: .8rem; font-weight: 600;
           border: none; background: none; cursor: pointer; color: #64748b;
           border-bottom: 2px solid transparent; margin-bottom: -2px;
           letter-spacing: .03em; transition: color .15s, border-color .15s; }
.tab-btn:hover { color: #0f172a; }
.tab-btn.active { color: #2563eb; border-bottom-color: #2563eb; }
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* Dumped tables */
.dump-section { padding: 1.25rem 1.5rem; border-bottom: 1px solid #f1f5f9; }
.dump-section:last-child { border-bottom: none; }
.dump-title { font-size: .8rem; font-weight: 700; text-transform: uppercase;
              letter-spacing: .06em; color: #0f172a; margin-bottom: .75rem; }
.dump-meta  { font-size: .72rem; color: #94a3b8; margin-bottom: .6rem; }
.dump-table { width: 100%; border-collapse: collapse; font-size: .82rem; }
.dump-table th { background: #0f172a; color: #f8fafc; padding: .45rem .8rem;
                 text-align: left; font-size: .72rem; letter-spacing: .05em; }
.dump-table td { padding: .45rem .8rem; border-bottom: 1px solid #f1f5f9;
                 font-family: monospace; font-size: .78rem; word-break: break-all; }
.dump-table tr:last-child td { border-bottom: none; }
.dump-table tr:nth-child(even) td { background: #f8fafc; }
.null-val { color: #94a3b8; font-style: italic; }
"""

_JS = """
function showTab(btn, panelId) {
  var run = btn.closest('.run');
  run.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
  run.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
  btn.classList.add('active');
  document.getElementById(panelId).classList.add('active');
}
"""

_SKIP_FIELDS = frozenset({"type", "severity", "url", "inject_url", "endpoint"})

_SEV_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(text: object) -> str:
    return _html.escape(str(text))


def _sev_badge(sev: str) -> str:
    colour = _SEV_COLORS.get(sev.lower(), "#6b7280")
    return f'<span class="badge" style="background:{colour}">{_esc(sev.upper())}</span>'


def _sev_bar(findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        return ""
    chips = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev)
        if not n:
            continue
        colour = _SEV_COLORS.get(sev, "#6b7280")
        chips.append(
            f'<span class="sev-chip" style="background:{colour}">'
            f'<span class="chip-count">{n}</span>'
            f'&nbsp;{_esc(sev.upper())}'
            f'</span>'
        )
    return (
        f'<div class="sev-bar">'
        f'<span class="sev-label">Findings</span>'
        f'{"".join(chips)}'
        f'</div>'
    )


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


def _render_table_dump(td: dict) -> str:
    table   = td.get("table", "?")
    columns = td.get("columns") or []
    rows    = td.get("rows") or []
    url     = td.get("url", "")
    param   = td.get("parameter", "")
    method  = td.get("method", "")

    meta_parts = []
    if url:
        meta_parts.append(f'<span class="loc">{_esc(url)}</span>')
    if param:
        meta_parts.append(f'param: <code>{_esc(param)}</code>')
    if method:
        meta_parts.append(f'method: <code>{_esc(method)}</code>')
    meta_html = " &nbsp;·&nbsp; ".join(meta_parts)

    if not columns and not rows:
        body = '<div class="no-findings">No rows returned.</div>'
    else:
        header_cells = "".join(f"<th>{_esc(c)}</th>" for c in columns)
        row_htmls = []
        for row in rows:
            cells = []
            for cell in row:
                if cell is None or cell == "":
                    cells.append('<td><span class="null-val">NULL</span></td>')
                else:
                    cells.append(f"<td>{_esc(cell)}</td>")
            row_htmls.append(f"<tr>{''.join(cells)}</tr>")
        body = (
            '<div style="overflow-x:auto">'
            '<table class="dump-table">'
            f"<thead><tr>{header_cells}</tr></thead>"
            f"<tbody>{''.join(row_htmls)}</tbody>"
            "</table>"
            "</div>"
        )

    row_count = f"{len(rows)} row{'s' if len(rows) != 1 else ''}"
    col_count = f"{len(columns)} column{'s' if len(columns) != 1 else ''}"

    return (
        f'<div class="dump-section">'
        f'<div class="dump-title">{_esc(table)}</div>'
        f'<div class="dump-meta">{row_count} &nbsp;·&nbsp; {col_count}'
        + (f" &nbsp;·&nbsp; {meta_html}" if meta_html else "")
        + f'</div>'
        f'{body}'
        f'</div>'
    )


def _render_result(result: dict, idx: int) -> str:
    target      = result.get("target", "")
    findings    = result.get("findings", [])
    table_dumps = result.get("table_dumps") or []
    total       = result.get("total_findings", len(findings))

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

    # Findings panel
    if not findings:
        findings_body = '<div class="no-findings">No findings.</div>'
        sev_bar_html  = ""
    else:
        findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "info").lower(), 99))
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
        findings_body = (
            "<table>"
            "<thead><tr>"
            "<th>#</th><th>Type</th><th>Severity</th>"
            "<th>Location</th><th>Details</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )
        sev_bar_html = _sev_bar(findings)

    findings_panel_id = f"findings-{idx}"
    tables_panel_id   = f"tables-{idx}"

    findings_tab_label = f"Findings ({total})"
    tables_tab_label   = f"Dumped Tables ({len(table_dumps)})"

    # Tab bar
    tables_btn_extra = "" if table_dumps else ' style="opacity:.4;cursor:default" disabled'
    tab_bar = (
        f'<div class="tab-bar">'
        f'<button class="tab-btn active" onclick="showTab(this,\'{findings_panel_id}\')">'
        f'{_esc(findings_tab_label)}</button>'
        f'<button class="tab-btn"{tables_btn_extra} onclick="showTab(this,\'{tables_panel_id}\')">'
        f'{_esc(tables_tab_label)}</button>'
        f'</div>'
    )

    # Tables panel
    if table_dumps:
        tables_body = "".join(_render_table_dump(td) for td in table_dumps)
    else:
        tables_body = '<div class="no-findings">No tables dumped.</div>'

    return (
        f'<div class="run">'
        f'<div class="run-header"><h2>{idx}. {_esc(target)}</h2></div>'
        f'<div class="meta">{meta_html}</div>'
        f'{sev_bar_html}'
        f'{tab_bar}'
        f'<div id="{findings_panel_id}" class="tab-panel active">{findings_body}</div>'
        f'<div id="{tables_panel_id}" class="tab-panel">{tables_body}</div>'
        f'</div>'
    )


def render_html(
    results: list[dict],
    tool_name: str = "",
    tool_version: str = "",
) -> str:
    """Generate a self-contained HTML scan report.

    Args:
        results:      List of ``ScanResult.to_dict()`` dicts, optionally with
                      a ``table_dumps`` key from ``dumps_to_dict()``.
        tool_name:    Tool name shown in the header (e.g. ``"BreachSQL"``).
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

    title   = _esc(f"{tool_name} Scan Report" if tool_name else "Scan Report")
    subline = f"Generated {_esc(now)}"

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
        f"<script>{_JS}</script>\n"
        "</head>\n"
        "<body>\n"
        f"<header><h1>{title}</h1><p>{subline}</p></header>\n"
        f"{runs_html}\n"
        f"<footer>Generated by {footer_name}</footer>\n"
        "</body>\n"
        "</html>"
    )
