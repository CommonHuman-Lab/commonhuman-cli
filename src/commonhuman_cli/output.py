# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Terminal output helpers: status printers, summary blocks, and PoC URL builder."""

from __future__ import annotations

import sys
import urllib.parse as _up
from typing import Callable

from commonhuman_cli.colour import BOLD, CYAN, DIM, GREEN, RED, YELLOW

__all__ = [
    "success", "warning", "error", "info", "debug",
    "print_header", "print_footer", "print_scan_meta",
    "print_finding", "print_finding_severity", "print_severity_summary", "print_errors",
    "proof_url",
    "write_json_output",
    "write_text_output",
]


# ---------------------------------------------------------------------------
# One-liner status printers
# ---------------------------------------------------------------------------

def success(msg: str) -> None:
    """Print a GREEN [+] confirmation line."""
    print(GREEN(f"[+] {msg}"))


def warning(msg: str) -> None:
    """Print a YELLOW [!] warning line."""
    print(YELLOW(f"[!] {msg}"))


def error(msg: str) -> None:
    """Print a RED [!] error line to stderr."""
    print(RED(f"[!] {msg}"), file=sys.stderr)


def info(msg: str) -> None:
    """Print a DIM [*] informational line."""
    print(DIM(f"[*] {msg}"))


def debug(msg: str) -> None:
    """Print a CYAN [~] debug line."""
    print(CYAN(f"[~] {msg}"))


# ---------------------------------------------------------------------------
# Summary block helpers
# ---------------------------------------------------------------------------

def print_header(title: str, width: int = 60) -> None:
    """Print a BOLD === title === header block."""
    print()
    print(BOLD("=" * width))
    print(BOLD(f"  {title}"))
    print(BOLD("=" * width))


def print_footer(width: int = 60) -> None:
    """Print a BOLD === closing separator."""
    print(BOLD("=" * width))


def print_scan_meta(
    target: str,
    duration_s: float,
    requests_sent: int,
    crawled_urls: int,
    params_tested: int,
    *,
    waf_detected: str | None = None,
    evasion_applied: str | None = None,
    **extra: str,
) -> None:
    """Print the standard scan metadata block.

    The five required positional args cover fields common to every tool.
    Pass tool-specific rows as keyword arguments, e.g.:
        print_scan_meta(..., **{"DBMS detected": result.dbms_detected or "Unknown"})
    """
    print(f"  Target        : {target}")
    print(f"  Duration      : {duration_s}s")
    print(f"  Requests sent : {requests_sent}")
    print(f"  URLs crawled  : {crawled_urls}")
    print(f"  Params tested : {params_tested}")
    print(f"  WAF detected  : {waf_detected or 'None'}")
    print(f"  Evasion used  : {evasion_applied or 'None'}")
    for key, val in extra.items():
        print(f"  {key:<14}: {val}")
    print()


def print_finding(
    index: int,
    tag: str,
    tag_colour_fn: Callable[[str], str],
    fields: list[tuple[str, str]],
    proof: str = "",
) -> None:
    """Print a single numbered finding block.

    Args:
        index:         1-based finding number.
        tag:           Finding label, e.g. "ERROR-BASED SQLi".
        tag_colour_fn: Colour function to wrap the tag, e.g. RED or YELLOW.
        fields:        Ordered list of (label, value) rows.
        proof:         Optional PoC URL; omitted when empty.
    """
    print(f"  {index}. {tag_colour_fn(f'[{tag}]')}")
    for label, value in fields:
        print(f"     {label:<10}: {value}")
    if proof:
        print(f"     {'Proof':<10}: {CYAN(proof)}")
    print()


def print_finding_severity(
    index: int,
    tag: str,
    severity: str,
    fields: list[tuple[str, str]],
    proof: str = "",
) -> None:
    """Like print_finding but colours the tag by severity automatically.

    Args:
        index:    1-based finding number.
        tag:      Finding label, e.g. "REFLECTED XSS".
        severity: Severity string from ``commonhuman_cli.severity.Severity``.
        fields:   Ordered list of (label, value) rows.
        proof:    Optional PoC URL; omitted when empty.
    """
    from commonhuman_cli.severity import severity_colour, severity_label
    colour_fn = severity_colour(severity)
    full_tag  = f"{tag} [{severity_label(severity).strip()}]"
    print(f"  {index}. {colour_fn(f'[{full_tag}]')}")
    for label, value in fields:
        print(f"     {label:<10}: {value}")
    if proof:
        print(f"     {'Proof':<10}: {CYAN(proof)}")
    print()


def print_severity_summary(counts: dict[str, int]) -> None:
    """Print a compact severity count summary line.

    Args:
        counts: Dict mapping severity string → number of findings.
                Unknown severity strings are grouped under "other".

    Example output::

        Severity  : CRITICAL 0  HIGH 3  MEDIUM 1  LOW 0  INFO 2
    """
    from commonhuman_cli.severity import SEVERITY_ORDER, severity_colour
    parts: list[str] = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        colour_fn = severity_colour(sev) if n > 0 else DIM
        parts.append(colour_fn(f"{sev.upper()} {n}"))
    print(f"  {'Severity':<14}: {'  '.join(parts)}")


def print_errors(errors: list[str]) -> None:
    """Print a RED errors block; no-ops on an empty list."""
    if not errors:
        return
    print(RED("  Errors:"))
    for e in errors:
        print(f"    - {e}")


# ---------------------------------------------------------------------------
# JSON file output
# ---------------------------------------------------------------------------

def write_text_output(text: str, path: str) -> None:
    """Write *text* to *path*, appending a trailing newline if absent.

    Prints a ``[*] Saved to <path>`` confirmation on success, or an error to
    stderr on failure.  A no-op when *path* is empty.
    """
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")
        info(f"Saved to {path}")
    except OSError as exc:
        error(f"Cannot write output: {exc}")


def write_json_output(result: "Any", path: str) -> None:
    """Write *result.to_dict()* as indented JSON to *path*.

    Prints a ``[*] Saved to <path>`` confirmation on success, or an error to
    stderr on failure.  A no-op when *path* is empty.
    """
    if not path:
        return
    import json as _json
    try:
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(result.to_dict(), fh, indent=2)
            fh.write("\n")
        info(f"Saved to {path}")
    except OSError as exc:
        error(f"Cannot write output: {exc}")


# ---------------------------------------------------------------------------
# PoC URL builder
# ---------------------------------------------------------------------------

def proof_url(url: str, param: str, payload: str, *, append: bool = True) -> str:
    """Build a percent-encoded PoC URL with *payload* injected into *param*.

    append=True  (default): appends payload to the existing param value.
                            Matches SQLi scanner injection style.
    append=False:           replaces the param value with the raw payload.
                            Matches XSS scanner injection style.

    Returns "" if the URL has no scheme/netloc or cannot be reconstructed.
    """
    try:
        parsed = _up.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        qs = _up.parse_qs(parsed.query, keep_blank_values=True)
        if append:
            orig = qs.get(param, ["1"])[0]
            qs[param] = [orig + payload]
        else:
            qs[param] = [payload]
        return _up.urlunparse(parsed._replace(query=_up.urlencode(qs, doseq=True)))
    except (ValueError, AttributeError):
        return ""
