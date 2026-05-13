# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import sys

from commonhuman_cli.colour import BOLD, DIM, YELLOW

__all__ = ["safe_int", "prompt", "prompt_bool", "section"]


def safe_int(val: str, default: int, lo: int, hi: int) -> int:
    """Parse *val* as int, clamped to [lo, hi]. Returns *default* on error."""
    try:
        return max(lo, min(int(val), hi))
    except (TypeError, ValueError):
        return default


def prompt(label: str, default: str = "", hint: str = "") -> str:
    """Display a labelled input prompt and return the entered value.

    Returns *default* if the user presses Enter with no input.
    Exits cleanly on Ctrl+C or EOF.
    """
    hint_str = f"  {DIM(hint)}" if hint else ""
    if default:
        display = f"{BOLD(label)} {DIM(f'[{default}]')}{hint_str}: "
    else:
        display = f"{BOLD(label)}{hint_str}: "
    try:
        val = input(display).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val if val else default


def prompt_bool(label: str, default: bool = False) -> bool:
    """Display a Y/n prompt and return the boolean result."""
    default_str = "Y/n" if default else "y/N"
    display = f"{BOLD(label)} {DIM(f'[{default_str}]')}: "
    try:
        val = input(display).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not val:
        return default
    return val in ("y", "yes", "1", "true")


def section(title: str) -> None:
    """Print a dimmed section divider for interactive mode."""
    print()
    print(DIM("  ─── " + title + " " + "─" * max(0, 40 - len(title))))
