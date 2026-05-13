# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import sys


def _use_colour() -> bool:
    """Evaluated at call time so stdout redirections are always respected."""
    return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _use_colour():
        return text
    return f"\033[{code}m{text}\033[0m"


RED    = lambda t: _c("31;1",    t)  # noqa: E731
GREEN  = lambda t: _c("38;5;46", t)  # noqa: E731
YELLOW = lambda t: _c("33;1",    t)  # noqa: E731
CYAN   = lambda t: _c("36",      t)  # noqa: E731
BOLD   = lambda t: _c("1",       t)  # noqa: E731
DIM    = lambda t: _c("2",       t)  # noqa: E731


def render_banner(text: str) -> str:
    """Wrap a banner string in CYAN, ready for print()."""
    return CYAN(text)
