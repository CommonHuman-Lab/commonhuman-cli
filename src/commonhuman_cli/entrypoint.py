# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import re
import sys

__all__ = [
    "load_url_list",
    "compile_exclude_patterns",
    "parse_headers",
    "validate_timeout",
]


def load_url_list(path: str) -> list[str]:
    """Read a file of target URLs, one per line. Skips blanks and # comments.

    Exits with code 2 on I/O error.
    """
    try:
        with open(path) as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
    except OSError as e:
        print(f"[!] Cannot read URL list: {e}", file=sys.stderr)
        sys.exit(2)


def compile_exclude_patterns(
    patterns: list[str],
    exit_on_error: bool = True,
) -> list[re.Pattern]:
    """Compile a list of regex strings into Pattern objects.

    exit_on_error=True (default): prints to stderr and sys.exit(2) on bad regex.
    exit_on_error=False:          raises ValueError instead (useful in tests).
    """
    compiled: list[re.Pattern] = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat))
        except re.error as e:
            msg = f"[!] Invalid --exclude pattern '{pat}': {e}"
            if exit_on_error:
                print(msg, file=sys.stderr)
                sys.exit(2)
            raise ValueError(msg) from e
    return compiled


def parse_headers(header_list: list[str]) -> dict[str, str]:
    """Convert a list of "KEY:VALUE" strings into a dict.

    Splits on the first colon only so header values may contain colons
    (e.g. "Authorization: Bearer token:extra").
    Entries without a colon are silently ignored.
    """
    headers: dict[str, str] = {}
    for h in header_list:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def validate_timeout(timeout: int, min_val: int = 5) -> None:
    """Warn to stderr if *timeout* is below *min_val*. Does not clamp."""
    if timeout < min_val:
        print(
            f"[!] --timeout {timeout} is below minimum; clamping to {min_val}s",
            file=sys.stderr,
        )
