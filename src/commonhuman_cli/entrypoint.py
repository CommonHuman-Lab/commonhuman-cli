# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import re
import sys

__all__ = [
    "load_url_list",
    "load_wordlist",
    "compile_exclude_patterns",
    "parse_headers",
    "parse_auth_cred",
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


def load_wordlist(path: str, sort_by_length: bool = False) -> list[str]:
    """Read a wordlist file — one entry per line. Skips blanks and # comments.

    sort_by_length=True: shorter entries first (faster signal acquisition on
    common endpoints before rarer long paths).
    Exits with code 2 on I/O error.
    """
    try:
        with open(path) as fh:
            entries = [
                line.rstrip("\n")
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
        if sort_by_length:
            entries.sort(key=lambda x: (len(x), x))
        return entries
    except OSError as e:
        print(f"[!] Cannot read wordlist: {e}", file=sys.stderr)
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


def parse_auth_cred(cred: str) -> tuple[str, str]:
    """Split ``"username:password"`` into ``(username, password)``.

    Splits on the first colon only, so passwords that themselves contain
    colons are handled correctly.

    Raises:
        ValueError: *cred* is empty or contains no colon.
    """
    if not cred or ":" not in cred:
        raise ValueError(
            f"auth_cred must be in 'username:password' format, got {cred!r}"
        )
    username, _, password = cred.partition(":")
    return username, password


def validate_timeout(timeout: int, min_val: int = 5) -> None:
    """Warn to stderr if *timeout* is below *min_val*. Does not clamp."""
    if timeout < min_val:
        print(
            f"[!] --timeout {timeout} is below minimum; clamping to {min_val}s",
            file=sys.stderr,
        )
