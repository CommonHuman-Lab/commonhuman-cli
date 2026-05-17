# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Severity levels for scan findings — shared across all CommonHuman-Lab tools.

Usage::

    from commonhuman_cli.severity import Severity, severity_colour, CRITICAL, HIGH

    # In a finding dataclass:
    severity: str = Severity.HIGH

    # In output code:
    colour_fn = severity_colour(finding.severity)
    print(colour_fn(f"[{finding.severity}] {finding.url}"))
"""

from __future__ import annotations

from typing import Callable

from commonhuman_cli.colour import RED, YELLOW, CYAN, GREEN, DIM

__all__ = [
    "Severity",
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    "severity_colour",
    "severity_label",
    "SEVERITY_ORDER",
]


class Severity:
    """String constants for finding severity levels.

    Designed as a simple namespace of constants rather than an Enum so that
    finding dataclasses can use ``severity: str = Severity.HIGH`` without
    importing an Enum type — keeping finding dataclasses dependency-light.
    """
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# Convenience aliases at module level
CRITICAL = Severity.CRITICAL
HIGH     = Severity.HIGH
MEDIUM   = Severity.MEDIUM
LOW      = Severity.LOW
INFO     = Severity.INFO

# Ordered from most to least severe (useful for sorting / filtering)
SEVERITY_ORDER: list[str] = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

# Numeric scores for sorting / ranking
_SEVERITY_SCORE: dict[str, int] = {
    CRITICAL: 4,
    HIGH:     3,
    MEDIUM:   2,
    LOW:      1,
    INFO:     0,
}


def severity_colour(severity: str) -> Callable[[str], str]:
    """Return the terminal colour function appropriate for *severity*.

    Falls back to DIM for unknown values.

    Example::

        colour = severity_colour(Severity.HIGH)
        print(colour("[HIGH] Reflected XSS confirmed"))
    """
    return {
        CRITICAL: RED,
        HIGH:     RED,
        MEDIUM:   YELLOW,
        LOW:      CYAN,
        INFO:     DIM,
    }.get(severity, DIM)


def severity_label(severity: str) -> str:
    """Return a fixed-width uppercase severity label for display.

    Example: ``severity_label("high")`` → ``"HIGH    "``
    """
    return severity.upper().ljust(8)


def severity_score(severity: str) -> int:
    """Return a numeric score for sorting (higher = more severe)."""
    return _SEVERITY_SCORE.get(severity, 0)
