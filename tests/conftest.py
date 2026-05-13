# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Session-level fixtures shared across all test layers."""

from __future__ import annotations

import logging

import pytest


@pytest.fixture()
def force_colour(monkeypatch):
    """Force colour output on. Patches _use_colour directly so capsys capture
    (which replaces sys.stdout with a StringIO) doesn't interfere."""
    import commonhuman_cli.colour
    monkeypatch.setattr(commonhuman_cli.colour, "_use_colour", lambda: True)


@pytest.fixture()
def no_colour(monkeypatch):
    """Force colour output off. Same reasoning as force_colour."""
    import commonhuman_cli.colour
    monkeypatch.setattr(commonhuman_cli.colour, "_use_colour", lambda: False)


@pytest.fixture(autouse=True)
def _isolate_loggers():
    """Remove all handlers from any logger created during a test."""
    yield
    # Clean up every logger touched during the test so handlers don't bleed
    # across tests when setup_logging is called multiple times.
    for _, logger in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger):
            logger.handlers.clear()
            logger.propagate = True
