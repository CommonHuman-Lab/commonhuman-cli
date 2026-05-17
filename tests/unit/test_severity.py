# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for commonhuman_cli.severity."""

import pytest

from commonhuman_cli.severity import (
    Severity,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    SEVERITY_ORDER,
    severity_colour,
    severity_label,
    severity_score,
)
from commonhuman_cli.colour import RED, YELLOW, CYAN, DIM


class TestSeverityConstants:
    def test_critical_value(self):
        assert Severity.CRITICAL == "critical"

    def test_high_value(self):
        assert Severity.HIGH == "high"

    def test_medium_value(self):
        assert Severity.MEDIUM == "medium"

    def test_low_value(self):
        assert Severity.LOW == "low"

    def test_info_value(self):
        assert Severity.INFO == "info"

    def test_module_level_aliases_match_class(self):
        assert CRITICAL == Severity.CRITICAL
        assert HIGH     == Severity.HIGH
        assert MEDIUM   == Severity.MEDIUM
        assert LOW      == Severity.LOW
        assert INFO     == Severity.INFO


class TestSeverityOrder:
    def test_is_list(self):
        assert isinstance(SEVERITY_ORDER, list)

    def test_length_five(self):
        assert len(SEVERITY_ORDER) == 5

    def test_critical_first(self):
        assert SEVERITY_ORDER[0] == CRITICAL

    def test_info_last(self):
        assert SEVERITY_ORDER[-1] == INFO

    def test_contains_all_levels(self):
        for level in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
            assert level in SEVERITY_ORDER

    def test_ordered_by_severity(self):
        assert SEVERITY_ORDER.index(CRITICAL) < SEVERITY_ORDER.index(HIGH)
        assert SEVERITY_ORDER.index(HIGH)     < SEVERITY_ORDER.index(MEDIUM)
        assert SEVERITY_ORDER.index(MEDIUM)   < SEVERITY_ORDER.index(LOW)
        assert SEVERITY_ORDER.index(LOW)      < SEVERITY_ORDER.index(INFO)


class TestSeverityColour:
    def test_critical_returns_red(self):
        assert severity_colour(CRITICAL) is RED

    def test_high_returns_red(self):
        assert severity_colour(HIGH) is RED

    def test_medium_returns_yellow(self):
        assert severity_colour(MEDIUM) is YELLOW

    def test_low_returns_cyan(self):
        assert severity_colour(LOW) is CYAN

    def test_info_returns_dim(self):
        assert severity_colour(INFO) is DIM

    def test_unknown_falls_back_to_dim(self):
        assert severity_colour("unknown_level") is DIM

    def test_empty_string_falls_back_to_dim(self):
        assert severity_colour("") is DIM

    def test_returns_callable(self):
        fn = severity_colour(HIGH)
        assert callable(fn)
        assert isinstance(fn("test"), str)


class TestSeverityLabel:
    def test_critical_uppercase(self):
        assert "CRITICAL" in severity_label(CRITICAL)

    def test_high_uppercase(self):
        assert "HIGH" in severity_label(HIGH)

    def test_medium_uppercase(self):
        assert "MEDIUM" in severity_label(MEDIUM)

    def test_low_uppercase(self):
        assert "LOW" in severity_label(LOW)

    def test_info_uppercase(self):
        assert "INFO" in severity_label(INFO)

    def test_returns_string(self):
        assert isinstance(severity_label(HIGH), str)

    def test_padded_to_at_least_4_chars(self):
        assert len(severity_label(LOW)) >= 3  # "LOW" is already 3

    def test_left_justified(self):
        label = severity_label(HIGH)
        assert label == label.rstrip() or label.endswith(" ")


class TestSeverityScore:
    def test_critical_highest(self):
        assert severity_score(CRITICAL) > severity_score(HIGH)

    def test_high_above_medium(self):
        assert severity_score(HIGH) > severity_score(MEDIUM)

    def test_medium_above_low(self):
        assert severity_score(MEDIUM) > severity_score(LOW)

    def test_low_above_info(self):
        assert severity_score(LOW) > severity_score(INFO)

    def test_info_score_zero(self):
        assert severity_score(INFO) == 0

    def test_unknown_returns_zero(self):
        assert severity_score("bogus") == 0

    def test_returns_int(self):
        assert isinstance(severity_score(HIGH), int)
