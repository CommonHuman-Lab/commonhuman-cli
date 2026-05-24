# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
commonhuman-cli — shared CLI/terminal UX primitives for CommonHuman-Lab tools.

Quick imports:

    from commonhuman_cli.output import success, warning, error
    from commonhuman_cli.logging import setup_logging, get_logger
    from commonhuman_cli.reporter import ScanResultBase
    from commonhuman_cli.prompts import prompt, prompt_bool, section
    from commonhuman_cli.entrypoint import load_url_list, parse_headers
"""

from commonhuman_cli.colour import (
    RED, GREEN, YELLOW, CYAN, BOLD, DIM,
    render_banner,
)
from commonhuman_cli.logging import (
    FINDING, StingLogger, get_logger, setup_logging, ScanResultHandler,
)
from commonhuman_cli.output import (
    success, warning, error, info, debug,
    print_header, print_footer, print_scan_meta,
    print_finding, print_finding_severity, print_severity_summary, print_errors,
    proof_url,
)
from commonhuman_cli.severity import (
    Severity,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    severity_colour, severity_label, severity_score,
    SEVERITY_ORDER,
)
from commonhuman_cli.prompts import safe_int, prompt, prompt_bool, section
from commonhuman_cli.reporter import ScanResultBase
from commonhuman_cli.entrypoint import (
    load_url_list, compile_exclude_patterns, parse_headers, validate_timeout,
)

__version__ = "0.1.6"

__all__ = [
    "__version__",
    # colour
    "RED", "GREEN", "YELLOW", "CYAN", "BOLD", "DIM", "render_banner",
    # logging
    "FINDING", "StingLogger", "get_logger", "setup_logging", "ScanResultHandler",
    # output
    "success", "warning", "error", "info", "debug",
    "print_header", "print_footer", "print_scan_meta",
    "print_finding", "print_finding_severity", "print_severity_summary",
    "print_errors", "proof_url",
    # severity
    "Severity", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    "severity_colour", "severity_label", "severity_score", "SEVERITY_ORDER",
    # prompts
    "safe_int", "prompt", "prompt_bool", "section",
    # reporter
    "ScanResultBase",
    # entrypoint
    "load_url_list", "compile_exclude_patterns", "parse_headers", "validate_timeout",
]
