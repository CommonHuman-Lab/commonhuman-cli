# commonhuman-cli

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/commonhuman-cli.svg)](https://pypi.org/project/commonhuman-cli/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Zero deps](https://img.shields.io/badge/Dependencies-zero-brightgreen.svg)](pyproject.toml)

**Shared CLI/terminal UX primitives for CommonHuman-Lab tools** — colour, logging, output formatting, interactive prompts, and scan result infrastructure. One place. No duplication.

```bash
pip install commonhuman-cli
```

---

## Why it exists

The CommonHuman-Lab toolkit is built around a consistent operator experience — every tool speaks the same visual language, responds to the same flags, and produces output you can pipe without surprises.

`commonhuman-cli` is the single source of truth for that experience. Tools that use it get:

- **Instant consistency** — colour conventions, log prefixes, and summary layout are shared, not agreed upon.
- **Zero boilerplate** — interactive wizard mode, URL list loading, header parsing, and exclude-pattern compilation are one import away.
- **Correct behaviour from day one** — lazy TTY detection, thread-safe scan results, and namespace-isolated logging come built in.
- **A single place to improve** — a fix or a new UX pattern lands in every tool at once.

---

## Quick start

```python
from commonhuman_cli.output import success, warning, error
from commonhuman_cli.logging import setup_logging, get_logger
from commonhuman_cli.reporter import ScanResultBase
from commonhuman_cli.prompts import prompt, prompt_bool, section
from commonhuman_cli.entrypoint import load_url_list, parse_headers
```

---

## What's in it

| Module | Purpose |
| ------ | ------- |
| `commonhuman_cli.colour` | ANSI colour functions, lazy TTY detection, banner rendering |
| `commonhuman_cli.logging` | `FINDING` custom level, `StingLogger`, coloured handler, `setup_logging()` |
| `commonhuman_cli.output` | Status printers, summary block helpers, `proof_url()` |
| `commonhuman_cli.prompts` | Interactive prompt helpers for wizard-mode CLIs |
| `commonhuman_cli.reporter` | `ScanResultBase` dataclass — thread-safe, serialisable |
| `commonhuman_cli.entrypoint` | URL list loading, header parsing, exclude pattern compilation |

---

## Modules

### `colour`

Lazy TTY detection — evaluated at call time, not import time, so pipe redirections are always respected.

```python
from commonhuman_cli.colour import RED, GREEN, YELLOW, CYAN, BOLD, DIM, render_banner

print(GREEN("[+] finding confirmed"))
print(RED("[!] critical"))
print(DIM("[*] scanning..."))
print(render_banner(BANNER))   # wraps your tool's ASCII art in CYAN
```

Colour is automatically stripped when stdout is not a TTY (files, pipes, CI).

---

### `logging`

Custom `FINDING` level (25 — between `INFO` and `WARNING`), coloured handler, and namespaced setup so two tools can run in the same process without interfering.

```python
from commonhuman_cli.logging import setup_logging as _base

# In your tool's _cli/logging.py:
def setup_logging(verbose: bool, quiet: bool) -> None:
    _base(verbose, quiet, logger_name="breachsql")
```

```python
from commonhuman_cli.logging import get_logger

log = get_logger("breachsql.scanner")
log.info("scanning %s", url)
log.finding("SQLi confirmed in param %s", param)   # GREEN [+]
log.warning("WAF detected")                         # YELLOW [!]
log.debug("raw response: %s", body[:200])           # CYAN [~]
```

| Level | Prefix | Colour |
| ----- | ------ | ------ |
| `DEBUG` | `[~]` | CYAN |
| `INFO` | `[*]` | DIM |
| `FINDING` (25) | `[+]` | GREEN |
| `WARNING`+ | `[!]` | YELLOW |

---

### `output`

One-liner status printers and structured summary block helpers.

```python
from commonhuman_cli.output import (
    success, warning, error, info, debug,
    print_header, print_footer, print_scan_meta, print_finding, print_errors,
    proof_url,
)

# Status lines
success("3 findings confirmed")
warning("WAF detected — switching to evasion mode")
error("connection refused")         # → stderr

# Summary block
print_header("BreachSQL — Scan Summary")
print_scan_meta(
    target="https://target.com",
    duration_s=4.2,
    requests_sent=312,
    crawled_urls=18,
    params_tested=47,
    waf_detected="Cloudflare",
    **{"DBMS detected": "mysql"},   # tool-specific extra rows
)

# Finding block
from commonhuman_cli.colour import RED
print_finding(
    index=1,
    tag="ERROR-BASED SQLi",
    tag_colour_fn=RED,
    fields=[
        ("Param",    "id"),
        ("URL",      "https://target.com/item?id=1"),
        ("DBMS",     "mysql"),
        ("Payload",  "' AND 1=1--"),
        ("Evidence", "You have an error in your SQL syntax"),
    ],
    proof=proof_url("https://target.com/item?id=1", "id", "' AND 1=1--", append=True),
)

print_errors(result.errors)
print_footer()
```

#### `proof_url()`

Builds a percent-encoded PoC URL. The `append` flag controls injection style:

```python
# SQLi style — appends payload to the original value
proof_url("https://t.com/s?id=1", "id", "' AND 1=1--", append=True)
# → https://t.com/s?id=1%27+AND+1%3D1--

# XSS style — replaces the value entirely
proof_url("https://t.com/s?q=x", "q", "<script>alert(1)</script>", append=False)
# → https://t.com/s?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

# Returns "" on malformed or schemeless URLs — never throws
proof_url("not-a-url", "q", "payload")  # → ""
```

---

### `prompts`

Interactive wizard helpers — identical behaviour across all tools.

```python
from commonhuman_cli.prompts import prompt, prompt_bool, section, safe_int

section("Target")
url = prompt("  Target URL", hint="https://target.com/search?q=test")

section("Scan options")
level = safe_int(prompt("  Scan level", default="1"), default=1, lo=1, hi=3)
crawl = prompt_bool("  Enable crawler", default=False)
```

`safe_int` clamps to `[lo, hi]` and returns `default` on non-numeric input. `prompt` and `prompt_bool` both exit cleanly on `Ctrl+C` / `EOF`.

---

### `reporter`

Base dataclass for scan results. Inherit from it and add tool-specific finding lists.

```python
from commonhuman_cli.reporter import ScanResultBase
from dataclasses import dataclass, field

@dataclass
class ScanResult(ScanResultBase):
    # base provides: target, duration_s, waf_detected, stats, log, errors, _lock
    dbms_detected: str | None = None
    error_based:   list = field(default_factory=list)
    boolean_based: list = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.error_based) + len(self.boolean_based)

    def to_dict(self) -> dict:
        d = self._base_dict()            # common fields pre-populated
        d["dbms_detected"] = self.dbms_detected
        d["total_findings"] = self.total_findings
        return d

# Usage
result = ScanResult(target="https://target.com")
result.requests_sent += 1
result.append_error("connection timeout")   # thread-safe
result.finish()                              # sets duration_s
```

All `_append()` calls are protected by a `threading.Lock` — safe for multi-threaded scanners.

---

### `entrypoint`

Boilerplate that every `__main__.py` needs, extracted once.

```python
from commonhuman_cli.entrypoint import (
    load_url_list, compile_exclude_patterns, parse_headers, validate_timeout,
)

urls     = load_url_list(args.url_list)          # skips blanks and # comments, exit(2) on IOError
patterns = compile_exclude_patterns(args.exclude) # exit(2) on bad regex
headers  = parse_headers(args.header)             # ["Key:Val"] → {"Key": "Val"}
validate_timeout(args.timeout)                    # warns to stderr if below minimum
```

---

## Design principles

- **Zero runtime dependencies** — stdlib only. Tools keep their own deps (`requests`, `selenium`, etc.).
- **No framework** — plain functions and one dataclass. Nothing to learn, nothing to fight.
- **Lazy TTY detection** — colour is checked at print time, not import time. Pipes and redirects always work.
- **Namespace isolation** — `setup_logging(logger_name="yourtool")` scopes all logging so two tools coexist in the same process.
- **Composition over inheritance** — `ScanResultBase` gives you the shared fields; your `ScanResult` adds finding lists. No abstract base classes.

---

## Tests

```bash
git clone https://github.com/CommonHuman-Lab/commonhuman-cli.git
cd commonhuman-cli
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
pytest tests/unit/            # isolated unit tests only
pytest tests/regression/      # behavioural contracts from migrated tools
```

---

## 📜 License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
