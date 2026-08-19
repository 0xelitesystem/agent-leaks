"""Render scan and redact results: ANSI terminal report or JSON.

Nothing in this module ever touches a raw secret value. By the time a
Finding reaches here it only carries the masked preview and the sha256.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .detectors import Severity
from .transcripts import FileScan, Finding, RedactResult

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_CYAN = "\x1b[36m"

_SEVERITY_STYLE = {
    Severity.HIGH: (_RED, "HIGH"),
    Severity.MEDIUM: (_YELLOW, "MED "),
}


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, *styles: str, enabled: bool = True) -> str:
    if not enabled or not styles:
        return text
    return "".join(styles) + text + _RESET


def _totals(scans: list[FileScan]) -> dict[str, int]:
    return {
        "files_scanned": len(scans),
        "files_with_findings": sum(1 for s in scans if s.findings),
        "findings": sum(len(s.findings) for s in scans),
        "high": sum(s.count(Severity.HIGH) for s in scans),
        "medium": sum(s.count(Severity.MEDIUM) for s in scans),
    }


def _finding_line(finding: Finding, color: bool) -> str:
    style, label = _SEVERITY_STYLE[finding.severity]
    times = f"  ×{finding.occurrences}" if finding.occurrences > 1 else ""
    return (f"  {_paint('⚠ ' + label, style, enabled=color)}"
            f" {finding.detector.ljust(24)}"
            f" line {str(finding.line).ljust(5)}"
            f" {finding.preview}{times}")


def render_scan_terminal(scans: list[FileScan], color: bool | None = None) -> str:
    color = _colors_enabled() if color is None else color
    totals = _totals(scans)
    lines: list[str] = []
    out = lines.append

    out("")
    out(_paint("  agent-leaks", _BOLD, _CYAN, enabled=color)
        + _paint(" - secrets in your agent transcripts", _DIM, enabled=color))
    out("")

    for scan in scans:
        if not scan.findings and len(scans) > 1:
            continue  # in `all` mode, only show files that have findings
        out(_paint(f"  {Path(scan.path).name}  -  {scan.project}  -  "
                   f"{scan.lines} lines", _DIM, enabled=color))
        if not scan.findings:
            out("  " + _paint("✓ clean, no secrets found", _GREEN, enabled=color))
        else:
            for finding in scan.findings:
                out(_finding_line(finding, color))
        out("")

    if len(scans) > 1:
        out(_paint(
            f"  scanned {totals['files_scanned']} transcript(s)  -  "
            f"{totals['files_with_findings']} contain secrets",
            _BOLD, enabled=color))
    if totals["findings"]:
        out(_paint(
            f"  {totals['findings']} unique secret(s)  -  "
            f"{totals['high']} high  -  {totals['medium']} medium",
            _BOLD, _RED if totals["high"] else _YELLOW, enabled=color))
        out(_paint("  run `leaks redact <file> --write` to scrub them",
                   _DIM, enabled=color))
    elif len(scans) > 1:
        out("  " + _paint("✓ all clean, no secrets found", _GREEN, enabled=color))
    out("")
    return "\n".join(lines)


def _finding_dict(finding: Finding) -> dict:
    return {
        "detector": finding.detector,
        "severity": finding.severity.value,
        "line": finding.line,
        "occurrences": finding.occurrences,
        "preview": finding.preview,
        "sha256_8": finding.sha8,
        "marker": finding.marker,
    }


def render_scan_json(scans: list[FileScan]) -> str:
    return json.dumps({
        "files": [{
            "path": scan.path,
            "project": scan.project,
            "lines": scan.lines,
            "findings": [_finding_dict(f) for f in scan.findings],
        } for scan in scans],
        "totals": _totals(scans),
    }, indent=2)


def render_redact_terminal(result: RedactResult, color: bool | None = None) -> str:
    color = _colors_enabled() if color is None else color
    lines: list[str] = []
    out = lines.append

    out("")
    out(_paint("  agent-leaks", _BOLD, _CYAN, enabled=color)
        + _paint(" - redact", _DIM, enabled=color))
    out(_paint(f"  {Path(result.path).name}", _DIM, enabled=color))
    out("")

    if not result.findings:
        out("  " + _paint("✓ clean, nothing to redact", _GREEN, enabled=color))
        out("")
        return "\n".join(lines)

    for finding in result.findings:
        out(_finding_line(finding, color) + _paint(f"  -> {finding.marker}",
                                                   _DIM, enabled=color))
    out("")

    occurrences = sum(f.occurrences for f in result.findings)
    if result.written:
        out(_paint(f"  redacted {len(result.findings)} secret(s) "
                   f"({occurrences} occurrence(s)) across "
                   f"{result.lines_changed} line(s)", _BOLD, _GREEN, enabled=color))
        if result.backup_path:
            out(_paint(f"  backup written to {result.backup_path}",
                       _DIM, enabled=color))
    else:
        out(_paint(f"  dry run: {len(result.findings)} secret(s) "
                   f"({occurrences} occurrence(s)) on {result.lines_changed} "
                   f"line(s) would be redacted", _BOLD, _YELLOW, enabled=color))
        out(_paint("  file NOT modified. re-run with --write "
                   "(add --backup to keep a .bak)", _DIM, enabled=color))
    out("")
    return "\n".join(lines)
