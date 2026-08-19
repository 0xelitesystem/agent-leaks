"""agent-leaks: find and redact secrets your coding agent left in transcripts.

Installed as the `leaks` command (and `agent-leaks` alias).

Usage:
  leaks scan <transcript.jsonl | session-id-prefix | latest | all> [options]
  leaks redact <transcript.jsonl | session-id-prefix> [--write] [--backup]

Options:
  --project NAME    only consider transcripts whose project folder matches
  --json            emit machine-readable JSON instead of the terminal report
  --fail-on-find    exit 1 when any secret is found (CI / hook gate)
  --write           redact: actually rewrite the file (default is a dry run)
  --backup          redact: save <file>.bak before writing
  --no-color        disable ANSI colors

Exit codes: 0 clean (or findings without --fail-on-find; redact dry runs
always count as clean), 1 findings with --fail-on-find, 2 errors.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import render_redact_terminal, render_scan_json, render_scan_terminal
from .transcripts import (
    FileScan,
    discover_transcripts,
    redact_file,
    resolve_target,
    scan_file,
)


def run_scan(target: str, project: str | None = None) -> list[FileScan]:
    """Library entry point: scan one transcript (or 'all') and return results."""
    if target == "all":
        paths = discover_transcripts(project)
        if not paths:
            raise FileNotFoundError("no transcripts found under ~/.claude/projects")
    else:
        paths = [resolve_target(target, project)]
    return [scan_file(path) for path in paths]


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        scans = run_scan(args.target, args.project)
    except (FileNotFoundError, OSError) as exc:
        print(f"agent-leaks: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(render_scan_json(scans))
    else:
        color = False if args.no_color else None
        print(render_scan_terminal(scans, color=color))

    if args.fail_on_find and any(scan.findings for scan in scans):
        return 1
    return 0


def _cmd_redact(args: argparse.Namespace) -> int:
    try:
        path = resolve_target(args.target)
        result = redact_file(path, write=args.write, backup=args.backup)
    except (FileNotFoundError, OSError) as exc:
        print(f"agent-leaks: {exc}", file=sys.stderr)
        return 2

    color = False if args.no_color else None
    print(render_redact_terminal(result, color=color))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leaks",
        description="Find and redact secrets your coding agent left in "
                    "plaintext session transcripts.",
    )
    parser.add_argument("--version", action="version",
                        version=f"agent-leaks {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan transcript(s) for leaked secrets")
    scan.add_argument("target",
                      help="transcript path, session-id prefix, 'latest', or 'all'")
    scan.add_argument("--project", help="filter session discovery by project name")
    scan.add_argument("--json", action="store_true", help="JSON output")
    scan.add_argument("--fail-on-find", action="store_true",
                      help="exit 1 if any secret is found (for CI/hooks)")
    scan.add_argument("--no-color", action="store_true", help="plain output")
    scan.set_defaults(func=_cmd_scan)

    redact = sub.add_parser("redact",
                            help="redact secrets in a transcript (dry run by default)")
    redact.add_argument("target", help="transcript path or session-id prefix")
    redact.add_argument("--write", action="store_true",
                        help="rewrite the file in place (default: dry run)")
    redact.add_argument("--backup", action="store_true",
                        help="save <file>.bak before writing")
    redact.add_argument("--no-color", action="store_true", help="plain output")
    redact.set_defaults(func=_cmd_redact)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles often default to cp1252, which can't print ✓/⚠/....
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
