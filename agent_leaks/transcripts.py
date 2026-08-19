"""Scan and redact Claude Code session transcripts (JSONL).

Format notes (observed against Claude Code 2.x transcripts):
- Each line is a JSON object with a top-level "type".
- "assistant" records carry message.content blocks (text / tool_use),
  "user" records carry tool_result blocks plus a sibling toolUseResult.
- Many other record types exist (system, attachment, ai-title,
  file-history-snapshot, ...) and secrets can surface in ANY of them.
  A file-history-snapshot of your .env is still your .env.

So instead of modeling record types, both scan and redact walk the
parsed JSON of every line recursively and visit every string value.

Redaction never does string replacement on the raw line: a secret that
contains JSON-escaped characters on disk would dodge it. Each line is
json.loads'ed, every string is rewritten with the secret spans spliced
out, and the record is re-serialized with json.dumps. The output stays
valid JSONL that Claude Code can still load. Lines without secrets (and
lines that aren't valid JSON) are passed through byte-identical.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import SecretHit, Severity, find_secrets, mask, sha256_hex


@dataclass
class Finding:
    """One unique secret found in one file (occurrences counted)."""

    detector: str
    severity: Severity
    sha256: str  # full hex digest of the secret value, safe to show
    preview: str  # masked, e.g. "sk-a…(46 chars)"
    line: int  # 1-based JSONL line of the first occurrence
    occurrences: int = 1

    @property
    def sha8(self) -> str:
        return self.sha256[:8]

    @property
    def marker(self) -> str:
        return f"[REDACTED:{self.detector}:{self.sha8}]"


_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1}


def _sorted_findings(findings: dict[str, Finding]) -> list[Finding]:
    return sorted(findings.values(),
                  key=lambda f: (_SEVERITY_ORDER[f.severity], f.line, f.detector))


@dataclass
class FileScan:
    """Scan outcome for one transcript file."""

    path: str
    findings: list[Finding] = field(default_factory=list)
    lines: int = 0  # non-empty lines scanned

    @property
    def project(self) -> str:
        return Path(self.path).parent.name

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)


@dataclass
class RedactResult:
    """Outcome of a redact pass (dry run or write) on one file."""

    path: str
    findings: list[Finding] = field(default_factory=list)
    lines_changed: int = 0
    written: bool = False
    backup_path: str = ""


def iter_strings(obj):
    """Yield every string value anywhere inside parsed JSON."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_strings(item)
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from iter_strings(value)


def _transform_strings(obj, fn):
    """Rebuild parsed JSON with fn applied to every string value."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_transform_strings(item, fn) for item in obj]
    if isinstance(obj, dict):
        return {key: _transform_strings(value, fn) for key, value in obj.items()}
    return obj


def _record_hit(findings: dict[str, Finding], hit: SecretHit, line: int) -> Finding:
    digest = sha256_hex(hit.value)
    finding = findings.get(digest)
    if finding is None:
        finding = Finding(
            detector=hit.detector.name,
            severity=hit.detector.severity,
            sha256=digest,
            preview=mask(hit.value),
            line=line,
        )
        findings[digest] = finding
    else:
        finding.occurrences += 1
    return finding


def scan_file(path: str | Path) -> FileScan:
    """Scan one transcript: every string value of every record type."""
    path = Path(path)
    findings: dict[str, Finding] = {}
    lines = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            if not raw.strip():
                continue
            lines += 1
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                # Malformed line: best-effort scan of the raw text so a
                # secret doesn't escape just because the JSON is broken.
                for hit in find_secrets(raw):
                    _record_hit(findings, hit, lineno)
                continue
            for text in iter_strings(record):
                for hit in find_secrets(text):
                    _record_hit(findings, hit, lineno)
    return FileScan(path=str(path), findings=_sorted_findings(findings), lines=lines)


def _redact_string(text: str, findings: dict[str, Finding], lineno: int) -> str:
    """Replace every secret span in one string with its marker."""
    hits = find_secrets(text)
    if not hits:
        return text
    for hit in sorted(hits, key=lambda h: h.start, reverse=True):
        finding = _record_hit(findings, hit, lineno)
        text = text[:hit.start] + finding.marker + text[hit.end:]
    return text


def redact_file(path: str | Path, *, write: bool = False,
                backup: bool = False) -> RedactResult:
    """Redact secrets in a transcript. Dry run unless write=True.

    Every line is parsed, walked, and re-serialized only if it actually
    contained a secret; all other lines stay byte-identical. The result
    is always valid JSONL.
    """
    path = Path(path)
    raw = path.read_text(encoding="utf-8")
    had_trailing_newline = raw.endswith("\n")

    findings: dict[str, Finding] = {}
    out_lines: list[str] = []
    lines_changed = 0

    for lineno, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            out_lines.append(line)
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            out_lines.append(line)  # never rewrite what we can't re-serialize
            continue
        before = len(findings)
        before_occurrences = sum(f.occurrences for f in findings.values())
        new_record = _transform_strings(
            record, lambda s: _redact_string(s, findings, lineno))
        after_occurrences = sum(f.occurrences for f in findings.values())
        if len(findings) > before or after_occurrences > before_occurrences:
            out_lines.append(json.dumps(new_record, ensure_ascii=False,
                                        separators=(",", ":")))
            lines_changed += 1
        else:
            out_lines.append(line)

    result = RedactResult(
        path=str(path),
        findings=_sorted_findings(findings),
        lines_changed=lines_changed,
    )

    if write and result.findings:
        if backup:
            backup_path = str(path) + ".bak"
            shutil.copy2(path, backup_path)  # backup FIRST; abort on failure
            result.backup_path = backup_path
        content = "\n".join(out_lines) + ("\n" if had_trailing_newline else "")
        path.write_text(content, encoding="utf-8", newline="\n")
        result.written = True

    return result


def projects_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".claude" / "projects"


def discover_transcripts(project_filter: str | None = None) -> list[Path]:
    """All transcript files under ~/.claude/projects, newest first."""
    root = projects_dir()
    if not root.is_dir():
        return []
    found: list[Path] = []
    for project in sorted(root.iterdir()):
        if not project.is_dir():
            continue
        if project_filter and project_filter.lower() not in project.name.lower():
            continue
        found.extend(project.glob("*.jsonl"))
    return sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)


def resolve_target(target: str, project_filter: str | None = None) -> Path:
    """Turn a CLI target (path, session id, or 'latest') into a file path."""
    direct = Path(target)
    if direct.is_file():
        return direct
    transcripts = discover_transcripts(project_filter)
    if target == "latest":
        if not transcripts:
            raise FileNotFoundError("no transcripts found under ~/.claude/projects")
        return transcripts[0]
    for candidate in transcripts:
        if candidate.stem.startswith(target):
            return candidate
    raise FileNotFoundError(f"no transcript matching {target!r}")
