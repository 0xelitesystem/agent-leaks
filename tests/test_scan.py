"""Scanning whole transcripts: line numbers, dedupe, every record type,
and the guarantee that no output format ever contains a raw secret."""

from __future__ import annotations

import json

from conftest import FAKE_ANTHROPIC, FAKE_AWS

from agent_leaks.cli import main
from agent_leaks.detectors import Severity
from agent_leaks.report import (
    render_redact_terminal,
    render_scan_json,
    render_scan_terminal,
)
from agent_leaks.transcripts import redact_file, scan_file


def test_scan_finds_planted_secrets_with_line_numbers(leaky_transcript):
    scan = scan_file(leaky_transcript)
    by_name = {f.detector: f for f in scan.findings}
    assert set(by_name) == {"anthropic-api-key", "aws-access-key-id"}
    # First occurrence is the tool_result on JSONL line 3.
    assert by_name["anthropic-api-key"].line == 3
    assert by_name["aws-access-key-id"].line == 3
    assert all(f.severity is Severity.HIGH for f in scan.findings)


def test_scan_dedupes_by_value_and_counts_occurrences(leaky_transcript):
    scan = scan_file(leaky_transcript)
    anthropic = next(f for f in scan.findings if f.detector == "anthropic-api-key")
    # Same key appears in tool_result content, toolUseResult.stdout, and
    # the file-history-snapshot: one finding, three occurrences.
    assert anthropic.occurrences == 3


def test_scan_reaches_file_history_snapshot_records(tmp_path):
    record = {
        "type": "file-history-snapshot",
        "messageId": "m1",
        "snapshot": {"trackedFileBackups": {
            ".env": {"content": f"KEY={FAKE_ANTHROPIC}"}}},
    }
    path = tmp_path / "snap.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    scan = scan_file(path)
    assert [f.detector for f in scan.findings] == ["anthropic-api-key"]
    assert scan.findings[0].line == 1


def test_scan_clean_transcript_has_no_findings(clean_transcript):
    scan = scan_file(clean_transcript)
    assert scan.findings == []
    assert scan.lines == 4


def test_no_output_format_ever_contains_the_raw_secret(leaky_transcript):
    scan = scan_file(leaky_transcript)
    terminal = render_scan_terminal([scan], color=False)
    terminal_colored = render_scan_terminal([scan], color=True)
    as_json = render_scan_json([scan])
    for output in (terminal, terminal_colored, as_json):
        assert FAKE_ANTHROPIC not in output
        assert FAKE_AWS not in output
    # ...but the masked previews are there.
    assert f"sk-a…({len(FAKE_ANTHROPIC)} chars)" in terminal
    assert f"AKIA…({len(FAKE_AWS)} chars)" in terminal


def test_json_report_is_valid_json_with_expected_shape(leaky_transcript):
    scan = scan_file(leaky_transcript)
    payload = json.loads(render_scan_json([scan]))
    assert payload["totals"]["findings"] == 2
    assert payload["totals"]["high"] == 2
    assert payload["totals"]["medium"] == 0
    finding = payload["files"][0]["findings"][0]
    assert set(finding) == {"detector", "severity", "line", "occurrences",
                            "preview", "sha256_8", "marker"}


def test_preview_cannot_inject_terminal_escapes(tmp_path, capsys):
    # A stored \u001b decodes to a real ESC; ESC c resets the terminal and
    # ESC[3J wipes scrollback, erasing the HIGH findings printed above.
    records = [{"type": "user", "toolUseResult": {"stdout": (
        f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\n"
        "DEPLOY_TOKEN=\x1bcQw9eR7tY5uI3oP1aSdFgHjKl\n"
        "SESSION_SECRET=\x1b[3JZx8Cv7Bn6Mm5Ll4Kk3Jj9Hh\n"
        "API_KEY=\u202e\x9b\x07Rt5Yu7Io9Pa1Sd3Fg5Hj\n")}}]
    path = tmp_path / "esc.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n",
                    encoding="utf-8")
    assert "\x1b" not in path.read_text(encoding="utf-8")  # stored escaped

    scan = scan_file(path)
    assert len(scan.findings) == 4
    redacted = redact_file(path)
    unsafe = ("\x1b", "\x07", "\x9b", "\u202e")
    for output in (render_scan_terminal([scan], color=False),
                   render_redact_terminal(redacted, color=False)):
        for ch in unsafe:
            assert ch not in output
        # Still recognisable: the escaped head and the length survive.
        assert "\\x1bcQw…(26 chars)" in output
        assert "\\x1b[3J…(27 chars)" in output
        assert "\\u202e\\x9b\\x07R…(23 chars)" in output
        assert f"sk-a…({len(FAKE_ANTHROPIC)} chars)" in output
    colored = render_scan_terminal([scan], color=True)
    for seq in ("\x1bc", "\x1b[3J", "\x07", "\x9b", "\u202e"):
        assert seq not in colored

    assert main(["scan", str(path), "--no-color"]) == 0
    assert main(["redact", str(path), "--no-color"]) == 0
    out = capsys.readouterr().out
    for ch in unsafe:
        assert ch not in out


def test_malformed_line_is_still_scanned(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text('{"type":"assistant", broken json ' + FAKE_AWS + "\n",
                    encoding="utf-8")
    scan = scan_file(path)
    assert [f.detector for f in scan.findings] == ["aws-access-key-id"]
