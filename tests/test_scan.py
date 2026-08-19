"""Scanning whole transcripts: line numbers, dedupe, every record type,
and the guarantee that no output format ever contains a raw secret."""

from __future__ import annotations

import json

from conftest import FAKE_ANTHROPIC, FAKE_AWS

from agent_leaks.detectors import Severity
from agent_leaks.report import render_scan_json, render_scan_terminal
from agent_leaks.transcripts import scan_file


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
    assert f"sk-a...({len(FAKE_ANTHROPIC)} chars)" in terminal
    assert f"AKIA...({len(FAKE_AWS)} chars)" in terminal


def test_json_report_is_valid_json_with_expected_shape(leaky_transcript):
    scan = scan_file(leaky_transcript)
    payload = json.loads(render_scan_json([scan]))
    assert payload["totals"]["findings"] == 2
    assert payload["totals"]["high"] == 2
    assert payload["totals"]["medium"] == 0
    finding = payload["files"][0]["findings"][0]
    assert set(finding) == {"detector", "severity", "line", "occurrences",
                            "preview", "sha256_8", "marker"}


def test_malformed_line_is_still_scanned(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text('{"type":"assistant", broken json ' + FAKE_AWS + "\n",
                    encoding="utf-8")
    scan = scan_file(path)
    assert [f.detector for f in scan.findings] == ["aws-access-key-id"]
