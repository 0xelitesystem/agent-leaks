"""CLI behavior: exit codes, --json validity, dry-run vs --write."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import FAKE_ANTHROPIC

from agent_leaks.cli import main


def test_scan_clean_exits_0(clean_transcript, capsys):
    assert main(["scan", clean_transcript, "--no-color"]) == 0
    assert "clean" in capsys.readouterr().out


def test_scan_with_findings_exits_0_without_flag(leaky_transcript):
    assert main(["scan", leaky_transcript, "--no-color"]) == 0


def test_scan_fail_on_find_exits_1(leaky_transcript):
    assert main(["scan", leaky_transcript, "--fail-on-find", "--no-color"]) == 1


def test_scan_fail_on_find_clean_exits_0(clean_transcript):
    assert main(["scan", clean_transcript, "--fail-on-find", "--no-color"]) == 0


def test_scan_missing_target_exits_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.jsonl")]) == 2
    assert "agent-leaks:" in capsys.readouterr().err


def test_scan_json_is_valid_and_masked(leaky_transcript, capsys):
    assert main(["scan", leaky_transcript, "--json"]) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["totals"]["findings"] == 2
    assert FAKE_ANTHROPIC not in out


def test_scan_terminal_never_prints_secret(leaky_transcript, capsys):
    main(["scan", leaky_transcript, "--no-color"])
    assert FAKE_ANTHROPIC not in capsys.readouterr().out


def test_redact_dry_run_exits_0_and_does_not_modify(leaky_transcript, capsys):
    original = Path(leaky_transcript).read_bytes()
    assert main(["redact", leaky_transcript, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "dry run" in out
    assert FAKE_ANTHROPIC not in out
    assert Path(leaky_transcript).read_bytes() == original


def test_redact_write_modifies_file(leaky_transcript):
    assert main(["redact", leaky_transcript, "--write", "--no-color"]) == 0
    text = Path(leaky_transcript).read_text(encoding="utf-8")
    assert FAKE_ANTHROPIC not in text
    assert "[REDACTED:anthropic-api-key:" in text


def test_redact_write_with_backup(leaky_transcript):
    assert main(["redact", leaky_transcript, "--write", "--backup",
                 "--no-color"]) == 0
    assert Path(leaky_transcript + ".bak").exists()


def test_redact_missing_target_exits_2(tmp_path):
    assert main(["redact", str(tmp_path / "nope.jsonl")]) == 2


def test_demo_session_scan_finds_all_planted_families():
    demo = Path(__file__).parent.parent / "examples" / "demo-session.jsonl"
    from agent_leaks.transcripts import scan_file
    scan = scan_file(demo)
    names = {f.detector for f in scan.findings}
    # Stripe is covered in test_detectors; it's kept out of the committed
    # demo file so the repo never ships a Stripe-shaped literal.
    assert names == {"anthropic-api-key", "aws-access-key-id",
                     "connection-string", "github-token", "jwt"}
