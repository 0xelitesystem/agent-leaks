"""Redaction: dry run touches nothing, --write produces valid JSONL with
the secret gone and everything else preserved, and JSON-escaped secrets
(the case naive string replacement gets wrong) survive the round trip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import (
    FAKE_ANTHROPIC,
    FAKE_AWS,
    FAKE_GITHUB,
    assistant_text,
    tool_result,
)

from agent_leaks.detectors import sha256_hex
from agent_leaks.transcripts import redact_file, scan_file


def _read_lines(path) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()


def test_dry_run_reports_but_does_not_modify(leaky_transcript):
    original = Path(leaky_transcript).read_bytes()
    result = redact_file(leaky_transcript)  # write defaults to False
    assert result.findings
    assert not result.written
    assert result.backup_path == ""
    assert Path(leaky_transcript).read_bytes() == original


def test_write_round_trip(leaky_transcript):
    original_records = [json.loads(line) for line in _read_lines(leaky_transcript)]
    result = redact_file(leaky_transcript, write=True)
    assert result.written

    text = Path(leaky_transcript).read_text(encoding="utf-8")
    # The secrets are gone...
    assert FAKE_ANTHROPIC not in text
    assert FAKE_AWS not in text
    # ...replaced by markers carrying the detector + sha prefix...
    assert f"[REDACTED:anthropic-api-key:{sha256_hex(FAKE_ANTHROPIC)[:8]}]" in text
    assert f"[REDACTED:aws-access-key-id:{sha256_hex(FAKE_AWS)[:8]}]" in text

    # ...the file is still valid JSONL with the same records in order...
    new_records = [json.loads(line) for line in _read_lines(leaky_transcript)]
    assert len(new_records) == len(original_records)
    assert [r.get("type") for r in new_records] == \
           [r.get("type") for r in original_records]

    # ...and every non-secret value is identical in meaning: redacting the
    # original records in memory yields exactly what's now on disk.
    def scrub(obj):
        if isinstance(obj, str):
            obj = obj.replace(FAKE_ANTHROPIC,
                              f"[REDACTED:anthropic-api-key:{sha256_hex(FAKE_ANTHROPIC)[:8]}]")
            obj = obj.replace(FAKE_AWS,
                              f"[REDACTED:aws-access-key-id:{sha256_hex(FAKE_AWS)[:8]}]")
            return obj
        if isinstance(obj, list):
            return [scrub(v) for v in obj]
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        return obj

    assert new_records == [scrub(r) for r in original_records]


def test_redacted_file_rescans_clean(leaky_transcript):
    redact_file(leaky_transcript, write=True)
    assert scan_file(leaky_transcript).findings == []


def test_untouched_lines_stay_byte_identical(leaky_transcript):
    before = _read_lines(leaky_transcript)
    redact_file(leaky_transcript, write=True)
    after = _read_lines(leaky_transcript)
    # Lines 1, 2, 5 carry no secrets and must not be rewritten at all.
    for idx in (0, 1, 4):
        assert after[idx] == before[idx]


def test_backup_written_before_redaction(leaky_transcript):
    original = Path(leaky_transcript).read_bytes()
    result = redact_file(leaky_transcript, write=True, backup=True)
    assert result.backup_path == leaky_transcript + ".bak"
    assert Path(result.backup_path).read_bytes() == original
    assert Path(leaky_transcript).read_bytes() != original


def test_json_escaped_secret_is_redacted_and_file_stays_valid(escaped_transcript):
    path, conn = escaped_transcript
    # Sanity: the secret contains characters that are escaped on disk, so
    # a naive replace of the raw value against the raw line would miss it.
    raw = Path(path).read_text(encoding="utf-8")
    assert conn not in raw
    assert json.dumps(conn)[1:-1] in raw

    result = redact_file(path, write=True)
    assert [f.detector for f in result.findings] == ["connection-string"]

    new_records = [json.loads(line) for line in _read_lines(path)]  # still valid
    blob = json.dumps(new_records)
    assert "Sup3r" not in blob
    assert 'pa\\s' not in blob and "w0rd" not in blob
    assert "[REDACTED:connection-string:" in blob
    # The non-secret remainder of the same string survived.
    assert "name = acme" in blob


def test_redact_clean_file_writes_nothing(clean_transcript):
    original = Path(clean_transcript).read_bytes()
    result = redact_file(clean_transcript, write=True, backup=True)
    assert result.findings == []
    assert not result.written
    assert not Path(clean_transcript + ".bak").exists()
    assert Path(clean_transcript).read_bytes() == original


def test_lone_surrogate_record_is_redacted_not_wiped(tmp_path):
    # Node's JSON.stringify stores a lone surrogate (output cut mid-emoji)
    # as a \ud83d escape; json.loads turns it back into a real lone
    # surrogate, which UTF-8 can't encode. The write must not wipe the file.
    first = json.dumps(assistant_text("Checking the build output."))
    second = ('{"type":"user","toolUseResult":{"stdout":"truncated emoji '
              '\\ud83d ' + FAKE_AWS + '"}}')
    path = tmp_path / "surrogate.jsonl"
    path.write_text(first + "\n" + second + "\n", encoding="utf-8")

    result = redact_file(path, write=True)
    assert result.written
    text = path.read_text(encoding="utf-8")
    assert FAKE_AWS not in text
    lines = text.split("\n")
    assert lines[0] == first
    assert lines[2] == ""
    marker = f"[REDACTED:aws-access-key-id:{sha256_hex(FAKE_AWS)[:8]}]"
    assert json.loads(lines[1])["toolUseResult"]["stdout"] == \
        "truncated emoji \ud83d " + marker
    assert scan_file(path).findings == []


def test_lone_surrogate_redact_write_via_cli_keeps_file(tmp_path):
    from agent_leaks.cli import main
    path = tmp_path / "surrogate_cli.jsonl"
    path.write_text('{"type":"user","toolUseResult":{"stdout":"cut \\ud83d '
                    + FAKE_AWS + '"}}\n', encoding="utf-8")
    assert main(["redact", str(path), "--write", "--no-color"]) == 0
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n") and FAKE_AWS not in text
    assert json.loads(text)["toolUseResult"]["stdout"].startswith("cut \ud83d ")


def test_unencodable_output_refuses_write_and_keeps_original(
        leaky_transcript, monkeypatch):
    # Whatever produces an unencodable line, the original must survive.
    import agent_leaks.transcripts as transcripts
    original = Path(leaky_transcript).read_bytes()
    monkeypatch.setattr(transcripts.json, "dumps",
                        lambda *args, **kwargs: '{"x":"\ud800"}')
    with pytest.raises(UnicodeError):
        redact_file(leaky_transcript, write=True)
    monkeypatch.undo()
    assert Path(leaky_transcript).read_bytes() == original
    assert sorted(p.name for p in Path(leaky_transcript).parent.iterdir()) \
        == ["leaky.jsonl"]


def test_failed_replace_leaves_original_untouched(leaky_transcript, monkeypatch):
    import agent_leaks.transcripts as transcripts
    original = Path(leaky_transcript).read_bytes()

    def boom(*args, **kwargs):
        raise OSError("simulated failure while replacing the file")

    monkeypatch.setattr(transcripts.os, "replace", boom)
    with pytest.raises(OSError):
        redact_file(leaky_transcript, write=True)
    monkeypatch.undo()
    assert Path(leaky_transcript).read_bytes() == original
    # The temp file is cleaned up; nothing else lands next to the transcript.
    assert sorted(p.name for p in Path(leaky_transcript).parent.iterdir()) \
        == ["leaky.jsonl"]


@pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\x85"],
                         ids=["U+2028", "U+2029", "U+0085"])
def test_unicode_line_separators_do_not_split_records(tmp_path, sep):
    # JSON.stringify writes these three raw; only "\n" ends a JSONL record.
    records = [
        tool_result("t1", f"GITHUB_TOKEN={FAKE_GITHUB} docs{sep}tail"),
        tool_result("t2", f"AWS_ACCESS_KEY_ID={FAKE_AWS}\n"),
        assistant_text(f"prose{sep}with a separator and no secret"),
    ]
    path = tmp_path / "separators.jsonl"
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records)
                    + "\n", encoding="utf-8")
    before = path.read_text(encoding="utf-8").split("\n")
    assert sep in before[0] and sep in before[2]

    result = redact_file(path, write=True)
    assert {f.detector: f.line for f in result.findings} == \
        {"github-token": 1, "aws-access-key-id": 2}
    assert result.lines_changed == 2

    after_text = path.read_text(encoding="utf-8")
    assert FAKE_GITHUB not in after_text and FAKE_AWS not in after_text
    after = after_text.split("\n")
    assert len(after) == len(before) == 4 and after[3] == ""
    for line in after[:3]:
        json.loads(line)  # every record is still valid JSON
    assert after[2] == before[2]  # the secret-free record is byte-identical
    assert scan_file(path).findings == []
