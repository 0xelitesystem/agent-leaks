"""Redaction: dry run touches nothing, --write produces valid JSONL with
the secret gone and everything else preserved, and JSON-escaped secrets
(the case naive string replacement gets wrong) survive the round trip."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import FAKE_ANTHROPIC, FAKE_AWS

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
