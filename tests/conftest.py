"""Fixture transcripts built in Claude Code's JSONL shape.

Every secret in here is fake and inert. They exist only so the
detectors have realistic-shaped strings to find.
"""

from __future__ import annotations

import json

import pytest

# --- fake secrets shared across tests -----------------------------------
FAKE_ANTHROPIC = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE1234567890"
FAKE_OPENAI = "sk-proj-FAKEFAKEFAKEFAKEFAKE12345"
FAKE_GITHUB = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
FAKE_GITHUB_PAT = "github_pat_" + "FAKE2026" * 7  # 56 chars after the prefix
FAKE_AWS = "AKIAFAKEFAKEFAKE1234"
FAKE_SLACK = "xoxb-1234567890-FAKEFAKEFAKE"
# Built from fragments so no `sk_live_...`-shaped literal is ever committed.
# GitHub push protection flags Stripe's format even on inert fakes. The value
# is reassembled at runtime, so the detector still has a real-shaped string.
FAKE_STRIPE = "sk_" + "live_FAKEFAKEFAKEFAKEFAKE1234"
FAKE_GOOGLE = "AIza" + "FAKE0fake1FAKE2fake3FAKE4fake5FAKE6"  # 35 after AIza
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJmYWtlIjoidHJ1ZSJ9.FAKEsignatureFAKEsig"
FAKE_CONN = "postgres://admin:Sup3rFakePassw0rd@db.internal.fake:5432/prod"
FAKE_GENERIC = "kJ8s9dF3hG2lQ7wXzR4tY6uNpB5mC0vA"  # high entropy, no prefix
FAKE_PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
            "-----END RSA PRIVATE KEY-----")


def assistant_text(text: str) -> dict:
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T12:00:00.000Z",
        "sessionId": "fixture-session",
        "cwd": "C:\\fake\\project",
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    }


def assistant_tool(tool_id: str, name: str, tool_input: dict) -> dict:
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T12:00:00.000Z",
        "sessionId": "fixture-session",
        "cwd": "C:\\fake\\project",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input},
        ]},
    }


def tool_result(tool_id: str, content: str, is_error: bool = False) -> dict:
    return {
        "type": "user",
        "timestamp": "2026-06-10T12:00:01.000Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tool_id,
             "content": content, "is_error": is_error},
        ]},
        "toolUseResult": (f"Error: Exit code 1\n{content}" if is_error
                          else {"stdout": content, "stderr": "", "interrupted": False}),
    }


def snapshot(content: str) -> dict:
    """A file-history-snapshot record, the type most tools never scan."""
    return {
        "type": "file-history-snapshot",
        "messageId": "msg-fixture-1",
        "timestamp": "2026-06-10T12:00:02.000Z",
        "snapshot": {"trackedFileBackups": {".env": {"content": content}}},
    }


def write_jsonl(path, records: list[dict]) -> str:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n",
                    encoding="utf-8")
    return str(path)


@pytest.fixture
def leaky_transcript(tmp_path):
    """An agent cats a .env (anthropic + aws keys), then the same .env
    rides along in a file-history-snapshot. Lines: env output on line 3,
    snapshot on line 4."""
    env = (f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\n"
           f"AWS_ACCESS_KEY_ID={FAKE_AWS}\n")
    records = [
        assistant_text("Checking the configuration."),
        assistant_tool("t1", "Bash", {"command": "cat .env"}),
        tool_result("t1", env),
        snapshot(env),
        assistant_text("Config looks fine."),
    ]
    return write_jsonl(tmp_path / "leaky.jsonl", records)


@pytest.fixture
def clean_transcript(tmp_path):
    records = [
        assistant_text("Running the test suite."),
        assistant_tool("t1", "Bash", {"command": "pytest -q"}),
        tool_result("t1", "12 passed in 0.8s"),
        assistant_text("All green, nothing secret here."),
    ]
    return write_jsonl(tmp_path / "clean.jsonl", records)


@pytest.fixture
def escaped_transcript(tmp_path):
    """A connection string whose password carries JSON-escaped characters
    (backslash + quote), the case naive raw-line replacement gets wrong."""
    conn = 'mysql://root:pa\\s"w0rd@db.fake:3306'
    records = [
        assistant_tool("t1", "Bash", {"command": "cat config.ini"}),
        tool_result("t1", f"dsn = {conn}\nname = acme\n"),
    ]
    path = write_jsonl(tmp_path / "escaped.jsonl", records)
    return path, conn
