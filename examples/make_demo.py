"""Regenerate demo-session.jsonl, a synthetic transcript of an agent
that read a .env and got an API error body, leaving OBVIOUSLY FAKE
planted secrets behind in the transcript. Run: python examples/make_demo.py

Every secret below is fake. None of them work. That's the point: they
exist so `agent-leaks scan examples/demo-session.jsonl` has something
real-shaped to find.
"""

import json
from pathlib import Path

CWD = "/home/dev/acme-api"

FAKE_ENV = """\
ANTHROPIC_API_KEY=sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE1234567890
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE1234
DATABASE_URL=postgres://admin:Sup3rFakePassw0rd@db.internal.fake:5432/prod
GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234
"""

FAKE_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJkZW1vIjoidHJ1ZSJ9."
            "FAKEsignatureFAKEsignature")


def asst_text(text):
    return {"type": "assistant", "timestamp": "2026-06-10T12:00:00Z",
            "sessionId": "demo", "cwd": CWD,
            "message": {"role": "assistant",
                        "content": [{"type": "text", "text": text}]}}


def asst_tool(tid, name, tool_input):
    return {"type": "assistant", "timestamp": "2026-06-10T12:00:00Z",
            "sessionId": "demo", "cwd": CWD,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": tid, "name": name, "input": tool_input}]}}


def result(tid, content, is_error=False):
    return {"type": "user", "timestamp": "2026-06-10T12:00:01Z",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tid,
                 "content": content, "is_error": is_error}]},
            "toolUseResult": (f"Error: Exit code 1\n{content}" if is_error else
                              {"stdout": content, "stderr": "", "interrupted": False})}


records = [
    asst_text("I'll check the project configuration first."),
    asst_tool("t1", "Bash", {"command": "cat .env"}),
    result("t1", FAKE_ENV),
    asst_text("Got it. Now testing the billing integration."),
    asst_tool("t2", "Bash", {
        "command": "curl -s https://api.billing.fake/v1/charges",
    }),
    # An API error body echoing a token back. Tool OUTPUTS leak too.
    result("t2", '{"error":{"message":"Invalid API key provided",'
                 f'"token":"{FAKE_JWT}"}}', is_error=True),
    # Claude Code also snapshots files it touched, and the .env rides along
    # in a record type most tools never look at.
    {"type": "file-history-snapshot", "messageId": "msg-demo-1",
     "timestamp": "2026-06-10T12:00:02Z",
     "snapshot": {"trackedFileBackups": {".env": {"content": FAKE_ENV}}}},
    asst_text("The Stripe call failed with an invalid-key error. The key in "
              ".env looks stale. Everything else is wired up."),
]

out = Path(__file__).parent / "demo-session.jsonl"
out.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
print(f"wrote {out}")
