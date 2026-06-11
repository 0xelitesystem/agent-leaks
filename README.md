# agent-leaks

> Your agent read your `.env` three weeks ago. **That key is still sitting in a plaintext transcript.**

`agent-leaks` scans Claude Code session transcripts for leaked secrets and redacts them in place. It finds the API keys, tokens, connection strings, and private keys that ended up in `~/.claude/projects/` — from every `cat .env`, every grep hit on a credentials file, every API error body your agent ever saw — and scrubs them without breaking the transcript.

Zero dependencies. Pure Python stdlib. Works offline — no API keys, nothing leaves your machine.

## The problem

Claude Code persists everything an agent sees to plaintext JSONL transcripts in `~/.claude/projects/<project>/<session>.jsonl`, forever. File contents your agent read — including secrets — are stored verbatim. This is [a known, open issue](https://github.com/anthropics/claude-code/issues/44868): read file contents are persisted to disk in plaintext, and a `CLAUDE.md` rule saying "never read .env" is advisory — the model can ignore it, and one `cat .env` inside a script's output bypasses it entirely.

This is not theoretical. [agentfluent#72](https://github.com/frederick-douglas-pearce/agentfluent/issues/72) documents **two live Anthropic API keys** found sitting in session JSONL files. Every transcript viewer, every backup, every synced home directory carries them along.

Tools like claude-vault work on *prevention* — keeping secrets out of the agent's view in the first place. agent-leaks is the other half: **detection + remediation for what's already in your transcripts**. You probably have months of session history from before you hardened anything. This is the tool that goes back and cleans it.

## What it finds

```
  agent-leaks — secrets in your agent transcripts

  demo-session.jsonl · examples · 8 lines
  ⚠ HIGH anthropic-api-key        line 3     sk-a…(47 chars)  ×3
  ⚠ HIGH aws-access-key-id        line 3     AKIA…(20 chars)  ×3
  ⚠ HIGH connection-string        line 3     post…(35 chars)  ×3
  ⚠ HIGH github-token             line 3     ghp_…(40 chars)  ×3
  ⚠ MED  jwt                      line 6     eyJh…(68 chars)  ×2

  5 unique secret(s) · 4 high · 1 medium
  run `leaks redact <file> --write` to scrub them
```

That's a real scan of [`examples/demo-session.jsonl`](examples/demo-session.jsonl) — a synthetic transcript (all planted secrets are fake) where an agent ran `cat .env` and then got a token echoed back in an API error body. Note the `×3`: the same `.env` shows up in the tool result, the `toolUseResult` mirror, **and** a `file-history-snapshot` record — a record type most tools never look at. agent-leaks walks every string in every record type, so nothing rides along unseen. (This repo ships no Stripe-shaped literal anywhere — Stripe detection is covered in the unit tests with values assembled at runtime, so GitHub push protection has nothing to flag. Fitting, for a secrets tool.)

Run it yourself:

```bash
leaks scan examples/demo-session.jsonl
```

No full secret value is ever printed, logged, or written to a report — previews are first-4-chars + length, and dedupe keys are sha256 digests.

## Install

```bash
pip install git+https://github.com/0xelitesystem/agent-leaks
```

Python ≥ 3.10. No dependencies.

## Usage

The CLI installs as `leaks` (with `agent-leaks` as an alias).

```bash
# Scan your most recent Claude Code session
leaks scan latest

# Scan a specific session by id prefix, or any transcript path
leaks scan 8dcbd9b2
leaks scan ~/.claude/projects/<project>/<session>.jsonl

# Scan EVERY transcript on the machine, with per-file findings + totals
leaks scan all
leaks scan all --project acme-api

# Machine-readable output / CI gate (exit 1 when anything is found)
leaks scan latest --json
leaks scan all --fail-on-find

# Redact: dry run first (default — shows what would change, writes nothing)
leaks redact 8dcbd9b2

# Then actually scrub, keeping a .bak of the original
leaks redact 8dcbd9b2 --write --backup
```

Exit codes: `0` clean (findings without `--fail-on-find` and redact dry runs also exit 0), `1` findings with `--fail-on-find`, `2` errors.

## Detectors

| Detector | Severity | Fires on |
|---|---|---|
| `anthropic-api-key` | HIGH | `sk-ant-…` |
| `openai-api-key` | HIGH | `sk-…` / `sk-proj-…` (never double-fires on `sk-ant-`) |
| `github-token` | HIGH | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` tokens |
| `github-fine-grained-pat` | HIGH | `github_pat_…` |
| `aws-access-key-id` | HIGH | `AKIA…` |
| `slack-token` | HIGH | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` |
| `stripe-live-key` | HIGH | `sk_live_…` / `rk_live_…` |
| `google-api-key` | HIGH | `AIza…` |
| `connection-string` | HIGH | `postgres://user:pass@…` (also mysql, mongodb, redis, amqp) |
| `private-key-block` | HIGH | `-----BEGIN … PRIVATE KEY-----` (redacts through the END marker) |
| `jwt` | MEDIUM | three-segment `eyJ…` tokens |
| `generic-credential` | MEDIUM | `API_KEY=` / `SECRET=` / `TOKEN=` / `PASSWORD=` … assignments where the value is ≥12 chars, Shannon entropy > 3.5 bits/char, and not an obvious placeholder |

Findings are deduped by sha256 of the secret value; repeated occurrences are counted, not re-reported.

## How redaction works

Each secret occurrence is replaced with `[REDACTED:<detector>:<first-8-of-sha256>]` — the sha prefix means you can still tell "the same key leaked in 4 sessions" after the value itself is gone.

Redaction is **not** string replacement on the raw file. Every line is JSON-parsed, every string value is walked recursively, secret spans are spliced out, and the record is re-serialized — so secrets containing JSON-escaped characters (quotes, backslashes) are caught, and the output stays valid JSONL that Claude Code can still load. Lines with nothing to redact are passed through byte-identical. Dry run is the default; `--write` is explicit, `--backup` keeps a `.bak`.

## Honest limitations

- Detection is regex-based. Secrets with no recognizable shape — a random hex blob with no `KEY=` label, a password in prose — will be missed. The entropy heuristic on the generic detector trades recall for precision: it has false negatives by design.
- Redaction can't un-leak anything. If the transcript was synced to a backup service, shared, or piped through another tool before you scrubbed it, that copy still has the secret. **Rotate any real key this tool finds.** Redaction is cleanup, not revocation.
- `scan all` reads every transcript on the machine; on years of history that's a lot of JSON. It's still fast (stdlib, single pass), but it's not instant.

## Part of the agent accountability suite

- [agent-receipts](https://github.com/0xelitesystem/agent-receipts) — did the agent's claims ("tests pass") match reality?
- **agent-leaks** — did it leak secrets into the transcript?
- [agent-blast-radius](https://github.com/0xelitesystem/agent-blast-radius) — what irreversible actions did it take?
- [agent-rules](https://github.com/0xelitesystem/agent-rules) — did it follow your `CLAUDE.md`?
- [agent-cost](https://github.com/0xelitesystem/agent-cost) — where did the tokens and money go?

## Roadmap

- [ ] Pre-commit hook mode for repos that version transcript directories
- [ ] `agent-leaks watch` — tail the active session, flag secrets as they land
- [ ] Custom detector config (`~/.agent-leaks.toml`: your own patterns + allowlist)
- [ ] Other agent CLI transcript formats (Codex CLI, OpenCode, Gemini CLI)

## Development

```bash
git clone https://github.com/0xelitesystem/agent-leaks
cd agent-leaks
pip install -e .[dev]
pytest
```

`examples/make_demo.py` regenerates the demo transcript; every planted secret in it is fake.

## License

[MIT](LICENSE)
