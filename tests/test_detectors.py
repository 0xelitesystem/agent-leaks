"""Detector coverage: every pattern fires on a true positive, the
filters reject placeholders/low-entropy values, and masking never
reveals the secret."""

from __future__ import annotations

import pytest
from conftest import (
    FAKE_ANTHROPIC,
    FAKE_AWS,
    FAKE_CONN,
    FAKE_GENERIC,
    FAKE_GITHUB,
    FAKE_GITHUB_PAT,
    FAKE_GOOGLE,
    FAKE_JWT,
    FAKE_OPENAI,
    FAKE_PEM,
    FAKE_SLACK,
    FAKE_STRIPE,
)

from agent_leaks.detectors import find_secrets, mask, shannon_entropy


@pytest.mark.parametrize("text,expected", [
    (FAKE_ANTHROPIC, "anthropic-api-key"),
    (FAKE_OPENAI, "openai-api-key"),
    ("sk-FAKEFAKEFAKEFAKEFAKE12345", "openai-api-key"),
    (FAKE_GITHUB, "github-token"),
    ("gho_" + "A1b2C3d4" * 5, "github-token"),
    (FAKE_GITHUB_PAT, "github-fine-grained-pat"),
    (FAKE_AWS, "aws-access-key-id"),
    (FAKE_SLACK, "slack-token"),
    (FAKE_STRIPE, "stripe-live-key"),
    ("rk_" + "live_FAKEFAKEFAKEFAKEFAKE9876", "stripe-live-key"),
    (FAKE_GOOGLE, "google-api-key"),
    (FAKE_JWT, "jwt"),
    (FAKE_PEM, "private-key-block"),
    (FAKE_CONN, "connection-string"),
    ("mongodb+srv://app:s3cretPW@cluster0.fake.net", "connection-string"),
    (f"API_KEY={FAKE_GENERIC}", "generic-credential"),
    (f'MY_ACCESS_KEY: "{FAKE_GENERIC}"', "generic-credential"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 30 else None)
def test_detector_fires(text, expected):
    hits = find_secrets(f"prefix {text} suffix")
    assert [h.detector.name for h in hits] == [expected]


def test_anthropic_key_does_not_double_fire_openai():
    hits = find_secrets(FAKE_ANTHROPIC)
    assert len(hits) == 1
    assert hits[0].detector.name == "anthropic-api-key"


def test_labelled_specific_key_fires_once_not_also_generic():
    hits = find_secrets(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}")
    assert [h.detector.name for h in hits] == ["anthropic-api-key"]
    hits = find_secrets(f"GITHUB_TOKEN={FAKE_GITHUB}")
    assert [h.detector.name for h in hits] == ["github-token"]


def test_private_key_block_captures_through_end_marker():
    hits = find_secrets(f"before\n{FAKE_PEM}\nafter")
    assert len(hits) == 1
    assert hits[0].value.endswith("-----END RSA PRIVATE KEY-----")


def test_private_key_header_alone_still_fires():
    hits = find_secrets("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert [h.detector.name for h in hits] == ["private-key-block"]


@pytest.mark.parametrize("text", [
    "API_KEY=test",                       # too short
    "PASSWORD=password123",               # too short, dictionary
    "PASSWORD=aaaabbbbccccdddd",          # long enough, entropy ~2.0
    "API_KEY=your_api_key_value_here",    # placeholder: your_
    "TOKEN=<paste-your-token-here>",      # placeholder: < >
    "SECRET=${SECRET_FROM_ENV_VAR}",      # placeholder: $
    "API_KEY={{ vault.api_key_value }}",  # placeholder: {{
    "SECRET=example_value_123456",        # placeholder: example
    "TOKEN=xxx_not_a_real_token_xxx",     # placeholder: xxx
    "NODE_ENV=production",                # no credential keyword
])
def test_generic_detector_rejects_noise(text):
    assert find_secrets(text) == []


def test_generic_detector_accepts_high_entropy_value():
    hits = find_secrets(f"DATABASE_PASSWORD='{FAKE_GENERIC}'")
    assert [h.detector.name for h in hits] == ["generic-credential"]
    assert hits[0].value == FAKE_GENERIC  # the value, not the assignment


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0
    assert shannon_entropy(FAKE_GENERIC) > 3.5


def test_mask_never_reveals_secret():
    masked = mask(FAKE_ANTHROPIC)
    assert masked == f"sk-a…({len(FAKE_ANTHROPIC)} chars)"
    assert FAKE_ANTHROPIC not in masked
    assert FAKE_ANTHROPIC[4:] not in masked


def test_multiple_secrets_in_one_string_all_found():
    blob = f"a={FAKE_AWS} b={FAKE_SLACK} c={FAKE_GOOGLE}"
    names = {h.detector.name for h in find_secrets(blob)}
    assert names == {"aws-access-key-id", "slack-token", "google-api-key"}
