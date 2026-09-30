"""Secret detectors: regex patterns + entropy/placeholder filters.

Each Detector is a name, a severity, a compiled pattern, the capture
group that holds the secret value (0 = whole match), and an optional
validator for patterns that need more than a regex (the generic
key=value detector filters on length, Shannon entropy, and obvious
placeholders).

Two rules every detector obeys:
- Findings are deduped by sha256 of the secret value, and the raw value
  is never rendered anywhere. `mask()` is the only preview.
- Case-insensitivity is always a compile flag, never an inline `(?i)`
  mid-pattern (a hard error on Python 3.14).
"""

from __future__ import annotations

import enum
import hashlib
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


class Severity(enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Random ~= secret; English ~= not."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def mask(value: str) -> str:
    """Safe preview: first 4 chars + total length. Never the value."""
    return f"{value[:4]}…({len(value)} chars)"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# Substrings that mark a value as a stand-in, not a live credential.
_PLACEHOLDER_MARKERS = (
    "example", "placeholder", "your_", "xxx", "____", "<", ">", "$", "{{",
)


def _generic_value_ok(value: str) -> bool:
    """Gate for the generic detector: long, high-entropy, not a placeholder.

    The entropy gate (> 3.5 bits/char) is what keeps precision high.
    Nobody cleans up a tool that cries wolf on `NODE_ENV=production`.
    """
    if len(value) < 12:
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return False
    return shannon_entropy(value) > 3.5


@dataclass(frozen=True)
class Detector:
    name: str
    severity: Severity
    pattern: re.Pattern
    group: int = 0  # capture group holding the secret value
    validate: Callable[[str], bool] | None = None


@dataclass
class SecretHit:
    """One secret occurrence inside a single string."""

    detector: Detector
    value: str
    start: int
    end: int


# Order matters: specific detectors first. When spans overlap, the
# earlier detector wins: `ANTHROPIC_API_KEY=sk-ant-…` is claimed by the
# Anthropic detector before the OpenAI or generic patterns can
# double-fire on the same characters.
DETECTORS: list[Detector] = [
    Detector(
        "private-key-block", Severity.HIGH,
        # Capture through the END marker when present so redaction wipes
        # the key material, not just the header line.
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
                   r"(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)?"),
    ),
    Detector(
        "anthropic-api-key", Severity.HIGH,
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ),
    Detector(
        "openai-api-key", Severity.HIGH,
        # Negative lookahead keeps sk-ant-… out of this detector's reach.
        re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    ),
    Detector(
        "github-token", Severity.HIGH,
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
    ),
    Detector(
        "github-fine-grained-pat", Severity.HIGH,
        re.compile(r"github_pat_[A-Za-z0-9_]{50,}"),
    ),
    Detector(
        "aws-access-key-id", Severity.HIGH,
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    Detector(
        "slack-token", Severity.HIGH,
        re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ),
    Detector(
        "stripe-live-key", Severity.HIGH,
        re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    ),
    Detector(
        "google-api-key", Severity.HIGH,
        re.compile(r"AIza[A-Za-z0-9_\-]{35}"),
    ),
    Detector(
        "connection-string", Severity.HIGH,
        re.compile(r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)"
                   r"://[^:\s/]+:[^@\s/]+@", re.IGNORECASE),
    ),
    Detector(
        "jwt", Severity.MEDIUM,
        re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\."
                   r"[A-Za-z0-9_\-]{8,}"),
    ),
    Detector(
        "generic-credential", Severity.MEDIUM,
        # Anchored at a word start with bounded name runs, so the cost is
        # linear in the input: two unbounded `\w*` around the keyword
        # backtracked cubically on text like "token" * 800.
        re.compile(r"""(?<!\w)\w{0,64}?(?:API_KEY|APIKEY|SECRET|TOKEN|PASSWORD"""
                   r"""|PASSWD|PRIVATE_KEY|ACCESS_KEY)\w{0,64}?"""
                   r"""\s*[=:]\s*['"]?([^\s'"`;,]{12,})""",
                   re.IGNORECASE),
        group=1,
        validate=_generic_value_ok,
    ),
]


def find_secrets(text: str) -> list[SecretHit]:
    """All secret occurrences in one string, overlap-deduped.

    Detectors run in priority order; a match whose span overlaps an
    already-claimed span is dropped, so `GITHUB_TOKEN=ghp_…` yields
    exactly one hit (github-token), not a github-token plus a
    generic-credential on the same characters.
    """
    hits: list[SecretHit] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            value = match.group(detector.group)
            if not value:
                continue
            if "[REDACTED:" in value:
                continue  # idempotent: a marker is never a finding
            if detector.validate and not detector.validate(value):
                continue
            start, end = match.span(detector.group)
            if any(start < h.end and h.start < end for h in hits):
                continue
            hits.append(SecretHit(detector, value, start, end))
    hits.sort(key=lambda h: h.start)
    return hits
