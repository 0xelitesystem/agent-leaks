"""agent-leaks: find and redact secrets your coding agent left in transcripts."""

__version__ = "0.1.0"

from .cli import run_scan  # noqa: E402,F401  (public API)
from .transcripts import redact_file, scan_file  # noqa: E402,F401  (public API)
