"""The patterns that define each shell_exfil rule.

`ShellRule.find` reports exactly the spans these do. They backtrack, and are
quadratic on a long line, so they are kept here and run only on test input.
"""

from __future__ import annotations

import re

from forgd_verdict.detectors.shell_exfil import (
    _ENV_TO_NET,
    _NET_SINK,
    _SENSITIVE_SOURCE,
    _UPLOAD_FLAG,
)

REFERENCE: dict[str, re.Pattern[str]] = {
    "pipe-to-net": re.compile(rf"(?i){_SENSITIVE_SOURCE}[^|;&\n]*[|]\s*{_NET_SINK}"),
    "net-upload-sensitive": re.compile(
        rf"(?i){_NET_SINK}[^\n]*{_UPLOAD_FLAG}[^\n]*{_SENSITIVE_SOURCE}"),
    "env-to-net": _ENV_TO_NET,
    "remote-exec": re.compile(rf"(?i){_NET_SINK}[^\n|]*[|]\s*(?:sudo\s+)?(?:ba|z|d)?sh\b"),
}
